#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import harness_check as hc


def find_target_dir(name):
    for root in (ROOT / "harness" / "examples", ROOT / "targets"):
        d = root / name
        if (d / "manifest.yaml").is_file():
            return d
    return None


def file_hash(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        h.update(f.read(65536))
    return h.hexdigest()


def copy_new(source_dirs, corpus_dir, seen, max_size):
    copied = 0
    for src in source_dirs:
        src = Path(src)
        if not src.is_dir():
            continue
        for f in src.rglob("*"):
            if not f.is_file():
                continue
            try:
                if f.stat().st_size > max_size:
                    continue
                h = file_hash(f)
            except OSError:
                continue
            if h in seen:
                continue
            seen.add(h)
            shutil.copy2(f, corpus_dir / (h[:20] + "-sync"))
            copied += 1
    return copied


def engine_cmd_libfuzzer(binary, corpus_dir, crash_dir, fuzz, seconds, crashy):
    cmd = [str(binary), "-max_total_time=%d" % seconds,
           "-timeout=%d" % fuzz["timeout_sec"],
           "-rss_limit_mb=%d" % fuzz["rss_limit_mb"],
           "-malloc_limit_mb=%d" % fuzz["malloc_limit_mb"],
           "-max_len=%d" % fuzz["max_len"],
           "-print_final_stats=1",
           "-artifact_prefix=" + str(crash_dir) + os.sep,
           str(corpus_dir)]
    if crashy:
        cmd += ["-fork=1", "-ignore_crashes=1", "-ignore_ooms=1", "-ignore_timeouts=1"]
    return cmd


def engine_cmd_afl(binary, in_dir, out_dir, dict_path, fuzz, seconds, sanitizer):
    cmd = ["afl-fuzz", "-i", str(in_dir), "-o", str(out_dir),
           "-V", str(seconds)]
    if sanitizer == "address":
        cmd += ["-m", "none"]
    else:
        cmd += ["-m", str(fuzz["rss_limit_mb"])]
    cmd += ["-t", str(fuzz["timeout_sec"] * 1000)]
    if dict_path:
        cmd += ["-x", str(dict_path)]
    cmd += ["--", str(binary)]
    return cmd


def engine_cmd_honggfuzz(binary, in_dir, out_dir, crash_dir, ws_dir, dict_path,
                          fuzz, seconds, sanitizer):
    cmd = ["honggfuzz", "-i", str(in_dir), "-P",
           "--run_time", str(seconds), "-t", str(fuzz["timeout_sec"]),
           "-n", "1", "-W", str(ws_dir), "--crashdir", str(crash_dir),
           "--output", str(out_dir), "-F", str(fuzz["max_len"])]
    if dict_path:
        cmd += ["-w", str(dict_path)]
    if sanitizer != "address":
        cmd += ["--rlimit_as", str(fuzz["rss_limit_mb"])]
    cmd += ["-S", "--", str(binary)]
    return cmd


def run_campaign(target_name, duration_min, engines_wanted, workdir, cov_sample_min,
                 fresh, report_path):
    hc.load_env_file()
    target_dir = find_target_dir(target_name)
    if target_dir is None:
        print("target not found: %s" % target_name)
        return 2
    try:
        manifest = hc.load_manifest(target_dir)
    except hc.ManifestError as e:
        print("manifest error: %s" % e)
        return 2
    fuzz = manifest["fuzz"]
    engines_avail = hc.detect_engines()
    engines = [e for e in (engines_wanted or manifest["engines"])
               if engines_avail.get(e)]
    if not engines:
        print("no available engines for %s" % target_name)
        return 2

    seconds = int(duration_min * 60)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    camp_root = Path(workdir) / target_name / run_id
    camp_root.mkdir(parents=True, exist_ok=True)
    corpus_dir = camp_root / "corpus"
    corpus_dir.mkdir()
    logs_dir = camp_root / "logs"
    logs_dir.mkdir()
    crash_root = camp_root / "crashes"
    crash_root.mkdir()

    corpus_dir, notes, seed_err = hc.ensure_seeds(target_dir, manifest, camp_root)
    if seed_err:
        print("seed error: %s" % seed_err)
        return 2
    seen = set()
    for f in corpus_dir.iterdir():
        if f.is_file():
            seen.add(file_hash(f))
    if not fresh:
        prev = Path(workdir) / target_name / "latest_corpus"
        if prev.is_dir():
            copied = copy_new([prev], corpus_dir, seen, fuzz["max_len"] * 8)
            print("resumed corpus: %d new inputs from %s" % (copied, prev))
    initial_files = len(list(corpus_dir.iterdir()))
    print("[%s] target=%s engines=%s duration=%dmin corpus=%d files"
          % (run_id, target_name, ",".join(engines), duration_min, initial_files))

    binaries = {}
    for engine in engines:
        build_dir = camp_root / ("build-%s" % engine)
        binary, err = hc.build_target(target_dir, manifest, engine, "address",
                                      build_dir, engines_avail)
        if binary is None:
            print("build failed for %s: %s" % (engine, (err or "")[-500:]))
            return 2
        binaries[engine] = binary

    cv_binary, cv_err = hc.build_coverage_binary(target_dir, manifest,
                                                camp_root / "build-coverage",
                                                engines_avail)
    dict_path = target_dir / fuzz["dict"] if fuzz["dict"] else None
    crashy = bool(fuzz["expected_crash"])

    procs = {}
    envs = {}
    sync_sources = []
    if "libfuzzer" in engines:
        crash_dir = crash_root / "libfuzzer"
        crash_dir.mkdir()
        cmd = engine_cmd_libfuzzer(binaries["libfuzzer"], corpus_dir, crash_dir,
                                   fuzz, seconds, crashy)
        envs["libfuzzer"] = hc.sanitizer_env("address", fuzz)
        log = open(logs_dir / "libfuzzer.log", "w")
        procs["libfuzzer"] = subprocess.Popen(cmd, stdout=log, stderr=log,
                                              env={**os.environ,
                                                   **(envs["libfuzzer"] or {})})
    if "aflplusplus" in engines:
        afl_in = camp_root / "afl_in"
        shutil.copytree(corpus_dir, afl_in)
        out_dir = camp_root / "afl_out"
        crash_dir = crash_root / "aflplusplus"
        crash_dir.mkdir()
        cmd = engine_cmd_afl(binaries["aflplusplus"], afl_in, out_dir, dict_path,
                              fuzz, seconds, "address")
        envs["aflplusplus"] = {**hc.AFL_ENV,
                               **(hc.sanitizer_env("address", fuzz, afl=True) or {})}
        log = open(logs_dir / "aflplusplus.log", "w")
        procs["aflplusplus"] = subprocess.Popen(cmd, stdout=log, stderr=log,
                                                env={**os.environ, **envs["aflplusplus"]})
        sync_sources.append(out_dir)
    if "honggfuzz" in engines:
        hf_in = camp_root / "hf_in"
        shutil.copytree(corpus_dir, hf_in)
        hf_out = camp_root / "hf_out"
        hf_ws = camp_root / "hf_ws"
        crash_dir = crash_root / "honggfuzz"
        crash_dir.mkdir()
        cmd = engine_cmd_honggfuzz(binaries["honggfuzz"], hf_in, hf_out, crash_dir,
                                    hf_ws, dict_path, fuzz, seconds, "address")
        log = open(logs_dir / "honggfuzz.log", "w")
        procs["honggfuzz"] = subprocess.Popen(cmd, stdout=log, stderr=log,
                                              env=dict(os.environ))
        sync_sources.append(hf_out)

    start_time = time.time()
    stop = threading.Event()
    sync_state = {"copied": 0}

    def sync_loop():
        while not stop.is_set():
            time.sleep(30)
            sources = []
            for s in sync_sources:
                if "afl" in str(s):
                    for inst in Path(s).iterdir() if Path(s).is_dir() else []:
                        sources.append(inst / "queue")
                else:
                    sources.append(s)
            try:
                sync_state["copied"] += copy_new(sources, corpus_dir, seen,
                                                 fuzz["max_len"] * 4)
            except Exception as e:
                print("sync error: %s" % e)

    samples = []

    def cov_loop():
        if cv_binary is None:
            return
        while not stop.is_set():
            time.sleep(cov_sample_min * 60)
            try:
                r = hc.measure_coverage(cv_binary, corpus_dir,
                                       camp_root / "build-coverage", manifest)
                af = r.get("all_functions")
                if af:
                    samples.append({"t_min": round((time.time() - start_time) / 60, 1),
                                   "reached": af["reached"], "pct": af["pct"],
                                   "corpus_files": len(list(corpus_dir.iterdir()))})
                    print("  [cov t+%.0fmin] reached=%d (%s%%) corpus=%d"
                          % ((time.time() - start_time) / 60, af["reached"], af["pct"],
                             samples[-1]["corpus_files"]))
            except Exception as e:
                print("cov sample error: %s" % e)

    threads = [threading.Thread(target=sync_loop, daemon=True),
               threading.Thread(target=cov_loop, daemon=True)]
    for t in threads:
        t.start()

    deadline = start_time + seconds + 300
    for name, p in procs.items():
        try:
            p.wait(timeout=max(1, deadline - time.time()))
        except subprocess.TimeoutExpired:
            p.kill()
    stop.set()
    for t in threads:
        t.join(timeout=10)
    elapsed = round(time.time() - start_time, 1)

    sources = []
    for s in sync_sources:
        if "afl" in str(s):
            for inst in Path(s).iterdir() if Path(s).is_dir() else []:
                sources.append(inst / "queue")
        else:
            sources.append(s)
    try:
        sync_state["copied"] += copy_new(sources, corpus_dir, seen, fuzz["max_len"] * 4)
    except Exception as e:
        print("final sync error: %s" % e)
    final_files = len(list(corpus_dir.iterdir()))

    final_cov = {}
    if cv_binary is not None:
        try:
            final_cov = hc.measure_coverage(cv_binary, corpus_dir,
                                            camp_root / "build-coverage", manifest)
        except Exception as e:
            final_cov = {"skipped": str(e)}

    engine_stats = {}
    crash_artifacts = {}
    for name in engines:
        log_file = logs_dir / ("%s.log" % name)
        log_text = log_file.read_text(errors="replace") if log_file.is_file() else ""
        stats = {"execs_done": hc.achieved_runs(log_text)}
        if name == "aflplusplus":
            fs = hc.parse_fuzzer_stats(camp_root / "afl_out")
            for k in ("execs_done", "execs_per_sec", "corpus_count", "saved_crashes",
                      "saved_hangs", "stability"):
                if k in fs:
                    stats[k] = fs[k]
        if name == "libfuzzer":
            m = re.search(r"exec/s:\s*(\d+)", log_text)
            if m:
                stats["execs_per_sec"] = int(m.group(1))
        engine_stats[name] = stats
        artifacts = []
        ecrash = crash_root / name
        if ecrash.is_dir():
            artifacts = sorted(p for p in ecrash.iterdir() if p.is_file())
        if name == "aflplusplus":
            artifacts = []
            out_dir = camp_root / "afl_out"
            for inst in out_dir.iterdir() if out_dir.is_dir() else []:
                cd = inst / "crashes"
                if cd.is_dir():
                    artifacts += sorted(p for p in cd.iterdir() if p.name.startswith("id:"))
        crash_artifacts[name] = artifacts

    unique_bugs = {}
    all_crashes = []
    for name in engines:
        artifacts = crash_artifacts[name]
        if not artifacts:
            continue
        uniq, crashes, non_crashes, truncated = hc.crash_lifecycle(
            binaries[name], artifacts, fuzz["timeout_sec"],
            env=hc.sanitizer_env("address", fuzz))
        for c in uniq:
            key = c["stack_hash"]
            if key not in unique_bugs:
                c2 = dict(c)
                c2["engine"] = name
                unique_bugs[key] = c2
        for c in crashes:
            c2 = dict(c)
            c2["engine"] = name
            all_crashes.append(c2)
        engine_stats[name]["crash_files"] = len(artifacts)
        engine_stats[name]["non_reproducible_or_resource"] = len(non_crashes)

    minimized_dir = camp_root / "corpus_min"
    if "libfuzzer" in engines:
        minimized_dir.mkdir()
        cmd = [str(binaries["libfuzzer"]), "-merge=1", "-rss_limit_mb=%d" % fuzz["rss_limit_mb"],
               "-max_total_time=180", "-timeout=%d" % fuzz["timeout_sec"],
               str(minimized_dir), str(corpus_dir)]
        subprocess.run(cmd, capture_output=True, timeout=400,
                       env={**os.environ, **(envs.get("libfuzzer") or {})})
    else:
        shutil.copytree(corpus_dir, minimized_dir)
    minimized_files = len(list(minimized_dir.iterdir()))

    latest = Path(workdir) / target_name / "latest_corpus"
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(minimized_dir, latest)

    report = {
        "schema_version": 1,
        "campaign": {"target": target_name, "run_id": run_id,
                     "duration_min": duration_min, "elapsed_sec": elapsed,
                     "engines": engines, "crashy_target": crashy,
                     "resumed": not fresh and initial_files > 0},
        "corpus": {"initial_files": initial_files, "final_files": final_files,
                   "synced_from_other_engines": sync_state["copied"],
                   "minimized_files": minimized_files},
        "coverage_samples": samples,
        "final_coverage": final_cov,
        "engine_stats": engine_stats,
        "crashes": all_crashes,
        "unique_bugs": list(unique_bugs.values()),
        "campaign_dir": str(camp_root),
    }
    out = Path(report_path) if report_path else Path(workdir) / target_name / "last_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n==== CAMPAIGN %s (%s) ====" % (target_name, run_id))
    print("duration: %.1f min (%ss)" % (elapsed / 60, elapsed))
    print("corpus: %d -> %d files (%d synced) -> %d minimized"
          % (initial_files, final_files, sync_state["copied"], minimized_files))
    cov0 = samples[0] if samples else None
    af_final = (final_cov or {}).get("all_functions") or {}
    if cov0 and af_final:
        print("coverage: %s%% (t+%.0fmin) -> %s%% final | reached %d -> %d"
              % (cov0["pct"], cov0["t_min"], af_final.get("pct"), cov0["reached"],
                 af_final.get("reached")))
    for name in engines:
        print("  %-12s %s" % (name, engine_stats[name]))
    if unique_bugs:
        print("unique bugs: %d" % len(unique_bugs))
        for b in unique_bugs.values():
            print("  [%s] %s: %s" % (b["engine"], b["class"], b["artifact"]))
            print("    repro: %s %s" % (binaries[b["engine"]], b["artifact"]))
    else:
        print("unique bugs: 0")
    print("report: %s" % out)
    print("campaign dir: %s" % camp_root)
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="AIFuzz campaign runner: multi-engine parallel fuzzing with shared corpus, coverage sampling, crash aggregation and corpus minimization",
        epilog="campaigns stack: each run resumes workdir/<target>/latest_corpus from the previous campaign (use --fresh to start over)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--duration", type=float, required=True, help="minutes")
    ap.add_argument("--engines", help="comma separated subset of manifest engines")
    ap.add_argument("--workdir", default=str(Path.home() / ".aifuzz" / "campaigns"))
    ap.add_argument("--cov-sample", type=float, default=5, help="minutes between coverage samples")
    ap.add_argument("--fresh", action="store_true", help="do not resume previous campaign corpus")
    ap.add_argument("--json", default=None)
    opts = ap.parse_args()
    engines_wanted = [e for e in (opts.engines or "").split(",") if e] or None
    return run_campaign(opts.target, opts.duration, engines_wanted, opts.workdir,
                        opts.cov_sample, opts.fresh, opts.json)


if __name__ == "__main__":
    sys.exit(main())
