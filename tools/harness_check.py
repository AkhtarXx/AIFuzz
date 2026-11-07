#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE_DIR = ROOT / "harness" / "include"

SCHEMA_VERSION = 2
AIFUZZ_VERSION = "0.1.0"

MANIFEST_TOP_KEYS = {"name", "description", "language", "sources", "fuzz", "build",
                     "engines", "sanitizers", "tags"}
FUZZ_KEYS = {"max_len", "timeout_sec", "dict", "seeds", "seed_gen", "expected_crash",
             "rss_limit_mb", "malloc_limit_mb", "custom_mutator", "allocator_may_return_null"}
BUILD_KEYS = {"cflags", "ldflags"}
LANGUAGES = {"c", "cpp"}
KNOWN_ENGINES = {"libfuzzer", "aflplusplus", "honggfuzz"}
KNOWN_SANITIZERS = {"address", "undefined"}

STAT_RES = [
    re.compile(r"#\d+\s+\w+\s+cov:\s*(\d+)\s+ft:\s*(\d+)"),
    re.compile(r"#\d+:\s+cov:\s*(\d+)\s+ft:\s*(\d+)"),
]
EXECS_RE = re.compile(r"exec/s:\s*(\d+)")
RUNS_RE = re.compile(r"#(\d+)[\s:]")

LINT_RULES = [
    ("error", re.compile(r"\bexit\s*\("), "exit() breaks the fuzz loop"),
    ("error", re.compile(r"\b_exit\s*\("), "_exit() breaks the fuzz loop"),
    ("error", re.compile(r"\bsystem\s*\("), "system() is forbidden in targets"),
    ("error", re.compile(r"\bsrand\s*\("), "srand() breaks determinism"),
    ("error", re.compile(r"\brand\s*\(\s*\)"), "rand() breaks determinism"),
    ("error", re.compile(r"\brand_r\s*\("), "rand_r() breaks determinism"),
    ("error", re.compile(r"\btime\s*\(\s*(?:NULL|0)\s*\)"), "time() breaks determinism"),
    ("error", re.compile(r"\blongjmp\s*\("), "longjmp escapes the harness contract"),
    ("warn", re.compile(r"\babort\s*\("), "abort() must only be reachable by the bug itself"),
    ("warn", re.compile(r"\bclock_gettime\s*\("), "clock_gettime can break determinism"),
    ("warn", re.compile(r"\bgettimeofday\s*\("), "gettimeofday can break determinism"),
    ("warn", re.compile(r"\bgetenv\s*\("), "getenv() can break determinism"),
    ("warn", re.compile(r"\bfopen\s*\("), "file I/O slows fuzzing"),
    ("warn", re.compile(r"\bprintf\s*\("), "printf slows fuzzing"),
    ("warn", re.compile(r"\bpthread_create\s*\("), "threads must be joined before return"),
]

AFL_ENV = {
    "AFL_NO_UI": "1",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    "AFL_SKIP_CPUFREQ": "1",
    "AFL_NO_AFFINITY": "1",
    "AFL_FAST_CAL": "1",
}

AFL_DRIVER_CANDIDATES = [
    "/usr/local/lib/libAFLDriver.a",
    "/usr/lib/libAFLDriver.a",
    "/usr/lib/afl/libAFLDriver.a",
]

AFL_STABILITY_MIN = 90.0
SPEED_MIN_EXEC_PER_SEC = 50


class ManifestError(Exception):
    pass


def fresh_dir(path):
    path = Path(path)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def run_cmd(cmd, env=None, timeout=600, cwd=None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(cmd, capture_output=True, text=True, env=full_env,
                          timeout=timeout, cwd=cwd)


def run_gate(cmd, env=None, timeout=600, cwd=None):
    try:
        return run_cmd(cmd, env=env, timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired as e:
        so = e.stdout if isinstance(e.stdout, str) else (e.stdout or b"").decode("utf-8", "replace")
        se = e.stderr if isinstance(e.stderr, str) else (e.stderr or b"").decode("utf-8", "replace")
        return subprocess.CompletedProcess(
            cmd, -124, so,
            se + "\nAIFUZZ-TIMEOUT: process exceeded wall guard (%ss)" % timeout)


def clang_version(cc):
    try:
        r = run_cmd([cc, "--version"], timeout=30)
        out = r.stdout or r.stderr
        return out.splitlines()[0].strip()[:120] if out else "?"
    except Exception:
        return "?"


def strip_c_comments(text):
    out = []
    i = 0
    n = len(text)
    state = "code"
    quote = ""
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
                continue
            if c in "\"'":
                state = "str"
                quote = c
                out.append(c)
                i += 1
                continue
            out.append(c)
            i += 1
        elif state == "line":
            if c == "\\" and nxt == "\n":
                out.append("  \n")
                i += 2
                continue
            if c == "\n":
                state = "code"
                out.append(c)
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
                continue
            out.append(c if c == "\n" else " ")
            i += 1
        else:
            if c == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if c == quote:
                state = "code"
                out.append(c)
            else:
                out.append(" ")
            i += 1
    return "".join(out)


def validate_manifest(m):
    errors = []
    if not isinstance(m, dict):
        return ["manifest root must be a mapping"]
    unknown = sorted(set(m) - MANIFEST_TOP_KEYS)
    if unknown:
        errors.append("unknown manifest key(s): %s" % ", ".join(map(str, unknown)))
    name = m.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("name must be a non-empty string")
    elif "/" in name or "\\" in name:
        errors.append("name must not contain path separators")
    if not isinstance(m.get("description"), str) or not m.get("description", "").strip():
        errors.append("description must be a non-empty string")
    if m.get("language") not in LANGUAGES:
        errors.append("language must be one of: %s" % ", ".join(sorted(LANGUAGES)))
    srcs = m.get("sources")
    if not isinstance(srcs, list) or not srcs or not all(isinstance(s, str) and s.strip() for s in srcs):
        errors.append("sources must be a non-empty list of file names")
    engines = m.get("engines")
    if not isinstance(engines, list) or not engines:
        errors.append("engines must be a non-empty list")
    else:
        bad = [str(e) for e in engines if e not in KNOWN_ENGINES]
        if bad:
            errors.append("unknown engine(s): %s (known: %s)" % (", ".join(bad), ", ".join(sorted(KNOWN_ENGINES))))
    sanitizers = m.get("sanitizers")
    if not isinstance(sanitizers, list) or not sanitizers:
        errors.append("sanitizers must be a non-empty list")
    else:
        bad = [str(s) for s in sanitizers if s not in KNOWN_SANITIZERS]
        if bad:
            errors.append("unknown sanitizer(s): %s (known: %s)" % (", ".join(bad), ", ".join(sorted(KNOWN_SANITIZERS))))
    tags = m.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        errors.append("tags must be a list of strings")
    fuzz = m.get("fuzz", {})
    if not isinstance(fuzz, dict):
        errors.append("fuzz must be a mapping")
        fuzz = {}
    else:
        unknown = sorted(set(fuzz) - FUZZ_KEYS)
        if unknown:
            errors.append("unknown fuzz key(s): %s" % ", ".join(map(str, unknown)))
        for key, lo, hi in (("max_len", 1, 10000000), ("timeout_sec", 1, 3600),
                            ("rss_limit_mb", 64, 262144), ("malloc_limit_mb", 64, 262144)):
            v = fuzz.get(key)
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi):
                errors.append("fuzz.%s must be an integer in [%d, %d]" % (key, lo, hi))
    build = m.get("build", {})
    if not isinstance(build, dict):
        errors.append("build must be a mapping")
    else:
        unknown = sorted(set(build) - BUILD_KEYS)
        if unknown:
            errors.append("unknown build key(s): %s" % ", ".join(map(str, unknown)))
        for key in ("cflags", "ldflags"):
            v = build.get(key, [])
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                errors.append("build.%s must be a list of strings" % key)
    if "custom_mutator" in fuzz and not isinstance(fuzz["custom_mutator"], bool):
        errors.append("fuzz.custom_mutator must be a boolean")
    if "allocator_may_return_null" in fuzz and not isinstance(fuzz["allocator_may_return_null"], bool):
        errors.append("fuzz.allocator_may_return_null must be a boolean")
    if "expected_crash" in fuzz and not isinstance(fuzz["expected_crash"], bool):
        errors.append("fuzz.expected_crash must be a boolean")
    if fuzz.get("expected_crash") is True:
        sanitizers = m.get("sanitizers")
        if isinstance(sanitizers, list) and "address" not in sanitizers:
            errors.append("expected_crash targets must include the address sanitizer (crash-hunt gate runs only under ASan)")
    for key in ("dict", "seeds", "seed_gen"):
        if fuzz.get(key) is not None and not isinstance(fuzz.get(key), str):
            errors.append("fuzz.%s must be a file/dir name or null" % key)
    return errors


def load_manifest(target_dir):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required: sudo apt-get install -y python3-yaml")
    manifest_path = target_dir / "manifest.yaml"
    if not manifest_path.is_file():
        return None
    raw = manifest_path.read_text(encoding="utf-8")
    try:
        import yaml
        m = yaml.safe_load(raw) or {}
    except Exception as e:
        first = str(e).splitlines()[0] if str(e) else "parse error"
        raise ManifestError("invalid YAML: %s" % first)
    errors = validate_manifest(m)
    if errors:
        raise ManifestError("; ".join(errors))
    fuzz = dict(m.get("fuzz") or {})
    fuzz.setdefault("max_len", 4096)
    fuzz.setdefault("timeout_sec", 25)
    fuzz.setdefault("dict", None)
    fuzz.setdefault("seeds", None)
    fuzz.setdefault("seed_gen", None)
    fuzz.setdefault("expected_crash", False)
    fuzz.setdefault("rss_limit_mb", 2560)
    fuzz.setdefault("malloc_limit_mb", fuzz["rss_limit_mb"])
    fuzz.setdefault("custom_mutator", False)
    fuzz.setdefault("allocator_may_return_null", False)
    m["fuzz"] = fuzz
    build = dict(m.get("build") or {})
    build.setdefault("cflags", [])
    build.setdefault("ldflags", [])
    m["build"] = build
    m.setdefault("tags", [])
    for src in m["sources"]:
        if not (target_dir / src).is_file():
            raise ManifestError("source file missing: %s" % src)
    if fuzz["dict"] is not None and not (target_dir / fuzz["dict"]).is_file():
        raise ManifestError("dictionary file missing: %s" % fuzz["dict"])
    if fuzz["seeds"] is not None and not (target_dir / fuzz["seeds"]).is_dir():
        raise ManifestError("seeds dir missing: %s" % fuzz["seeds"])
    if fuzz["seed_gen"] is not None and not (target_dir / fuzz["seed_gen"]).is_file():
        raise ManifestError("seed_gen script missing: %s" % fuzz["seed_gen"])
    return m


def probe_libfuzzer():
    cc = shutil.which("clang")
    if not cc:
        return None
    tmpd = Path(tempfile.mkdtemp(prefix="aifuzz-probe-"))
    try:
        probe_src = tmpd / "probe.c"
        probe_src.write_text(
            "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s){return 0;}\n",
            encoding="utf-8")
        r = run_cmd([cc, "-fsanitize=fuzzer", str(probe_src), "-o", str(tmpd / "probe.out")],
                    timeout=120)
        if r.returncode == 0:
            return {"cc": cc, "detail": clang_version(cc)}
        return None
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def find_afl_driver():
    for cand in AFL_DRIVER_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return None


def detect_engines():
    engines = {}
    engines["libfuzzer"] = probe_libfuzzer()
    afl_cc = shutil.which("afl-clang-fast")
    driver = find_afl_driver()
    if afl_cc and driver:
        engines["aflplusplus"] = {"cc": afl_cc, "driver": driver, "detail": clang_version(afl_cc)}
    else:
        engines["aflplusplus"] = None
    hf_cc = shutil.which("hfuzz-clang")
    engines["honggfuzz"] = {"cc": hf_cc, "detail": clang_version(hf_cc)} if hf_cc else None
    return engines


def sanitizer_flags(sanitizer):
    if sanitizer == "address":
        return ["-fsanitize=address"]
    if sanitizer == "undefined":
        return ["-fsanitize=undefined", "-fno-sanitize-recover=all"]
    return []


def ensure_seeds(target_dir, manifest, work):
    fuzz = manifest["fuzz"]
    corpus = fresh_dir(work / "corpus")
    notes = []
    seeds_rel = fuzz.get("seeds")
    tree_seeds = target_dir / seeds_rel if seeds_rel else None
    have = False
    if tree_seeds is not None and tree_seeds.is_dir():
        files = [p for p in sorted(tree_seeds.iterdir()) if p.is_file()]
        if files:
            for f in files:
                shutil.copy2(f, corpus / f.name)
            have = True
        else:
            notes.append("declared seeds dir is empty")
    gen = fuzz.get("seed_gen")
    if not have and gen:
        gen_out = fresh_dir(work / "gen_seeds")
        r = run_gate([sys.executable, str(target_dir / gen), str(gen_out)], timeout=180)
        if r.returncode != 0:
            return corpus, notes, "seed_gen failed: %s" % ((r.stderr or r.stdout or "")[-500:])
        produced = 0
        for f in sorted(gen_out.iterdir()):
            if f.is_file():
                shutil.copy2(f, corpus / f.name)
                produced += 1
        if produced == 0:
            notes.append("seed_gen produced no seeds")
        have = True
    if not have:
        notes.append("no seeds available; starting from empty corpus")
    return corpus, notes, None


def load_env_file():
    env_path = Path.home() / ".aifuzz" / "env.sh"
    if not env_path.is_file():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[7:]
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def expand_flags(flags):
    return [os.path.expandvars(f) for f in flags]


def build_target(target_dir, manifest, engine, sanitizer, build_dir, engines):
    build_dir.mkdir(parents=True, exist_ok=True)
    lang = manifest["language"]
    common = ["-g", "-O1", "-fno-omit-frame-pointer", "-I" + str(INCLUDE_DIR)]
    common += expand_flags(list(manifest.get("build", {}).get("cflags", [])))
    ldflags = expand_flags(list(manifest.get("build", {}).get("ldflags", [])))
    sflags = sanitizer_flags(sanitizer)
    objects = []
    if engine == "libfuzzer":
        cc = engines["libfuzzer"]["cc"]
        cxx = cc + "++" if not cc.endswith("++") else cc
        compiler = cc if lang == "c" else cxx
        for src in manifest["sources"]:
            obj = build_dir / (Path(src).stem + ".o")
            r = run_gate([compiler, "-c", str(target_dir / src), "-o", str(obj)]
                        + common + sflags + ["-fsanitize=fuzzer-no-link"])
            if r.returncode != 0:
                return None, r.stderr[-4000:]
            objects.append(str(obj))
        binary = build_dir / "fuzz_target"
        r = run_gate([compiler] + objects + sflags + ["-fsanitize=fuzzer"] + ldflags +
                     ["-o", str(binary)])
        if r.returncode != 0:
            return None, r.stderr[-4000:]
        return binary, None
    if engine == "aflplusplus":
        info = engines.get("aflplusplus")
        if not info:
            return None, "afl-clang-fast or libAFLDriver.a missing"
        cc = info["cc"]
        cxx = cc + "++" if not cc.endswith("++") else cc
        compiler = cc if lang == "c" else cxx
        for src in manifest["sources"]:
            obj = build_dir / (Path(src).stem + ".o")
            r = run_gate([compiler, "-c", str(target_dir / src), "-o", str(obj)]
                        + common + sflags)
            if r.returncode != 0:
                return None, r.stderr[-4000:]
            objects.append(str(obj))
        binary = build_dir / "fuzz_target"
        r = run_gate([compiler] + objects + sflags + [info["driver"]] + ldflags +
                     ["-o", str(binary)])
        if r.returncode != 0:
            return None, r.stderr[-4000:]
        return binary, None
    if engine == "honggfuzz":
        info = engines.get("honggfuzz")
        if not info:
            return None, "hfuzz-clang missing"
        cc = info["cc"]
        cxx = cc + "++" if not cc.endswith("++") else cc
        compiler = cc if lang == "c" else cxx
        binary = build_dir / "fuzz_target"
        cmd = [compiler]
        for src in manifest["sources"]:
            cmd.append(str(target_dir / src))
        cmd += common + sflags + ldflags + ["-o", str(binary)]
        r = run_gate(cmd)
        if r.returncode != 0:
            return None, r.stderr[-4000:]
        return binary, None
    return None, "unknown engine %s" % engine


def parse_libfuzzer_stats(out):
    cov = ft = 0
    for rx in STAT_RES:
        for m in rx.finditer(out):
            if int(m.group(1)) > cov:
                cov = int(m.group(1))
            if int(m.group(2)) > ft:
                ft = int(m.group(2))
    execs = 0
    for m in EXECS_RE.finditer(out):
        execs = int(m.group(1))
    return cov, ft, execs


def achieved_runs(out):
    best = 0
    for m in RUNS_RE.finditer(out):
        v = int(m.group(1))
        if v > best:
            best = v
    return best


def sanitizer_env(sanitizer, fuzz, afl=False):
    if sanitizer != "address":
        return None
    opts = "max_allocation_size_mb=%d" % fuzz["malloc_limit_mb"]
    if fuzz.get("allocator_may_return_null"):
        opts += ":allocator_may_return_null=1"
    if afl:
        opts = "abort_on_error=1:symbolize=0:detect_leaks=0:" + opts
    return {"ASAN_OPTIONS": opts}


def classify_run(rc, out):
    if "AIFUZZ-TIMEOUT" in out or rc == -124:
        return "wall-timeout"
    if "allocation-size-too-big" in out or "exceeds maximum supported size" in out:
        return "oom"
    if "ERROR: AddressSanitizer:" in out:
        return "asan-crash"
    if "ERROR: LeakSanitizer" in out or "ERROR: libFuzzer: leak" in out:
        return "leak"
    if "ERROR: libFuzzer: out-of-memory" in out or rc == 71:
        return "oom"
    if "ERROR: libFuzzer: timeout" in out or rc == 70:
        return "timeout"
    if "runtime error:" in out or "SUMMARY: UndefinedBehaviorSanitizer" in out:
        return "ubsan"
    if "ERROR: libFuzzer: deadly signal" in out:
        return "signal"
    if rc != 0:
        return "exit-code-%d" % rc
    return None


def libfuzzer_run(binary, corpus_dir, fuzz, scratch_dir, seed, runs, box, sanitizer=None):
    scratch = fresh_dir(scratch_dir)
    stray = scratch / "artifacts"
    stray.mkdir(parents=True, exist_ok=True)
    t = fuzz["timeout_sec"]
    cmd = [str(binary), "-runs=%d" % runs, "-seed=%d" % seed,
           "-timeout=%d" % t, "-rss_limit_mb=%d" % fuzz["rss_limit_mb"],
           "-malloc_limit_mb=%d" % fuzz["malloc_limit_mb"],
           "-max_len=%d" % fuzz["max_len"], "-max_total_time=%d" % box,
           "-artifact_prefix=" + str(stray) + os.sep,
           str(scratch), str(corpus_dir)]
    r = run_gate(cmd, env=sanitizer_env(sanitizer, fuzz),
                 timeout=box + 2 * t + 120)
    out = r.stdout + r.stderr
    cov, ft, _ = parse_libfuzzer_stats(out)
    return {"rc": r.returncode, "cov": cov, "ft": ft, "out": out,
            "issue": classify_run(r.returncode, out)}


def crash_tolerated(issue, expect_crash):
    return expect_crash and issue in ("asan-crash", "signal")


def libfuzzer_smoke(binary, corpus_dir, fuzz, scratch_dir, runs, box, expect_crash=False,
                    sanitizer=None):
    r = libfuzzer_run(binary, corpus_dir, fuzz, scratch_dir, 1, runs, box, sanitizer)
    ok = (r["rc"] == 0 and r["issue"] is None) or crash_tolerated(r["issue"], expect_crash)
    return {"ok": ok, "issue": r["issue"], "cov": r["cov"], "ft": r["ft"],
            "early_crash": crash_tolerated(r["issue"], expect_crash),
            "tail": r["out"][-800:]}


def libfuzzer_speed(binary, fuzz, scratch_dir, runs, box, expect_crash=False, sanitizer=None):
    base = fresh_dir(scratch_dir)
    empty_corpus = fresh_dir(base / "empty_corpus")
    start = time.time()
    r = libfuzzer_run(binary, empty_corpus, fuzz, base / "scratch", 42, runs, box, sanitizer)
    elapsed = time.time() - start
    done = achieved_runs(r["out"])
    rate = int(done / elapsed) if elapsed > 0 else 0
    ok = rate >= SPEED_MIN_EXEC_PER_SEC and (
        r["issue"] is None or crash_tolerated(r["issue"], expect_crash))
    return {"exec_per_sec": rate, "ok": ok, "issue": r["issue"],
            "early_crash": crash_tolerated(r["issue"], expect_crash)}


def libfuzzer_stability(binary, corpus_dir, fuzz, work, runs, box, expect_crash=False,
                        sanitizer=None):
    a = libfuzzer_run(binary, corpus_dir, fuzz, work / "stab_a", 7, runs, box, sanitizer)
    b = libfuzzer_run(binary, corpus_dir, fuzz, work / "stab_b", 7, runs, box, sanitizer)
    delta = abs(a["cov"] - b["cov"]) + abs(a["ft"] - b["ft"])
    issues_ok = all(crash_tolerated(x["issue"], expect_crash) or x["issue"] is None
                    for x in (a, b))
    return {"ok": delta == 0 and issues_ok,
            "cov_delta": delta, "cov": b["cov"], "ft": b["ft"],
            "issue": a["issue"] or b["issue"],
            "early_crash": crash_tolerated(a["issue"] or b["issue"], expect_crash)}


def classify_crash_output(text):
    if "AIFUZZ-TIMEOUT" in text:
        cls = "wall-timeout"
    elif "allocation-size-too-big" in text or "exceeds maximum supported size" in text:
        cls = "oom"
    elif "ERROR: AddressSanitizer:" in text:
        m = re.search(r"ERROR: AddressSanitizer:\s*(\S+)", text)
        cls = "asan-" + (m.group(1) if m else "unknown")
    elif "runtime error:" in text or "SUMMARY: UndefinedBehaviorSanitizer" in text:
        cls = "ubsan"
    elif "ERROR: LeakSanitizer" in text or "ERROR: libFuzzer: leak" in text:
        cls = "leak"
    elif "ERROR: libFuzzer: out-of-memory" in text:
        cls = "oom"
    elif "ERROR: libFuzzer: timeout" in text:
        cls = "timeout"
    elif "ERROR: libFuzzer: deadly signal" in text:
        cls = "signal"
    else:
        cls = "unknown"
    frames = re.findall(r"#\d+\s+0x[0-9a-f]+\s+in\s+([^\n]+)", text)
    if cls == "ubsan":
        m = re.search(r"SUMMARY: UndefinedBehaviorSanitizer:\s*([^\n]+)", text)
        if m:
            frames = [m.group(1).strip()] + frames
    return cls, [f.strip() for f in frames[:5]]


def stack_hash(cls, frames):
    key = cls + "|" + "|".join(f.strip() for f in frames[:3])
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]


def replay_once(binary, artifact, timeout_sec, env=None):
    r = run_gate([str(binary), str(artifact)], timeout=2 * timeout_sec + 60, env=env)
    out = r.stdout + r.stderr
    crashed = r.returncode != 0 or "ERROR:" in out or "runtime error:" in out
    cls, frames = classify_crash_output(out)
    return crashed, cls, frames


def crash_lifecycle(binary, artifacts, timeout_sec, budget_sec=300, env=None):
    crashes = []
    non_crashes = []
    truncated = False
    start = time.time()
    for art in artifacts[:20]:
        if time.time() - start > budget_sec:
            truncated = True
            non_crashes.append({"artifact": str(art), "class": "replay-budget-exceeded",
                                "deterministic": None})
            continue
        results = [replay_once(binary, art, timeout_sec, env) for _ in range(3)]
        all_crash = all(c for c, _, _ in results)
        cls = results[0][1]
        frames = results[0][2]
        if not all_crash:
            non_crashes.append({"artifact": str(art), "class": cls or "non-reproducible",
                                "deterministic": False})
            continue
        if cls in ("oom", "timeout", "leak", "wall-timeout"):
            non_crashes.append({"artifact": str(art), "class": cls, "deterministic": True})
            continue
        crashes.append({"artifact": str(art), "class": cls, "top_frames": frames,
                        "stack_hash": stack_hash(cls, frames), "deterministic": True})
    uniq = {}
    for c in crashes:
        uniq.setdefault(c["stack_hash"], c)
    return list(uniq.values()), crashes, non_crashes, truncated


def libfuzzer_hunt(binary, corpus_dir, dict_path, fuzz, seconds, artifact_dir, campaign_dir,
                  sanitizer=None):
    artifact_dir = fresh_dir(artifact_dir)
    campaign_dir = fresh_dir(campaign_dir)
    cmd = [str(binary), "-max_total_time=%d" % seconds,
           "-timeout=%d" % fuzz["timeout_sec"],
           "-rss_limit_mb=%d" % fuzz["rss_limit_mb"],
           "-malloc_limit_mb=%d" % fuzz["malloc_limit_mb"],
           "-max_len=%d" % fuzz["max_len"],
           "-artifact_prefix=" + str(artifact_dir) + os.sep,
           str(campaign_dir), str(corpus_dir)]
    if dict_path:
        cmd.insert(1, "-dict=" + str(dict_path))
    start = time.time()
    r = run_gate(cmd, env=sanitizer_env(sanitizer, fuzz),
                 timeout=seconds + 2 * fuzz["timeout_sec"] + 120)
    elapsed = time.time() - start
    artifacts = sorted(p for p in artifact_dir.iterdir() if p.is_file())
    return artifacts, round(elapsed, 1), r


def afl_replay_smoke(binary, corpus_dir, expect_crash=False, env=None):
    files = sorted(p for p in corpus_dir.iterdir() if p.is_file())
    args = [str(binary)] + [str(f) for f in files]
    start = time.time()
    r = run_gate(args, timeout=120, env=env)
    elapsed = time.time() - start
    rate = round(len(files) / elapsed, 1) if elapsed > 0 else 0
    out = r.stdout + r.stderr
    issue = classify_run(r.returncode, out)
    ok = (r.returncode == 0 and issue is None) or crash_tolerated(issue, expect_crash)
    return {"ok": ok, "issue": issue,
            "early_crash": crash_tolerated(issue, expect_crash),
            "replay_per_sec": rate, "replayed": len(files),
            "tail": out[-800:]}


def parse_fuzzer_stats(out_dir):
    stats = {}
    for inst in sorted(Path(out_dir).iterdir()):
        f = inst / "fuzzer_stats"
        if f.is_file():
            for line in f.read_text(errors="replace").splitlines():
                if " : " in line:
                    k, v = line.split(" : ", 1)
                    stats[k.strip()] = v.strip()
            break
    return stats


def afl_hunt(binary, corpus_dir, dict_path, seconds, out_dir, fuzz, sanitizer):
    out_dir = fresh_dir(out_dir)
    if sanitizer == "address":
        mem_arg = ["-m", "none"]
    else:
        mem_arg = ["-m", str(fuzz["rss_limit_mb"])]
    cmd = ["afl-fuzz", "-i", str(corpus_dir), "-o", str(out_dir),
           "-V", str(seconds)] + mem_arg + ["-t", str(fuzz["timeout_sec"] * 1000)]
    if dict_path:
        cmd += ["-x", str(dict_path)]
    cmd += ["--", str(binary)]
    start = time.time()
    merged_env = dict(AFL_ENV)
    senv = sanitizer_env(sanitizer, fuzz, afl=True)
    if senv:
        merged_env.update(senv)
    r = run_gate(cmd, env=merged_env, timeout=seconds + 300)
    elapsed = time.time() - start
    stats = parse_fuzzer_stats(out_dir)
    crash_files = []
    for inst in out_dir.iterdir():
        cd = inst / "crashes"
        if cd.is_dir():
            crash_files += sorted(p for p in cd.iterdir()
                                 if p.is_file() and p.name.startswith("id:"))
    return crash_files, round(elapsed, 1), stats


def honggfuzz_campaign(binary, corpus_dir, dict_path, seconds, work_dir, fuzz, sanitizer):
    workspace = fresh_dir(work_dir / "workspace")
    crashdir = fresh_dir(work_dir / "crashes")
    out_dir = fresh_dir(work_dir / "out")
    cmd = ["honggfuzz", "-i", str(corpus_dir), "-P",
           "--run_time", str(seconds), "-t", str(fuzz["timeout_sec"]),
           "-n", "1", "-W", str(workspace), "--crashdir", str(crashdir),
           "--output", str(out_dir), "-F", str(fuzz["max_len"])]
    if dict_path:
        cmd += ["-w", str(dict_path)]
    if sanitizer != "address":
        cmd += ["--rlimit_as", str(fuzz["rss_limit_mb"])]
    cmd += ["-S", "--", str(binary)]
    start = time.time()
    r = run_gate(cmd, timeout=seconds + 300)
    elapsed = time.time() - start
    crash_files = sorted(p for p in crashdir.iterdir() if p.is_file())
    return crash_files, round(elapsed, 1), r


def lint_target(target_dir, manifest):
    findings = []
    abi_seen = False
    for src in manifest["sources"]:
        text = (target_dir / src).read_text(encoding="utf-8", errors="replace")
        if "LLVMFuzzerTestOneInput" in text:
            abi_seen = True
        stripped = strip_c_comments(text)
        for sev, rx, msg in LINT_RULES:
            for i, line in enumerate(stripped.splitlines(), 1):
                if rx.search(line):
                    findings.append({"severity": sev, "file": src, "line": i, "message": msg})
    if not abi_seen:
        findings.append({"severity": "error", "file": manifest["sources"][0], "line": 0,
                         "message": "missing LLVMFuzzerTestOneInput entry point"})
    return findings


def has_lint_errors(findings):
    return any(f["severity"] == "error" for f in findings)


def hunt_gate(binary, artifacts, elapsed, timeout_sec, engine_label, env=None):
    unique, all_crashes, non_crashes, truncated = crash_lifecycle(
        binary, artifacts, timeout_sec, env=env)
    gate = {"found": bool(unique), "seconds": elapsed,
            "unique_bugs": len(unique), "crash_count": len(all_crashes),
            "non_crashes": non_crashes, "replay_truncated": truncated,
            "crashes": unique}
    if unique:
        gate["repro_cmd"] = "%s %s" % (binary, unique[0]["artifact"])
        gate["crash_class"] = unique[0]["class"]
    return gate


def custom_mutator_check(binary, corpus_dir, fuzz, work, sanitizer):
    scratch = fresh_dir(work / "mutcheck")
    r = libfuzzer_run(binary, corpus_dir, fuzz, scratch, 7, 500, 20, sanitizer)
    activated = "Custom" in r["out"]
    return {"ok": activated, "early_crash": r["issue"] is not None}


def coverage_measure(target_dir, manifest, corpus_dir, work, engines):
    fuzz = manifest["fuzz"]
    if not engines.get("libfuzzer"):
        return {"skipped": "libFuzzer toolchain unavailable"}
    build_dir = work / "build-coverage"
    fresh_dir(build_dir)
    cc = engines["libfuzzer"]["cc"]
    common = ["-g", "-O1", "-fno-omit-frame-pointer", "-I" + str(INCLUDE_DIR)]
    common += expand_flags(list(manifest.get("build", {}).get("cflags", [])))
    cov_flags = ["-fprofile-instr-generate", "-fcoverage-mapping"]
    objects = []
    for src in manifest["sources"]:
        obj = build_dir / (Path(src).stem + ".o")
        r = run_gate([cc, "-c", str(target_dir / src), "-o", str(obj)] + common + cov_flags)
        if r.returncode != 0:
            return {"skipped": "coverage build failed"}
        objects.append(str(obj))
    binary = build_dir / "fuzz_target"
    r = run_gate([cc] + objects + cov_flags + ["-fsanitize=fuzzer", "-fsanitize=address"]
                 + expand_flags(list(manifest.get("build", {}).get("ldflags", [])))
                 + ["-o", str(binary)])
    if r.returncode != 0:
        return {"skipped": "coverage link failed"}
    files = sorted(p for p in corpus_dir.iterdir() if p.is_file())
    if not files:
        return {"skipped": "empty corpus"}
    profraw = build_dir / "cov.profraw"
    r = run_gate([str(binary)] + [str(f) for f in files],
                 env={"LLVM_PROFILE_FILE": str(profraw)},
                 timeout=fuzz["timeout_sec"] * (len(files) + 5) + 120)
    if not profraw.is_file():
        return {"skipped": "no profile written"}
    profdata = build_dir / "cov.profdata"
    r = run_gate(["llvm-profdata", "merge", "-sparse", str(profraw), "-o", str(profdata)])
    if r.returncode != 0:
        return {"skipped": "profdata merge failed"}
    r = run_gate(["llvm-cov", "export", str(binary), "-instr-profile=" + str(profdata)])
    if r.returncode != 0:
        return {"skipped": "llvm-cov export failed"}
    try:
        data = json.loads(r.stdout)
    except ValueError:
        return {"skipped": "llvm-cov json parse failed"}
    source_names = set(manifest["sources"])
    total = 0
    reached = 0
    bin_total = 0
    bin_reached = 0
    for region in data.get("data", []):
        for fn in region.get("functions", []):
            bin_total += 1
            if fn.get("count", 0) > 0:
                bin_reached += 1
            fnames = fn.get("filenames", [])
            if not any(any(f.endswith(s) for s in source_names) for f in fnames):
                continue
            total += 1
            if fn.get("count", 0) > 0:
                reached += 1
    result = {}
    if total > 0:
        result["harness"] = {"reached": reached, "total": total,
                            "pct": round(100.0 * reached / total, 1)}
    if bin_total > 0:
        result["all_functions"] = {"reached": bin_reached, "total": bin_total,
                                  "pct": round(100.0 * bin_reached / bin_total, 1)}
    if not result:
        return {"skipped": "no functions found"}
    return result


def validate_target(target_dir, manifest, opts, engines):
    name = manifest["name"]
    work = Path(opts.workdir) / "targets" / name
    fresh_dir(work)
    fuzz = manifest["fuzz"]
    corpus_dir, notes, seed_err = ensure_seeds(target_dir, manifest, work)
    results = []
    if seed_err:
        return {"name": name, "status": "fail", "reason": seed_err,
                "notes": notes, "lint": [], "results": []}
    dict_path = target_dir / fuzz["dict"] if fuzz["dict"] else None
    corpus_size = len([p for p in corpus_dir.iterdir() if p.is_file()])
    runs_eff = opts.smoke_runs + corpus_size

    findings = lint_target(target_dir, manifest)
    lint_ok = not has_lint_errors(findings)

    for engine in manifest["engines"]:
        if opts.engines and engine not in opts.engines:
            continue
        for sanitizer in manifest["sanitizers"]:
            if opts.sanitizers and sanitizer not in opts.sanitizers:
                continue
            entry = {"engine": engine, "sanitizer": sanitizer, "gates": {},
                     "limits": {"max_len": fuzz["max_len"], "timeout_sec": fuzz["timeout_sec"],
                                "rss_limit_mb": fuzz["rss_limit_mb"],
                                "malloc_limit_mb": fuzz["malloc_limit_mb"]}}
            if not engines.get(engine):
                entry["status"] = "skip"
                entry["reason"] = "engine toolchain not available on this host"
                results.append(entry)
                continue
            build_dir = work / ("build-%s-%s" % (engine, sanitizer))
            fresh_dir(build_dir)
            t0 = time.time()
            binary, err = build_target(target_dir, manifest, engine, sanitizer,
                                       build_dir, engines)
            entry["gates"]["build"] = {"ok": binary is not None,
                                       "seconds": round(time.time() - t0, 1)}
            if binary is None:
                entry["status"] = "fail"
                entry["reason"] = "build failed"
                entry["log"] = (err or "")[-2000:]
                results.append(entry)
                continue
            entry["binary"] = str(binary)
            expect_crash = fuzz["expected_crash"] and sanitizer == "address"

            if engine == "libfuzzer":
                smoke = libfuzzer_smoke(binary, corpus_dir, fuzz, work / "smoke1",
                                        runs_eff, opts.smoke_box, expect_crash, sanitizer)
                entry["gates"]["smoke"] = {k: smoke[k] for k in ("ok", "issue", "cov", "ft", "early_crash")}
                if not smoke["ok"]:
                    entry["status"] = "fail"
                    entry["reason"] = "smoke failed: %s" % (smoke["issue"] or "see log")
                    entry["log"] = smoke["tail"]
                    results.append(entry)
                    continue
                speed = libfuzzer_speed(binary, fuzz, work / "speed1",
                                        5000, min(20, opts.smoke_box), expect_crash, sanitizer)
                entry["gates"]["speed"] = speed
                if not speed["ok"]:
                    entry["status"] = "fail"
                    entry["reason"] = "speed gate failed (%d exec/s, min %d) issue=%s" % (
                        speed["exec_per_sec"], SPEED_MIN_EXEC_PER_SEC, speed["issue"])
                    results.append(entry)
                    continue
                if not opts.skip_stability:
                    stab = libfuzzer_stability(binary, corpus_dir, fuzz, work,
                                                runs_eff, opts.smoke_box, expect_crash, sanitizer)
                    entry["gates"]["stability"] = {k: stab[k] for k in
                                                    ("ok", "cov_delta", "cov", "ft", "early_crash")}
                    if not stab["ok"]:
                        entry["status"] = "fail"
                        entry["reason"] = "unstable target (cov delta %s, issue %s)" % (
                            stab["cov_delta"], stab["issue"])
                        results.append(entry)
                        continue
                if fuzz["custom_mutator"]:
                    cm = custom_mutator_check(binary, corpus_dir, fuzz, work, sanitizer)
                    entry["gates"]["custom_mutator"] = cm
                    if not cm["ok"]:
                        entry["status"] = "fail"
                        entry["reason"] = "custom mutator declared but never invoked"
                        results.append(entry)
                        continue
                if expect_crash and not opts.skip_crash_hunt:
                    art_dir = work / ("artifacts-%s-%s" % (engine, sanitizer))
                    camp_dir = work / ("hunt-%s" % sanitizer)
                    artifacts, elapsed, _ = libfuzzer_hunt(binary, corpus_dir, dict_path,
                                                           fuzz, opts.crash_timeout,
                                                           art_dir, camp_dir, sanitizer)
                    gate = hunt_gate(binary, artifacts, elapsed, fuzz["timeout_sec"], engine,
                                     env=sanitizer_env(sanitizer, fuzz))
                    entry["gates"]["crash_hunt"] = gate
                    if not gate["found"]:
                        entry["status"] = "fail"
                        entry["reason"] = "expected crash not found/reproducible within %ds" % opts.crash_timeout
                        results.append(entry)
                        continue
            elif engine == "aflplusplus":
                smoke = afl_replay_smoke(binary, corpus_dir, expect_crash,
                                         env=sanitizer_env(sanitizer, fuzz, afl=True))
                entry["gates"]["smoke"] = {k: smoke[k] for k in
                                           ("ok", "issue", "replay_per_sec", "replayed")}
                if not smoke["ok"]:
                    entry["status"] = "fail"
                    entry["reason"] = "seed replay failed: %s" % (smoke["issue"] or "see log")
                    entry["log"] = smoke["tail"]
                    results.append(entry)
                    continue
                if expect_crash and not opts.skip_crash_hunt:
                    out_dir = work / ("afl-campaign-%s" % sanitizer)
                    crash_files, elapsed, stats = afl_hunt(binary, corpus_dir, dict_path,
                                                           opts.crash_timeout, out_dir,
                                                           fuzz, sanitizer)
                    gate = hunt_gate(binary, crash_files, elapsed, fuzz["timeout_sec"], engine,
                                     env=sanitizer_env(sanitizer, fuzz))
                    stab_pct = None
                    raw = stats.get("stability", "")
                    if raw.endswith("%"):
                        try:
                            stab_pct = float(raw[:-1])
                        except ValueError:
                            stab_pct = None
                    gate["campaign_stats"] = {k: stats.get(k) for k in
                                              ("execs_done", "execs_per_sec", "corpus_count",
                                               "saved_crashes", "saved_hangs")}
                    gate["stability_pct"] = stab_pct
                    entry["gates"]["crash_hunt"] = gate
                    if not gate["found"]:
                        entry["status"] = "fail"
                        entry["reason"] = "expected crash not found/reproducible within %ds (afl-fuzz)" % opts.crash_timeout
                        results.append(entry)
                        continue
                    if stab_pct is not None and stab_pct < AFL_STABILITY_MIN:
                        entry["status"] = "fail"
                        entry["reason"] = "afl stability %.2f%% below %.1f%%" % (stab_pct, AFL_STABILITY_MIN)
                        results.append(entry)
                        continue
            elif engine == "honggfuzz":
                seconds = opts.crash_timeout if expect_crash else min(10, opts.smoke_box)
                hf_dir = work / ("honggfuzz-%s" % sanitizer)
                crash_files, elapsed, _ = honggfuzz_campaign(binary, corpus_dir, dict_path,
                                                             seconds, hf_dir, fuzz, sanitizer)
                if expect_crash:
                    gate = hunt_gate(binary, crash_files, elapsed, fuzz["timeout_sec"], engine)
                    entry["gates"]["crash_hunt"] = gate
                    if not gate["found"]:
                        entry["status"] = "fail"
                        entry["reason"] = "expected crash not found/reproducible within %ds (honggfuzz)" % seconds
                        results.append(entry)
                        continue
                else:
                    entry["gates"]["smoke"] = {"ok": len(crash_files) == 0,
                                               "crashes": len(crash_files),
                                               "seconds": elapsed}
                    if crash_files:
                        entry["status"] = "fail"
                        entry["reason"] = "unexpected crash(s) found by honggfuzz: %s" % [
                            p.name for p in crash_files[:3]]
                        results.append(entry)
                        continue

            entry["status"] = "pass" if lint_ok else "fail"
            if not lint_ok:
                entry["reason"] = "lint errors"
            results.append(entry)

    hard = [r for r in results if r.get("status") in ("pass", "fail")]
    if any(r["status"] == "fail" for r in hard):
        status = "fail"
    elif not hard:
        status = "skip"
    else:
        status = "pass"
    coverage = coverage_measure(target_dir, manifest, corpus_dir, work, engines)
    return {"name": name, "manifest": manifest, "lint": findings, "notes": notes,
            "coverage": coverage, "results": results, "status": status}


def git_info():
    sha = "unknown"
    dirty = None
    try:
        r = run_cmd(["git", "-C", str(ROOT), "rev-parse", "HEAD"], timeout=15)
        if r.returncode == 0:
            sha = r.stdout.strip()
        r2 = run_cmd(["git", "-C", str(ROOT), "status", "--porcelain"], timeout=15)
        if r2.returncode == 0:
            dirty = bool(r2.stdout.strip())
    except Exception:
        pass
    return {"sha": sha, "dirty": dirty}


def build_report_skeleton(opts, engines):
    tools = {"python": platform.python_version()}
    if engines.get("libfuzzer"):
        tools["clang"] = engines["libfuzzer"]["detail"]
    if engines.get("aflplusplus"):
        tools["aflplusplus"] = engines["aflplusplus"]["detail"]
    if engines.get("honggfuzz"):
        tools["honggfuzz"] = engines["honggfuzz"]["detail"]
    return {
        "schema_version": SCHEMA_VERSION,
        "aifuzz_version": AIFUZZ_VERSION,
        "run_id": "%s-%s" % (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                             uuid.uuid4().hex[:8]),
        "generated": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "machine": platform.machine()},
        "tools": tools,
        "git": git_info(),
        "cli": {k: getattr(opts, k) for k in
                ("smoke_runs", "smoke_box", "crash_timeout", "skip_crash_hunt",
                 "skip_stability", "allow_skip")},
        "engines_available": {},
        "targets": [],
        "summary": {},
    }


def dump_report(report, path):
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        os.replace(tmp, path)
        return True
    except OSError as e:
        print("REPORT WRITE FAILED: %s" % e)
        return False


def main():
    load_env_file()
    ap = argparse.ArgumentParser(
        description="AIFuzz harness validator: build, smoke, speed, stability, crash-hunt and lint a fuzz target across engines",
        epilog="exit codes: 0 = all gates passed, 1 = gate failures, 2 = no gates executed (fail-closed; override with --allow-skip). Docs: docs/HARNESS_STANDARD.md")
    ap.add_argument("--targets", action="append",
                    help="directory containing target dirs with manifest.yaml (repeatable; defaults: harness/examples + targets)")
    ap.add_argument("--target", action="append",
                    help="restrict validation to this target name (repeatable)")
    ap.add_argument("--engines", help="comma separated engine filter, e.g. libfuzzer,aflplusplus")
    ap.add_argument("--sanitizers", help="comma separated sanitizer filter, e.g. address")
    ap.add_argument("--smoke-runs", type=int, default=2000)
    ap.add_argument("--smoke-box", type=int, default=30,
                    help="max seconds per smoke/stability run")
    ap.add_argument("--crash-timeout", type=int, default=60,
                    help="seconds to fuzz for expected_crash targets")
    ap.add_argument("--workdir", default=str(Path.home() / ".aifuzz" / "work"))
    ap.add_argument("--json", default=None, help="path for machine readable report")
    ap.add_argument("--skip-crash-hunt", action="store_true")
    ap.add_argument("--skip-stability", action="store_true")
    ap.add_argument("--allow-skip", action="store_true",
                    help="do not fail when zero gates executed")
    ap.add_argument("--list-targets", action="store_true")
    opts = ap.parse_args()

    default_roots = [ROOT / "harness" / "examples", ROOT / "targets"]
    roots = [Path(r).resolve() for r in (opts.targets or default_roots)]
    manifest_paths = []
    for root in roots:
        if not root.is_dir():
            sys.exit("targets dir not found: %s" % root)
        manifest_paths += sorted(root.glob("*/manifest.yaml"))
    if not manifest_paths:
        sys.exit("no manifest.yaml found under %s" % ", ".join(str(r) for r in roots))

    if opts.list_targets:
        for mp in manifest_paths:
            print(mp.parent.name)
        return 0

    engines = detect_engines()
    print("engine availability:")
    for k in ("libfuzzer", "aflplusplus", "honggfuzz"):
        v = engines.get(k)
        if v:
            print("  %-12s AVAILABLE  %s" % (k, v.get("detail") or v.get("cc", "")))
        else:
            print("  %-12s missing" % k)

    opts.engines = set(filter(None, (opts.engines or "").split(","))) or None
    opts.sanitizers = set(filter(None, (opts.sanitizers or "").split(","))) or None

    report = build_report_skeleton(opts, engines)
    report["engines_available"] = {k: bool(v) for k, v in engines.items()}
    workdir = Path(opts.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    json_path = Path(opts.json) if opts.json else workdir / "report.json"

    failures = 0
    passes = 0
    skips = 0
    repro_lines = []
    seen_names = set()
    report_ok = True
    try:
        for mp in manifest_paths:
            target_dir = mp.parent
            if opts.target and target_dir.name not in opts.target:
                continue
            try:
                manifest = load_manifest(target_dir)
            except ManifestError as e:
                print("\n=== validating %s ===" % target_dir.name)
                print("  manifest error: %s" % e)
                report["targets"].append({"name": target_dir.name, "status": "fail",
                                          "reason": "manifest error: %s" % e,
                                          "results": [], "lint": [], "notes": []})
                failures += 1
                if not dump_report(report, json_path):
                    report_ok = False
                continue
            if manifest is None:
                continue
            if opts.target and manifest["name"] not in opts.target:
                continue
            if manifest["name"] in seen_names:
                print("\n=== validating %s ===" % manifest["name"])
                print("  manifest error: duplicate target name")
                report["targets"].append({"name": manifest["name"], "status": "fail",
                                          "reason": "duplicate target name",
                                          "results": [], "lint": [], "notes": []})
                failures += 1
                if not dump_report(report, json_path):
                    report_ok = False
                continue
            seen_names.add(manifest["name"])
            print("\n=== validating %s ===" % manifest["name"])
            try:
                result = validate_target(target_dir, manifest, opts, engines)
            except Exception as e:
                import traceback
                tb = traceback.format_exc()[-1500:]
                result = {"name": manifest["name"], "status": "fail",
                          "reason": "validator internal error: %s" % e,
                          "log": tb, "results": [], "lint": [], "notes": []}
            report["targets"].append(result)
            if not dump_report(report, json_path):
                report_ok = False
            for r in result.get("results", []):
                st = r.get("status")
                if st == "fail":
                    failures += 1
                elif st == "pass":
                    passes += 1
                else:
                    skips += 1
                print("  %-12s %-10s %s %s" % (r["engine"], r["sanitizer"],
                                                (st or "?").upper(), r.get("reason", "")))
                for gate, info in r.get("gates", {}).items():
                    if isinstance(info, dict):
                        brief = {k: info[k] for k in info
                                 if k in ("cov", "ft", "exec_per_sec", "seconds", "found",
                                          "cov_delta", "ok", "unique_bugs", "crash_count",
                                          "stability_pct", "replay_per_sec", "issue", "crash_class")}
                        if brief:
                            print("      %-10s %s" % (gate, brief))
                hunt = r.get("gates", {}).get("crash_hunt") or {}
                if hunt.get("repro_cmd"):
                    repro_lines.append("[%s/%s] %s: %s" % (result["name"], r["engine"],
                                                           hunt.get("crash_class", "crash"),
                                                           hunt["repro_cmd"]))
            lint_summary = {}
            for f in result.get("lint", []):
                lint_summary[f["severity"]] = lint_summary.get(f["severity"], 0) + 1
            for note in result.get("notes", []):
                print("  note: %s" % note)
            cov = result.get("coverage") or {}
            if cov:
                print("  coverage: %s" % cov)
            print("  lint: %s" % (lint_summary or "clean"))
            print("  target status: %s" % result.get("status", "?").upper())
    finally:
        total_hard = passes + failures
        if failures:
            code = 1
        elif total_hard == 0 and not opts.allow_skip:
            code = 2
        else:
            code = 0
        if not report_ok and code == 0:
            code = 1
        report["summary"] = {"pass": passes, "fail": failures, "skip": skips,
                             "exit_code": code}
        if not dump_report(report, json_path):
            code = 1 if code == 0 else code

    print("\n==== SUMMARY ====")
    print("PASS %d  FAIL %d  SKIP %d" % (passes, failures, skips))
    if failures:
        for t in report["targets"]:
            for r in t.get("results", []):
                if r.get("status") == "fail":
                    print("  FAIL %s [%s/%s]: %s" % (t["name"], r["engine"],
                                                     r["sanitizer"], r.get("reason", "?")))
            if t.get("status") == "fail" and not t.get("results"):
                print("  FAIL %s: %s" % (t["name"], t.get("reason", "?")))
    if repro_lines:
        print("crash reproducers:")
        for line in repro_lines:
            print("  " + line)
    print("report: %s" % json_path)
    print("exit code: %d" % code)
    return code


if __name__ == "__main__":
    sys.exit(main())
