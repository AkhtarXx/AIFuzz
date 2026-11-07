#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT / "tools" / "campaign.py"


def load_plan(path):
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_one(entry, workdir, cov_sample):
    target = entry["target"]
    duration = float(entry.get("duration_min", 5))
    engines = entry.get("engines")
    cmd = [sys.executable, str(CAMPAIGN), "--target", target,
           "--duration", str(duration), "--workdir", workdir,
           "--cov-sample", str(cov_sample)]
    if engines:
        cmd += ["--engines", ",".join(engines)]
    if entry.get("fresh"):
        cmd += ["--fresh"]
    print("[orchestrator] starting %s (%.0f min)" % (target, duration))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=duration * 60 + 1800)
    print(r.stdout[-3000:])
    if r.returncode != 0:
        print("[orchestrator] %s FAILED (rc=%d)" % (target, r.returncode))
        print(r.stderr[-1500:])
    return target, r.returncode


def main():
    ap = argparse.ArgumentParser(
        description="AIFuzz orchestrator: run a campaign plan across multiple targets with a bounded worker pool",
        epilog="plan format:\n  parallel: 2\n  campaigns:\n    - target: libpng_decode\n      duration_min: 30\n    - target: structure_demo\n      duration_min: 10\n      engines: [libfuzzer]")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--workdir", default=str(Path.home() / ".aifuzz" / "campaigns"))
    ap.add_argument("--parallel", type=int, default=None)
    ap.add_argument("--cov-sample", type=float, default=5)
    opts = ap.parse_args()

    plan = load_plan(opts.plan)
    entries = plan.get("campaigns") or []
    if not entries:
        sys.exit("plan has no campaigns")
    parallel = opts.parallel or int(plan.get("parallel", 1))
    print("[orchestrator] %d campaigns, parallel=%d" % (len(entries), parallel))

    results = {}
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = [pool.submit(run_one, e, opts.workdir, opts.cov_sample) for e in entries]
        for fut in futures:
            target, rc = fut.result()
            results[target] = rc

    aggregate = {"campaigns": [], "failed": [t for t, rc in results.items() if rc != 0]}
    for entry in entries:
        target = entry["target"]
        report_path = Path(opts.workdir) / target / "last_report.json"
        if report_path.is_file():
            with open(report_path, "r", encoding="utf-8") as f:
                rep = json.load(f)
            af_final = (rep.get("final_coverage") or {}).get("all_functions") or {}
            aggregate["campaigns"].append({
                "target": target,
                "duration_min": rep["campaign"]["duration_min"],
                "engines": rep["campaign"]["engines"],
                "corpus_final": rep["corpus"]["final_files"],
                "corpus_minimized": rep["corpus"]["minimized_files"],
                "coverage_pct_final": af_final.get("pct"),
                "functions_reached_final": af_final.get("reached"),
                "unique_bugs": len(rep.get("unique_bugs") or []),
            })

    agg_path = Path(opts.workdir) / "aggregate_report.json"
    agg_path.parent.mkdir(parents=True, exist_ok=True)
    with open(agg_path, "w", encoding="utf-8") as f:
        json.dump(aggregate, f, indent=2, default=str)

    print("\n==== ORCHESTRATOR DASHBOARD ====")
    print("%-22s %-9s %-8s %-10s %-12s %s" % ("target", "dur(min)", "corpus", "cov%", "reached", "bugs"))
    for c in aggregate["campaigns"]:
        print("%-22s %-9s %-8s %-10s %-12s %s" % (
            c["target"], c["duration_min"], c["corpus_minimized"],
            c["coverage_pct_final"], c["functions_reached_final"], c["unique_bugs"]))
    if aggregate["failed"]:
        print("failed campaigns: %s" % ", ".join(aggregate["failed"]))
        return 1
    print("aggregate report: %s" % agg_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
