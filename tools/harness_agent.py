#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools" / "harness_check.py"

RULES = """You are writing a fuzz harness that must pass the AIFuzz harness standard
(docs/HARNESS_STANDARD.md) and be accepted by an automated validator.

Hard rules:
- Export exactly: int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
- Tolerate ANY input (empty, huge, malformed). Never exit(), abort(), system(), longjmp.
- Deterministic: no time(), rand(), srand(), rand_r(), clock_gettime(), getenv().
- Fast: aim for thousands of executions per second; no file or network I/O; no logging.
- Derive every branch from the input bytes; keep global state out of iterations.
- C only, ONE complete file. Allowed includes: stdint.h, stddef.h, string.h, stdlib.h
  and "aifuzz/fzdata.h".
- fzdata.h API:
    FzData d = fz_init(data, size);
    uint8_t fz_u8(FzData *d);  uint16_t fz_u16le(FzData *d);
    uint32_t fz_u32le(FzData *d);
    const uint8_t *fz_bytes(FzData *d, size_t max, size_t *out_len);
    bool fz_empty(FzData *d);  size_t fz_remaining(const FzData *d);
  All getters return 0 when exhausted; never read data[i] past size.
- Gates that will judge you: build (clang -O1, ASan), smoke (no crash on any input),
  speed (>= 50 exec/s measured from empty corpus), stability (identical coverage across
  identical-seed runs), lint (the rules above), and coverage measurement.
- If a planted memory bug is expected: keep it simple, ASan-detectable, reachable from
  crafted input; note that at -O1 LLVM eliminates malloc+dead-stores+free chains and
  folds `if (p)` under ASan - use memcpy or volatile-pointer patterns to keep bugs alive.
"""


def load_spec(path):
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_prompt(spec, failures):
    fuzz = spec.get("fuzz", {})
    parts = [RULES, "", "TARGET SPEC:", "name: %s" % spec.get("name"),
             "description: %s" % spec.get("description", ""),
             "language: %s" % spec.get("language", "c")]
    if spec.get("harness_hint"):
        parts.append("harness requirements:\n%s" % spec["harness_hint"])
    if fuzz.get("expected_crash"):
        parts.append("A planted, ASan-detectable memory bug IS expected in this target.")
    if failures:
        parts.append("")
        parts.append("PREVIOUS ATTEMPT FAILED. Validator report summary:")
        parts.append(failures)
        parts.append("Fix every issue and output the corrected, complete C source.")
    else:
        parts.append("")
        parts.append("Output the complete C source file now. Output ONLY code - "
                     "no markdown fences, no commentary.")
    return "\n".join(parts)


def run_llm(command, prompt):
    r = subprocess.run(command, shell=True, input=prompt, capture_output=True,
                       text=True, timeout=600)
    if r.returncode != 0:
        return None, "llm-command failed (rc=%d): %s" % (r.returncode, r.stderr[-500:])
    return r.stdout, None


def write_manifest(spec, target_dir):
    fuzz = spec.get("fuzz", {})
    lines = [
        "name: %s" % spec["name"],
        "description: %s" % spec.get("description", "LLM-generated harness"),
        "language: %s" % spec.get("language", "c"),
        "sources: [fuzz_target.c]",
        "build:",
    ]
    build = spec.get("build", {})
    cflags = build.get("cflags", [])
    ldflags = build.get("ldflags", [])
    lines.append("  cflags: [%s]" % ", ".join(cflags))
    lines.append("  ldflags: [%s]" % ", ".join(ldflags))
    lines.append("fuzz:")
    for key, default in (("max_len", 4096), ("timeout_sec", 10),
                         ("expected_crash", False), ("custom_mutator", False)):
        if key in fuzz or key in ("max_len", "expected_crash"):
            lines.append("  %s: %s" % (key, fuzz.get(key, default)))
    engines = spec.get("engines", ["libfuzzer"])
    sanitizers = spec.get("sanitizers", ["address"])
    lines.append("engines: [%s]" % ", ".join(engines))
    lines.append("sanitizers: [%s]" % ", ".join(sanitizers))
    lines.append("tags: [llm-generated]")
    (target_dir / "manifest.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_validator(workdir, targets_root, name, timeout):
    report_path = Path(workdir) / "hcheck-report.json"
    cmd = [sys.executable, str(CHECKER), "--targets", str(targets_root),
           "--target", name, "--workdir", str(Path(workdir) / "hcheck"),
           "--json", str(report_path), "--crash-timeout", str(timeout),
           "--smoke-box", "20"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if not report_path.is_file():
        return None, r.stdout[-2000:] + r.stderr[-2000:]
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f), None


def summarize_failures(report):
    out = []
    for target in report.get("targets", []):
        if target.get("status") == "fail" and not target.get("results"):
            out.append("manifest error: %s" % target.get("reason"))
        for entry in target.get("results", []):
            if entry.get("status") != "fail":
                continue
            out.append("[%s/%s] failed: %s" % (entry.get("engine"),
                                               entry.get("sanitizer"),
                                               entry.get("reason", "?")))
            log = entry.get("log")
            if log:
                out.append("diagnostics:\n%s" % log[-1500:])
    if not out:
        out.append("validator internal failure - see report")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="AIFuzz Harness Agent: LLM proposes a harness, the validator judges it, failures are fed back for repair",
        epilog="llm-command contract: reads the prompt on stdin, writes the complete C source on stdout. "
               "Examples: 'ollama run qwen2.5-coder', 'python3 my_api_script.py', 'cat fixtures/good_harness.c'")
    ap.add_argument("--spec", required=True, help="YAML target spec")
    ap.add_argument("--llm-command", required=True)
    ap.add_argument("--max-iterations", type=int, default=3)
    ap.add_argument("--crash-timeout", type=int, default=30)
    ap.add_argument("--workdir", default=str(Path.home() / ".aifuzz" / "agent"))
    opts = ap.parse_args()

    spec = load_spec(opts.spec)
    name = spec["name"]
    work = Path(opts.workdir)
    targets_root = work / "agent-targets"
    target_dir = targets_root / name
    target_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(spec, target_dir)

    print("=== AIFuzz Harness Agent: %s ===" % name)
    failures = None
    for iteration in range(1, opts.max_iterations + 1):
        prompt = build_prompt(spec, failures)
        source, err = run_llm(opts.llm_command, prompt)
        if source is None:
            print("iteration %d: %s" % (iteration, err))
            return 2
        (target_dir / "fuzz_target.c").write_text(source, encoding="utf-8")
        print("iteration %d: candidate written (%d bytes), validating..." % (
            iteration, len(source)))
        report, err = run_validator(work, targets_root, name, opts.crash_timeout)
        if report is None:
            print("iteration %d: validator crashed:\n%s" % (iteration, err))
            return 2
        target_report = next((t for t in report.get("targets", [])
                              if t.get("name") == name), {})
        status = target_report.get("status")
        cov = target_report.get("coverage") or {}
        print("iteration %d: target status=%s coverage=%s" % (iteration, status, cov))
        if status == "pass":
            print("SUCCESS after %d iteration(s)" % iteration)
            print("target dir: %s" % target_dir)
            print("report: %s" % (work / "hcheck-report.json"))
            return 0
        failures = summarize_failures(report)
        print("iteration %d: failures:\n%s" % (iteration, failures[:800]))
    print("FAILED: harness not accepted within %d iterations" % opts.max_iterations)
    return 1


if __name__ == "__main__":
    sys.exit(main())
