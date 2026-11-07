# AIFuzz

A unified, all-in-one fuzzing system: orchestrates the world's best fuzzing engines
(AFL++, libFuzzer, honggfuzz) behind one harness standard, with an AI harness-generation
loop (LLM proposes, the validator gates), on Linux (WSL2) and Windows.

- Research + full architecture blueprint: `RESEARCH_REPORT.md`
- Harness contract & target spec: `docs/HARNESS_STANDARD.md`
- Multi-round expert review + remediation log: `docs/HARNESS_REVIEW.md`

## Quickstart (WSL Ubuntu)

```
# one-time environment setup (clang, AFL++, honggfuzz from source, instrumented libpng16)
wsl -d Ubuntu-26.04 -u root -- bash /mnt/c/Users/hp/Desktop/AIFuzz/scripts/setup_wsl.sh
# or, if the apt packages are already installed and you have no sudo password prompt:
#   wsl -d Ubuntu-26.04 -- bash -lc 'AIFUZZ_BUILD_HONGGFUZZ=1 bash /mnt/c/Users/hp/Desktop/AIFuzz/scripts/setup_wsl.sh'

# sync repo into WSL-local filesystem (fast builds), then validate everything
wsl -d Ubuntu-26.04 -- bash -lc 'bash /mnt/c/Users/hp/Desktop/AIFuzz/scripts/sync_to_wsl.sh && python3 ~/AIFuzz/tools/harness_check.py --crash-timeout 30'
```

## Layout

```
docs/HARNESS_STANDARD.md   harness standard (ABI, rules, gates, schema)
docs/HARNESS_REVIEW.md    multi-round expert review + remediation log
harness/include/           header-only C helpers (fzdata.h input consumer)
harness/examples/          example targets (planted-bug self-tests, structure-aware demo)
targets/                   real targets (libpng_decode: instrumented libpng16 static build)
tools/harness_check.py     validator: build / smoke / speed / stability / crash-hunt / lint / coverage
tools/harness_agent.py     LLM harness-generation loop (propose -> validate -> repair)
specs/                     agent target specs (input for harness generation)
tests/                     pytest suite for the validator core
.github/workflows/ci.yml   CI: toolchain + instrumented libs + unit tests + full validation + agent loop
Dockerfile                 pinned reproducible environment (same image runs CI and workers)
scripts/                   WSL environment setup + repo sync
```

## The validator

- Engines: libFuzzer, AFL++ and honggfuzz — build, smoke, speed (>= 50 exec/s from empty
  corpus), stability, crash lifecycle (3x replay, classification, stack-hash dedup),
  comment-aware lint, and a source-coverage metric (`llvm-cov`: harness + all instrumented
  functions, i.e. the library itself when linked instrumented).
- Exit codes: 0 = pass, 1 = gate failures, 2 = nothing executed (fail-closed).
- Report: `~/.aifuzz/work/report.json` (schema v2: provenance, crash classifications,
  stack hashes, repro commands, coverage). Per-run artifacts under `~/.aifuzz/work/targets/`.
- Unit tests: `wsl -d Ubuntu-26.04 -- bash -lc 'python3 -m pytest ~/AIFuzz/tests -q'`

## The harness agent (AIFuzz thesis)

```
python3 tools/harness_agent.py --spec specs/agent_demo.yaml \
  --llm-command 'ollama run qwen2.5-coder' --workdir ~/.aifuzz/agent
```

The LLM proposes a harness from the spec; the validator judges it against every gate;
failure diagnostics are fed back for repair until accepted or out of iterations.
Any stdin->stdout LLM works (ollama, an API script, or a fixture).
CI proves the loop with a stub LLM (bad harness -> rejected with diagnostics -> repaired -> accepted).

## Real targets

`targets/libpng_decode` links a from-source libpng16 build compiled with
ASan + SanitizerCoverage + profile instrumentation, so the fuzzer gets feedback
and bug detection *inside* the library and `llvm-cov` reports real reached-functions
(~500 edges on the seed corpus alone).

## Phase 2: campaigns + orchestration

Long multi-engine ensemble campaigns (ClusterFuzz-style shared corpus, live cross-engine
corpus sync, periodic coverage sampling, crash aggregation with cross-engine dedup,
corpus minimization, and stacking across runs):

```
# single campaign: 30 minutes, all engines in parallel
wsl -d Ubuntu-26.04 -- bash -lc 'cd ~/AIFuzz && python3 tools/campaign.py --target libpng_decode --duration 30'

# orchestrated plan (worker pool, aggregate dashboard)
wsl -d Ubuntu-26.04 -- bash -lc 'cd ~/AIFuzz && python3 tools/orchestrator.py --plan specs/campaigns.yaml --parallel 2'
```

Campaigns live under `~/.aifuzz/campaigns/<target>/<run-id>/` (corpus, minimized corpus,
crash artifacts with repro commands, engine logs, coverage time-series). Each run resumes
`latest_corpus` from the previous campaign automatically — fuzzing state compounds.
First orchestrated run (libpng 30min + 3 targets): coverage 25.0% → 27.4% (128 → 140
library functions), corpus 185 → 944 → 403 minimized, 8.5M libFuzzer + 2.5M AFL executions,
crash files deduped to unique bugs per stack hash.

## Roadmap

Phase 1: harness standard + validator + adversarial review hardening (done)
Phase 2: campaigns + orchestrator (done — triage service and dashboards next)
Phase 3: AI layer at scale — harness generation on real targets, triage agent
Phase 4: Windows closed-source targets (WinAFL/Jackalope workers) + distributed scale
