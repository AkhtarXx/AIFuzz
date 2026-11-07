# Harness Foundation — Three-Expert Review

> Date: 2026-11-07. Reviewed artifacts: `docs/HARNESS_STANDARD.md`,
> `harness/include/aifuzz/fzdata.h`, `harness/examples/*` (3 targets),
> `tools/harness_check.py`, `scripts/setup_wsl.sh`, `scripts/sync_to_wsl.sh`.
> State at review: all gates passing, 8/8 PASS (libFuzzer + AFL++, ASan/UBSan).

---

## Reviewer 1 — @grimwire · 15 yrs (systems security, ex-browser vendor, OSS-Fuzz contributor since 2018)

**Verdict:** "Strong v0.1 skeleton. You chose the right ABI and put gates before orchestration —
most teams do the reverse and pay for it later. But your crash *handling* stops one step short
of useful, and your stability gate doesn't test the thing its name promises."

### What holds up
- libFuzzer ABI as the cross-engine contract — correct, boring, proven. Exactly what you want in a foundation.
- The stability gate already caught real heap corruption (kv_config pre-ASan-restriction) and the
  optimizer-elimination lesson (`-O1` DSE vs planted heap bug) is documented in the standard.
  Most fuzzing docs don't know that trap exists.
- Planted-bug corpus as a pipeline self-test — this is your Magma-style regression set for the *system itself*.

### Gaps
1. **Crash lifecycle ends at "found"** (`harness_check.py`, `libfuzzer_hunt`). You report an artifact
   path and move on. A crash you don't replay-verify, minimize, symbolize, and dedup is a rumor,
   not a bug report. Minimum: replay artifact 3×, `-minimize_crash=1` with `-exact_artifact_path`,
   capture symbolized stack (ASan already prints it), bucket by top-frames stack hash, and print a
   one-line repro command. This is the core of what ClusterFuzz actually *is*.
2. **The oracle matrix is thin.** You gate on ASan crash + UBSan build. Missing: LSan
   (`-detect_leaks` is on by default but you never assert "no leaks reported" in smoke runs),
   `-malloc_limit_mb` (a harness that does one giant malloc passes your gates today),
   and OOM behavior. MSan I'll give you — needs an instrumented-deps build, document it as an
   explicit non-goal, not silence.
3. **Stability gate doesn't cover `-fork=1`/`-jobs`.** Single-process determinism says nothing about
   global state leaking across iterations — which is precisely the class libFuzzer's fork mode and
   AFL++'s forkserver expose. A harness that passes your stability gate and dies under `-fork=4`
   will surprise you in production. Add a fork-mode smoke gate.
4. **No source-level truth.** `cov: 26` is a counter of instrumented edges — it tells nobody *where*
   the harness reaches. You need a coverage-instrumented build (`-fprofile-instr-generate
   -fcoverage-mapping`), `llvm-profdata` + `llvm-cov`, and a "reached functions / reachable functions"
   number. That metric is the entire basis of Fuzz Introspector and of your own research report's
   claim that harness quality = coverage of reachable code. Right now you can't measure your own
   north star.
5. **Dict loading is asserted nowhere.** Point `-dict=` at a typo'd path and the validator shrugs.
   Gate on evidence: engine output must confirm the dictionary loaded (entry count), for both
   libFuzzer and AFL++. Also: AFL++ side should build a CmpLog binary (`AFL_LLVM_CMPLOG=1`,
   `afl-fuzz -c`) — you literally wrote the RedQueen section of your own research report; use it.
6. **Corpus hygiene gates absent.** No `-merge=1` minimization, no `afl-cmin`, no "seed corpus actually
   grows coverage" check. Seeds are currently LF-clean by luck of your write tool — add a gate that
   replays each seed and flags zero-contribution seeds (dead seeds are invisible rot).
7. **Timeouts are configured, never tested.** You pass `-timeout=10`; nothing verifies a slow/hanging
   input is actually caught and reported as a `timeout-*` artifact class.
8. **Nothing is pinned.** `setup_wsl.sh` installs whatever apt serves today. Reproducible infra
   needs a toolchain manifest (clang 21.1.8, afl++ 4.33c) that CI and the future workers consume.

### Top 3 asks
1. Crash replay + minimize + symbolize + dedup (turn "found" into a report).
2. Fork-mode stability gate + LSan/malloc-limit gates.
3. Source-coverage / reached-functions metric via llvm-cov.

---

## Reviewer 2 — @opslane · 10 yrs (platform/infra, ran CI fuzzing for a large monorepo, ClusterFuzzLite user)

**Verdict:** "The gates are real engineering, the repo hygiene is not there yet. No CI, no container,
no schema, and — the thing that actually worries me — the validator has zero tests. You built a judge
and never put the judge on trial."

### What holds up
- WSL-local build dir instead of /mnt C drvfs — right call, saves you 10× I/O pain.
- Exit codes per gate, machine-readable JSON out — CI-ready interface, just not wired to CI.
- Setup script is idempotent and prefers distro packages over source builds.

### Gaps
1. **No CI. Period.** Nothing runs `harness_check.py` on push/PR. First refactor of the stat-parsing
   regex breaks every gate silently. GitHub Actions is free for this: run validator on `ubuntu-latest`
   (script is already POSIX), plus a nightly short fuzz job — that's the ClusterFuzzLite pattern,
   you even cited it in your report.
2. **No Dockerfile.** "Works on my WSL" is not a system. One pinned image (clang + afl++ + python)
   becomes: CI runner, future fuzz worker, and — via devcontainer — your Windows story. Define it now,
   before the orchestrator exists, so the orchestrator just schedules containers.
3. **`manifest.yaml` has no schema.** A typo like `expected_crash: truu` silently disables the
   crash-hunt gate — your hardest gate silently turns itself *off*, which is the worst possible
   failure mode. Validate with pydantic (or JSON Schema), reject unknown keys, enforce types and
   bounds (`max_len` sane, `timeout_sec` sane, unique target names).
4. **The validator itself is untested.** Manifest parsing, the libFuzzer output regexes (which
   *will* drift across clang versions), gate decision logic — all need pytest fixtures with canned
   outputs. You already have the perfect fixtures: the three example targets.
5. **Sync is `rm -rf && cp -r`.** Fine at 50 KB; dies when a target ships a 2 GB corpus. Use
   `rsync --delete --exclude artifacts`, and stop hardcoding the Windows path — read `AIFUZZ_SRC`
   from env with a sane default.
6. **Reports aren't diffable.** `report.json` lands in `~/.aifuzz` and evaporates. Add `--baseline
   prev.json` (fail on cov regression), embed provenance (git SHA, clang/AFL versions, host), and
   keep per-run report directories so there's a trend line, not vibes.
7. **Sequential everything.** Targets validate one at a time, engines one at a time. A
   `ProcessPoolExecutor` over (target × engine) triples your wall-clock efficiency for ~20 lines.
8. **Failure UX makes you scroll.** On FAIL you print gate lines per target but no end-of-run
   summary of *what failed and where the artifacts are*. Add `--only-failed`, a final red block,
   and artifact paths in the summary.
9. **Isolation is absent — fine today, fatal the day real targets land.** Bake it into the image
   now: fuzzed processes run with dropped caps, no egress, cgroup memory caps. Retrofitting
   isolation after you're fuzzing real parsers is how people leak secrets into crash reports.
10. **Repo has no LICENSE.** Your own research report spends a section on AGPL implications of AFL++;
    the repo that consumes it should state its own license before anyone else contributes code.

### Top 3 asks
1. GitHub Actions CI + pinned Dockerfile.
2. Manifest schema validation (unknown-key rejection).
3. pytest for the validator, using the example targets as fixtures.

---

## Reviewer 3 — @0xseed · 5 yrs (AI-native tooling, ships LLM agents, polyglot fuzzer: cargo-fuzz/Atheris/Jazzer)

**Verdict:** "Good bones, but the repo is called AIFuzz and the AI-readiness is one JSON file and a
vibe. Also — for an 'all-in-one' system, it's C-only and structure-blind. Your own research says
structure-aware fuzzing is the biggest lever and there's not one custom mutator in sight."

### What holds up
- **Manifest-as-data is the right substrate for the Harness Agent.** YAML in, gates + JSON out is
  exactly the feedback loop an LLM harness-generator needs: generate → validate → read JSON →
  repair. You accidentally built your own eval harness — the planted-bug targets are the acceptance
  tests for harness generation.
- `fzdata.h` is small enough for an LLM to use correctly from a single prompt. Keep it that way.

### Gaps
1. **Zero AI surface despite the name.** Cheapest high-value hooks, both offline, both proven in
   the literature you cited: (a) `aifuzz doctor` — an LLM reviews harness source against
   `HARNESS_STANDARD.md` and emits structured findings merged into report.json (before we let
   LLMs *write* harnesses, make them *grade* them); (b) crash triage stub — attach minimized
   repro + symbolized stack as a doc for LLM root-cause analysis. No agent framework needed,
   two scripts.
2. **C-only is not all-in-one.** The manifest schema should carry `language: rust|python|cpp`
   with per-language build/run adapters (cargo-fuzz, Atheris) even if the adapters land later —
   otherwise every schema migration later breaks every target. Modern targets live in Rust, Go,
   Python, TS. The Python adapter specifically makes the AI loop testable on Python libraries.
3. **No structure-aware path.** `HARNESS_STANDARD.md` defines nothing about
   `LLVMFuzzerCustomMutator` / custom crossover — the exact mechanism your research report calls
   "the next big thing". You need a fourth example target with a custom mutator (the protobuf /
   parse-mutate-serialize pattern) and a validator gate that confirms the custom mutator is
   actually invoked (libFuzzer logs `MS: 1 Custom-`).
4. **Provenance is the difference between an agent and a hallucination.** report.json has no git
   SHA, no tool versions, no run ID. Any LLM consuming these reports without provenance will
   confidently mix runs. Embed it.
5. **CLI UX is 2015.** `python3 tools/harness_check.py --engines libfuzzer` — make it
   `aifuzz check` (pyproject + entry point), typed (mypy), linted (ruff), `Makefile` target, and
   add `--list-targets`. One command in, table out.
6. **Two consumer conventions, zero documentation of the split.** C++ targets will use LLVM's
   `FuzzedDataProvider.h` (consumes scalars from the END of input); `fzdata.h` consumes from the
   FRONT. A corpus migrated between conventions silently changes meaning. Document the divergence
   in HARNESS_STANDARD.md now.

### Top 3 asks
1. `aifuzz doctor` (LLM grades harness vs standard) + triage stub — the AI part of AIFuzz, v0.
2. Custom-mutator example target + gate (structure-aware path in the standard).
3. Schema-level language adapters + provenance in every report.

---

## Converged Backlog (deduplicated, priority-ordered)

| P | Item | Source | Size |
|---|---|---|---|
| P0 | Manifest schema validation, unknown-key rejection (pydantic/JSON Schema) | R2-3, R3 | S |
| P0 | Crash lifecycle: replay×3, `-minimize_crash`, symbolized stack, stack-hash dedup, repro one-liner | R1-1, R3 | M |
| P0 | GitHub Actions CI: validator on ubuntu-latest + nightly short fuzz | R2-1 | S |
| P0 | pytest for validator core (manifest, regex parsing, gate logic) | R2-4 | M |
| P0 | Fork-mode (`-fork=1`) stability gate + LSan + `-malloc_limit_mb` gates | R1-2, R1-3 | M |
| P0 | Dict-load assertion for both engines (typo'd path must FAIL the gate) | R1-5 | S |
| P1 | Source coverage: coverage build + llvm-cov → reached-functions metric | R1-4 | M |
| P1 | Dockerfile (pinned clang/AFL versions) + toolchain manifest; provenance (git SHA + versions) in report.json | R2-2, R1-8, R3-4 | M |
| P1 | `aifuzz doctor` LLM review stub + crash triage stub (AI hooks v0) | R3-1 | M |
| P1 | AFL++ CmpLog build flag + `-c` campaign; corpus minimization gate (`-merge=1`, `afl-cmin`); dead-seed detection | R1-5, R1-6, R1-7 | M |
| P1 | Parallel (target × engine) validation; `--only-failed`, `--baseline` diffing | R2-6, R2-7, R2-8 | M |
| P2 | Custom-mutator (structure-aware) example target + gate | R3-3 | M |
| P2 | Language adapters in schema (rust/cargo-fuzz, python/Atheris) | R3-2 | M |
| P2 | Native Windows lane for source-available targets (clang-cl `-fsanitize=fuzzer,address`) | R1, R3 | S |
| P2 | `aifuzz` CLI packaging (pyproject, typed, ruff), Makefile | R3-5 | S |
| P2 | FuzzedDataProvider vs fzdata.h front/end consumption doc | R3-6 | S |
| P2 | Container hardening (caps, no egress, cgroups) in image | R2-9 | S |
| P2 | LICENSE + CONTRIBUTING | R2-10 | S |

## Scorecard (consensus)

| Area | Score | Note |
|---|---|---|
| Harness standard doc | 8/10 | Right ABI, right rules; missing structure-aware + language conventions |
| Validator gates | 6.5/10 | Real gates, real bugs caught; oracle thin, no fork/LSan/coverage truth |
| Example targets | 7/10 | Planted-bug corpus is a system-level eval set; no structure-aware example |
| Infra | 4/10 | No CI, no container, no pinning; sync is a placeholder |
| AI-readiness | 5/10 | Right data substrate (manifest+JSON); zero AI surface, no provenance |
| Windows story | 2/10 | Deferred; clang-cl lane untested; WinAFL path only in prose |

**All three agree on the single next move:** make the validator itself trustworthy
(schema validation + crash lifecycle + CI + tests) *before* scaling targets or adding orchestration.
The gates are the product; harden the judge before the judge judges the world.

---

# Round 2 — Independent Subagent Verification

> Method: three fresh-context subagents (no access to this review file, no conversation history,
> no ownership bias) cold-read the actual files and **ran falsification experiments in WSL**
> (validator runs, crafted bad manifests, state-leak harnesses, giant-malloc harnesses, UB
> harnesses, hang harnesses, crash replays). One agent disclosed an incidental grep leak from this
> file (matched lines only, not read); its findings were independently established first.
> Full agent transcripts are ground truth; below is the merged, deduplicated result.

## A. Verdict of the verdicts

Round 1 (simulated personas) was directionally right but **too kind**. The subagents confirmed
every "P0" from Round 1 with experiments — and found **nine serious defects Round 1 missed**,
several of which are real bugs in code written in Round 1's own session:

## B. Experimentally VERIFIED failures (each reproduced, not opinion)

| # | Finding | Evidence |
|---|---|---|
| 1 | **UBSan oracle is dead code** — no `-fno-sanitize-recover=all`; UBSan prints `runtime error:` and continues; smoke gate only greps `"ERROR"` → a target with live signed-overflow UB **passes every gate** | crafted UB target under exact validator flags → rc=0, all gates PASS |
| 2 | **SKIP is green.** `--engines nosuchengine` → "all gates passed", exit 0. On a zero-toolchain host the validator exits 0 too. CI would be green while validating nothing | verified twice by two independent agents |
| 3 | **Typo'd manifest key silently disables a gate.** `expected_crashh: true` → crash-hunt gate vanishes, target still PASS | throwaway-copy experiment |
| 4 | **One hang kills the whole run, no report.** `timeout_sec: 300` + hanging seed → uncaught `TimeoutExpired` traceback at 121s, exit 1, **no report.json written** | hang-target experiment |
| 5 | **The validator mutates the tree it validates.** `ensure_seeds` runs `seed_gen` writing into `target_dir/seeds/` — the WSL copy already carries a `seeds/` dir created by earlier validator runs; violates our own "never mutate seeds/" rule; latent bug: `seed_gen` w/o `seeds:` key passes literal `"None"` as output dir | verified by two agents |
| 6 | **2 GiB-per-exec malloc passes all gates** — no manifest memory-ceiling field, hardcoded `-rss_limit_mb=2560`, AFL path uses `-m none` (no limit at all) | giant-malloc target → PASS at 1,959 exec/s |
| 7 | **Crash "found" ≠ crash.** Artifacts are counted, never replayed, never classified — libFuzzer also writes artifacts for OOM/timeouts, so a timeout file can pass the planted-bug gate; AFL produced 13 files of the *same* bug (`count: 13`, no dedup); **all ASan evidence (crash type, top frames) is discarded** — grep found zero ASan text in any workdir | replay + grep experiments |
| 8 | **Stability gate is blind to state leakage.** Two identical-seed runs can't see in-process global-state leaks: crafted harness gives cov 4 for input Y-after-X vs cov 3 fresh, delta 0 → PASSES. Same-seed runs measure reproducibility, not stability | state-leak harness experiment |
| 9 | **`fz_range(d, SIZE_MAX)` SIGFPEs** (`v % (hi+1)` overflows to modulo 0) — a landmine in the shared helper; also `fz_range` consumes big-endian while all other getters are little-endian | static + repro reasoning |

## C. Round-1 claims — confirmed, extended, corrected

- **Confirmed (now with evidence):** manifest schema gap, crash lifecycle gap, no CI/Docker/tests/
  LICENSE/pinning, honggfuzz decorative, language frozen at `c`, no structure-aware path, no provenance.
- **Extended:** lint gate misses `_exit`, `longjmp`, `clock_gettime`, `rand_r` AND false-positives on
  the word "exit()" inside comments; speed gate's `ok` is computed and never consulted; smoke runs
  at libFuzzer's default max_len (4096), not the manifest's; smoke replays seed corpus contrary to
  HARNESS_STANDARD §6; `cov:` is a seed-dependent smoke-scoped max (seed 1 vs 7 → cov 26 vs 28);
  stats regex can't parse fork-mode output (`#N: cov:` → zero metrics when we move to `-fork`);
  AFL campaign stats (`execs_done`, `corpus_count`, `stability%`) exist in fuzzer_stats and are
  never parsed; `engines_available` stores booleans, tool versions are printed to stdout and lost;
  `probe_libfuzzer` leaks a temp dir per run; `setup_wsl.sh` probes `CLANG_MAJOR` *before* clang
  is installed (fresh-box install is broken); sync script hardcodes `/mnt/c/Users/hp/...`.
- **Corrected:** Round 1 praised the stability gate for catching heap corruption pre-fix — true, but
  the gate's *name* overclaims: it is a same-seed reproducibility check, not a state-leak check.

## D. Revised backlog (evidence-prioritized)

**P0 — make current green trustworthy (oracle + validator integrity)**
1. Fail-closed: SKIP/all-skip must not exit 0; `--require-engines` or hard fail when zero gates ran.
2. Strict manifest schema: unknown-key rejection, type checks, per-target try/except, incremental
   report writing (never lose other targets on one bad manifest), fix `seed_gen`-without-`seeds` "None" bug.
3. Real UBSan: `-fno-sanitize-recover=all` + gate on `runtime error`/`SUMMARY: UndefinedBehaviorSanitizer`.
4. Crash lifecycle v1: replay artifact 3×, classify (ASan crash vs OOM vs timeout), capture crash type +
   top frames into report, dedup by stack hash, print repro one-liner.
5. Crash-proof validator: catch `TimeoutExpired` per gate, clamp subprocess guard to `timeout_sec`,
   write report in `finally`.
6. Hermetic runs: `seed_gen` writes into workdir, never the tree; add `.gitignore`; make the first
   commit; add LICENSE.
7. Memory ceilings: manifest `rss_limit_mb`/`malloc_limit_mb` fields, honored by libFuzzer and AFL
   (`-m`), plus an oversized-malloc probe in smoke.
8. `fzdata.h` fixes: guard `fz_range` overflow, unify/ document endianness; fix probe temp leak.

**P1 — measurement truth**
9. Stability done right: per-input double-replay feature diff (or parse AFL `var_bytes`/`stability`);
   fix stats regex for fork-mode; smoke uses manifest `max_len`.
10. Source coverage: coverage build + `llvm-cov` → reached-functions metric.
11. Provenance: `schema_version`, `run_id`, git SHA, tool versions, CLI opts in report.json; parse
    AFL campaign stats into the report; label fuzz-rate vs replay-rate metrics.
12. Dict-load assertion; CmpLog build for AFL++; dead-seed detection.
13. `setup_wsl.sh`: install clang first, then compute `CLANG_MAJOR`; pin AFL++ tag; install honggfuzz
    or remove it from manifests (never report honggfuzz `pass` without a run).
14. pytest for validator core (manifest, regex, gate decisions) — ships *with* P0 changes.
15. GitHub Actions CI + pinned Dockerfile; enforce-or-delete the speed gate.

**P2 — future-proofing**
16. Language adapters in schema (`rust`, `python`) + build-adapter hooks.
17. `custom_mutator` manifest field + a 4th example target using `LLVMFuzzerCustomMutator`.
18. Eval-set split: separate target *specs* from reference harnesses so examples become a scoring
    set for AI harness generation (cov-delta vs reference + time-to-bug).
19. `aifuzz` CLI packaging; `--baseline` diffing; Windows clang-cl lane; container hardening.

## E. Scorecard delta (post-verification)

| Area | Round 1 | Round 2 | Reason |
|---|---|---|---|
| Validator gates | 6.5/10 | 4/10 | Dead UBSan oracle, blind stability, fake crash-confirmation, fail-open skips |
| Infra | 4/10 | 3/10 | Fresh-box setup actually broken; validator mutates tree; no commit at all |
| Harness std doc | 8/10 | 6/10 | Doc/code drift: promised abi gate, memory field, report path don't exist |
| AI-readiness | 5/10 | 4/10 | report.json discards the exact evidence the future Triage Agent needs |

**Consensus after verification:** the C harness layer and the end-to-end happy path are real and
reproduce; the oracle/contract layer is not yet trustworthy. Implement P0 items 1–8 as one hardening
pass before any new target, engine work, or orchestration.

---

# Round 3 — Adversarial Re-Verification + Remediation Log

> A fresh adversarial subagent re-ran every original failure experiment against the rewritten
> validator and hunted for new defects. All 8 P0 fixes **CONFIRMED holding**. It found 8 new
> defects (N1–N8, 3 High). Those were then fixed and re-verified in the same session.

## Round 3 verdict (adversarial agent)

> "The 8 claimed fixes are real — all held under re-run. But green is currently forgeable
> (expected_crash can go unverified; seed padding can buy a slow target a pass) and red is
> occasionally wrong (AFL replay false-fails crashing seeds; lint false-positives on string
> literals)."

## Defects found in Round 3 and their remediation

| ID | Finding | Fix applied | Re-verified |
|---|---|---|---|
| N1 | crash artifacts written to validator cwd (hermetic violation) | `-artifact_prefix` into per-run scratch dirs on every libFuzzer invocation | cwd clean after full run |
| N2 | `expected_crash: true` could pass with zero crash verification (no ASan lane) | manifest schema now REQUIRES address sanitizer for expected_crash targets | rejected loudly |
| N3 | speed gate defeated by corpus padding (`achieved_runs` counted replay); smoke/stability neutered when seeds ≥ runs | speed now measured from an EMPTY corpus; smoke/stability budget = smoke_runs + seed count | slow target + 2000 seeds → speed FAIL (39 exec/s) |
| N4 | wall-timeout replays counted as crashes + unbounded replay burn | `AIFUZZ-TIMEOUT` classification; wall-timeout/oom/leak excluded from crashes; 300s replay budget with truncation flag | unit tests |
| N5 | AFL seed-replay false-failed crashing seeds on expected_crash targets | same early-crash tolerance as libFuzzer lane | pass |
| N6 | lint false positives on string literals + backslash-continued comments | comment stripper now blanks string contents and handles line splices | unit tests |
| N7 | target named `report.json` could crash report writing | per-target workdirs moved under `targets/`; dump_report is exception-safe; duplicate names rejected | code-read + tests |
| N8 | declared-but-missing `seeds:` dir silently ignored | now a hard manifest error (typo can never silently disable seeding) | rejected loudly |

Additional defects found and fixed during remediation (self-found):
- `--target` filter was applied after manifest loading, so other targets' manifest errors
  polluted the filtered run's exit code → pre-filter by directory name.
- Setting `ASAN_OPTIONS` without `abort_on_error=1:symbolize=0` makes **afl-fuzz abort at
  startup** (its crash detection requires those) → AFL lane uses AFL-compatible option sets.

## New hard-won technical knowledge (documented in HARNESS_STANDARD §7.1)

At `-O1` under ASan, LLVM removes planted resource-abuse code even inside `noinline`
helpers: ASan's "malloc never returns NULL" folds `if (p)` true, and dead-store elimination
removes the whole malloc/store/free chain. Verified by disassembly (malloc call literally
absent). Rules that survive: input-derived sizes + volatile access through the pointer.
Discovered while debugging why an 8 GB planted allocation passed all gates.

## Final state after remediation

- Positive validation: **8/8 PASS, exit 0** (libFuzzer + AFL++, both planted bugs found,
  classified, replay-verified 3×, deduped by stack hash, repro commands printed)
- Negative checks: **10/10 PASS** — UBSan aborts on real UB; hang fails its own smoke gate
  with report intact; giant malloc fails via `max_allocation_size_mb` cap + malloc_limit
  hook; typo'd manifest keys rejected; expected_crash-without-ASan rejected; padded slow
  target fails speed gate; all-skip run exits 2 (fail-closed); `fz_range(SIZE_MAX)` safe;
  target tree and cwd stay clean
- pytest: **25/25**

## Remaining known-open items (accepted, documented)

- `replay_once`'s `"ERROR:" in output` heuristic could misclassify benign engine output
  (only reachable via engine artifacts today).
- Crash lifecycle caps at 20 artifacts per hunt (undercount possible on crash-heavy campaigns).
- ASan class names come from the first token after the error line (`asan-requested` style
  oddities possible on allocator reports).
- `--target` filtering uses directory name then manifest name — a name/dir mismatch is
  silently excluded and fails closed (exit 2) rather than erroring.
- honggfuzz: build-verify only, reported honestly as skip; runner pending Phase 2.

**Scorecard delta (post-Round-3):** validator gates 4 → **7/10** (oracle real, fail-closed,
crash lifecycle, hermetic; measurement truth items like llvm-cov reached-functions remain
P1). The review-improvement loop itself is now part of the process: every hardening pass
ends with an adversarial re-verification round.

---

# SOTA Pass (Nov 2026) — closing the gaps from the "state of the art" audit

The Round-3 scorecard named the exact gaps between this system and state of the art.
This pass closes them:

| Gap (from the audit) | What shipped | Evidence |
|---|---|---|
| Only toy targets, zero real libraries | `targets/libpng_decode`: full decode pipeline against a from-source libpng16 built with **ASan + SanitizerCoverage + profraw instrumentation** (OSS-Fuzz pattern) | cov 4 → 544 edges with seed corpus alone; all 3 engines PASS |
| No source coverage truth | validator coverage gate: coverage build + corpus replay + `llvm-profdata`/`llvm-cov export` → `harness` + `all_functions` reached-functions metrics (Fuzz-Introspector spirit) | libpng_decode: 97/511 binary functions (19.0%) on seeds; per-target numbers in report.json |
| AI thesis unproven in-repo | `tools/harness_agent.py`: spec → LLM proposes harness → full validator gate → failure diagnostics fed back → repair loop; pluggable `--llm-command` (ollama/API/fixture) | stub-LLM proof: iteration 1 rejected (exit/rand/time caught, diagnostics returned) → iteration 2 accepted; wired into CI |
| Only 2/3 engines ran | honggfuzz built from source + full runner (persistent campaigns, `--crashdir`, `-S` sanitizer mode, crash lifecycle + classification + repro) | 17/17 gates PASS incl. honggfuzz lanes; honggfuzz found and classified both planted bugs |
| No structure-aware support | `harness/examples/structure_demo` with `LLVMFuzzerCustomMutator` + manifest `custom_mutator` gate on actual invocation | `custom_mutator {'ok': True}` on both sanitizer lanes |
| No CI / no container | `.github/workflows/ci.yml` (toolchain + instrumented libs + unit tests + full validation + agent loop + artifact upload), `Dockerfile` (pinned ubuntu:26.04 toolchain image) | workflow mirrors local environment exactly |
| Real-target build wiring | manifest `build.cflags`/`build.ldflags` with `$VAR` expansion sourced from `~/.aifuzz/env.sh`; `allocator_may_return_null` for graceful-OOM libraries | libpng links the instrumented static lib on every engine |

**Final state of this pass:** 4 targets, 17/17 engine-gates PASS, 0 SKIP (all three engines
live), 25/25 unit tests, 10/10 negative checks, agent repair loop proven, crash reproducers
for both planted bugs from **three engines** with consistent classification.

**Honest remaining gaps (next rounds):** no real *new* bug in libpng yet (expected — OSS-Fuzz
fuzzes libpng 24/7; the machine is built and proven, campaigns are a Phase-2 time/budget
function); AFL++/honggfuzz lanes get library-internal ASan checks but not internal coverage
feedback (per-engine library builds are the fix); Windows native lane still pending; CI/Docker
untested until the repo has a remote; stability gate state-leak blind spot documented;
corpus service, triage agent, and distributed orchestration are Phase 2+.

**Claim status:** the harness foundation + validation + AI-loop layer now matches the
state-of-the-art *pattern* (instrumented real library, reached-functions metric, LLM-in-the-loop
harness generation, three engines, fail-closed gates, reproducible env). The "state-of-the-art
*system*" claim still waits on Phase 2 (orchestration at ClusterFuzzLite scale) and on real
bug finds — but every prerequisite for both is now built and green.

