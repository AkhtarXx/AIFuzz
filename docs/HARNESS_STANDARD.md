# AIFuzz Harness Standard (v0.1)

This document defines the contract every AIFuzz fuzz target must follow. It is based on the
research in `RESEARCH_REPORT.md` (libFuzzer/AFL++/OSS-Fuzz conventions, Google's
good-fuzz-target rules) so that one harness runs under every engine we orchestrate.

## 1. The ABI (cross-engine standard)

Every fuzz target exports exactly one entry point:

```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
```

This is the libFuzzer ABI and it is driven by:

| Engine | How it drives the harness |
|---|---|
| libFuzzer | `-fsanitize=fuzzer` links its own `main` |
| AFL++ | `afl-clang-fast` build + `libAFLDriver.a` (or raw `afl-fuzz` persistent mode) |
| honggfuzz | `hfuzz-clang` build, in-process persistent mode, native support for this ABI |
| Centipede (future) | same ABI |
| WinAFL/Jackalope (Windows, future) | different model: target function loops; handled by a separate adapter |

## 2. Harness rules (hard requirements)

1. Accept any input: empty, huge, malformed. Never reject by exiting.
2. Never call `exit()`, `abort()` (except the bug itself), `system()`, or longjmp out.
3. Deterministic: no `time()`, `srand()`, `rand()`, `getenv()` affecting control flow.
   If the target library needs a seeded PRNG, seed it from the input or a constant.
   Use `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` to disable fuzzing-hostile features
   (CRC checks, timestamps, randomness).
4. Fast: no disk writes, no logging, no network, no O(n^3) loops. Target >1k execs/sec.
5. Narrow: one target per format/API. Split big parsers into several targets.
6. No global state leaks between iterations (or accept that only fork modes work).
7. Threads must be joined before returning.
8. No unbounded allocations; declare memory ceiling via manifest.

Violations of 1–3 are caught by `tools/harness_check.py` lint; 4 is caught by the exec/s gate.

## 3. Target layout

```
harness/examples/<target_name>/
├── fuzz_target.c        # the harness (or several .c/.cc files listed in manifest)
├── manifest.yaml        # target metadata + engine matrix
├── dictionary.txt       # optional, libFuzzer/AFL dictionary format
├── seeds/               # optional, initial corpus (one file per input)
└── make_seeds.py        # optional, generates seeds/ when missing (binary formats)
```

## 4. manifest.yaml schema

```yaml
name: chunked_format            # required, unique, no path separators; must equal the directory name
description: one-liner          # required
language: c                     # c | cpp
sources: [fuzz_target.c]        # required, relative to target dir
build:
  cflags: [-I$AIFUZZ_LIBPNG16_INC]   # extra compile flags; $VARs expanded from env + ~/.aifuzz/env.sh
  ldflags: [$AIFUZZ_LIBPNG16_LIB, -lz]  # extra link flags/libraries (real targets)
fuzz:
  max_len: 512                  # default 4096, 1..10000000
  timeout_sec: 10               # default 25, 1..3600
  dict: dictionary.txt          # optional; file MUST exist or validation fails loudly
  seeds: seeds                  # optional COMMITTED seed dir; MUST exist if declared
  seed_gen: make_seeds.py       # optional; alternative to committed seeds (runs if no seeds); output goes to the workdir, never the tree
  expected_crash: true          # boolean (strict); requires the address sanitizer — the crash-hunt gate is inescapable
  rss_limit_mb: 2560            # default 2560; passed to libFuzzer -rss_limit_mb / AFL -m (non-ASan builds)
  malloc_limit_mb: 2560         # default = rss_limit_mb; passed to libFuzzer -malloc_limit_mb + ASAN_OPTIONS max_allocation_size_mb
  custom_mutator: false         # true = target defines LLVMFuzzerCustomMutator; validator gates on actual invocation
  allocator_may_return_null: true  # true = ASAN_OPTIONS allocator_may_return_null=1 (libraries that gracefully handle failed huge allocations, e.g. image decoders)
engines: [libfuzzer, aflplusplus, honggfuzz]   # which engines to validate against
sanitizers: [address, undefined]
tags: [example, binary-format]
```

Manifests are **strictly validated**: unknown keys, wrong types (e.g. `expected_crash: truu`),
or missing declared files (sources/dict/seed_gen) are hard target-level failures — a typo can
never silently disable a gate. Note: with ASan builds, AFL campaigns run with `-m none`
(ASan reserves huge virtual address space); libFuzzer enforces rss/malloc limits in-process.

## 5. Input consumption helpers

For C targets use `harness/include/aifuzz/fzdata.h` (header-only, deterministic):

```c
#include "aifuzz/fzdata.h"

FzData d = fz_init(data, size);
if (fz_remaining(&d) < 5) return 0;
uint8_t  t = fz_u8(&d);        // scalars consume from the front, 0 when exhausted
uint16_t l = fz_u16le(&d);
size_t   n = fz_range(&d, 63); // uniform-ish value in [0, 63]
size_t got = 0;
const uint8_t *payload = fz_bytes(&d, l, &got);  // bulk consume, no copy
```

For C++ targets LLVM's `<FuzzedDataProvider.h>` (shipped with clang) is also acceptable.
Rules: never read `data[i]` past `size`; derive every decision from the input.

## 6. Validation gates (tools/harness_check.py)

A harness is ACCEPTED only if it passes all gates for every available engine:

| Gate | Meaning | Rule |
|---|---|---|
| build | compiles + links with each engine's compiler wrapper | errors block |
| smoke | seed corpus replays cleanly + time-boxed light fuzzing (no dictionary, manifest max_len, rss/malloc limits enforced) | no crash/leak/OOM/timeout/UB |
| speed | measured exec/s (libFuzzer, dedicated run) | hard fail < 50/s, warn < 500/s |
| stability | two identical-seed runs reach identical cov/ft | delta must be 0; AFL campaigns additionally gate on measured stability% ≥ 90 |
| crash-hunt | only for `expected_crash: true` under ASan: fuzz with dict for `crash_timeout` seconds | at least one artifact must replay-deterministically as a real crash (3× replay), classified (ASan type / UBSan / signal), deduped by top-frames stack hash; OOM/timeout/leak artifacts do NOT count |
| lint | comment-aware regex checks for rule violations (§2) | errors block, warnings listed |

The validator is **hermetic**: `seed_gen` output goes to the workdir, the target tree and
seeds dir are never written to. The validator is **crash-proof**: per-gate wall-clock guards,
per-target error capture, and report.json is written incrementally — one bad target can never
destroy the run's results.

Exit codes: `0` = all executed gates passed · `1` = gate failures · `2` = zero gates executed
(fail-closed; override with `--allow-skip`). A run that validates nothing can never exit green.

**Coverage metric (per target):** after engine gates, the validator builds a
`-fprofile-instr-generate -fcoverage-mapping` variant, replays the seed corpus through it,
merges with `llvm-profdata` and exports with `llvm-cov`. The report carries two numbers:
`coverage.harness` (functions of the harness source reached) and `coverage.all_functions`
(every instrumented function in the binary — for instrumented-library targets like
`targets/libpng_decode` this is the real reached-functions metric in the Fuzz Introspector
spirit). This is the number the future Harness Agent optimizes.

Report: machine-readable JSON at `<workdir>/report.json` (default `~/.aifuzz/work/report.json`),
schema versioned (`schema_version: 2`) with full provenance (run id, git SHA, tool versions,
CLI options), per-gate details, crash classifications with top stack frames, stack hashes,
and one-line reproducers.

## 7. Seeds & dictionaries

- Seeds: small, valid, varied. Regenerable via `seed_gen` for binary formats (checked in).
  The validator generates `seed_gen` output **into its workdir** — the target tree is never touched.
- Dictionaries: libFuzzer format (`kw="\x41\x49"`, `# comments`). Magic bytes, keywords,
  protocol tokens. A declared dictionary file that does not exist is a hard validation failure.
- The corpus belongs to the engine runtime, not the target dir. Never mutate seeds/.
- libFuzzer takes a writable corpus dir as the first argv and read-only source dirs after
  that; the validator always passes a fresh scratch dir first so runs are reproducible.
- The lint gate is comment-aware (a commented-out `exit()` is not a violation) and knows
  `_exit`, `longjmp`, `rand_r`, `clock_gettime` etc. ABI presence is checked on raw source.

### 7.1 Planted-bug targets (self-test corpus)

Targets with `expected_crash: true` encode a known bug to prove the pipeline end-to-end.

- Planted memory bugs must be ASan-detectable; restrict `sanitizers: [address]` for these
  targets. A heap/stack overwrite under a non-ASan build corrupts memory nondeterministically
  and will (correctly) fail the stability gate.
- At `-O1`, LLVM eliminates `malloc` + dead stores + `free` patterns entirely: a planted
  overflow can be optimized away before Asan instruments it. Prevent escape analysis from
  proving the buffer is dead — write through a `__attribute__((noinline))` helper (see
  `kv_config/fuzz_target.c`) or use library calls like `memcpy` that Asan intercepts
  (see `chunked_format/fuzz_target.c`).
- `noinline` is NOT sufficient (verified by disassembly): LLVM's intraprocedural DSE
  removes the allocation *inside* the helper, and ASan's "malloc never returns NULL"
  knowledge (`allocator_may_return_null=0` default) folds the `if (p)` guard to true.
  Two rules keep resource bugs alive at any `-O` level: (1) derive sizes from the input,
  (2) access the allocation through a volatile pointer (`*(volatile char *)p = 1;`) so the
  allocation is observable. See the oomtest negative fixture used by the validator checks.
- Resource-abuse planted bugs (giant single allocations) are caught by the validator via
  the `ASAN_OPTIONS=max_allocation_size_mb` allocator cap it sets for ASan builds —
  plus libFuzzer's `-malloc_limit_mb` hook. Under AFL++ the cap is
  `abort_on_error=1:symbolize=0:detect_leaks=0:...` (AFL++ aborts on incompatible ASAN_OPTIONS).
- Keep the crash-relevant condition input-derived and seeded close to (but not at) the
  boundary so engines reach it in seconds, not minutes.

## 8. Engine build matrix

| Engine | Compiler | Sanitizer flags | Fuzz-time driver |
|---|---|---|---|
| libfuzzer | `clang` | ASan: `-fsanitize=address`; UBSan: `-fsanitize=undefined -fno-sanitize-recover=all` (UB aborts, it never "recovers" silently) | binary itself |
| aflplusplus | `afl-clang-fast` | same as above | binary for smoke, `afl-fuzz` for campaigns (`-m none` under ASan, manifest rss limit otherwise) |
| honggfuzz | `hfuzz-clang` | same as above | `honggfuzz -P` persistent campaigns (auto-detected), crashes to `--crashdir`, `-S` sanitizer mode |

Custom mutators (`LLVMFuzzerCustomMutator`) are a libFuzzer feature; declare
`custom_mutator: true` and the validator gates on the mutator actually being invoked
(libFuzzer logs `MS: ... Custom-`). See `harness/examples/structure_demo`.

Real targets live under `targets/` (examples under `harness/examples/`); the validator
scans both roots and `--targets` is repeatable. System libraries can be replaced by
instrumented builds via `build.cflags`/`build.ldflags` with `$VARS` sourced from
`~/.aifuzz/env.sh` (see `scripts/setup_wsl.sh` which builds an ASan+SanCov+profraw
libpng16 and exports the paths).

Environment quirks (WSL2): `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`,
`AFL_SKIP_CPUFREQ=1`, `AFL_NO_AFFINITY=1` are set by the validator automatically.

## 9. Windows / Linux unification

Source of truth is this repo (Windows side). Builds and fuzzing run inside WSL Ubuntu on
the Linux filesystem (fast I/O) after `scripts/sync_to_wsl.sh`. Closed-source Windows PE
targets later go through a separate adapter (WinAFL/Jackalope worker), but every
source-available target uses this single standard.
