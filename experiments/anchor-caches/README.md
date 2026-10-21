# Cyclic and usefulness-retained anchor caches

Neither cache earns default promotion in this bounded comparison. Both regress
source/log compression size and time. Useful retention preserves a profitable
older match under deliberate collision pressure, but improves on current rars by
only three archive bytes in that case. Default builds retain the existing finder.

## Implementation and fixed controls

The two opt-in Cargo features are `experimental-anchor-cyclic` and
`experimental-anchor-useful`, available through `rars` and `rars-cli`. Enabling
both selects useful retention. Both use a dense 64 KiB recent chain and 4,096
older anchors in 256 buckets of 16 entries, sampled at 256-byte intervals.
Cyclic replacement advances a bucket cursor. Useful replacement evicts the
lowest aged score, with deterministic cursor tie breaking. Its score estimates
literal savings minus distance bits for verified matches; it does not measure
actual Huffman cost or parser-selected savings. All matches use exact source
bytes and the existing word-at-a-time match verifier.

The parser, its repricing and recent-distance logic, dictionary selection,
filters, and RAR serialization remain the existing implementations. The cache
features replace candidate discovery in the RAR5/RAR7 encoder. They do not add a
decoder or alter the RAR format. Heap arrays use the existing controlled-memory
budget. Anchor distances are capped at `u32::MAX` to fit the optimal parser's
existing match records, even when absolute source positions exceed four GiB.

The comparison fixes rars at level 3 (the existing optimal parser), a 4 MiB
dictionary, filters disabled, one thread, non-solid RAR5 output, and a 256 MiB
controlled-memory allowance. The native control uses RAR 7.23 with `-ma5 -m3
-md4096k -mt1 -s- -mc-`. Native RAR has its own parser.

This is a **whole finder substitution** versus baseline: baseline optimal mode
uses the full-window tree on these files; the experiments use recent chains plus
anchors, including their insertion and search schedules. Only cyclic versus
useful holds those schedules fixed and isolates retention/scoring policy.

## Measured results

Six frozen, single-member workloads total 709,616 bytes. Source/log data uses
128 KiB of frozen Rust source and 128 KiB of deterministic logs. Four fixtures
reuse the mechanical runner's related-release, shifted-repeat, dictionary-gap
and unrelated-data generators. The sixth is a declared synthetic bucket-pressure
case, not representative workload evidence. It repeats the first 1,024 bytes at
offsets 66,048 and 140,288 in 196,608 bytes of `ANCH`-prefixed 256-byte blocks.
[corpus.json](corpus.json) records every input hash and seed.

Each variant ran separately with 15 paired confirmations per workload, in
addition to one screening sample and one warmup per workload. The runner shuffles
encoder role order deterministically within each task. Only one timed job ran
at once on the Apple M3 Pro host (36 GiB RAM, macOS 26.6.2 ARM64). Wall time
includes process startup and file I/O. Ratios below are medians of within-task
candidate/baseline ratios; values above 1 mean slower encoding.

| Workload | Current bytes | Cyclic bytes | Useful bytes | Cyclic time ratio (95% interval) | Useful time ratio (95% interval) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Source and logs | 35,101 | 35,468 | 35,473 | 1.178 (1.136–1.223) | 1.172 (1.119–1.237) |
| Related releases | 1,403 | 1,404 | 1,404 | 0.985 (0.926–1.077) | 1.030 (0.985–1.075) |
| Shifted repeat | 8,650 | 8,650 | 8,650 | 0.981 (0.928–1.020) | 1.033 (1.009–1.066) |
| Dictionary distance | 172,331 | 172,332 | 172,332 | 1.073 (0.989–1.388) | 1.062 (0.999–1.097) |
| Unrelated data | 24,733 | 24,733 | 24,733 | 0.990 (0.885–1.024) | 0.986 (0.572–1.090) |
| Hot prefix pressure | 192,801 | 193,803 | 192,798 | 1.026 (0.983–1.451) | 1.081 (1.030–1.432) |

Useful retention saves 1,005 bytes versus cyclic replacement on the pressure
fixture, and three bytes versus baseline. Source/log archives grow 1.05–1.06%.
Encoder CPU medians increase on every workload; peak RSS has no consistent
improvement (paired medians range from −2.2% to +2.3%).
[results.json](results.json) includes archive hashes, encode wall/CPU/RSS,
native and rars extraction wall/RSS, paired ratios and build provenance.

Intervals are exploratory per-workload bootstrap estimates (5,000 resampled
medians), with no correction for multiple comparisons. Many samples are close
to a roughly 14 ms process-launch floor. Small timing differences cannot establish
a throughput gain. These are small warm/uncontrolled-cache desktop cases, not
large-input, cold-selective-extraction, server or general RAR parity evidence.

## Correctness and project checks

All 102 tasks per variant completed and revalidated their retained receipts.
Every archive was integrity-tested and extracted by native RAR and rars, with
contents, paths, POSIX file modes and whole-second mtimes checked. That is 204
candidate archives, or 612 archives including baseline/native controls, extracted
successfully by both decoders. Candidate archive hashes were identical across
the 15 measured repetitions of each workload. Owner/group, ACLs and extended
attributes were not measured.

A separate [36-case native smoke matrix](native-smoke.json) covers all three
binaries, RAR5/RAR7, lazy/optimal parsing, plain data, an explicit delta filter,
and solid two-member history. RAR7 uses a fractional 3 MiB dictionary. Native RAR
integrity tests, extraction and content/path/mode/mtime checks all passed. This
establishes compatibility for the tested cases, not universal qualification.

Focused checks passed: 10 cache tests, 218 default encoder tests, 219 encoder
tests for each cache feature, formatting, and Clippy for rars/rars-cli with all
targets/features and warnings denied. Tests exercise retention, aging, quotas,
collisions, dictionary reach, wide positions, budgeting and actual emitted older
matches in both parsers/formats.

The required release gate is **not green**. With Python 3.14 selected, its
formatting, workspace Clippy, Rust tests (2,895 passed, 17 ignored), benchmark
smokes and external-decoder checks passed. Python had 716 passes and 11 failures:
nine filename cases and two local-timezone rewrite cases. The gate stopped there;
the subsequent npm/WASM stage was not reached. The initial system-Python attempt
also stopped because Python 3.9 is below the binding's supported minimum.

## Frozen revisions and reproduction

- Current rars baseline: `d4664689177ad50c5b94906e882e4a36fd3aca8f`.
- Measured cache source: `967c539f7bc8f4da74b4c4cc6bea0dca1d295d36`.
- Mechanical runner: `5dc3301d603a11ed4bc8267c3867275eb8a672cd`, delivered
  separately in [PR #79](https://github.com/bitplane/rars/pull/79).
- Native RAR: [7.23 macOS ARM64](https://www.rarlab.com/rar/rarmacos-arm-723.tar.gz).
- Compiler: Rust 1.97.1 Homebrew. Binary and runner SHA-256 hashes are in
  `results.json`; the corpus source snapshot is pinned in `corpus.json`.

Build separate release binaries from the baseline and measured cache revisions
with `cargo build --release --locked -p rars-cli`, adding the respective Cargo
feature for each cache. Keep the binaries outside the checkout, then use the
runner/fixture scripts from the pinned runner revision. The fixture's source
snapshot is reachable through that runner branch on the fork. Generate the
inputs once in a new output directory:

```sh
python3 experiments/anchor-caches/prepare_corpus.py \
  --output /absolute/experiment \
  --repository /absolute/repository-with-pinned-history \
  --fixture-script /absolute/pinned-runner/scripts/hybrid_fixtures.py
```

For each cache, initialize a separate controls experiment. Its generated plan
fixes dictionary, filters and threads and limits screening to 300 host-seconds
and confirmation to 600 host-seconds, with a 60-second task timeout:

```sh
python3 /absolute/pinned-runner/scripts/hybrid_candidates.py init \
  --output /absolute/run-cyclic --experiment controls --profile desktop \
  --repository /absolute/clean-measured-cache-checkout \
  --rars /absolute/bin/rars-cyclic --baseline /absolute/bin/rars-current \
  --native-rar /absolute/native/rar \
  --corpus /absolute/experiment/corpus/manifest.json \
  --plan /absolute/experiment/plan.json --seed 20261017
python3 /absolute/run-cyclic/frozen/hybrid_candidates.py run /absolute/run-cyclic
python3 /absolute/run-cyclic/frozen/hybrid_candidates.py status /absolute/run-cyclic
```

Repeat with a different output directory and the useful binary, after the cyclic
run finishes. The journal resumes unfinished tasks and preserves verified
completions. Keep raw frozen inputs, task receipts and archives locally; native
RAR binaries are not included in this repository. The results here were frozen
before dispatch; these report-only additions were made afterward.
