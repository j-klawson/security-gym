---
id: D2
title: Purpose of the eBPF channels
status: decided
decided: 2026-11-08
decided_by: author
source: author, 2026-11-08
affects: [SPEC-CORPUS 5, SPEC-BENCH 3, SPEC-BENCH 4]
related: [D1, D3, D12]
---
# D2. Purpose of the eBPF channels

## Context

The specification must commit to a purpose for the kernel channels, because the known defects are tolerable for some purposes and fatal for others. eBPF is 97.51% of `exp_30d_heavy_v4` events and `ebpf_file` alone is 90.77% (`data/provenance/BENIGN_COMPOSITION_AUDIT_20261108.md` Section 3: 20,975,760 and 19,525,522 of 21,511,208). As-built, the kernel channels carry the address-presence artifact (defect 6), cross-host PID collision (defect 2), byte-reversed `connect` addresses (defect 4), address-less `accept` events (defect 5), and window-inheritance labeling (defect 7).

**Exp 13 figure conflict (unresolved).** CLAUDE.md, TODO.md, and earlier spec text cite Exp 13 as a 60% MAE reduction with Cohen's d = 2.577. That figure is under review by the author; the code cannot settle it, and no document cites it as current until the author confirms (README OI-INDEX-4).

## Options

- **Purpose 1: kernel-channel detection and host attribution.** The agent infers compromise from kernel evidence (canonical signal: `execve` with `parent_comm=redis-server`, a service spawning a shell) and contains the host or process it attributes that evidence to. This is the EDR analogy and the reason the target slate exists. As-built it is unsupported: file and process events can be attributed to a host only through the enriched `src_ip`, which is the leak; `accept` has no peer address; benign ancestry is corrupted. It requires PID namespacing, symmetric sessions (D1 Option B), the `accept4` peer capture, and probably re-collection.
- **Purpose 2: volume and distractor realism.** eBPF is mostly benign kernel churn that the agent must not overreact to; it makes detection hard by burying signal. Tolerates the address defects (no eBPF addresses used for control) but still needs a realistic benign distribution, so it also implies a busy single-host collection.
- **Purpose 3: prediction-ablation axis.** Whether kernel telemetry improves a predictive head. As-built this is confounded by PID collision and address presence; no result can be attributed to kernel signal until both are fixed. The next step is to re-run Exp 13 on a corrected corpus and report how much survives.

## Recommendation

The analysis recommended Purpose 1 as the headline role, gated on (a) per-host PID namespacing, (b) a symmetric process-subtree session, (c) `accept4` peer-address capture, and (d) a single-host collection on a host that is both coherent and realistically busy. Until these land, eBPF-channel and kernel-targeting results are reported as preliminary.

## Decision

**Decided 2026-11-08: Purpose 1 is the headline; Purposes 2 and 3 are also adopted.** The first experiment on the corrected corpus repeats Exp 13 under honest (attack-agnostic, host-ambient) delivery; survival or collapse of the effect is a finding either way.

## Consequences

- Every gate listed under Purpose 1 becomes a requirement of the corrected corpus (SPEC-CORPUS 5, 6, 7).
- The benchmark reports log-only and log-plus-kernel conditions (SPEC-BENCH 4).
- No document may cite Exp 13 as a 60% improvement until the author confirms which result is current.

## Open sub-items

- Which Exp 13 figure the project cites (affects README, CLAUDE.md, TODO.md, and SPEC-BENCH 8).
