---
id: SPEC-BENCH
title: security-gym control benchmark
version: 0.1-draft
status: draft
date: 2026-11-09
verified_against: a70aeda (package 0.6.2)
scope:
  - examples/
  - benchmarks/          # planned: protocol files, runner, analyzer
depends_on: [SPEC-ENV, SPEC-CORPUS]
decisions: [D2, D5, D9, D10, D11, D13, D15]
---

# SPEC-BENCH: Control Benchmark

## Abstract

This document specifies what makes security-gym a benchmark: a pinned evaluation
protocol, control metrics computed per attack instance, baselines evaluated under
that protocol, and reporting obligations. None of this exists as built; the
document states the requirements the protocol must meet and the decisions it
waits on. Conventions, principles, and the glossary are in
[README.md](README.md).

## 1. Introduction

### 1.1 Scope

Evaluation of agents on SPEC-ENV environments over SPEC-CORPUS streams, and the
experiments required of the corrected corpus.

### 1.2 As-built

No evaluation protocol is pinned in the repository. `examples/benchmark.py`
reports precision, recall, F1, and mean reward from a single seed (lines 38-40,
74-76), which measures per-event classification, not control. The baselines are a
random policy, two rule heuristics (`threshold_agent.py`, `keyword_agent.py`), and
a pass-only floor; no learning control agent has been evaluated. Every reward
figure produced to date carries the grading defects of SPEC-ENV ENV-R-130 and
ENV-R-150.

## 2. Conventions and Terminology

As in [README.md](README.md) Section 2. "Benchmark" means this protocol together
with its baseline results, never a single stream.

## 3. Benchmark Definition

- **BENCH-R-001** (MUST). The benchmark is versioned. A protocol version pins the
  environment version and registered ID, the action set, the observation
  configuration, the reward table, the streams (by digest), and the statistics
  reported.
- **BENCH-R-002**. The relation between the first protocol version and the
  process-level actions of D11 is open. If D11 lands after the first protocol
  freeze, either protocol version 1 declares the address-level action set with the typed target
  as a named extension point and version 2 adds the process-level actions with its
  own baselines, or the freeze waits for D11 (decided with D10).
- **BENCH-R-003** (MUST). A protocol version is published only after SPEC-ENV
  ENV-R-130, ENV-R-150, ENV-R-151, and ENV-R-152 are met.

## 4. Streams and Configuration

- **BENCH-R-010** (MUST). The protocol names its streams by digest. The core scope
  is the 7-day and 30-day streams of the corrected corpus; the 90-day and 365-day
  streams serve drift measurements. If the first benchmark numbers are produced before the
  corrected corpus is released, the protocol states whether they use a
  pre-release of the corrected corpus or the legacy streams with the SPEC-ENV
  ENV-R-060 caveat.
- **BENCH-R-011** (MUST). The protocol fixes the full configuration of SPEC-ENV
  ENV-R-230: mode, `block_visibility`, `block_ttl`, `defense_state_obs`,
  `target_slate_size`, and the reward specification. The values are open
  (OI-BENCH-1).
- **BENCH-R-012** (MUST). Every configuration run under the protocol records which
  observation sources are present (log-only or log plus kernel), since
  process-level actions exist only with kernel channels (SPEC-ENV ENV-R-091).

## 5. Control Metrics

The metric set is open (D10). Candidates, all computed from `info` by an
evaluation harness, never by the agent:

| Metric | Definition | Requires |
|---|---|---|
| Containment | fraction of an instance's events after its first effective control that are suppressed | `instance_id` (D13), `action_effective` |
| Time to containment | events and stream-seconds from instance start to first effective control | instance start (D13) |
| Collateral | benign events dropped, attributed by class | ground truth |
| Recovery | steps from a false block to its unblock | reachable `unblock` |
| False-positive rate of blocks | blocks of benign targets over all blocks | ground truth |
| Attackers released while active | unblocks of an address whose instance is still emitting | `instance_id` |
| Observable fraction | fraction of the stream not suppressed | defense layer |
| Isolation usage | steps under isolation | D5 |
| Drift | each metric across the 90-day and 365-day streams | long streams |

- **BENCH-R-020** (MUST). Per-instance metrics are computed per `instance_id`, not
  per source `campaign_id` or per address.
- **BENCH-R-021** (MUST). Detection metrics (precision, recall, F1) MAY be reported
  beside control metrics but MUST NOT be reported as the benchmark score.
- **BENCH-R-022** (MUST). Metrics are computed from a run record written per
  (agent, stream, seed): one row per step with `event_id`, `instance_id`,
  `is_malicious`, action, resolved target, `action_effective`, and whether the
  event was suppressed, plus the final defense state. The record is the only input
  to scoring.
- **BENCH-R-023** (MUST). Each metric is a pure function over the run record and
  is reported on its own, with a defined value for degenerate cases (for example
  time to containment of a never-contained instance, recovery when no false block
  occurred). Tests use hand-built records with known values, including one where
  detection F1 is high and containment is zero (the inert-action case), which must
  show the gap.
- **BENCH-R-024** (MUST). Suppression is attributed at the source: the environment
  reports suppressed benign and suppressed malicious events as separate counters
  in `info` (SPEC-ENV ENV-R-132), or the run record derives them.
- **BENCH-R-025** (MUST). The protocol declares one aggregate control score with
  its weights in the protocol file, overridable from the command line with the
  override recorded. Detection F1 and the control aggregate are reported side by
  side with their difference, per agent and per attack type. The weights, and
  whether F1 is a component of the aggregate or reported only beside it, are open
  (OI-BENCH-3).

## 6. Protocol

- **BENCH-R-030** (MUST). The protocol is a configuration file plus a runner, not
  prose: streams, step budget per stream, seed count, warm-up handling, and the
  statistics reported.
- **BENCH-R-031** (MUST). Stream seed and policy seed are separate. Paired
  comparisons share stream seeds and vary policy seeds (SPEC-ENV ENV-R-213).
- **BENCH-R-032** (MUST). Results report mean, standard deviation, and the seed
  count; comparisons between two conditions report an effect size (Cohen's d) with
  a paired test.
- **BENCH-R-033** (MUST NOT). The environment exposes no warm-up or evaluation
  phase (P3); any warm-up exclusion is applied by the analyzer and stated.
- **BENCH-R-034** (MUST). The protocol file (`benchmarks/protocol.yaml`) names the
  streams (resolved through the release manifest, SPEC-CORPUS CORPUS-R-141), step
  budget per stream, warm-up steps excluded from scoring, seeds, observation mode,
  the full configuration of SPEC-ENV ENV-R-230, the reward-matrix overlay, and the
  metric weights. The analyzer computes a hash of the protocol file and of the
  environment version and refuses to tabulate records whose hash differs.
- **BENCH-R-035** (MUST). The runner enumerates agents by streams by seeds, writes
  one record per cell under `benchmarks/results/<protocol_hash>/`, is resumable
  (a cell with a complete record is skipped), and before each run verifies that
  the stream's digest matches the manifest.
- **BENCH-R-036** (MUST). The analyzer reports per-agent means with standard
  deviation across seeds, per-stream and per-attack-type breakdowns, and paired
  differences between agents over shared (stream, seed) cells with standard error,
  95% interval, and Cohen's d. Result tables in README.md are generated by the
  analyzer, not typed.
- **BENCH-R-037** (MUST). The seed count is chosen from the within-cell standard
  deviation of the random and learning baselines measured in a pilot, and the
  choice and its basis are recorded in the protocol file (OI-BENCH-4). The
  environment is deterministic given the stream seed, so the policy is the main
  stochastic element.
- **BENCH-R-038** (SHOULD). Once instance identity and the runner exist, the
  analyzer also reports: the cumulative control aggregate against step index
  (anytime curve, which also shows drift on the 90-day and 365-day streams);
  per-instance containment segmented by instance-size quartile; and the Spearman
  correlation between agents of per-instance containment, which separates
  instances hard for every agent from weak agents and serves as a corpus
  diagnostic.

## 7. Baselines

- **BENCH-R-040** (MUST). At least one learning control baseline (for example
  streaming SARSA over the same observation) is evaluated under the protocol, to
  establish whether the control problem is learnable.
- **BENCH-R-041** (MUST). The heuristic agents and the pass-only floor are
  reported under the control metrics, so that comparisons are like for like.
- **BENCH-R-042** (MUST). Baseline orderings are reported under the default reward
  table and under the reward-matrix overlays of D9, so that sensitivity of the
  ordering to the reward specification is visible.

## 8. Reporting

- **BENCH-R-050** (MUST). Every published number states the protocol version,
  environment version, stream digests, full configuration (SPEC-ENV ENV-R-230),
  reward table, seeds, and the commit that produced it.
- **BENCH-R-051** (MUST). A result produced on the legacy v4.1 streams states the
  legacy defects it is exposed to (SPEC-CORPUS 15) and, for text mode with default
  channels, the `current_src` leak (SPEC-ENV ENV-R-060).
- **BENCH-R-052** (MUST). The analyzer runs the separability check (SPEC-CORPUS
  CORPUS-R-130) on every stream it reports on and refuses to report on a stream
  that fails it, unless the failure is named in the report.

## 9. Required Experiments

- **BENCH-R-060** (MUST). The first experiment on the corrected corpus repeats
  Exp 13 under honest (attack-agnostic, host-ambient) delivery; survival or
  collapse of the effect is reported either way (D2). Whether the earlier Exp 13
  figure is cited at all is open (README.md OI-INDEX-4).

## 10. Security and Integrity Considerations

A benchmark score is only as valid as the label-blindness of the observation and
the alignment of the reward. BENCH-R-003 and BENCH-R-052 exist because both have
failed in this project: a reward that pays without effect and graded on the wrong
event, and observation channels that carry construction artifacts correlated with
the label. Agents that read `info` during evaluation are disqualified until D8 is
decided, and thereafter by rule.

## 11. Open Issues

- **OI-BENCH-1.** The published default configuration (BENCH-R-011). The
  baselines are regenerated under whatever is fixed here.
- **OI-BENCH-2.** Whether the first benchmark paper reports on a pre-release of the
  corrected corpus or on the legacy streams (BENCH-R-010).
- **OI-BENCH-3.** Weights of the control aggregate, and whether detection F1 is a
  component of it or reported only beside it (BENCH-R-025).
- **OI-BENCH-4.** Seed count and per-stream step budget, after a pilot measures
  within-cell standard deviation (BENCH-R-037).
- **OI-BENCH-5.** Whether to build an `inspect_ai` adapter (Appendix A.3), and if
  so where it sits relative to ROADMAP Phase 15.

## 12. References

- [README.md](README.md), [SPEC-ENV.md](SPEC-ENV.md),
  [SPEC-CORPUS.md](SPEC-CORPUS.md).
- Decision records D2, D5, D9, D10, D11, D13, D15 in
  [decisions/](decisions/README.md).
- Microsoft ACES Evals (https://github.com/microsoft/ACESEvals, commit `2c76fbdea`): source of the
  practices in Appendix A.

## Appendix A. Practices Adopted from and Declined from ACES Evals (informative)

A comparison with Microsoft's ACES evaluation suite (2026-11-07) concluded that
its protocol is not adoptable as a whole, since it is sample-based and LLM-centric
with no continuing-environment semantics, but that several of its practices
transfer.

### A.1 Adopted

| ACES practice | Here |
|---|---|
| Digest-verified artifact manifest materialized before use (`range_logs.yaml`, `MaterializeRangeLogs`) | SPEC-CORPUS CORPUS-R-141; BENCH-R-035 preflight |
| Declared unit of analysis (sample IDs) | attack instance, `instance_id` (D13); BENCH-R-020 |
| Atomic scorers with a declared aggregate and an override | BENCH-R-022 to BENCH-R-025 |
| Protocol as configuration plus runner plus analyzer (`run_saber_sim_matrix.sh`, `analyze_saber_sim_matrix.py`) | BENCH-R-030, BENCH-R-034 to BENCH-R-036 |
| Budget curves, effort segmentation, difficulty agreement (ACES Experiments 9a, 12, 13) | BENCH-R-038 |
| Disclosure of score-moving configuration (ACES warns on unset `reasoning_effort`; here `include_risk_reward` moved the pass-only figure by 0.073 before 0.6.0) | BENCH-R-050 and the protocol hash |

### A.2 Declined

| ACES practice | Reason |
|---|---|
| `inspect_ai` as the execution engine | Sample-based and LLM-centric; no continuing-environment semantics; ACES pins a fork. |
| LLM-as-judge for the primary metric | Exact per-event ground truth and a fully observable defense layer exist; a judge adds noise without validity. |
| Refusal-adjusted scoring | A policy over a discrete action space cannot refuse. |
| Cost and reward-per-dollar axes | Not meaningful for a policy run over tens of millions of steps; events per second and update cost per event are the analogues. |
| Cross-domain equal-weight normalization | One domain; equal weighting across streams of different length is undesirable, since drift appears only in the long streams. |
| Container sandbox per sample | The environment is a database reader. |
| Judge rubric clauses as prompt text | The precision discipline they encode is already in the reward table and consequence term. |

### A.3 Deferred: an `inspect_ai` adapter

Feasible as a task whose dataset is (stream, seed, budget) samples, whose solver
runs a Gymnasium policy without calling a model, and whose scorers emit the
control metrics; logs would then be readable by `inspect view`, and an LLM agent
driving the environment through a tool could be compared with native policies
under one log format. Costs: a dependency on a framework that assumes a model;
samples lasting hours; and an LLM-versus-policy comparison confounded by temporal
uniformity, since an LLM cannot be called tens of millions of times and would act
on summaries, which is a different task. Once BENCH-R-035 exists the adapter is a
thin wrapper over the runner (OI-BENCH-5).
