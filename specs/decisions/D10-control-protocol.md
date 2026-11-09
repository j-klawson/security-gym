---
id: D10
title: Control metrics and pinned evaluation protocol
status: open
affects: [SPEC-BENCH 3, SPEC-BENCH 5, SPEC-BENCH 6, SPEC-BENCH 7, SPEC-BENCH 8]
related: [D5, D9, D11, D13, D15]
---
# D10. Control metrics and pinned evaluation protocol

## Context

The project describes itself as a benchmark, but no evaluation protocol is pinned in the repository (no protocol file; `examples/benchmark.py` runs a single seed), and the published baselines report precision, recall, F1, and mean reward (`examples/benchmark.py:38-40`, `:74-76`), which measure classification, not control. The example agents are a random policy, two rule heuristics, and a pass-only floor (`examples/random_agent.py`, `threshold_agent.py`, `keyword_agent.py`); `rlsecd` supplies prediction heads, not a control policy. The composed streams carry no instance identifier (`data/composer.py:543-545` copies the source `campaign_id`), so per-instance metrics cannot be computed. Every reward-based number to date carries the alignment defect recorded in D9.

## Options

The decision is whether to commit to, and what to include in:

1. **Control metrics**, in the environment or an evaluation wrapper: containment (fraction of an attack instance's events after the first effective block that are suppressed), time to containment (events and stream-seconds from instance start to effective block), collateral (benign events dropped, attributed by class), recovery (steps from a false block to its unblock), isolation usage, and drift of each across the 90-day and 365-day streams. Three behavioral diagnostics are reported beside the score: the false-positive rate of blocks, the fraction of attackers released while still active, and the fraction of the stream that remains observable.
2. **A pinned protocol** as configuration plus runner: streams, step budget per stream, seed count, warm-up handling, and reported statistics (mean, standard deviation, effect size where two conditions are compared).
3. **At least one learning control baseline** under that protocol.
4. **Heuristic agents reported under the control metrics**, for a like-for-like comparison.

## Recommendation

The analysis recommended all four as required for the word "benchmark" to be accurate, with the configurable reward matrix (D9) as a prerequisite.

## Decision

Open. Publication blocker for the benchmark.

## Consequences

Depends on D5, D9, D13 (per-instance metrics), D15 (the protocol must name the stream mode), and the published default configuration (mode, `block_visibility`, `block_ttl`, `defense_state_obs`, `target_slate_size`, `reward_config`). The conflict with D11 is recorded in the register's Sequencing section and is asked together with this decision.
