---
id: D15
title: Composition locus and adversary model
status: open
affects: [SPEC-CORPUS 11, SPEC-ENV 9, SPEC-BENCH 4, SPEC-BENCH 6]
related: [D13, D16, D10, D3]
---
# D15. Composition locus and adversary model

## Context

As-built, composition is offline: `StreamComposer` (`data/composer.py`) cycles benign events to fill a duration and transplants attack events on a Poisson schedule, deterministic given a seed (schedule `:500`, transplant `:616`, downsample hash `:180`); `composition_meta.composed_at` and `schema_version.applied_at` differ per run. Replay is deterministic given the database and `reset(start_id)`; the only stochastic element at replay time is throttle dropping, seeded from `reset(seed)` (`envs/log_stream_env.py:870`); `reset(seed=None)` leaves it unseeded.

An agent-conducted review (an AI agent prompted in an RL-researcher role, 2026-11-07) found the non-stationarity largely cosmetic: benign is cycled and attacks are independent Poisson draws, so there is little drift for step-size adaptation methods to track. On 2026-11-08 the author ruled out live honeypot ingestion (no real kernel; chronos-sec covers it) and rejected synthetic telemetry as the primary direction (it collapses the real-telemetry niche against the simulator-based CybORG/CAGE family). Runtime trace scheduling remained under consideration: recorded benign background replayed, recorded attack instances injected by a scheduler. Architecturally this splits `StreamComposer` into a corpus layer (labeled, attributed, instance-identified recordings) and a scheduler layer (which recording, when, address rewriting).

## Options

- **Offline only**: streams are composed once and pinned.
- **Seeded open-loop runtime scheduler**: every scheduling decision (benign segment, attack instance, offset, address rewrite) is drawn in fixed order from the generator seeded by `reset(seed)`; the stream seed is separate from any policy seed, so paired comparisons share the former and vary the latter; a pinned offline stream is the same code path materialized for one seed and hashed. A drifting schedule (late first appearances, recurrences) becomes a configuration.
- **Defense-state-conditioned adversary**: the scheduler reacts to the agent's controls.

## Recommendation

The analysis recommended the seeded open-loop runtime scheduler, with pinned streams as the same code path materialized, and no defense-state-conditioned adversary. Adaptive adversaries are a non-goal (README Section 4), which fixes the adversary half.

## Decision

Open. Must be decided with D13 and before D10, since the protocol must name the stream mode.

## Consequences

Under every branch, the corpus-layer work (D12 labeling, D1 sessions, D13 identifiers) is identical. A test asserts that two runs with equal seed and configuration produce byte-identical observation sequences (SPEC-ENV 9).
