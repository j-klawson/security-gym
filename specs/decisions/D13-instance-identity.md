---
id: D13
title: Attack instance definition and identifiers
status: open
affects: [SPEC-CORPUS 6, SPEC-CORPUS 10, SPEC-CORPUS 11, SPEC-CORPUS 12, SPEC-BENCH 5, SPEC-ENV 10]
related: [D3, D8, D10, D12, D15]
---
# D13. Attack instance definition and identifiers

## Context

Composed streams have no unit of analysis. `_transplant_session` copies the source `campaign_id` onto every transplanted event (`data/composer.py:524-548`), and a transplanted instance is a random slice of a source campaign, so two placements of one recording cannot be distinguished and a stream cannot say where an instance starts or ends. The harness records little: `AttackResult` (`attacks/modules/base.py:59-70`) stores a phase name, start and end times, and a set of source addresses; `campaign_id` names one campaign run.

Per-instance quantities need an identifier: containment and time to containment (D10), the fraction of attackers released while still active, detection latency, and adaptation on first appearance and retention on recurrence. A multi-stage attack crosses source addresses (reconnaissance from one address, credential attack from another), so the address cannot tie its stages together.

## Options

- **Whole source campaign per instance**, with an `instance_id` stamped on every transplanted event and ground truth reachable through `info` only (the original register recommendation).
- **Three identifiers minted outside the telemetry** (recommended 2026-11-09 with the capture architecture): `recording_id`, minted by the scenario harness at capture, naming one recorded execution of a scenario; `stage_id`, minted by the harness at each stage transition; `instance_id`, minted by the stream scheduler at composition or `reset(seed)`, naming one placement of a recording in a stream (a recurrence of the same recording receives a new one). All three live in the label stream, never in event text or parsed fields.

**Granularity.** Independently of the identifier scheme: whether one instance is a whole recording (every stage, in order) or a slice of one, as the legacy composer's random one-third slices are. Whole recordings make instances comparable and give the kill-chain stage sequence meaning; slices yield more instances per stream. Under the three-identifier scheme a slice would still carry its `stage_id` values, so the two choices are separable.

## Recommendation

The analysis recommends the three-identifier split: it ties the stages of a multi-stage attack across addresses, which the address cannot do, and distinguishes recurrences of one recording, which the current composer cannot.

## Decision

Open. Needed before the re-collection campaign plan is written.

## Consequences

Gates the per-instance control metrics (SPEC-BENCH 5) and the Step 2 adaptation and retention measures. Determines label-stream columns in the corrected schema (SPEC-CORPUS 12) and the `info` ground-truth fields (SPEC-ENV 10).
