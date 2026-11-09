---
id: D11
title: Process-level action primitives and the report action
status: partially decided
decided: 2026-11-08
decided_by: author
source: author, 2026-11-08
affects: [SPEC-ENV 6, SPEC-ENV 6.3, SPEC-ENV 7, SPEC-ENV 8.7]
related: [D7, D9, D10, D1]
---
# D11. Process-level action primitives and the `report` action

## Context

As-built the action is `Discrete(6)` (pass, alert, throttle, block_source, unblock, isolate) plus `risk_score` and a slate `target` (`envs/log_stream_env.py:262-268`). Only throttle, block_source, and unblock are address-level; isolate is host-wide by source class; pass and alert change no state. Target selection lets an agent block a host on kernel evidence, but no action targets a process, port, or account (`:668-708`).

## Options

- Keep the address-level action set.
- Add process-level primitives (kill process, close port, disable account), each with a consequence model and a reward row.
- Separately, land Phase 11 `report` (SOC escalation) before or after the action-space freeze.

## Recommendation

The analysis recommended deciding before freezing the action space, or deferring explicitly.

## Decision

**Decided 2026-11-08: process-level actions are in scope.** The agent must be able to kill a malicious process, close an individual network port, and disable a user account when kernel evidence attributes compromise to a process or account rather than an address. Each needs:

- a consequence model in the defense layer, stated as which future recorded events it suppresses (the process's subtree under D1's session definition; connections on the port; authentication and session events of the account), under the effectiveness rule (an action that changes no state scores 0);
- a row in the reward matrix, supplied through the D9 overlay and graded under the same alignment rule as address actions;
- label-blindness of its target: the target is named from the observation (a pid, port, or account the agent has seen), never from `info`.

These actions are available only when the kernel channel is present; in a log-only configuration they are absent or masked, and the protocol records which. The target becomes typed (address, process, port, account), which the single address slate cannot express. `Discrete(6)` is not frozen.

## Consequences

- SPEC-ENV 6 and 7 gain a typed target and three consequence models; D7 must report the new controls in the defense-state channel.
- The protocol (D10) pins whatever this design produces; the scheduling conflict is recorded in the register's Sequencing section.

## Open sub-items

- **Phase 11 `report` before or after the freeze.** Landing it before: one discrete index, one reward row, and a defined effect, since an action with no effect always scores 0, so `report` needs a consequence (for example an escalation cost and suppression of repeat alerts for the named target) or it is `alert` by another name; design cost moderate, code cost small. Deferring it: the published action space excludes it, and adding it later changes the Gymnasium contract, requires a new environment version ID, and re-runs the baselines.
