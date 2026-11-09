---
id: D5
title: Exit path for isolate
status: open
affects: [SPEC-ENV 7.3, SPEC-ENV 6]
related: [D9, D10]
---
# D5. Exit path for `isolate`

## Context

`isolate` sets `_is_isolated = True` and nothing clears it except `reset()` (`envs/log_stream_env.py:704-708`, `:855`; hybrid `:292`). Isolation drops every network-originated event (`ebpf_network`, `web_access`, `web_error`, `auth_log`; `:363-371`), while `syslog`, `journal`, `ebpf_file`, and `ebpf_process` continue. On a continuing stream with no episode boundary (`terminated` is always False), a single `isolate` permanently ends network observability. `isolate` is graded on every step it is chosen (+0.25 during attack, -2.0 during benign; `:96-112`).

## Options

- A dedicated de-isolation action.
- A TTL on isolation analogous to `block_ttl`.
- `unblock` clears isolation when the current event has no address.
- Document isolation as terminal and justify it.

## Recommendation

The analysis recommended a TTL plus an explicit de-isolation path, since a permanently absorbing action contradicts the continuing-environment principle.

## Decision

Open.

## Consequences

Blocks the action-space freeze (SPEC-ENV 6) and the recovery metric in the control protocol (SPEC-BENCH 5). A new action or TTL parameter widens the configuration surface (SPEC-ENV 11).
