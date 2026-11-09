---
id: SPEC-ENV
title: security-gym environment contract
version: 0.1-draft
status: draft
date: 2026-11-09
verified_against: a70aeda (package 0.6.2; environment code unchanged since d5519e2, 0.6.0)
scope:
  - src/security_gym/envs/
  - src/security_gym/adapters/
  - tests/test_env.py
  - tests/test_env_hybrid.py
  - tests/test_reward_alignment.py
depends_on: [SPEC-CORPUS]
decisions: [D4, D5, D6, D7, D8, D9, D11, D13, D15]
---

# SPEC-ENV: Environment Contract

## Abstract

This document specifies the Gymnasium contract of security-gym: what the
environment consumes, what the agent observes, which actions it may take, how the
simulated defense layer responds, how reward is computed and aligned, and what
the `info` dictionary carries. Conventions, principles (P1 to P6), and the
glossary are in [README.md](README.md).

## 1. Introduction

### 1.1 Scope

The two registered environments `SecurityLogStream-Text-v0` and
`SecurityLogStream-Hybrid-v0`, and the `SecurityGymStream` adapter. Both
environments share the action space, defense state, reward, and stream semantics;
they differ only in the encoding of some observation channels.

### 1.2 Out of scope

How streams are produced (SPEC-CORPUS); how agents are evaluated (SPEC-BENCH).

## 2. Conventions and Terminology

As in [README.md](README.md) Section 2. "Event on screen" means the most recent
event delivered to the agent, whose effects the current observation reflects.
"Next visible event" means the next event in replay order that the defense layer
does not drop.

## 3. Environment Model

- **ENV-R-001** (MUST). The environment replays a recorded event stream in
  replay order. No component other than the defense layer (Section 7) alters,
  generates, or reorders events.
  Conformance: met (`log_stream_env.py:345-401`).
- **ENV-R-002** (MUST). `terminated` is always `False`. `truncated` is `True` only
  when the stream is exhausted.
  Conformance: met. [test: tests/test_env.py::TestStreamBehavior::test_terminated_always_false]
- **ENV-R-003** (MUST). Both registered IDs resolve through `gymnasium.make`.
  Registration SHOULD occur through exactly one mechanism.
  Conformance: partial; registration fires both at import (`__init__.py`) and via
  the `pyproject.toml` entry point.
  [test: tests/test_env.py::TestGymnasiumRegistration::test_gymnasium_make]
- **ENV-R-004** (MUST). The Text and Hybrid environments MUST satisfy one shared
  conformance suite covering action space, defense state, reward, and step
  semantics, so that the two cannot drift.
  Conformance: not met; the hybrid class duplicates `reset` and `step`
  (`log_stream_env_hybrid.py:276-387`) and no parametrized suite spans both.
  `tests/test_reward_alignment.py` is parametrized over both classes and is the
  first instance.
- **ENV-R-005** (SHOULD). Text and Hybrid are one environment with a per-channel
  encoder strategy rather than a subclass that re-implements `reset` and `step`
  with a grandparent `super()` call and hand-mirrored state. Sequenced after
  ENV-R-004, which freezes the contract the consolidation must preserve.
- **ENV-R-006** (MUST). Ring-buffer and observation-building logic has one
  implementation shared by both environments and the adapter. Conformance: not
  met; it exists three times (base environment, hybrid environment,
  `adapters/scan_stream.py`).
- **ENV-R-007** (MUST). The adapter depends only on public names of the
  environment modules. Conformance: not met; `adapters/scan_stream.py:28-40`
  imports `_CHANNELS`, `_RISK_MAP`, `_SOURCE_TO_CHANNEL`, `_EBPF_SOURCE_MAP`,
  `_STRUCTURED_CHANNELS`, and `_TEXT_CHANNELS`.
- **ENV-R-008** (MUST). Deprecated public API (`security_gym.features`,
  `security_gym.envs.wrappers`, `security_gym.targets.builder`, all deprecated
  since 0.3.0) is removed in a deliberate 1.0 namespace prune, not piecemeal.
  Before removal, no live code may depend on it. Conformance: not met;
  `attacks/config.py:14` imports `ATTACK_STAGES` and `ATTACK_TYPES` from
  `security_gym.targets.builder`, and `envs/wrappers.py:103` reads
  `info["session_id"]`, which the environment never sets.

## 4. Event Input Contract

The environment consumes one stream database with the `events` table specified
in SPEC-CORPUS 12. Each column belongs to exactly one class:

| Column | Class | Reaches the agent through |
|---|---|---|
| `id` | replay control | nothing (`info` only) |
| `timestamp` | replay control | inter-event deltas, TTLs, line text |
| `source` | observation routing | channel identity |
| `raw_line` | observation payload | text channels |
| `parsed` | observation payload | hybrid kernel channels |
| `src_ip` | observation payload and control key | line text, target slate, defense state |
| `username`, `service` | observation payload | line text only |
| `session_id` | advisory | nothing |
| `is_malicious`, `campaign_id`, `attack_type`, `attack_stage`, `severity`, attribution identifiers | ground truth | nothing (`info` only) |

- **ENV-R-010** (MUST NOT). No ground-truth column reaches any observation
  channel, directly or through a derived quantity (P1).
- **ENV-R-011** (MUST). Sources route to channels as follows; an unknown source
  routes to `syslog`.

  | Source | Channel |
  |---|---|
  | `auth_log` | `auth_log` |
  | `syslog`, `journal` | `syslog` |
  | `web_access`, `web_error` | `web_log` |
  | `ebpf_process` | `process_events` |
  | `ebpf_network` | `network_events` |
  | `ebpf_file` | `file_events` |

  Conformance: met (`log_stream_env.py:115-124`, `:436`). The valid source set is
  the module constant `security_gym.data.event_store.VALID_SOURCES`
  (`data/event_store.py:15-18`). A new source extends both this table and the
  observation space.
- **ENV-R-012** (MUST NOT). The environment does not read `session_id`.
  Conformance: met.

## 5. Observation Space

### 5.1 Common

- **ENV-R-020** (MUST). The observation is a `Dict`. Each text channel is the
  most recent `tail_lines` lines (default 500) of its ring buffer, joined by
  newline and truncated to the trailing `max_chars` characters (default 50,000).
  Conformance: met. [test: tests/test_env.py::TestObservationSpace::test_ring_buffer_tail_semantics]

### 5.2 Text mode (`SecurityLogStream-Text-v0`)

```
auth_log, syslog, web_log                       Text
process_events, network_events, file_events     Text
system_stats                                    Box(3)      (Section 5.4)
defense_state                                   Text        (Section 5.5; on by default)
target_slate                                    Text        (Section 5.6; on by default)
```

### 5.3 Hybrid mode (`SecurityLogStream-Hybrid-v0`)

Log channels remain `Text`. Kernel channels are `float32` arrays of the most
recent `tail_events` rows (default 50); string fields are hashed with mmh3 under
per-field seeds and time deltas are encoded as `log(1 + dt)`, per channel,
clamped at zero (`envs/ebpf_encoding.py`).

```
process_events  Box(50, 8)  [log_dt, pid, ppid, uid, syscall, comm_hash, parent_comm_hash, tree_depth]
network_events  Box(50, 7)  [log_dt, pid, uid, syscall, dst_ip_hash, dst_port, comm_hash]
file_events     Box(50, 6)  [log_dt, pid, uid, syscall, flags, path_hash]
system_stats    Box(3)
defense_state   Box(6)      (Section 5.5)
target_slate    Box(64, 3)  (Section 5.6)
```

- **ENV-R-021** (SHOULD NOT). A hybrid column SHOULD NOT be constant on collector
  data. Conformance: not met; the `file_events` `uid` column is always zero
  because the collector emits no `uid` on `open` or `unlink` (SPEC-CORPUS 5).
- **ENV-R-022** (MUST). `tree_depth` is computed from process ancestry within one
  host namespace. Conformance: not met on the legacy corpus; depth is kept in one
  pid-keyed dictionary (`log_stream_env_hybrid.py:160`, `:182`, `:213-217`), so
  cross-host PID collision corrupts it, and each `exit` event (which carries no
  `ppid`) resets its pid's depth to zero.

### 5.4 `system_stats`

- **ENV-R-030**. Disposition open (D4). Until D4 is decided, `system_stats` is the
  constant `[0.5, 0.3, 0.2]` on every step and zeros on the exhaustion
  observation (`log_stream_env.py:451`, `:463`), and agents and baselines MUST NOT
  treat it as evidence of host state.

### 5.5 `defense_state`

- **ENV-R-040** (MUST). When `defense_state_obs` is true (the default since 0.6.0),
  the observation reports the agent's own control state. Text mode renders
  `=== defense state ===` with blocked and throttled address lists (sorted, capped
  at `DEFENSE_STATE_MAX_LISTED` = 20), isolation, `events_suppressed`,
  `seconds_since_change`, and a `current_src` line. Hybrid mode encodes `Box(6)` =
  `[n_blocked, n_throttled, is_isolated, current_src_blocked,
  current_src_throttled, seconds_since_last_change]`.
  Conformance: met. [test: tests/test_env.py::TestDefenseStateObservation::test_present_by_default]
- **ENV-R-041** (MUST). `seconds_since_change` advances in event time from the
  last actual change of defense state, including `block_ttl` expiry, and is never
  negative. Conformance: met.
  [test: tests/test_env.py::TestDefenseStateObservation::test_seconds_since_change_is_non_negative_and_advances]
- **ENV-R-042**. The field set is open (D7): candidates are per-address TTL
  remaining, an action-history count, a repeat-offender flag, and the typed
  controls D11 introduces.

### 5.6 `target_slate`

- **ENV-R-050** (MUST). When `target_slate_size` N is positive (default 64), the
  observation carries an N-slot list of addresses seen in delivered events. Text
  mode renders `=== targets ===`, a line `0 current_src: <addr|none>`, and one line
  per slot with `[BLOCKED]` and `[THROTTLED]` marks. Hybrid mode encodes
  `Box(N, 3)` = `[addr_hash, is_blocked, is_throttled]`, hashed with `SEED_IP` so a
  slot and a `network_events` row agree on a host.
  Conformance: met. [test: tests/test_env.py::TestExplicitTargeting::test_on_by_default]
- **ENV-R-051** (MUST). Slots are stable. When the slate is full, the least
  recently seen address that is neither blocked nor throttled is evicted;
  controlled addresses are pinned. If every slot is pinned, a new address is
  reachable only through target 0.
  Conformance: met. [test: tests/test_env.py::TestExplicitTargeting::test_controlled_address_is_pinned_against_eviction]

### 5.7 Label-blindness

- **ENV-R-060** (MUST NOT). No observation channel, including `defense_state` and
  `target_slate`, may carry information whose presence or value is determined by
  how the corpus labeled or enriched events (P1).
  Conformance: not met on the legacy corpus. The `current_src` lines of both
  default-on text channels render the current event's `src_ip` on every step
  (`log_stream_env.py:602-603`, `:760-769`). On legacy kernel file and process
  events an address exists only where the composer stamped the attacker address
  (SPEC-CORPUS 15, defect 6), so `current_src` being non-empty on a kernel event
  is a perfect label. Slate admission and eviction carry the same signal more
  weakly. The hybrid encodings do not render the address. Resolved for the
  corrected corpus by SPEC-CORPUS 6 and 7 (no enrichment); results on legacy
  streams in text mode with default channels MUST state this defect (OI-ENV-1).
- **ENV-R-061** (MUST). `defense_state` fields other than `current_src` are pure
  functions of the agent's own actions and the defense layer.
  Conformance: met. [test: tests/test_env.py::TestDefenseStateObservation::test_channel_leaks_no_ground_truth]

## 6. Action Space

### 6.1 Components

```
action      Discrete(6)      0 pass, 1 alert, 2 throttle, 3 block_source, 4 unblock, 5 isolate
risk_score  Box(1) in [0,10] auxiliary threat estimate
target      Discrete(N+1)    present iff target_slate_size N > 0
```

- **ENV-R-070**. The discrete action set is not frozen (D11). Process-level
  actions (Section 6.3) and possibly `report` (D11 sub-item) are added before any
  freeze, and the benchmark protocol pins the result (SPEC-BENCH 3).
- **ENV-R-071**. The status of `risk_score` is open (D6). Until decided it is
  unrewarded by default (Section 8.5).

### 6.2 Target resolution

- **ENV-R-080** (MUST). Target 0, or any action when targeting is disabled,
  resolves to the `src_ip` of the event on screen. Target k in 1..N resolves to the
  address in slot k, or to nothing if the slot is empty or out of range.
  Conformance: met (`log_stream_env.py:575-593`).
  [test: tests/test_env.py::TestExplicitTargeting::test_target_zero_preserves_the_legacy_binding]
- **ENV-R-081** (MUST). Only `throttle`, `block_source`, and `unblock` take a
  target. `pass` and `alert` change no state; `isolate` is host-wide.

### 6.3 Process-level actions (D11, decided)

- **ENV-R-090** (MUST). The action space provides kill-process, close-port, and
  disable-account actions. Each has (a) a consequence model in the defense layer
  stating which future recorded events it suppresses (the process subtree under
  the D1 session definition; connections on the port; authentication and session
  events of the account); (b) a reward row supplied through the reward matrix
  (Section 8.7); (c) a target named from the observation, never from `info`.
  Conformance: not met (not implemented).
- **ENV-R-091** (MUST). Process-level actions are available only when kernel
  channels are present; in a log-only configuration they are absent or masked,
  and the protocol records which.
- **ENV-R-092** (MUST). The target becomes typed (address, process, port,
  account). The single address slate of Section 5.6 cannot express this; the
  typed target is designed before the action space is frozen.

## 7. Defense State and Dynamics

### 7.1 Controls

- **ENV-R-100** (MUST). The defense layer holds a blocklist (all events of a
  blocked address are dropped), a throttle list (each event of a throttled
  address is dropped with probability `throttle_drop_rate`, default 0.9, from an
  RNG seeded by `reset(seed)`), and an isolation flag (all events of sources
  `ebpf_network`, `web_access`, `web_error`, and `auth_log` are dropped).
  Conformance: met (`log_stream_env.py:345-401`).
  [test: tests/test_env.py::TestDefenseActions::test_block_source_filters_future_events]
- **ENV-R-101** (MUST). `unblock` on an address clears both its block and its
  throttle. Blocking does not remove throttle membership.

### 7.2 Block recovery

- **ENV-R-110** (MUST). Under `block_visibility="drop"` (default) a blocked
  address's events are invisible. Under `"deny_log"` each dropped event is
  delivered as the line `"[FIREWALL DENY] " + raw_line`, a function of observable
  fields only. Conformance: met.
  [test: tests/test_env.py::TestBlockVisibilityDenyLog::test_deny_log_render_is_ground_truth_blind]
- **ENV-R-111** (MUST). With `block_ttl` set (event-seconds; default `None`), a
  block expires when an event of that address arrives at or after ban start plus
  TTL; the event is delivered live and the expiry counts as a defense-state
  change. Conformance: met.
  [test: tests/test_env.py::TestBlockTTL::test_block_ttl_auto_resurfaces_after_expiry]
- **ENV-R-112** (MUST). `unblock` is reachable under `"drop"` because controlled
  addresses are pinned in the slate. Conformance: met.
  [test: tests/test_env.py::TestExplicitTargeting::test_unblock_reachable_under_default_drop]

### 7.3 Isolation

- **ENV-R-120**. Exit path open (D5). As built, `isolate` is cleared only by
  `reset()`; on a continuing stream one `isolate` permanently removes the
  network-originated sources (kernel file and process events, `syslog`, and
  `journal` continue). Results MUST report isolation usage (SPEC-BENCH 5).

### 7.4 Effectiveness

- **ENV-R-130** (MUST). An action is effective if and only if it changed the
  defense state: `throttle` adds an address not already throttled; `block_source`
  adds an address not already blocked; `unblock` removes an address from either
  list; `isolate` sets isolation when it was not set. The effect of re-stamping an
  existing block under `block_ttl` (which extends the ban) is open (OI-ENV-2).
  Conformance: not met; `_apply_action` marks `throttle` and `block_source`
  effective on an already-controlled address (`log_stream_env.py:682-696`), so a
  policy naming a blocked attacker's pinned slot collects +1.0 per step
  indefinitely. Only `unblock` is gated correctly.
  [test: tests/test_reward_alignment.py::test_repeat_block_of_controlled_address_is_not_paid (xfail)]
- **ENV-R-131** (MUST). `info` reports, for every step, what the last action bound
  to (`action_target`), whether it was explicit (`action_target_explicit`), and
  whether it was effective (`action_effective`). Conformance: met.
- **ENV-R-132** (MUST). `info` reports suppressed benign and suppressed malicious
  events as separate counters (ground truth is available at suppression time), so
  collateral and containment can be attributed (SPEC-BENCH BENCH-R-024).
  Conformance: not met; `events_dropped` is a single unattributed count.

## 8. Reward

### 8.1 Composition

- **ENV-R-140** (MUST). Reward is the sum of the action term (8.3), the
  consequence term (8.4), and, when enabled, the risk term (8.5).

### 8.2 Grading alignment

- **ENV-R-150** (MUST). The action term and the risk term of `step(a)` are graded
  against the ground truth of the event on screen when `a` was chosen, never
  against the event delivered after the action.
  Conformance: not met. `step()` applies the action, advances, and grades against
  the next visible event (`log_stream_env.py:904-951`; hybrid
  `log_stream_env_hybrid.py:339-387`). Census over the full streams: under an
  all-pass policy the grading class differs from the acted-on event on 1,458 of
  4,891,541 steps of `exp_7d_brute_v4` and 38,195 of 21,511,208 steps of
  `exp_30d_heavy_v4`; under default `"drop"` visibility a first-sight block of an
  attacker is graded benign in 669 of 1,223 attacker runs (54.7%, 7-day) and
  13,643 of 29,583 (46.1%, 30-day) (TODO.md, Action Space section).
  [test: tests/test_reward_alignment.py (five cases per environment, xfail)]
- **ENV-R-151** (MUST). An explicitly targeted action is graded on the target's
  most recent label observed at or before the event on screen; if the target has
  never been observed labeled, on the event on screen.
  Conformance: not met; `_observe_address` records the next event's label before
  grading (`log_stream_env.py:929`, `:947`).
  [test: tests/test_reward_alignment.py::test_explicit_target_uses_only_labels_already_observed (xfail)]
- **ENV-R-152** (MUST). The final action before truncation is graded against the
  final event, not a synthetic label. Conformance: not met (`:918-925`).
  [test: tests/test_reward_alignment.py::test_final_action_is_graded_on_final_event (xfail)]

### 8.3 Action term

- **ENV-R-160** (MUST). The action term is read from a reward table indexed by
  action and by the class of the graded event. Defaults:

  | Action | Malicious | Benign |
  |---|---:|---:|
  | `pass` | -0.5 | 0.0 |
  | `alert` | +0.5 | -0.3 |
  | `throttle` | +0.75 | -0.5 |
  | `block_source` | +1.0 | -1.0 |
  | `unblock` | -0.5 | 0.0 |
  | `isolate` | +0.25 | -2.0 |

  Conformance: met (`log_stream_env.py:96-112`).
- **ENV-R-161** (MUST). A target-taking action (`throttle`, `block_source`,
  `unblock`) that is not effective (Section 7.4) scores 0.0. `pass`, `alert`, and
  `isolate` are graded on every step. Conformance: partial (see ENV-R-130).
  [test: tests/test_env.py::TestExplicitTargeting::test_action_on_empty_slot_scores_zero]

### 8.4 Consequence term

- **ENV-R-170** (MUST). Each event dropped by the defense layer between two steps
  contributes `+malicious_drop_reward` (default 0.1) if malicious and
  `-benign_drop_penalty` (default 0.5) if benign; unlabeled events contribute
  nothing. The accumulated sum is paid on the step whose action preceded the
  drops. Conformance: met (`log_stream_env.py:426-432`).

### 8.5 Risk term

- **ENV-R-180**. Status open (D6). When `include_risk_reward` is true (default
  false), the term is `-risk_weight * (risk_score - true_risk)^2` with
  `risk_weight` default 0.1 and `true_risk` from the stage map (benign 0, recon 3,
  initial_access 5, execution 8, persistence 9, exfiltration 10). It is subject to
  ENV-R-150.

### 8.6 Deny-log accounting

- **ENV-R-190** (MUST). When the event on screen is a surfaced deny-log line, the
  action and risk terms of the action chosen on it are zero and only the
  consequence term applies, so the drop is not counted twice. The episode-total
  consequence equals that of `"drop"` mode.
  Conformance: partial; the flag is evaluated on the next visible event rather
  than the event on screen (ENV-R-150).

### 8.7 Reward matrix

- **ENV-R-200**. Configurability open (D9; RECOMMENDED: the table values are read
  from a recorded configuration overlay). Whatever D9 decides, every published
  result MUST state the reward table it used (SPEC-BENCH 8).

## 9. Step Semantics

- **ENV-R-210** (MUST). `step(a)` performs, in order: (1) capture the ground truth
  and deny flag of the event on screen; (2) apply `a` to the defense state; (3)
  advance to the next visible event, accruing consequences of drops; (4) grade the
  action and risk terms against (1); (5) record the newly delivered event's
  address and label for the slate; (6) build the observation and `info` for the
  new event. Conformance: not met; steps (1), (4), and (5) are currently ordered
  as advance, record, then grade (ENV-R-150, ENV-R-151).
- **ENV-R-211** (MUST). `reset(seed, options)` clears all defense, slate, and
  buffer state, seeds the throttle RNG from `seed`, and starts at the first event
  with `id` greater than `options["start_id"]` (default 0).
  Conformance: met. [test: tests/test_env.py::TestDefenseStateObservation::test_reset_clears_state]
- **ENV-R-212** (MUST). Two runs with equal stream, configuration, seed, and
  action sequence produce identical observation, reward, and `info` sequences
  (P4). Conformance: met for seeded resets; `reset(seed=None)` leaves the throttle
  RNG unseeded, and an unparseable timestamp falls back to wall-clock time
  (`log_stream_env.py:831-834`), which breaks determinism and SHOULD instead raise.
  [test: tests/test_env.py::TestStreamBehavior::test_deterministic_replay]
- **ENV-R-213**. Stream delivery mode open (D15): whether the environment also
  composes streams at `reset(seed)` from a recorded corpus through a seeded
  scheduler. If adopted, the stream seed MUST be distinct from any policy seed.

## 10. `info` Dictionary

- **ENV-R-220** (MUST). `info` carries `event_id`, `timestamp`, `dt_seconds`,
  `source`, `src_ip`, `ground_truth` (`is_malicious`, `attack_type`,
  `attack_stage`, `campaign_id`, `true_risk`), `blocked_ips`, `throttled_ips`,
  `is_isolated`, `events_dropped`, `action_target`, `action_target_explicit`, and
  `action_effective`. On exhaustion `ground_truth` is a synthetic benign
  dictionary; a `reset` on an empty store returns `{"exhausted": True}`.
  Conformance: met (`log_stream_env.py:802-826`).
- **ENV-R-221**. Whether `info` is declared evaluation-only is open (D8;
  RECOMMENDED: yes, with any agent-usable field mirrored into an observation
  channel). Under the corrected corpus `ground_truth` gains the attribution
  identifiers of SPEC-CORPUS 6 (D13), reachable through `info` only.

## 11. Configuration Surface

- **ENV-R-230** (MUST). The parameters that define a run are: environment ID,
  `db_path` (or corpus digest under D15), `tail_lines`, `max_chars`, `tail_events`
  (hybrid), `throttle_drop_rate`, `block_visibility`, `block_ttl`,
  `defense_state_obs`, `target_slate_size`, and `reward_config`
  (`include_risk_reward`, `risk_weight`, `benign_drop_penalty`,
  `malicious_drop_reward`). Every published result MUST record all of them
  (SPEC-BENCH 8). The environment SHOULD expose its effective configuration as one
  serializable record. Conformance: partial; nothing is recorded by the
  environment itself.
- **ENV-R-231**. Defaults since 0.6.0: `defense_state_obs=True`,
  `target_slate_size=64`, `block_visibility="drop"`, `block_ttl=None`,
  `include_risk_reward=False`. Documentation MUST state these defaults.
  Conformance: met as of 2026-11-09 (the docstrings at `log_stream_env.py:144` and
  `log_stream_env_hybrid.py:78`, the comments at `log_stream_env.py:47` and
  `:216-223`, and the project CLAUDE.md previously described both channels as
  opt-in).

## 12. Security and Integrity Considerations

The integrity threat to this environment is information flow from ground truth to
the agent, which turns a control problem into label lookup and invalidates every
result built on it. Known flows and their status: `current_src` rendering of
enriched addresses (ENV-R-060, open on legacy streams); grading on a label the
agent has not yet observed (ENV-R-151, open); slate admission correlated with
enrichment (ENV-R-060). `info` sits beside the labels and is the remaining
escape hatch until D8 is decided. A second integrity threat is reward that pays
without effect (ENV-R-130), which an optimizing agent will find and exploit.
Replayed telemetry contains real exploit strings (for example JNDI lookups);
consumers that render observations into other systems (log pipelines, LLM
prompts) MUST treat observation text as untrusted input.

## 13. Open Issues

- **OI-ENV-1.** Kernel-targeting results on the legacy v4.1 streams: withdraw,
  caveat, or re-run with enrichment-only addresses excluded from both the slate
  and the `current_src` lines (a code change in `_observe_address`,
  `_render_target_slate`, and `_render_defense_state`). No new result is to be
  published on the legacy streams without saying which.
- **OI-ENV-2.** Whether re-stamping an existing block under `block_ttl` counts as
  effective (it changes the ban expiry, which is defense state).
- **OI-ENV-3.** Whether the alignment and effectiveness fixes (ENV-R-130, 150,
  151, 152) land before D9 or with it. Both change every reward number; the
  baselines are regenerated once either way.

## 14. References

- [README.md](README.md): conventions, principles P1 to P6, glossary.
- [SPEC-CORPUS.md](SPEC-CORPUS.md): stream and schema contract.
- [SPEC-BENCH.md](SPEC-BENCH.md): reporting obligations.
- Decision records D4 to D9, D11, D13, D15 in [decisions/](decisions/README.md).
- TODO.md, section "Action Space, Control Semantics": measurements behind
  ENV-R-130 and ENV-R-150.

## Appendix A. Requirements Not Met at `a70aeda`

| ID | Summary | Pinned by |
|---|---|---|
| ENV-R-004 | Shared Text/Hybrid conformance suite | partial: `tests/test_reward_alignment.py` |
| ENV-R-006 | One ring-buffer and observation implementation | none |
| ENV-R-007 | Adapter uses public names only | none |
| ENV-R-008 | Deprecated API removable (no live dependants) | none |
| ENV-R-021 | No constant hybrid column | none |
| ENV-R-022 | `tree_depth` within one host namespace | none (legacy data) |
| ENV-R-060 | Label-blind observation | none |
| ENV-R-090 | Process-level actions | none (not implemented) |
| ENV-R-130 | Effectiveness gate for throttle and block | xfail test |
| ENV-R-132 | Attributed suppression counters | none |
| ENV-R-150 | Grading on the event on screen | xfail tests |
| ENV-R-151 | Causal label for explicit targets | xfail test |
| ENV-R-152 | Final action graded on final event | xfail test |
| ENV-R-210 | Step ordering | xfail tests |
