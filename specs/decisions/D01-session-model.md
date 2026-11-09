---
id: D1
title: Session model
status: decided
decided: 2026-11-08
decided_by: author
source: author, 2026-11-08
affects: [SPEC-CORPUS 7, SPEC-CORPUS 12, SPEC-ENV 4]
related: [D3, D12, D13]
---
# D1. Session model

## Context

**As-built: four inconsistent notions under one column.** `session_id` is populated four different ways and consumed almost nowhere.

1. `auth_log` sets `session_id = f"{ip}:{port}"`, the client address and port (a 2-tuple; the server side is not encoded), and caches PID to (ip, session_id) so that PAM open and close events inherit it (`parsers/auth_log.py:99`, `:117-123`, `:134`).
2. `web_access` and `web_error` set `session_id = client_ip` (`parsers/web_access.py:85`, `parsers/web_error.py:80`). A session is a client host.
3. `syslog` and `journal` set nothing; `session_id` is `None`.
4. `ebpf` sets nothing (`ParsedEvent` default, `parsers/base.py:24`). Kernel events have no native session.

At composition, `_enrich_ebpf_fields` (`data/composer.py:196-246`; the stamp is at `:226-237`) fabricates a session for attack eBPF only: eBPF events sharing a campaign with log events are assigned `f"{dominant_ip}:ebpf_{short_cid}"`, keyed on the dominant attacker address, and a missing or `0.0.0.0` `src_ip` is overwritten with that address (`:234-235`). Benign eBPF stays `None`.

The `sessions` table is declared (`data/schema.py:45-54`) but no code inserts into it (no `INSERT INTO sessions` in `src/`, `attacks/`, `scripts/`, `server/`, or `tests/`).

**Consumers.** Neither environment reads `session_id`. The only in-repo consumer is the deprecated `SessionFeatureExtractor` (`features/session.py:118-123`), which keys per-session state as `session_id or src_ip or "unknown"`; `envs/wrappers.py:103` also reads `info.get("session_id")`, which the environment never sets. The one live consumer is external: `rlsecd` steps its learner only on session-mapped events, so `session_id` decides that project's update cadence (not verifiable from this repository).

**Sessions do not define ground truth.** Labels are assigned per event by `CampaignLabeler` (`attacks/collection/labeler.py:120-128`); sessions play no part in labeling.

**Leakage.** Because the fabricated session is applied to attack eBPF only, session structure separates attack from benign on key shape alone. On `exp_30d_heavy_v4`, nine synthetic `{ip}:ebpf_{cid}` sessions (of 14,248 distinct session IDs) carry 526,186 events, and the malicious share of session-mapped events is 38.4% against a 2.83% stream base rate. The 2.83% base rate is recorded in `data/provenance/BENIGN_COMPOSITION_AUDIT_20261108.md` Section 3 (609,520 of 21,511,208); the session counts are recorded in no provenance note and should be (SPEC-CORPUS OI-CORPUS-2). For a session-level scorer this is direct label leakage, and for `rlsecd` it also distorts which events are learned from. It is the same root cause as the eBPF address-presence artifact (asymmetric construction).

**Is a session required?** The environment does not need one: observation is per-event ring buffers, action binds to a target, reward and ground truth are per event. A session is useful only for (a) an optional session-level observation feature, (b) a session-level evaluation metric (for example containment per attack session), or (c) an external learner's cadence.

**Logs versus eBPF.** Log streams carry an address on the events that matter (auth, web), so a connection- or host-scoped session is natural and label-blind. eBPF streams carry no native session and, for file and process events, no address; a session there can come only from process-tree ancestry or must not exist. It must never come from the label or the campaign, which is what the current fabrication does.

## Options

- **A. Remove sessions from the environment contract.** Drop the dead `sessions` table, stop emitting `session_id` from parsers, remove the composer fabrication. External consumers derive their own cadence key (per address, or a fixed event-count window). Smallest change; directly removes the leak.
- **B. Define one coherent, symmetric session and materialize it.** For eBPF, a process subtree rooted at a session leader (`sshd`, `login`, `cron`, or the init child that starts a service), derived from per-host namespaced `pid`/`ppid`, defined for both classes alike. For logs, the existing connection or host proxy stated once and applied uniformly (the auth client address and port for `auth_log`, the client host for web, an explicit "no session" for system logs). Sessions are written to the `sessions` table, used only for optional observation or evaluation, never for labeling. Larger change; depends on the eBPF re-collection or re-derivation (D3).
- **C. Keep `session_id` as an opaque advisory key** with a single definition, no table, no environment consumption, documented as non-authoritative. Acceptable only with an explicit statement that no scorer may key on session structure.

Whichever option is chosen, the specification must state the single definition (or its removal), that sessions never determine `is_malicious`, and that construction is symmetric across classes.

## Recommendation

The analysis recommended Option A unless a feature consumes sessions, otherwise Option B.

## Decision

**Decided 2026-11-08: Option B.** One session definition: a process subtree rooted at its session leader, derived from per-host namespaced `pid`/`ppid` and applied identically to benign and attack events. Sessions are materialized in the `sessions` table, never used for labeling, and no scorer may key on session structure. For log sources: the auth client address and port for `auth_log`, the client host for web, and an explicit "no session" for system logs.

## Consequences

- Schema version 3: the `sessions` table becomes live (leader pid, host, start, end, event count) and parsed eBPF fields gain a host namespace.
- `session_id` is advisory metadata, never ground truth, never a scorer key.
- The fabrication in `_enrich_ebpf_fields` is removed, not replaced; the composer writes no session or address onto kernel events.
- Because B needs namespaced ancestry from a single host, it is sequenced with the D3 re-collection. Under the 2026-11-09 capture architecture the ancestry is available at capture time (fork tracing, process start time), which serves D1, D12, and D13 from one structure.

## Open sub-items

- Whether the per-column class (replay control, observation payload, ground truth, advisory) is recorded in the schema itself (a column comment or companion table).
