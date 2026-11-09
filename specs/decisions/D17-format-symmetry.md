---
id: D17
title: Source and surface-format symmetry across classes
status: open
affects: [SPEC-CORPUS 13, SPEC-ENV 5.7, SPEC-CORPUS 15]
related: [D3, D12]
---
# D17. Source and surface-format symmetry across classes

## Context

The `syslog` observation channel is perfectly separable by surface format in `exp_30d_heavy_v4` (`data/provenance/BENIGN_COMPOSITION_AUDIT_20261108.md` Section 4). `journal` events are routed to the `syslog` channel (`envs/log_stream_env.py:123`). All 26,459 `journal` events are malicious and rendered as journald JSON export lines; the corpus holds no benign `journal` event. Among `syslog`-source lines, 0 of 325 benign lines carry the hostname token and 256 of 256 malicious lines do. The channel holds 26,715 malicious against 325 benign events (98.8%). A rule reading the first character of a line and the fourth whitespace-delimited token classifies the channel without error. The `auth_log` scrub is symmetric; the `syslog` scrub is not.

Neither shipped detector reads this leak (audit Section 5): the keyword baseline uses semantic regexes (`examples/keyword_agent.py:40-82`) and `rlsecd`'s twelve features are per-address authentication statistics. The log-only detection problem is nonetheless easy by class balance: `auth_log` is 64.0% malicious in the 30-day stream and 49.9% in the 7-day stream. Any text-mode agent, including a language model, would see the leak on first inspection.

The leak is the same defect class as eBPF address presence (D3) and the asymmetric session (D1): a source or format present in one class only.

## Options

- Resolve by construction: benign and attack telemetry recorded on the same host through the same journald and scrub (D3).
- Re-scrub the legacy corpus (possible for the hostname token; not for the absent benign `journal` source).
- In either case, a validator requirement: per-source class presence (no source present in only one class) and a per-source surface-format report by class (line prefix class, hostname token, JSON prefix).

## Recommendation

The analysis recommended treating the data side as resolved by construction under D3 and adding the validator checks. The 2026-11-09 capture architecture generalizes the check into a separability gate over every source, field, line format, and process name (SPEC-CORPUS 13).

## Decision

Open as a validator requirement; the data side is resolved by D3.

## Consequences

Any release must pass the separability gate. For the legacy v4.1 streams, the leak is disclosed in the erratum (D12 sub-item).
