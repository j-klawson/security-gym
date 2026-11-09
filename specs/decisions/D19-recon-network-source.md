---
id: D19
title: Host network-layer source for reconnaissance
status: decided
decided: 2026-11-09
decided_by: author
source: author, session 2026-11-09
affects: [SPEC-CORPUS 5, SPEC-CORPUS 8]
related: [D3, D20]
---
# D19. Host network-layer source for reconnaissance

## Context

The existing reconnaissance module performs a half-open SYN scan with scapy. A half-open scan completes no handshake: no process returns from `accept4` and no service writes a log line, so none of the recorded sources (logs, syscall-level kernel events) observes it. Without a network-layer source on the target, the reconnaissance stage has almost no visible events.

## Options

- Add a host network-layer source (`nftables` logging or `conntrack` events) to the recorder.
- Add none, and record reconnaissance as what the running services and the syscall surface observe.

## Recommendation

The analysis presented both; a network-layer source was offered as the way to make half-open scans visible.

## Decision

**Decided 2026-11-09: none.** The reference target runs no `nftables` logging or `conntrack` capture, consistent with the production servers it stands in for. Reconnaissance data is what the services and the syscall surface observe.

## Consequences

- The dataset documentation states that half-open SYN scans are invisible to every recorded source.
- Reconnaissance stages that touch services (full connect scans, banner grabs, protocol handshakes that `sshd` logs as pre-authentication disconnects, HTTP path enumeration recorded in the nginx access log) produce observable, attributable events.
- Each reconnaissance stage declares in its acceptance expectations what it expects to be visible; a stage expected to be invisible is recorded in the ledger with zero attributed events rather than labeled by time window.
