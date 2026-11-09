---
id: D12
title: Kernel-event labeling rule and legacy-label disposition
status: partially decided
decided: 2026-11-08
decided_by: author
source: author, 2026-11-08
affects: [SPEC-CORPUS 6, SPEC-CORPUS 11, SPEC-CORPUS 13, SPEC-CORPUS 15]
related: [D1, D3, D13, D20]
---
# D12. Kernel-event labeling rule and legacy-label disposition

## Context

**Labeling rule as-built.** `CampaignLabeler._event_matches_window` (`attacks/collection/labeler.py:120-128`) labels an event malicious when its timestamp lies inside a phase window and, if the event carries a `src_ip`, that address belongs to the phase's attacker set; an event with no `src_ip` is labeled on the window alone (`:125-128`). The class docstring justifies the benign default by stating that the target host is isolated (`:39-40`). Sessions play no part in labeling.

**Defect 7 (audited 2026-11-07, `data/provenance/KERNEL_LABEL_AUDIT_20261107.md`).** The rule misattributes kernel events in both directions.

- Address-less kernel events (`openat`, `execve`, `exit`, `accept`) inherit the label of any window containing them. In `campaigns_v2.db`, 116 of 26,946 malicious `ebpf_file` events and 1 of 864 malicious `ebpf_process` events come from background processes no campaign started (`cron`, `tmux:`, `systemd-udevd`). A system-service tier (`systemd*`, `dbus-daemon`) of unsettled attribution is 22.70% to 47.56% of malicious kernel events by channel; the range spans two databases (`campaigns_v2.db` file channel 22.70%; v3 stream network channel 47.56%; audit Section 4).
- Addressed kernel events are malicious only if the address is an attacker's, so attack-caused connections to third parties are labeled benign: 80 Log4Shell JNDI callbacks (`comm=java` to port 1389, failing the address test through defect 4) and 6 payload-download DNS lookups (`comm=wget` to `8.8.8.8:53`). A further 350 nginx proxy connections into the vulnerable container are labeled benign and are arguably attack-caused. None of the 602 addressed `ebpf_network` events in scope is labeled malicious (audit Section 3).
- The composer loads only `is_malicious = 1` rows from a campaign database (`data/composer.py:141-143`), so every attack-caused event the labeler missed is absent from every composed stream; the v3 `exp_30d_heavy` stream contains no `comm=java` event, so its Log4Shell stage carries no kernel evidence of exploitation (audit Section 3; v4 not scanned).
- The parser derives `src_ip` for `connect` from the destination (`parsers/ebpf.py:87-89`), so the byte-reversed destination (defect 4) is the address the labeler tests.

**Log events are not exempt.** The rule was earlier described as correct for log events. It is correct only for log events that carry an attacker address (`auth_log`, web). The `syslog` and `journal` parsers set no `src_ip`, so those events are labeled on the window alone; the malicious `syslog` sample in `data/provenance/BENIGN_COMPOSITION_AUDIT_20261108.md` Section 4 is the hourly `CRON ... run-parts` job (SPEC-CORPUS 6.2). Five Log4Shell `web_access` requests (ids 29535 to 29539 in `campaigns_v2.db`) are labeled benign, 1.43% of 350 (audit H2).

**Validator.** `scripts/validate_labels.py` has nine structural checks and no semantic one; it passes on these data.

## Options

- Keep the window-plus-address rule.
- Replace it, for kernel events, with a process-ancestry test rooted at campaign-started processes, and have the composer carry attack-caused events regardless of their legacy label.

## Recommendation

The analysis recommended the ancestry test, composer carry-through, and the audit's H5 checks as semantic validator checks.

## Decision

**Decided 2026-11-08 as recommended.** For kernel events the window-plus-address test is replaced by a process-ancestry test: an event is attack-caused when its process descends from a process the campaign started (the attacker's `sshd` child, the shell, the command), or when it is a connection whose destination is in the attacker set under either octet order for data collected before 2026-08-28. The composer carries attack-caused events regardless of label. The H5 acceptance checks are added to `scripts/validate_labels.py`: the 80 `java` callbacks malicious; the 6 `wget` lookups malicious; the 5 `web_access` rows malicious; the 54 `cron`, 33 `systemd-udevd`, and 29 `tmux:` `ebpf_file` events and the 1 `cron` `ebpf_process` event benign; no regression on 308 `auth_log`, 1,336 `journal`, and 345 `web_access` malicious rows; unrelated-background tier at zero (all counts on `campaigns_v2.db`, audit H5).

The ancestry join is the same structure that derives sessions under D1, but labeling is rooted at campaign-started processes and sessions at any session leader; sessions still play no part in labeling.

## Consequences

- Under the 2026-11-09 capture architecture the ancestry is recorded at capture time (registration, marks inherited at fork), not reconstructed (SPEC-CORPUS 6). The H5 checks remain the acceptance test for the legacy-data path and a regression reference.
- The attribution of shared server processes, system reactions, and background is not settled by the ancestry rule; it is D20.

## Open sub-items

- Disposition of the legacy v4.1 labels: in-band erratum only, or a corrected re-release of the legacy streams.
- Kernel-targeting results on the legacy streams: withdrawn, caveated, or re-run with enrichment-only addresses excluded from the target slate and from both `current_src` lines (a code change in `_observe_address` and the two renderers). No new result is to be published on the legacy streams without stating which.
