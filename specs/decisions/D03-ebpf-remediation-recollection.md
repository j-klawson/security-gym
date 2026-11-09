---
id: D3
title: eBPF remediation by re-collection, and the background workload
status: partially decided
decided: 2026-11-08
decided_by: author
source: author, 2026-11-08 (re-collection); author, 2026-11-09 (busy host)
affects: [SPEC-CORPUS 4, SPEC-CORPUS 5, SPEC-CORPUS 9, SPEC-CORPUS 15]
related: [D1, D2, D12, D16, D17, D18, D19, D20]
---
# D3. eBPF remediation by re-collection, and the background workload

## Context

**Volume.** eBPF is 97.51% of `exp_30d_heavy_v4` events, `ebpf_file` alone 90.77% (`data/provenance/BENIGN_COMPOSITION_AUDIT_20261108.md` Section 3). 93.50% of that stream's events carry no `src_ip` (20,112,710 of 21,511,208, CLAUDE.md; no provenance note), and 99.9% of the address-less events are eBPF (an `openat` or `execve` has no peer address). This is structural, not a parsing gap.

**Defect: cross-host PID collision.** `scripts/build_benign.py:398-409` merges eBPF from frodo, 9600baud, and hopper with unnamespaced `pid`/`ppid`. `tree_depth` is computed from one pid-keyed dictionary (`envs/log_stream_env_hybrid.py:213-217`; declared `:160`, reset `:182`), so cross-host PID reuse corrupts the ancestry feature for benign events while single-host attack campaigns keep valid chains; any "ancestry helps" result is confounded with host of origin. A second corruption source: `exit` events carry no `ppid`, so each exit resets that pid's stored depth to 0 (`:214-217`).

**Defect: address presence is a near-perfect label (defect 6).** The composer stamps the attacker address onto attack eBPF only (`data/composer.py:226-237`). On `exp_30d_heavy_v4`, 499,084 of 499,084 addressed `ebpf_file` events and 16,841 of 16,841 addressed `ebpf_process` events are malicious; `ebpf_network` is 2.74% against a 2.83% base rate (CLAUDE.md defect 6; no provenance note). Contrary to earlier text, the address is rendered to the agent: the default-on `target_slate` and `defense_state` text channels print the current event's `src_ip` on every step (`envs/log_stream_env.py:602-603`, `:760-769`), so on kernel events address presence is a per-event label in the default text observation (SPEC-ENV ENV-R-060).

**Collector defects in every collection to date.** (4) Byte-reversed IPv4 on `connect`: fixed in the daemon 2026-08-28 (`server/ebpf_collector.py:229-250`), but all shipped data carries it; the parser derives `src_ip` from this field (`parsers/ebpf.py:82-89`), splitting one host into two identities across channels (`data/provenance/EBPF_IP_BYTE_ORDER_20260828.md`). (5) `accept` has no peer address: `sys_enter_accept4` never reads `upeer_sockaddr` (`server/ebpf_collector.py:160-171`). In `campaigns_v2.db` all 619 malicious `ebpf_network` events are address-less `accept`s and all 603 addressed events are benign `connect`s (`data/provenance/KERNEL_LABEL_AUDIT_20261107.md` Sections 3 and 5). The collector attaches six tracepoints; `exit` emits `pid, code`, and `open`/`unlink` carry no `uid`, so the hybrid `file_events` uid column is constant zero on collector data (SPEC-CORPUS 5; SPEC-ENV ENV-R-021).

**Defect: distributional realism.** Three heterogeneous hosts stacked and timestamp-cycled (`composer._cycle_source`, `data/composer.py:257-295`) reproduce no single host's kernel distribution. The kernel baseline spans 27.7 hours and is repeated verbatim about 26 times in the 30-day stream and about 316 times in the 365-day stream (extrapolated; BENIGN_COMPOSITION_AUDIT Sections 1 to 3). Not fixable by re-processing.

**Isildur as-built.** Isildur is a frozen, near-idle VM. An idle collection makes attacks trivially separable.

## Options

**Remediation.**

- **Re-derive** on existing data: namespace PIDs, replace the fabricated session with a process-tree session, reverse the `connect` octets. Mechanical and lossless for `connect`, but cannot recover the missing `accept` addresses or fix the multi-host chimera.
- **Re-collect** single-host with attacks. Removes the cross-host merge and the eBPF transplant path entirely; requires a realistic workload, since an idle host separates attacks trivially.

**Background workload (sub-item).** Fixed constraints: the workload runs during the attack campaigns as well as the benign collection, and benign and attack telemetry pass through the same collector, parser, scrubber, and labeler.

- **(a) Scripted benign workload drivers on Isildur.** A `benign/` module family mirroring `attacks/modules/`: SSH sessions running ordinary commands, a web client walking the nginx site, scheduled jobs, package queries, file edits, Redis reads and writes, each on a seeded `TimingProfile`. Cost: a module family comparable to three or four attack modules; a documented modeling choice of what a small server's ordinary week looks like; weeks of collection wall-clock. Risk: the benign vocabulary is only as wide as the driver set (narrow but honest); the host's own services supply most kernel activity regardless.
- **(b) A dedicated busy target VM** with real usage (for example mirrored or replayed personal web traffic). Cost: a new build and snapshot set, revalidation of every scenario, a second frozen host. Benefit: the richest background.
- **(c) Isildur plus replay of real request logs as stimulus.** Replay the scrubbed benign web log (7.9 million requests) against nginx at its recorded cadence, and drive real SSH logins at the benign auth corpus's cadence. Real stimulus distribution and real kernel response. Cost: a small replayer and account provisioning on the VM. The replayed web log is from 2013 (97.8% of `web_access`; BENIGN_COMPOSITION_AUDIT Section 1), which must be stated.

Options (a) and (c) compose. The benign collection should be long enough (weeks) that no cycle of it is replayed verbatim within an experiment, and the window-selection behavior (D16) is specified before the baseline is cut into streams.

## Recommendation

The analysis recommended fixing both collector defects, diagnosing by re-running Exp 13 on a re-derived corpus, and committing to re-collection if the effect collapsed or if D2 adopted Purpose 1 (which needs symmetric sessions the transplant path cannot provide).

## Decision

**Decided 2026-11-08: re-collect.** Fix the `accept4` peer-address capture (entry and exit probe pair, `BPF_HASH` keyed on `pid_tgid`), redeploy the corrected collector to Isildur, re-run every attack, and collect the kernel and log baseline there. The three-host benign merge is retired. The campaign plan schedules late first appearances and recurrences of attack techniques (continual-learning evaluation measures adaptation on first appearances and retention on recurrences) and varies timing profile, credential lists, and source addresses across runs of one technique, so that a recurrence is a distinct instance rather than a replay of one recording. The corrected corpus is a new dataset version with its own DOI.

**Decided 2026-11-09: busy host, with benign traffic generated in the lab.** Attack scenarios are recorded while the benign workload runs. Isildur is never exposed to the internet, so every benign request is produced by a workload driver under the project's control; option (b) in its live-usage form is excluded. On the same date the author adopted the capture architecture (SPEC-CORPUS 3 to 14): all sources, logs and kernel, are re-recorded together.

## Consequences

- Because the workload runs during attacks, labels can no longer rely on the host being otherwise quiet (the isolation premise at `attacks/collection/labeler.py:39-40`); attribution must be causal and assigned at capture time (SPEC-CORPUS 6).
- Every vulnerable service added for an attack must also receive generated benign traffic, or its activity becomes a label (SPEC-CORPUS 8, 9).
- Superseded records (v3, v4, v4.1) receive in-band errata (SPEC-CORPUS 14, 15).

## Open sub-items

- Composition of the generated workload: (a), (c), or (a) with (c). Blocks the start of the benign collection, not the collector fix or the scenario work.
