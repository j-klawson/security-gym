---
id: SPEC-CORPUS
title: security-gym corpus construction
version: 0.1-draft
status: draft
date: 2026-11-09
verified_against: a70aeda (package 0.6.2)
scope:
  - server/
  - attacks/
  - campaigns/
  - configs/
  - scripts/
  - src/security_gym/data/
  - src/security_gym/parsers/
  - src/security_gym/scripts/download.py
  - scenarios/            # planned
depends_on: []
decisions: [D1, D2, D3, D12, D13, D14, D15, D16, D17, D18, D19, D20]
---

# SPEC-CORPUS: Corpus Construction

## Abstract

This document specifies how the telemetry security-gym replays is produced: the
reference target host, the recorder that captures every source, the attribution
of each event to its cause at capture time, the identifiers that tie multi-stage
attacks together, sessions, the scenario packages through which attacks are
added, the benign workload, the sealed recording, composition into streams, the
event schema, validation, and release. It also records the status of the legacy
v4.1 corpus. Conventions, principles (P1 to P6), and the glossary are in
[README.md](README.md).

## 1. Introduction

### 1.1 Scope

Everything upstream of the environment's input database (SPEC-ENV 4). Under D3
(decided 2026-11-08) every attack is re-run and re-recorded with log sources and
kernel telemetry captured together, and the benign baseline is recorded on the
same host by the same recorder. The architecture in Sections 3 to 13 was adopted
by the author on 2026-11-09.

### 1.2 Non-goals

Synthetic telemetry generation; live honeypot ingestion; host network-layer
capture (D19); recordings captured on hosts the maintainers do not operate (D18).

### 1.3 Root cause addressed

The legacy pipeline uses the event's address as a stand-in for its cause. An
address exists only on events with a network peer; most host telemetry (file
opens, process starts and exits, cron and journal lines) has none, so the legacy
labeler falls back to time-window membership and the legacy composer writes the
attacker address onto attack kernel events. Defects 1, 4, 5, 6, and 7 (Section
15), the `syslog` format split, and the `current_src` leak (SPEC-ENV 5.7) are
consequences of that substitution. This document replaces it: causation is
recorded when it happens, through process lineage, and identifiers are minted by
the components that know the facts rather than derived from telemetry.

## 2. Conventions and Terminology

As in [README.md](README.md) Section 2. A "generator" is any program that drives
traffic at the target, attack or benign. A "stage" is one phase of a scenario
(for example reconnaissance, credential access, execution).

## 3. Architecture

```
scenario package ──► harness ──registers──► recorder (on reference target)
benign driver   ──►          ──registers──►   │ kernel collector, journald, log tails,
                                              │ container logs, auditd; capture-time marks
                                              ▼
                                         recording (sealed, content-addressed)
                                              │ events + label stream + ledger + manifest
                                              ▼
                                      corpus (set of recordings, released with DOI)
                                              │
                                              ▼
                           composer / scheduler (D15) ──► stream ──► environment (SPEC-ENV)
```

- **CORPUS-R-001** (MUST). Benign and attack telemetry pass through the same
  reference target, recorder, parsers, scrubber, and attribution mechanism (P5).
- **CORPUS-R-002** (MUST). Attack scenarios are recorded while the benign
  workload runs (busy host; decided 2026-11-09, D3). The target is never exposed
  to the internet; every benign request is produced by a driver under project
  control (Section 9).

## 4. Reference Target

- **CORPUS-R-010** (MUST). The target host is built from a versioned definition:
  base image, kernel, collector build, recorder, and each vulnerable service as a
  container pinned by image digest. Isildur (Debian 11, kernel 5.10, BCC 0.18) is
  the first realization.
- **CORPUS-R-011** (MUST). Every recording names the reference-target version it
  was captured on (Section 10).
- **CORPUS-R-012** (MUST). The target runs no host network-layer capture
  (`nftables` logging, `conntrack`), consistent with the production servers it
  represents (D19).

Conformance: not met; Isildur is a hand-built VM maintained through snapshots
(`server/BUILD.md`).

## 5. Recorder and Telemetry Sources

- **CORPUS-R-020** (MUST). One recorder captures all sources continuously for the
  whole capture session and stamps each record on arrival from one clock.
- **CORPUS-R-021** (MUST). Sources: kernel events from the collector; `journald`
  in structured form (`_PID`, `_SYSTEMD_UNIT`, `_COMM`) alongside the rendered text
  log files the environment presents; nginx and application logs; container logs;
  auditd.
- **CORPUS-R-022** (MUST). Text log files are read as they are written (tailed),
  not pulled after the capture.
- **CORPUS-R-023** (MUST). The recorder's own activity and any management channel
  are excluded by cgroup membership, not by process name, and the exclusion is
  reported per recording.
- **CORPUS-R-024** (MUST). The kernel collector records, for every event: pid,
  thread ID, process start time (so a reused pid is distinguishable), cgroup ID,
  and host identity; for `execve`, ppid and parent comm; for `connect`, the
  destination address in correct byte order; for `accept4`, the peer address via
  an entry and exit probe pair (the `upeer_sockaddr` pointer stashed in a
  `BPF_HASH` keyed on `pid_tgid`); and `fork` via `sched_process_fork`, since
  `sshd` forks its session process without an `execve`.

Conformance of the collector at `a70aeda` (`server/ebpf_collector.py`): six
tracepoints (`sys_enter_execve`, `sched_process_exit`, `sys_enter_connect`,
`sys_enter_accept4`, `sys_enter_openat`, `sys_enter_unlinkat`; lines 73, 97, 136,
160, 187, 204). Emitted fields: `execve` pid, ppid, uid, comm, parent comm, args;
`exit` pid and exit code; `connect` pid, uid, comm, destination (byte order fixed
2026-08-28, line 250); `accept` pid, uid, comm and no peer address (lines 160-171);
`open` pid, comm, path, flags; `unlink` pid, comm, path. Missing against
CORPUS-R-024: `accept4` peer address, `fork`, thread ID, process start time,
cgroup ID, host identity, and `uid` on file events. The collector filters its own
pid and parent pid (lines 42-46, 283-290).

## 6. Registration, Attribution, and Identifiers

### 6.1 Registration

- **CORPUS-R-030** (MUST). Every generator registers with the recorder before it
  acts. A registration carries the generator's identifiers (Section 6.3) and the
  connection it is about to open (source address and source port). The recorder
  appends each registration to the ledger.
- **CORPUS-R-031** (MUST). Generators open connections only through the harness
  context (Section 8), which performs the registration, so a scenario author
  cannot omit it.

### 6.2 Capture-time attribution

- **CORPUS-R-040** (MUST). When `accept4` returns a connection whose peer matches a
  registration, the accepting process (or thread, where the service model allows)
  is marked with the registration's identifier.
- **CORPUS-R-041** (MUST). Marks are inherited at `fork` and cleared at exit, in a
  kernel-side map, so attribution follows the kernel's parent and child relation
  as it happens and is immune to pid reuse.
- **CORPUS-R-042** (MUST). A log line inherits the mark of the process that wrote
  it, joined on the syslog header pid or the journal `_PID`. A web access line
  joins on the registered client address and port.
- **CORPUS-R-043** (MUST NOT). Marks and identifiers never appear in an event's
  raw text or parsed fields. No in-band marker (a distinctive username,
  User-Agent, or command comment) may be used to carry attribution, since any such
  marker is readable by the agent (P1).
- **CORPUS-R-044** (MUST). Every event receives an attribution class. Benign
  workload events are attributed through their drivers' registrations by the same
  mechanism as attack events (P5). The treatment of shared server processes,
  system reactions, and unregistered background activity is open (D20).
- **CORPUS-R-045** (MUST). The binary label `is_malicious` is derived from the
  attribution class by a rule stated in the release (D20), never from time-window
  membership or address membership alone (D12).

Conformance: not met. The legacy labeler (`attacks/collection/labeler.py:120-128`)
labels an event malicious when its timestamp lies in a phase window and, if it
carries `src_ip`, that address is in the phase's attacker set; address-less
events (all kernel file and process events, every `syslog` and `journal` line) are
labeled on the window alone.

### 6.3 Identifiers

- **CORPUS-R-050** (MUST). Identifiers are minted by the component that knows the
  fact and are never derived from telemetry:

  | Identifier | Minted by | Names |
  |---|---|---|
  | `recording_id` | scenario harness, at capture | one recorded execution of a scenario |
  | `stage_id` | scenario harness, at each stage transition | one stage within a recording; ties the stages of a multi-stage attack together across different source addresses |
  | `instance_id` | composer or scheduler, per placement | one occurrence of a recording in a stream; a recurrence of the same recording receives a new one |

  Status: recommended answer to D13 (open). The legacy composer copies the source
  `campaign_id` onto every transplanted event (`data/composer.py:524-548`), so two
  occurrences of one recording are indistinguishable.
- **CORPUS-R-051** (MUST). Identifiers are ground truth (SPEC-ENV 4) and reach the
  environment's consumers through `info` only.

### 6.4 Acceptance checks carried from the legacy audit (D12)

- **CORPUS-R-060** (MUST). Applied to recordings of the legacy scenarios, the
  attribution reproduces the kernel-label audit's H5 expectations
  (`data/provenance/KERNEL_LABEL_AUDIT_20261107.md`): Log4Shell `java` JNDI
  callbacks and payload-download `wget` DNS lookups are attack-attributed; the
  Log4Shell `web_access` requests are attack-attributed; `cron`, `systemd-udevd`,
  and `tmux:` activity is not attack-attributed; no regression on attack-attributed
  `auth_log`, `journal`, and `web_access` events. Counts are re-established per
  recording, since the legacy counts (80, 6, 5, 54, 33, 29, 1; 308, 1,336, 345)
  describe `campaigns_v2.db` only.

## 7. Sessions (D1, decided)

- **CORPUS-R-070** (MUST). One session definition applies identically to both
  classes: for kernel events, a process subtree rooted at its session leader
  (`sshd` session child, `login`, `cron`, or the init child that starts a service),
  derived from host-namespaced process identity; for log events, the client
  address and port for `auth_log`, the client host for web sources, and an explicit
  absence of session for system logs.
- **CORPUS-R-071** (MUST). Sessions are materialized in the `sessions` table and
  are never used for labeling. No scorer keys on session structure.
- **CORPUS-R-072** (MUST NOT). No pipeline stage writes a session identifier or an
  address onto an event of one class only.

Conformance: not met. `session_id` is the client address and port for `auth_log`
(`parsers/auth_log.py:99`), the client address for web sources, absent for
`syslog`, `journal`, and kernel events, and fabricated as
`{dominant_ip}:ebpf_{short_cid}` for attack kernel events only by
`_enrich_ebpf_fields` (`data/composer.py:196-246`, stamp at 226-237). The
`sessions` table (`data/schema.py:45-54`) is never written.

## 8. Scenario Packages

- **CORPUS-R-080** (MUST). An attack is added as a self-contained package:

  ```
  scenarios/<name>/
    manifest.yaml       identifier, version, CVE where applicable, ATT&CK technique and
                        tactic, stages, required services, license, author
    driver.py           stage code written against the harness interface
    service/            vulnerable service container (pinned digest) and its configuration
    benign/             benign workload driver for every service the package adds (required)
    variation.yaml      what may vary between runs: credentials, timing profile,
                        payloads, source addresses
    expectations.yaml   acceptance checks on the recording, including what each stage
                        expects to be visible
  ```
- **CORPUS-R-081** (MUST). Drivers open connections only through the harness
  context (`ctx.connect()`, `ctx.http_session()`, `ctx.ssh()`), which registers each
  connection first. The legacy `AttackModule` interface and `AttackModuleRegistry`
  (`attacks/modules/base.py:75-142`) evolve into this interface.
- **CORPUS-R-082** (MUST). A package that adds a service ships a benign driver for
  that service. A service active only during attacks makes its process names,
  files, and log formats a perfect label (P5).
- **CORPUS-R-083** (MUST). ATT&CK technique and tactic identifiers are validated
  against the ATT&CK knowledge base when the package is validated. (Legacy defect:
  `full_killchain.yaml` and `redis_killchain.yaml` tag the T1046 scan `TA0043`;
  T1046 is a Discovery technique, `TA0007`.)
- **CORPUS-R-084** (MUST). Runs of one scenario vary per `variation.yaml` so that a
  recurrence is a distinct instance. The campaign plan schedules late first
  appearances and recurrences of techniques (D3).
- **CORPUS-R-085** (MUST). Reconnaissance stages declare in `expectations.yaml`
  what they expect to be visible. A half-open SYN scan completes no handshake, so
  no process returns from `accept4` and no service logs it; it is invisible to every
  recorded source. Such a stage is recorded in the ledger with zero attributed
  events and is not labeled by time window. Stages that touch services (full
  connect scans, banner grabs, pre-authentication disconnects logged by `sshd`,
  HTTP path enumeration in the nginx access log) produce attributable events (D19).
- **CORPUS-R-086** (MUST). Outside contributions arrive as scenario packages by
  pull request; maintainers run accepted packages on the reference target and
  publish the resulting recordings. Recordings captured on contributor-operated
  hosts are not accepted into the corpus (D18).

## 9. Benign Workload

- **CORPUS-R-090** (MUST). The benign workload is generated in the lab by drivers
  that register exactly as attack drivers do. Its composition (scripted drivers,
  replay of real request logs as stimulus, or both) is open (D3 remaining
  sub-item); live external traffic is excluded.
- **CORPUS-R-091** (MUST). The benign capture is long enough that no segment of it
  repeats verbatim within one composed stream. (Legacy: the kernel baseline spans
  27.7 hours and is repeated about 26 times in `exp_30d_heavy_v4`;
  `BENIGN_COMPOSITION_AUDIT_20261108.md`.)
- **CORPUS-R-092** (SHOULD). Drivers that install scheduled jobs (cron, timers) own
  them through registration, which shrinks the unattributed background class.

## 10. Recordings

- **CORPUS-R-100** (MUST). One run of one scenario on the reference target, with
  the benign workload active, produces a sealed, content-addressed recording: the
  events, the label stream, the ledger, the validation report, and a manifest
  carrying the digests of the reference-target version, collector build, service
  images, scenario version, and repository commit.
- **CORPUS-R-101** (MUST). Recordings are immutable. A correction produces a new
  recording with a new digest.

## 11. Composition and Scheduling

- **CORPUS-R-110** (MUST). The composer (or scheduler) consumes recordings by
  digest, not campaign databases by path, and mints `instance_id` at each
  placement.
- **CORPUS-R-111** (MUST). From a recording it injects the events attributed to the
  scenario (and those of any class D20 assigns to the scenario) into the benign
  stream; the recording's own benign background is not injected twice.
- **CORPUS-R-112** (MUST). A stream is a pure function of the corpus digest, the
  composition configuration, and one seed (P4). Whether composition also runs at
  `reset(seed)` as a seeded runtime scheduler is open (D15); a pinned offline
  stream is then the same code path materialized for one seed and hashed. A test
  asserts that equal inputs produce byte-identical event sequences.
- **CORPUS-R-113** (MUST). Benign window selection is configurable and recorded
  (D16, open).
- **CORPUS-R-114** (MUST NOT). The composer does not filter by label. (Legacy: it
  loads only `is_malicious = 1` rows from campaign databases,
  `data/composer.py:141-143`, so attack-caused events the labeler missed never
  reach any stream.)
- **CORPUS-R-115** (MUST NOT). The composer writes no address, session, or other
  structural field onto events (CORPUS-R-072).

Legacy behavior (informative): a Poisson attack schedule (`campaigns_per_day`)
with an ATT&CK-weighted type mix, benign sources cycled from each source's
earliest timestamp (`_cycle_source`, `data/composer.py:257-295`), kernel events
downsampled by a hash keyed on the source timestamp before cycling (the v4
streams record a 24.2% eBPF downsampling parameter, per CLAUDE.md), and attack sessions transplanted with intra-session timing preserved.
`composition_meta` records input paths but no digests (`data/composer.py:708-716`).

## 12. Event Schema

- **CORPUS-R-120** (MUST). The corrected corpus uses schema version 3: the version
  2 `events` columns (`id`, `timestamp`, `source`, `raw_line`, `parsed`,
  `is_malicious`, `campaign_id`, `attack_type`, `attack_stage`, `severity`,
  `session_id`, `src_ip`, `username`, `service`); host-namespaced process identity
  in `parsed` for kernel events; the attribution class and identifiers of Section 6;
  and a live `sessions` table (leader process, host, start, end, event count).
- **CORPUS-R-121** (MUST). Each column is declared as one of replay control,
  observation payload, ground truth, or advisory (SPEC-ENV 4). Whether the class is
  recorded in the schema itself is open (OI-CORPUS-1).
- **CORPUS-R-122** (MUST). Valid sources: `auth_log`, `syslog`, `web_access`,
  `web_error`, `journal`, `ebpf_process`, `ebpf_network`, `ebpf_file`. A new source
  extends this list, SPEC-ENV ENV-R-011, and the observation space together.
- **CORPUS-R-123** (MUST). Parsers convert raw lines to `ParsedEvent` through the
  decorator registry; every parser stores `event_type` in `fields`; syslog-format
  timestamps (BSD and RFC 3339) are converted to UTC; parsers retain the process
  identifier present in the line header so CORPUS-R-042 can join on it.

## 13. Validation

- **CORPUS-R-130** (MUST). A recording is accepted only if it passes:
  1. Scenario acceptance: the package's `expectations.yaml`.
  2. Separability: for every source, field, line format, and process name,
     presence alone does not separate the attribution classes perfectly. This
     generalizes every leak found to date (address presence on kernel events,
     journal JSON and hostname format in `syslog`, attack-only sessions) and
     implements D17's validator requirement.
  3. Integrity: recorder and management activity excluded; timestamps monotone per
     source; every event carries an attribution class; CORPUS-R-060 reproduced on
     the corresponding scenarios.
- **CORPUS-R-131** (MUST). The separability check runs on composed streams and on
  releases as well as on recordings.
- **CORPUS-R-132** (SHOULD). The separability check is implemented first against
  the legacy streams, where it is expected to fail on the known leaks; that failure
  validates the check.

Conformance: not met. `scripts/validate_labels.py` has nine structural checks and
no semantic or separability check.

## 14. Release and Provenance

- **CORPUS-R-140** (MUST). The corrected corpus is released as a new dataset
  version with its own DOI (D3).
- **CORPUS-R-141** (MUST). One digest-verified manifest is the source of truth for
  released artifacts, is regenerated from the live artifacts at publication, and is
  consumed by the downloader, which verifies every digest (D14 decides the file,
  not whether). Each manifest entry carries: canonical URL, Zenodo record or
  HuggingFace revision, archive sha256 and byte size, decompressed sha256 and byte
  size, event count, composition configuration and seed, and the composer version
  that produced it. The downloader verifies the archive digest before
  decompression and the decompressed digest or event count after, replaces an
  existing file whose digest does not match rather than skipping it, writes a
  `.verified` sidecar, and is HTTPS-only. Manifest entries are written by a
  publication script from the live artifacts (compress, hash, count), never by
  hand. Tests cover digest mismatch, event-count mismatch, replacement of a stale
  existing file, and manifest round-trip. Conformance: not met; `src/security_gym/scripts/download.py:13`,
  `:104-121` points at GitHub Releases and verifies nothing, while canonical
  artifacts are Zenodo and HuggingFace `.db.zst` files, and `croissant.json`
  checksums are unused.
- **CORPUS-R-142** (MUST). Every released version states in-band which known
  defects it carries. Superseded records (v3, v4, v4.1) receive in-band errata
  naming defects 4, 5, and 7 and the address and journal asymmetries; the
  disposition of the legacy labels (erratum only, or corrected re-release) is open
  (D12 sub-item).
- **CORPUS-R-143** (MUST). Release artifacts are verified by decompress-and-count
  against the live databases before upload; both stale-archive incidents
  (`V3_ARCHIVE_STALENESS_20260831.md`, `V4_ARCHIVE_STALENESS_20260726.md`) would
  have been caught by this check.

## 15. Legacy Corpus v4.1 (informative)

The released corpus (Zenodo 10.5281/zenodo.21763493; HuggingFace
`j-klawson/security-gym-v4`) is the corpus the as-built behavior of SPEC-ENV runs
on. Attack events were recorded on Isildur (`campaigns_v2.db`); benign logs come
from personal servers and benign kernel events from frodo, 9600baud, and hopper,
scrubbed to Isildur's identity (`benign_v4.db`). Known defects:

| # | Defect | Layer | Evidence |
|---|---|---|---|
| 1 | Sessions fabricated for attack kernel events only | composer | `data/composer.py:196-246`; D1 |
| 2 | Cross-host pid collision corrupts ancestry and `tree_depth` | build | `scripts/build_benign.py:398-409`; SPEC-ENV ENV-R-022 |
| 3 | Three hosts stacked and cycled reproduce no single host's distribution | build, composer | D3 |
| 4 | Byte-reversed IPv4 on `connect` (collector fixed 2026-08-28; shipped data unfixed) | collector | `EBPF_IP_BYTE_ORDER_20260828.md` |
| 5 | `accept` carries no peer address | collector | `server/ebpf_collector.py:160-171` |
| 6 | Address presence on kernel file and process events is a perfect label (499,084 of 499,084 addressed `ebpf_file` and 16,841 of 16,841 addressed `ebpf_process` events malicious in `exp_30d_heavy_v4`, per CLAUDE.md; no provenance note) | composer | SPEC-ENV ENV-R-060 |
| 7 | Window-based labeling misattributes kernel and address-less log events in both directions | labeler | `KERNEL_LABEL_AUDIT_20261107.md`; D12 |
| 8 | `syslog` channel separable by surface format; benign corpus thin (27.7 h kernel span, 325 benign `syslog` lines and no benign `journal` event in the 30-day stream) | build, composer | `BENIGN_COMPOSITION_AUDIT_20261108.md`; D16, D17 |

Log-only supervised results are unaffected by defects 1 to 6; defect 7 reaches the
log channels marginally (5 of 350 Log4Shell `web_access` requests labeled benign,
1.43%, in `campaigns_v2.db`) and through `syslog` and `journal` lines labeled on
the window alone.

## 16. Security Considerations

Scenario packages contain working exploit code and vulnerable service images.
They MUST run only against the reference target on an isolated network; the
target is never exposed to the internet (CORPUS-R-002). Contributed packages are
reviewed before execution, since a package runs code on maintainer
infrastructure; the harness interface (CORPUS-R-081) is also the place to confine
which hosts a driver may reach. Recordings MUST be scrubbed of credentials, key
material, and host identifiers that do not belong to the reference target (the
v4.1 release removed an SSH key fingerprint from `campaigns_v2.db`). Published
recordings contain real exploit payloads (for example JNDI lookup strings) and
MUST be labeled as such for downstream consumers. Attribution metadata is ground
truth; its exclusion from event text (CORPUS-R-043) is an integrity requirement of
every benchmark built on the corpus.

## 17. Open Issues

- **OI-CORPUS-1.** Whether the per-column class (CORPUS-R-121) is recorded in the
  schema (column comment or companion table).
- **OI-CORPUS-2.** The legacy counts in Section 15 and in the decision records were
  measured on specific databases (stated with each figure); several, including
  defect 6, rest on CLAUDE.md without a provenance note. Re-verify against the
  exact databases cited by any publication.
- **OI-CORPUS-3.** Whether the kernel's audit login-session identifier is available
  on the reference target kernel; if so it gives a kernel-native, inherited
  identifier for SSH sessions that simplifies CORPUS-R-041 and part of D20.

## 18. References

- [README.md](README.md): conventions, principles, glossary.
- [SPEC-ENV.md](SPEC-ENV.md) Section 4: the input contract this document produces.
- Decision records D1 to D3 and D12 to D20 in [decisions/](decisions/README.md).
- MITRE ATT&CK knowledge base.
- Provenance notes in `data/provenance/` (listed in README.md Section 7).
