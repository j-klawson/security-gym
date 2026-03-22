# security-gym Roadmap

Phased development plan for the security-gym Gymnasium environment.

## Phase 1 — Foundation ✅

Package skeleton, data layer, auth_log parser, event/hashed feature extractors, target builder, SecurityLogStreamEnv. 58 tests passing, `gymnasium.utils.check_env` passes.

## Phase 2 — Alberta Integration ✅

`SecurityGymStream` adapter (`adapters/scan_stream.py`), GitHub Actions CI (test + lint + security). 86 tests passing.

## Phase 3 — Parsers + Wrappers ✅

syslog, web_access, web_error, journal parsers; SessionFeatureExtractor (20-dim); HashedFeatureWrapper, SessionAggregationWrapper, WindowedWrapper, DecayingTraceWrapper; enriched env info dict (event_type, src_ip, username). 172 tests passing.

## Phase 4 — Attack Scripts ✅

YAML-driven campaign framework, MITRE ATT&CK-aligned phases, AttackModuleRegistry (recon/ssh_brute_force/log4shell/credential_stuffing/ssh_post_auth/redis_lua_escape), non-stationary timing profiles, IPManager (spoofed + aliased), LogCollector (SSH/SFTP), CampaignLabeler (time+IP matching), auditd parser, CampaignOrchestrator, CLI (`python -m attacks`). 6 attack modules covering 6 MITRE ATT&CK tactics (Reconnaissance, Credential Access, Initial Access, Execution, Discovery, Command and Control) with kill chain campaign support.

## Phase 5 — Data Collection ✅

Generate labeled attack datasets by running campaigns against the Isildur VM.

- Isildur VM fully configured (researcher user, SSH key + password auth, NOPASSWD sudo for ausearch)
- Docker stack deployed (Log4Shell on :8080, Nginx reverse proxy on :80)
- All log sources verified readable (auth_log, syslog, nginx access/error, journal)
- LogCollector auto-detects target timezone via SSH (`date +%z`), corrects BSD syslog timestamps
- SSH brute force campaign: 1,124 events (230 malicious, 894 benign)
- Log4Shell campaign: 169 events (151 malicious, 18 benign)
- Recon SYN scan campaign: 712 events (19 malicious, 693 benign)
- Combined 3-phase campaign (recon → SSH → Log4Shell): 1,029 events (868 malicious, 161 benign)
- Credential stuffing campaign: 361 events (197 malicious, 164 benign)
- Post-auth execution campaign: 591 events (237 malicious, 354 benign)
- Full kill chain campaign (recon → cred stuffing → post-auth): 1,156 events (562 malicious, 594 benign)
- Benign DB imported from 3 servers (1.45M events), scrubbed of identifying hostnames/domains/emails
- v1 experiment streams composed: 7d brute-only, 30d heavy, 90d mixed, 365d realistic (136k events, 897 campaigns)
- v2 experiment streams re-composed with eBPF: 7d (26k events, 6 campaigns), 30d (510k, 284), 90d (475k, 277), 365d (1.64M, 897)
- Dataset published to GitHub Releases and Zenodo (software DOI: 10.5281/zenodo.18810298, dataset DOI: 10.5281/zenodo.18901542)
- `security-gym` CLI for dataset download (`security-gym download`, `security-gym list`)

## Bugfix — event_type serialization & session enrichment (2026-03-04)

Fixed `event_type` being lost during EventStore serialization — the auth_log parser was the only parser that didn't store `event_type` in `fields["event_type"]`. Also added a safety net in EventStore to inject `event_type` into the parsed JSON if any parser omits it. Additionally, the auth_log parser now enriches PAM session open/close events with `src_ip` and `session_id` by caching PID→(ip, session_id) from preceding auth events. This unblocks rlsecd's `GymEventStoreSource` which needs `event_type` to distinguish auth_success from auth_failure without pattern-matching workarounds.

## Phase 6 — Experiments (Future)

Connect security-gym to alberta-framework and run continual learning experiments.

- Feed SecurityGymStream into MultiHeadMLPLearner
- Compare IDBD / Autostep / LMS optimizers on security log data
- Evaluate session vs. event vs. hashed feature representations
- Benchmark against chronos-sec honeypot results
- Non-stationarity analysis (concept drift across campaign phases)
- Kill chain cross-phase prediction: can agents learn that recon predicts execution?

## Open Design Question — Attack Type Encoding

The attack_type head (Head 1) currently uses **ordinal compression**: 8 categorical types mapped to a single float in [0, 1] via `index / 7`. This creates a false distance metric — MSE loss treats brute_force→credential_stuffing (error 0.02) as a smaller mistake than brute_force→exfiltration (error 1.0), even though these are unrelated categories. In practice, ObGD gradient capping and strong shared-trunk features mitigate this, but it's architecturally unsound.

The problem deepens at MITRE ATT&CK scale. The current 8-type taxonomy is a simplified subset; the full framework has ~200 techniques across 14 tactics, and grows with each ATT&CK release. Any encoding must handle this scale and remain stable as new techniques are added.

### Options

1. **One-hot (N neurons, cross-entropy loss)** — Standard classification. Clean separation, no false distances. But 200+ output neurons is expensive, every new technique requires retraining the output layer, and the encoding carries zero information about technique relationships.

2. **Learned embeddings (fixed-dim vector per technique)** — Each technique gets a dense vector (e.g., 16-dim) learned during training. Techniques with similar behavioral signatures converge to nearby embeddings. Scales better than one-hot, but still requires a growing lookup table and retraining when new techniques appear.

3. **Hierarchical encoding (tactic + technique, two heads)** — Encode MITRE tactic (14 categories) and technique-within-tactic separately. Mirrors ATT&CK's own structure. Tactically meaningful — confusing two techniques within the same tactic is a smaller error than confusing tactics. Scales to new techniques within existing tactics without changing the tactic head.

4. **Property-based encoding (behavioral features, not IDs)** — Encode observable attack *properties* rather than technique identity: network vs. host, lateral vs. vertical, noisy vs. stealthy, automated vs. manual, pre-auth vs. post-auth, etc. Fixed-dimension output regardless of technique count. A novel technique the agent has never seen still has recognizable properties. Most aligned with how human analysts think and with continual learning goals (generalization over memorization).

### Note: attack_stage is intentionally ordinal

Unlike attack_type, the attack_stage head (Head 2) has genuine sequential structure — the kill chain is a real progression (recon → initial_access → execution → persistence → exfiltration). Confusing adjacent stages is a smaller conceptual error than confusing distant ones, so the ordinal encoding's distance metric is meaningful here rather than arbitrary. Attackers can skip stages (e.g., stolen credentials → straight to post-auth host recon), but skipping stages doesn't break the ordering — it just means not every attack traverses every stage. Stages are assigned per-event based on campaign phase, so parallel kill chains (recon on host A while exfiltrating from host B) are already handled correctly.

### Current Decision

Keep ordinal compression for Phase 6 experiments. The 8-type taxonomy is a stepping stone; investing in one-hot now is throwaway work if the eventual answer is option 3 or 4. The ordinal baseline also provides a comparison point for whatever encoding replaces it. Revisit before Phase 8 (NetFlow) when the attack taxonomy will need to expand.

## Phase 7 — Streaming Server (Future)

Internet-facing service that serves composed streams to remote agents. Wraps SecurityGymStream with a network protocol (gRPC/WebSocket), authentication, and rate limiting. Enables multiple researchers and agents to consume the same composed stream without local DB access.

## Phase 8 — NetFlow Data (Future)

Extend security-gym with benign and attack NetFlow data generation. Attack traffic will likely be encrypted (TLS/SSH tunnels), making payload inspection useless — the learning agent must detect threats from flow metadata alone (packet sizes, timing, byte counts, duration, flags). This is an interesting test of whether continual learning agents can pick up on subtle distributional signatures in metadata when content is opaque.

- NetFlow v5/v9 or IPFIX collector and parser
- Benign flow generation (normal web browsing, DNS, software updates, etc.)
- Attack flow generation (C2 beacons, exfiltration over encrypted channels, lateral movement)
- Flow feature extractor (bytes/packets per flow, duration, inter-flow timing, port entropy)
- Ground-truth labeling for flow data (time+IP matching, same as log campaigns)
- StreamComposer support for mixed log + NetFlow experiment streams
- Evaluate whether metadata-only features are sufficient for detection without payload inspection

## Phase 9 — Kernel Event Telemetry ✅

Hook the RL agent directly into the Linux kernel for real-time observation of system-level events. Moves beyond log parsing to native kernel telemetry — the agent observes syscalls, process creation, file access, and network connections as they happen. This is the path toward an agent that can detect and respond to threats at the OS level rather than after the fact in log files.

- [x] eBPF-based event collection daemon (`server/ebpf_collector.py`, BCC tracepoints)
- [x] eBPF event parser and orchestration wrapper (`attacks/collection/ebpf_collector.py`)
- [x] eBPF labeling fix — kernel events during attack windows correctly labeled malicious via CampaignLabeler
- [x] All campaign YAMLs updated with `ebpf: {enabled: true, baseline_seconds: 30}`
- [x] Benign eBPF baseline collection script (`scripts/collect_ebpf_baseline.py`)
- [x] BUILD.md updated with BCC install, sudoers, V2 snapshot procedure
- [x] Composition configs updated for v2 databases (benign_v2.db, campaigns_v2.db)
- [x] Install BCC on Isildur (manual .deb install for kernel 5.10)
- [x] Sudoers rules for researcher (eBPF collector, pkill, python3)
- [x] Fix BPF compilation for Debian 11 / BCC 0.18 (kernel includes, `bpf_probe_read_kernel` for task_struct)
- [x] Fix orchestrator: Ed25519 key, sudo/nohup ordering, SSH transport keepalive
- [x] Collect benign eBPF baseline (997 events from ~1 hour manual collection)
- [x] Re-run all 7 campaigns with eBPF collection — 48,520 events (24,774 malicious, 23,746 benign)
- [x] Validate v2 labels — 5 PASS, 1 SKIP, 3 FAIL (all known/expected: eBPF spot-check, temporal order, session coherence)
- [x] Fix label validator crash (check 5: target array consistency — `collect_numpy` returns list of dicts, not numpy array)
- [ ] Create ISILDUR_READY_V2 snapshot on Frodo
- [x] Re-compose experiment streams from v2 databases — 4 streams with eBPF kernel events
- [x] Enrich eBPF event lines: PPID + parent_comm on process events, UID on network events
- **Extended benign eBPF baseline** — 24+ hour collection from Isildur covering cron jobs, log rotation, Docker health checks, diurnal patterns, with synthetic benign traffic (legitimate SSH sessions, web browsing through nginx). **Critical for Phase 13a v2 env:** current benign eBPF is only 997 events from 1-hour manual collection; structured channels will be sparse during benign periods without this, biasing the agent to associate eBPF activity with attacks. Re-compose experiment streams after collection to populate benign_v3.db with eBPF events.
- Attack campaigns that generate kernel-level telemetry (privilege escalation, rootkits, fileless malware)
- ~~Periodic kernel state summary as text~~ → superseded by Phase 13a structured eBPF channels (timestamp_delta encodes event rate natively)
- ~~Real-time streaming from kernel to agent (low-latency path, not log-based)~~ → addressed by Phase 13b LSM enforcement path
- ~~Integration with existing log + NetFlow streams for multi-modal observation~~ → addressed by Phase 13a hybrid observation space
- ~~Evaluate agent performance on kernel events vs. log-only vs. combined~~ → Phase 13a benchmark: v1 (text) vs v2 (hybrid)

## PyPI Publication

Publish `security-gym` to PyPI as a `0.x` alpha package (API may change). Packaging audit completed — source code and config are ready, only build artifacts need refreshing.

**Already done:**
- `pyproject.toml` metadata (description, classifiers, license, keywords, URLs)
- Hatch build config targets `src/security_gym` only (attacks/server/scripts excluded from wheel)
- CLI entry point (`security-gym` → download/list commands)
- Gymnasium env auto-registration via entry point
- Optional dependency extras (alberta, attacks, collection, dev, all)
- No hardcoded paths — all defaults overridable

**Remaining steps:**
- [x] Add `src/security_gym/py.typed` marker (empty file for type checker discovery)
- [x] Delete stale `dist/` (v0.1.0 wheels, missing 9 source files added since)
- [x] Bump version if needed (`git tag --sort=-v:refname | head -5` to check) — already at v0.3.0
- [x] Rebuild: `python -m build` — v0.3.0 wheel verified
- [x] Test install from wheel in clean venv, verify imports + CLI + `gym.make()`
- [x] GitHub Actions publish workflow (OIDC trusted publishing: build → TestPyPI → PyPI on `v*` tags)
- [x] Configure `testpypi` and `pypi` environments in GitHub repo settings (trusted publisher)
- [x] Publish to TestPyPI (v0.3.0 test, v0.3.1 full pipeline)
- [x] Publish to PyPI — v0.3.1 live at https://pypi.org/project/security-gym/

## Phase 9b — Redis CVE-2022-0543 Attack Module

Added `redis_lua_escape` attack module — exploits the Debian-specific Lua sandbox escape in Redis (CVSS 10.0) for unauthenticated RCE. Three-stage attack: Redis enumeration (INFO, CONFIG, DBSIZE, CLIENT LIST), Lua sandbox escape via `EVAL` + `package.loadlib()`, and post-exploitation system commands. Raw TCP/RESP protocol (no new dependencies). Six command profiles (system_info, user_enum, network_enum, redis_enum, persistence, full_recon).

- [x] `redis_lua_escape` attack module (`attacks/modules/redis_lua_escape.py`)
- [x] RESP protocol helpers (encode, read, command) — inline, ~80 lines
- [x] Campaign configs: `redis_exploit_only.yaml` (standalone), `redis_killchain.yaml` (recon → Redis → SSH pivot)
- [x] Tests: registration, RESP encoding, command profiles, dry-run, mocked execute, campaign YAML loading (30 total, all pass)
- [x] `server/BUILD.md` updated with Redis setup and CVE-2022-0543 documentation
- [x] Install Redis on Isildur (`apt install redis-server`, bind 0.0.0.0, protected-mode no)
- [x] Create ISILDUR_READY_V3 snapshot on Frodo
- [x] Run `redis_exploit_only` and `redis_killchain` campaigns against Isildur
- [x] campaigns_v2.db now 60,468 events (30,436 malicious, 30,032 benign) — +~12K from Redis campaigns
- [x] Labels validated: 5 PASS, 1 SKIP, 3 FAIL (all pre-existing/expected: eBPF spot-check, temporal order, session coherence)
- [x] Campaign YAMLs updated from `en0` (macOS) to `enp3s0` (Hopper/Linux) for all 8 aliased-strategy configs
- [x] Re-compose experiment streams with Redis attack data — completed as part of Phase 10 recompose (campaigns_v2.db already included Redis campaigns, labeled as web_exploit/execution/discovery by MITRE stage)

## Phase 9c — Multi-Server Benign eBPF Collection

Extend benign eBPF kernel telemetry from a 1-hour single-server manual collection (997 events) to 24-hour multi-server collections. Without this, v2 structured eBPF channels are sparse during benign periods, biasing the agent to associate eBPF activity with attacks.

**Sources:** 3 Debian 13.4 servers collected for 24 hours each: 9600baud (public web), hopper (lab/GPU), frodo (hypervisor). Combined data scrubbed to match isildur/192.168.2.201.

**Key concern:** 9600baud gets real attacks — eBPF network events from attacker IPs must be filtered.

- [x] `collect_ebpf_baseline.py` — allow omitting `--source` (create fresh DB), add `--ssh-port`
- [x] `build_benign_v3.py` — `MaliciousFilter` accumulates IPs from filtered auth/web events
- [x] `build_benign_v3.py` — `_carryover_ebpf()` filters `ebpf_network` events from malicious IPs
- [x] `build_benign_v3.py` — `--ebpf-source` supports multiple values (`action="append"`)
- [x] Tests: 13 new tests for IP tracking, eBPF filtering, multiple sources, report counts
- [x] `server/BUILD.md` — Debian 13 eBPF setup section
- [x] Install BCC + kernel headers on 9600baud, hopper, frodo (Debian 13.4, BCC 0.31)
- [x] Configure sudoers on each server (`/etc/sudoers.d/ebpf_collector`)
- [x] Run 24-hour eBPF collection on all 3 servers (2026-03-21/22) — 3,243,383 total events
  - frodo: 2,355,832 events (`data/ebpf_frodo.db`) — hypervisor, VMs, high file/process activity
  - 9600baud: 785,473 events (`data/ebpf_9600baud.db`) — public web server, real internet traffic
  - hopper: 102,078 events (`data/ebpf_hopper.db`) — lab/GPU server, quieter baseline
- [ ] Rebuild benign_v3.db with eBPF from 3 servers
- [ ] Re-compose and validate all 4 experiment streams
- [ ] Update CLAUDE.md with new eBPF event counts

## Phase 10 — Benign Data Rebuild (v3)

Rebuild the benign dataset from scratch to eliminate hospital PII (LHSC/SJHC staff names, phone numbers, org names in URL query parameters) that survived the original hostname scrub. The prior Zenodo record was deleted.

- [x] Create `scripts/build_benign_v3.py` — generic, reproducible build tool accepting any server log tarballs via `--source NAME:PATH`
- [x] 9-stage pipeline: Prep → Extract → Parse → Filter → Scrub → Insert → eBPF carryover → Sort → Verify → Report
- [x] Malicious traffic filtering: web attacks (path traversal, SQLi, XSS, JNDI, RFI, scanner UAs, exploit paths, suspicious methods) + auth attacks (failed password, invalid user, preauth close, max auth attempts)
- [x] PII scrubbing via external JSON config (`--scrub-config`) or `--no-scrub` for logs without PII; case-insensitive replacements; default config maps all sources to campaign target (`isildur` / `192.168.2.201`) with `.internal` TLD domains
- [x] Hostname regex support for common-word hostnames that need contextual syslog-header-only replacement (can, dallas)
- [x] Update all 4 composition configs (`benign_v2.db` → `benign_v3.db`)
- [x] Automated verification: PII absence, attack content absence, source distribution, temporal order, all-benign check
- [x] Build report JSON (`data/build_benign_report.json`) with full audit trail for methodology reproducibility
- [x] Temporal sort stage — re-orders all events by timestamp after multi-server merge, rebuilds sequential IDs
- [x] Build complete: 4 servers (can, dallas, isildur, sak) → 7,915,858 events (4.96 GB), all 5 checks PASS
- [x] Re-compose experiment streams from benign_v3.db + campaigns_v2.db (sequentially to avoid OOM on 24GB system)
  - exp_7d_brute.db: 140K events (114K benign, 26K attack), 6 campaigns, 101MB
  - exp_30d_heavy.db: 1.0M events (494K benign, 509K attack), 284 campaigns, 643MB
  - exp01_90d.db: 1.9M events (1.4M benign, 475K attack), 277 campaigns, 1.3GB
  - exp_365d_realistic.db: 9.4M events (7.8M benign, 1.6M attack), 897 campaigns, 6.5GB
  - All 4 streams validated: temporal order PASS, label consistency PASS, session coherence PASS
- [x] Publish v3 dataset to Zenodo (DOI: 10.5281/zenodo.18901542)
- [x] Update README / CITATION.cff with new DOI

## v0.3.3 Release (2026-03-07)

GitHub release and Zenodo archival of software and datasets.

- [x] Pre-release PII audit of all datasets (campaigns_v2.db, experiment streams, benign_v3.db)
- [x] Scrub SSH key fingerprint from campaigns_v2.db (replaced with synthetic)
- [x] Recompress campaigns_v2.db.zst and benign_v3.db.zst for release
- [x] Create DATASET_README.md with schema docs, quick start, and citation
- [x] GitHub release v0.3.3 — triggers Zenodo software archive (DOI: 10.5281/zenodo.18810298)
- [x] Separate Zenodo dataset deposit (DOI: 10.5281/zenodo.18901542) — 6 .zst files (502MB total)
- [x] Update CITATION.cff, README.md, .zenodo.json, ROADMAP.md, TODO.md with new DOIs
- [x] Tests: 233 passed, lint clean, no dependency vulnerabilities

## Phase 11 — Report Action / SOC Escalation (Future)

Add a `report` action (ACTION_REPORT = 6, expanding Discrete(6) → Discrete(7)) that simulates the agent escalating an event to a SOC analyst. Unlike `block`/`isolate` which are immediate and autonomous, `report` models the real-world path of filing an incident report and waiting for a human analyst to investigate and remediate.

**Mechanics:**
- Agent takes `report` action on a suspicious event → starts a "resolution timer" (configurable delay in events or wall-clock seconds, simulating SOC response time)
- During the delay, the attack continues — the agent still observes events and can take other actions
- After the delay, if the reported IP was truly malicious, the SOC "resolves" the incident: the attacker's IP is blocked and any persistence is cleaned up (events from that campaign cease)
- If the reported IP was benign, the SOC dismisses the report (no effect, mild penalty for false report)
- Resolution removes the attacker's source IP from the stream entirely (simulating the SOC stopping the attack at the network/host level)

**Reward design:**
- Correct report on malicious: large delayed positive reward when SOC resolves (higher than autonomous block, since SOC resolution is more thorough — cleans up persistence, not just blocks IP)
- False report on benign: negative penalty (wasted SOC time), but less than blocking benign traffic (no service disruption)
- Report cost: small immediate negative reward (SOC analyst time is a finite resource — prevents spamming reports)
- Key tradeoff: report is the *best* response to a real attack (thorough resolution) but has high latency — the agent must decide whether to block immediately (fast but incomplete) or report and wait (slow but complete)

**Why this matters:**
- Models the real-world SOC workflow — most security agents don't act alone, they escalate
- Creates a meaningful temporal credit assignment problem — the reward is delayed by the SOC response time
- Bridges to the autoresearch oracle pipeline — the "SOC analyst" can eventually be the fine-tuned LLM oracle
- Tests whether SARSA can learn to prefer delayed-but-larger rewards over immediate-but-smaller ones (report vs. block)

**Implementation:**
- [ ] Add ACTION_REPORT = 6, expand action space to Discrete(7)
- [ ] Report queue: track reported IPs with timestamps, configurable resolution delay
- [ ] SOC resolution logic: remove attacker from stream after delay (filter by campaign_id to catch session pivots)
- [ ] Reward table entries for report on malicious/benign
- [ ] `reward_config` keys: `report_cost`, `report_resolve_reward`, `false_report_penalty`, `soc_response_delay`
- [ ] Tests for report timing, resolution, false reports, multiple concurrent reports
- [ ] Update rlsecd action mapping for report action

## Phase 13 — Hybrid Observation Space & eBPF LSM (Future)

Restructure the observation space to reflect how security signals are actually consumed in production SOC tooling. Log channels (auth_log, syslog, web_log) stay as raw text — that's what analysts read in Splunk/Elastic. eBPF kernel channels switch from text to structured numeric arrays — mirroring Tetragon/Tracee/Falco JSON output that SOC platforms consume programmatically. New eBPF LSM hooks add security-decision-point signals that tracepoints can't provide, and create a path to kernel-level enforcement for Step 4a SARSA control.

**Motivation:** The current eBPF text format (`"2026-03-18T12:00:00Z execve pid=1234 ppid=1200 uid=0 comm=bash"`) is an artificial lossy step. These events are born as typed C structs in kernel space — the collector already has `event.pid`, `event.ppid`, `event.uid` as integers before flattening to text. No human reads eBPF events as raw text; SOC analysts consume them through structured dashboards. The agent wastes representational capacity learning to parse text that was never text to begin with.

### Phase 13a — Structured eBPF Observation Channels ✅

Convert the three eBPF text channels to fixed-width numeric arrays. No new kernel work required — restructures data that's already collected.

**Observation space change:**
```python
# Text channels (unchanged) — human-readable logs
"auth_log":         Text(max_length=max_chars)
"syslog":           Text(max_length=max_chars)
"web_log":          Text(max_length=max_chars)

# Structured eBPF channels — sliding window of N events × M fields
"process_events":   Box(shape=(tail_events, 8))
    # [log_delta, pid, ppid, uid, syscall_type, comm_hash, parent_comm_hash, tree_depth]
"network_events":   Box(shape=(tail_events, 7))
    # [log_delta, pid, uid, syscall_type, dst_ip_hash, dst_port, comm_hash]
"file_events":      Box(shape=(tail_events, 6))
    # [log_delta, pid, uid, syscall_type, flags_int, path_hash]

# System stats (unchanged)
"system_stats":     Box(shape=(3,))
```

`log_delta` = `log(1 + dt_seconds)` since previous event in that channel (log-scaled for gradient stability). String fields hashed via mmh3 with per-field seeds (SEED_COMM=0, SEED_IP=1, SEED_PATH=2) to prevent cross-channel aliasing. Process events include `tree_depth` derived from pid/ppid ancestry.

**Implementation:**

- [x] `StructuredRingBuffer` — circular numpy buffer with O(1) append and chronological snapshot (`envs/structured_buffer.py`)
- [x] `ebpf_encoding.py` — mmh3 hashing with per-field seeds, syscall enum, flag bitmask, log-scaled deltas, per-channel row extraction
- [x] `SecurityLogStreamEnvV2` — subclass with hybrid text + structured observation space, process tree depth tracking, per-channel timestamp deltas (`envs/log_stream_env_v2.py`)
- [x] `SecurityLogStream-v2` registered alongside v1 (backwards compatible)
- [x] `SecurityGymStream` `structured=True` mode — same hybrid observation in batch/streaming adapter
- [x] Tests: 288 passing (47 new: ring buffer, encoding, v2 env integration, adapter structured mode)
- [x] Read structured fields from existing `parsed` JSON column in EventStore — no schema changes needed
- [ ] Benchmark: compare agent training on v1 (all text) vs v2 (hybrid) on same experiment stream

**Data prerequisite:** Current experiment streams have very few benign eBPF events (only 997 from a 1-hour manual collection). The v2 structured channels will be sparse during benign periods, which could bias the agent to associate "eBPF activity = attack". Need extended benign eBPF collection before meaningful v1 vs v2 benchmarks — see Phase 9 backlog item.

### Phase 13b — eBPF LSM Hooks

Add BPF LSM programs to the collector to capture security decision events at the kernel enforcement layer. LSM hooks fire at the point where the kernel decides whether to allow or deny an operation — after path resolution, permission checks, and credential evaluation. This is strictly more informative than tracepoints, which only see syscall arguments before the kernel acts.

**Kernel prerequisite:** Isildur (Debian 11, kernel 5.10) supports BPF LSM but likely needs `CONFIG_BPF_LSM=y` and `lsm=...,bpf` boot parameter. Requires kernel reconfig or boot param change → new ISILDUR_READY_V4 snapshot.

**New LSM hooks (prioritized by security-gym value):**

| Priority | Hook | Signal | Attack Detection Value |
|----------|------|--------|----------------------|
| P0 | `bprm_check_security` | Binary execution with resolved path + creds | Payload execution, shell spawns, LOLBins |
| P0 | `file_open` | File access with resolved inode + mode + creds | Shadow file reads, config tampering, log deletion |
| P0 | `socket_connect` | Outbound connection with resolved socket + creds | Reverse shells, C2 callbacks, exfiltration |
| P1 | `ptrace_access_check` | Process debugging/injection attempts | Code injection, debugger attachment (common post-exploit) |
| P1 | `capable` | Capability checks (CAP_NET_RAW, CAP_SYS_ADMIN, etc.) | Privilege escalation attempts |
| P2 | `task_fix_setuid` | setuid/setgid transitions | SUID binary exploitation |
| P2 | `sb_mount` | Mount operations | Container escape, filesystem manipulation |
| P2 | `inode_link` / `inode_rename` | Hardlink creation, file renaming | Log tampering, binary replacement |

**New observation channel:**
```python
"lsm_events":      Box(shape=(tail_events, 9))
    # [timestamp_delta, hook_type, pid, ppid, uid, capability_bits,
    #  target_inode, object_hash, decision]
```

`hook_type` enum maps LSM hook names to integers (0=bprm_check, 1=file_open, 2=socket_connect, ...). `decision` is 0=allowed in observation mode; in control mode (Step 4a), it becomes the agent's previous enforcement decision for that hook, closing the perception-action loop.

**Enforcement path (bridges to rlsecd Step 4a):**

BPF LSM programs can return `-EPERM` to deny operations. This creates a direct mechanism for the SARSA control demon: instead of simulating `block`/`throttle` by dropping log events, the agent's action is compiled into a BPF map that the LSM hook reads in real-time. The kernel itself enforces the agent's decisions. This is the path from `rlsecd --gym` (simulated defense) to `rlsecd --live` (kernel-enforced defense).

**Implementation:**

- [ ] Check `CONFIG_BPF_LSM` on Isildur: `cat /boot/config-$(uname -r) | grep BPF_LSM`
- [ ] Enable BPF LSM if needed (boot param or kernel reconfig)
- [ ] Create ISILDUR_READY_V4 snapshot on Frodo
- [ ] New `BPF_LSM` C program strings in `server/ebpf_collector.py` — P0 hooks first
- [ ] LSM event struct: `lsm_event_t` with hook_type, pid, uid, capability, inode, decision fields
- [ ] Perf buffer + callback for LSM events (`_on_lsm`)
- [ ] LSM event parser in `src/security_gym/parsers/`
- [ ] `lsm_events` structured channel in env + adapter
- [ ] EventStore source type: `ebpf_lsm`
- [ ] Campaign labeling: LSM events labeled by same time+IP window matching as existing eBPF events
- [ ] Re-run campaigns with LSM collection enabled (campaigns_v3.db)
- [ ] Collect benign LSM baseline (24h) for normal capability checks, file opens, binary execution patterns
- [ ] Tests: LSM observation space, hook type enum, enforcement map read/write
- [ ] Enforcement map prototype: BPF hash map (`blocked_pids`, `blocked_inodes`) readable by LSM hooks, writable from userspace — proof-of-concept for Step 4a live control

### Phase 13 Dependencies & Ordering

- **13a is independent** — can start immediately, uses existing data, no kernel changes
- **13b depends on kernel config** — needs Isildur access for BPF LSM verification
- **13a should complete before Phase 6 experiments** — hybrid obs space is the representation the agent should be evaluated on
- **13b enforcement prototype feeds into rlsecd Step 4a** — the BPF enforcement map is the mechanism SARSA uses for live control
- **Phase 11 (Report Action) is independent** — can be developed in parallel with Phase 13

### Open Design Questions

1. **Hash collision strategy**: xxhash32 has ~1/4B collision rate. At the scale of Linux command names (~few thousand) and file paths (~few thousand unique during a campaign), collisions are negligible. But should we use a consistent hash→embedding lookup that the agent learns, rather than feeding raw hash values as floats?

2. **tail_events default**: Text channels use `tail_lines=500`. For structured channels, each "event" is a fixed-width row, so memory is predictable. Higher values (1000–2000) give the agent more temporal context without the truncation issues of text channels. Need to benchmark memory and training speed.

3. **Backward compatibility**: Register as `SecurityLogStream-v2` (hybrid obs) alongside existing `SecurityLogStream-v1` (all text). The v1→v2 migration in rlsecd needs the adapter to support both. Consider a `structured_ebpf=True` flag on the v1 env as a transitional path.

4. **LSM hook granularity**: P2 hooks (mount, inode_link, inode_rename) generate high event volume on normal systems. May need filtering (e.g., only log mount operations outside known mount points, only log inode operations on sensitive paths). This filtering logic lives in the BPF C program to avoid flooding the perf buffer.

## Phase 12 — Analysis & Publication (Future)

Results analysis, dataset release, and dissertation integration.

- Statistical analysis of learning curves across optimizers
- Publication-quality figures via alberta-framework analysis tools
- Public dataset release (anonymized log streams with ground-truth labels)
- Dissertation chapter: security-gym as an Alberta Plan Step 6/8 domain
