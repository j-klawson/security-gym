# security-gym Roadmap

Phased development plan for the security-gym Gymnasium environment.

## Phase 1 — Foundation ✅

Package skeleton, data layer, auth_log parser, event/hashed feature extractors, target builder, SecurityLogStreamEnv. 58 tests passing, `gymnasium.utils.check_env` passes.

## Phase 2 — Alberta Integration ✅

`SecurityGymStream` adapter (`adapters/scan_stream.py`), GitHub Actions CI (test + lint + security). 86 tests passing.

## Phase 3 — Parsers + Wrappers ✅

syslog, web_access, web_error, journal parsers; SessionFeatureExtractor (20-dim); HashedFeatureWrapper, SessionAggregationWrapper, WindowedWrapper, DecayingTraceWrapper; enriched env info dict (event_type, src_ip, username). 172 tests passing.

## Phase 4 — Attack Scripts ✅

YAML-driven campaign framework, MITRE ATT&CK-aligned phases, AttackModuleRegistry (recon/ssh_brute_force/log4shell/credential_stuffing/ssh_post_auth), non-stationary timing profiles, IPManager (spoofed + aliased), LogCollector (SSH/SFTP), CampaignLabeler (time+IP matching), auditd parser, CampaignOrchestrator, CLI (`python -m attacks`). 5 attack modules covering 6 MITRE ATT&CK tactics (Reconnaissance, Credential Access, Initial Access, Execution, Discovery, Command and Control) with full kill chain campaign support.

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
- Experiment streams composed: 7d brute-only, 30d heavy, 90d mixed, 365d realistic (136k events, 897 campaigns)
- Dataset published to GitHub Releases and Zenodo (DOI: 10.5281/zenodo.18810299)
- `security-gym` CLI for dataset download (`security-gym download`, `security-gym list`)

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

## Phase 9 — Kernel Event Telemetry (In Progress)

Hook the RL agent directly into the Linux kernel for real-time observation of system-level events. Moves beyond log parsing to native kernel telemetry — the agent observes syscalls, process creation, file access, and network connections as they happen. This is the path toward an agent that can detect and respond to threats at the OS level rather than after the fact in log files.

- [x] eBPF-based event collection daemon (`server/ebpf_collector.py`, BCC tracepoints)
- [x] eBPF event parser and orchestration wrapper (`attacks/collection/ebpf_collector.py`)
- [x] eBPF labeling fix — kernel events during attack windows correctly labeled malicious via CampaignLabeler
- [x] All campaign YAMLs updated with `ebpf: {enabled: true, baseline_seconds: 30}`
- [x] Benign eBPF baseline collection script (`scripts/collect_ebpf_baseline.py`)
- [x] BUILD.md updated with BCC install, sudoers, V2 snapshot procedure
- [x] Composition configs updated for v2 databases (benign_v2.db, campaigns_v2.db)
- [ ] Install BCC on Isildur and create ISILDUR_READY_V2 snapshot
- [ ] Collect benign eBPF baseline (~1 hour)
- [ ] Re-run all campaigns with eBPF collection enabled
- [ ] Re-compose experiment streams from v2 databases
- [ ] Validate v2 label accuracy
- Enrich eBPF event lines: PPID + parent_comm on process events, UID on network events
- Periodic kernel state summary as text (active PIDs, open sockets, privileged process count, new procs/conns per window) — injected into the event stream as a text line, not structured numerics, so the agent learns its own encoding. Revisit after Phase 6 baselines show whether the agent struggles with event-rate signals in raw text.
- Attack campaigns that generate kernel-level telemetry (privilege escalation, rootkits, fileless malware)
- Real-time streaming from kernel to agent (low-latency path, not log-based)
- Integration with existing log + NetFlow streams for multi-modal observation
- Evaluate agent performance on kernel events vs. log-only vs. combined

## Phase 10 — Analysis & Publication (Future)

Results analysis, dataset release, and dissertation integration.

- Statistical analysis of learning curves across optimizers
- Publication-quality figures via alberta-framework analysis tools
- Public dataset release (anonymized log streams with ground-truth labels)
- Dissertation chapter: security-gym as an Alberta Plan Step 6/8 domain
