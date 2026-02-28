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

## Phase 9 — Kernel Event Telemetry (Future)

Hook the RL agent directly into the Linux kernel for real-time observation of system-level events. Moves beyond log parsing to native kernel telemetry — the agent observes syscalls, process creation, file access, and network connections as they happen. This is the path toward an agent that can detect and respond to threats at the OS level rather than after the fact in log files.

- eBPF-based event collection (syscalls, process exec, file open, network connect)
- Kernel event parser and feature extractor
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
