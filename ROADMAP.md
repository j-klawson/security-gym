# security-gym Roadmap

Phased development plan for the security-gym Gymnasium environment.

## Phase 1 — Foundation ✅

Package skeleton, data layer, auth_log parser, event/hashed feature extractors, target builder, SecurityLogStreamEnv. 58 tests passing, `gymnasium.utils.check_env` passes.

## Phase 2 — Alberta Integration ✅

`SecurityGymStream` adapter (`adapters/scan_stream.py`), GitHub Actions CI (test + lint + security). 86 tests passing.

## Phase 3 — Parsers + Wrappers ✅

syslog, web_access, web_error, journal parsers; SessionFeatureExtractor (20-dim); HashedFeatureWrapper, SessionAggregationWrapper, WindowedWrapper, DecayingTraceWrapper; enriched env info dict (event_type, src_ip, username). 172 tests passing.

## Phase 4 — Attack Scripts ✅

YAML-driven campaign framework, MITRE ATT&CK-aligned phases, AttackModuleRegistry (recon/ssh_brute_force/log4shell), non-stationary timing profiles, IPManager (spoofed + aliased), LogCollector (SSH/SFTP), CampaignLabeler (time+IP matching), auditd parser, CampaignOrchestrator, CLI (`python -m attacks`). 49 tests passing.

## Phase 5 — Data Collection ✅

Generate labeled attack datasets by running campaigns against the Isildur VM.

- Isildur VM fully configured (researcher user, SSH key auth, NOPASSWD sudo for ausearch)
- PasswordAuthentication enabled for brute force module
- Docker stack deployed (Log4Shell on :8080, Nginx reverse proxy on :80)
- All log sources verified readable (auth_log, syslog, nginx access/error, journal)
- LogCollector auto-detects target timezone via SSH (`date +%z`), corrects BSD syslog timestamps
- SSH brute force campaign: 1,124 events (230 malicious, 894 benign)
- Log4Shell campaign: 169 events (151 malicious, 18 benign)
- Recon SYN scan campaign: 712 events (19 malicious, 693 benign)
- Combined 3-phase campaign (recon → SSH → Log4Shell): 1,029 events (868 malicious, 161 benign)
- Dataset published to GitHub Releases (`data-v1`) and Zenodo (DOI: 10.5281/zenodo.18810299)
- `security-gym` CLI for dataset download (`security-gym download`, `security-gym list`)

## Phase 6 — Experiments (Future)

Connect security-gym to alberta-framework and run continual learning experiments.

- Feed SecurityGymStream into MultiHeadMLPLearner
- Compare IDBD / Autostep / LMS optimizers on security log data
- Evaluate session vs. event vs. hashed feature representations
- Benchmark against chronos-sec honeypot results
- Non-stationarity analysis (concept drift across campaign phases)

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
