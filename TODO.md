# TODO

Current action items for security-gym development.

## Phase 5 — Data Collection

- [x] Run SSH brute force campaign against Isildur (`campaigns/ssh_brute_only.yaml`)
- [x] Run Log4Shell campaign against Isildur (`campaigns/log4shell_only.yaml`)
- [x] Run recon (SYN scan) campaign against Isildur (`campaigns/recon_only.yaml`)
- [x] Run combined multi-phase campaign (`campaigns/recon_ssh_log4shell.yaml`)
- [x] Collect logs from Isildur via SSH/SFTP (LogCollector)
- [x] Label collected logs with CampaignLabeler (time+IP matching)
- [ ] Validate labeled data in EventStore — spot-check label accuracy
- [ ] Verify auditd ground truth matches campaign execution windows (auditd currently timing out via paramiko)
- [x] Publish dataset to GitHub Releases and Zenodo (DOI: 10.5281/zenodo.18810299)

## Bugs Fixed (2026-02-27)

- [x] Move pyyaml from attacks extra to core dependencies (StreamComposer import)
- [x] Fix BSD syslog timestamp year inference in log collector
- [x] Fix timezone mismatch — collector now auto-detects target UTC offset via `date +%z`
- [x] Fix timezone over-correction for web_access/web_error parsers (only adjust BSD syslog parsers)
- [x] Route Log4Shell campaigns through nginx (:80) instead of direct (:8080)
- [x] Use `sudo -n` for ausearch in campaign configs (prevent paramiko TTY hang)
- [x] Set channel timeout on paramiko stdout/stderr reads

## Phase 5b — New Attack Campaigns

- [x] Set password for researcher account on Isildur for post-auth module
- [x] Run credential stuffing campaign: 361 events (197 malicious)
- [x] Run post-auth execution campaign: 591 events (237 malicious)
- [x] Run full kill chain campaign: 1,156 events (562 malicious)
- [x] Import benign logs from 3 servers into `data/benign.db` (1.45M events)
- [x] Scrub identifying hostnames/domains/emails from benign.db and campaigns.db
- [x] Fix composition config DB paths (relative to config parent dir: `../data/`)
- [x] Add 365-day realistic internet-facing server composition config
- [x] Re-compose all experiment streams with new attack types and scrubbed data
- [ ] Publish updated dataset to GitHub Releases (v0.2.0-data: campaigns.db + benign.db)

## Phase 9 — eBPF / v2 Data Collection

- [x] Fix eBPF labeling bug — route kernel events through CampaignLabeler instead of hardcoded benign
- [x] Add `ebpf: {enabled: true, baseline_seconds: 30}` to all 7 campaign YAMLs
- [x] Update campaign YAMLs to write to `data/campaigns_v2.db`
- [x] Update all 4 composition configs to read from `benign_v2.db` and `campaigns_v2.db`
- [x] Document BCC install, sudoers, and V2 snapshot in `server/BUILD.md`
- [x] Create `scripts/collect_ebpf_baseline.py` for benign eBPF baseline collection
- [x] Install BCC on Isildur (manual .deb install — `bpfcc-tools`, `python3-bpfcc`, `linux-headers-5.10.0-38-amd64`)
- [x] Add sudoers rules for researcher (eBPF collector + pkill)
- [x] Fix eBPF collector BPF compilation for Debian 11 / kernel 5.10 (added kernel includes, `bpf_probe_read_kernel`)
- [x] Enrich eBPF events: PPID + parent_comm on process events, UID on network events
- [x] Fix orchestrator: Ed25519 key, sudo/nohup ordering, pkill path, SSH transport keepalive
- [x] Collect benign eBPF baseline (997 events → benign_v2.db, now 1,446,555 total events)
- [x] Add `scripts/insert_ebpf_baseline.py` for manual eBPF baseline insertion
- [x] Add `scripts/run_all_campaigns.sh` for running all 7 campaigns sequentially
- [x] Re-run all 7 campaigns with eBPF — 48,520 events (24,774 malicious, 23,746 benign) across 8 campaign IDs
  - ebpf_file: 35,722 | journal: 9,689 | ebpf_network: 1,292 | ebpf_process: 1,014 | auth_log: 357 | web_access: 350 | syslog: 96
  - Attack types: brute_force (12,992), credential_stuffing (5,722), execution (5,276), web_exploit (694), discovery (90)
- [x] Validate v2 labels — 5 PASS, 1 SKIP, 3 FAIL (all known/expected)
- [x] Fix label validator check 5 crash — `collect_numpy` returns list of dicts, not numpy array; rewrote to use ground truth dict fields
- [ ] Create ISILDUR_READY_V2 snapshot on Frodo
- [x] Re-compose experiment streams from v2 databases (7d: 26k, 30d: 510k, 90d: 475k, 365d: 1.64M events)
- [ ] Publish v2 dataset to GitHub Releases

## Phase 6 — Experiments (Ready)

v2 experiment streams ready. chronos-sec v1 API migration complete (MultiChannelTextEncoder, GymRLAgent, gym_replication 48 conditions, gym_rl 6 conditions).

- [ ] Wire SecurityGymStream into alberta-framework's `run_multi_head_learning_loop()`
- [ ] Run baseline experiment: LMS on event features (24-dim)
- [ ] Run IDBD and Autostep comparisons
- [ ] Compare feature representations (event vs. hashed vs. session)
- [ ] Evaluate wrapper combinations (Windowed, DecayingTrace)
- [ ] Kill chain experiment: measure cross-phase predictive relationships

## Phase 7 — Streaming Server (Future)

- [ ] Design network protocol for stream serving (gRPC vs WebSocket)
- [ ] Add authentication and rate limiting
- [ ] Support multiple concurrent consumers on a single composed stream

## PyPI Publication ✅

- [x] Add `src/security_gym/py.typed` marker (PEP 561)
- [x] Delete stale `dist/` (v0.1.0 artifacts)
- [x] Create `.github/workflows/publish.yml` (OIDC trusted publishing: build → TestPyPI → PyPI on `v*` tags)
- [x] Configure GitHub environments (`testpypi`, `pypi`) with trusted publishers
- [x] Test publish to TestPyPI (v0.3.0)
- [x] Publish v0.3.1 to PyPI — https://pypi.org/project/security-gym/
- [x] Add PyPI badge to README

## Bugs Fixed (2026-03-04)

- [x] Fix event_type lost during EventStore serialization — auth_log parser now stores `event_type` in `fields` dict (was the only parser missing it)
- [x] EventStore safety net — `insert_event()` and `bulk_insert()` inject `event_type` into parsed JSON if parser omitted it
- [x] Enrich PAM session open/close events — auth_log parser now caches PID→(src_ip, session_id) from auth events to fill in missing IP/session_id on session events (185 events in exp_365d_realistic.db affected)
- [x] Re-compose experiment streams to pick up event_type and session enrichment fixes (existing v2 DBs retain old parsed JSON)
- [ ] Re-run campaigns to regenerate campaigns_v2.db with enriched session events (optional — only needed if downstream consumers read from campaigns_v2.db directly)

## Phase 10 — Benign Data Rebuild (v3)

- [x] Create `scripts/build_benign_v3.py` — generic build tool for any server log tarballs
- [x] Malicious traffic filtering (SSH brute force, scanner probes, SQLi/XSS/JNDI, exploit paths)
- [x] PII scrubbing — case-insensitive replacements, all sources mapped to campaign target (`isildur` / `192.168.2.201`), domains → `.internal` TLD
- [x] Update composition configs (`benign_v2.db` → `benign_v3.db`)
- [x] RFI attack filter (`auto_prepend_file`, `auto_append_file`, `allow_url_include`)
- [x] Temporal sort stage — re-orders events by timestamp after multi-server merge (eliminates temporal order violations)
- [x] Run build from 4 servers (can, dallas, isildur, sak): 7,915,858 events (4.96 GB), all checks PASS
- [x] Re-compose experiment streams from benign_v3.db + campaigns_v2.db (4 streams, all validated PASS)
- [ ] Publish v3 dataset to Zenodo (new DOI)
- [ ] Update README / CITATION.cff with new DOI

## Housekeeping

- [x] Add campaign YAML files for Log4Shell and recon-only scenarios
- [x] Comprehensive README with quick start, feature docs, dataset download
- [x] `security-gym` CLI for dataset download from GitHub Releases
- [x] Zenodo DOI badge and archive
- [x] Code quality pass — ruff auto-fixes (unused imports, f-string), mypy type annotations (scan_stream buffers, collect_numpy return type, float cast in reward), all zero errors
- [x] Update default `db_path` fallback in `attacks/config.py` from `campaigns.db` to `campaigns_v2.db`
- [ ] Document dataset schema and labeling methodology
- [ ] Investigate auditd timeout through paramiko (2-minute hang on `ausearch --raw`)
