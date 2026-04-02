# TODO

Current action items for security-gym development.

## Phase 5 — Data Collection ✅

- [x] Run SSH brute force campaign against Isildur (`campaigns/ssh_brute_only.yaml`)
- [x] Run Log4Shell campaign against Isildur (`campaigns/log4shell_only.yaml`)
- [x] Run recon (SYN scan) campaign against Isildur (`campaigns/recon_only.yaml`)
- [x] Run combined multi-phase campaign (`campaigns/recon_ssh_log4shell.yaml`)
- [x] Collect logs from Isildur via SSH/SFTP (LogCollector)
- [x] Label collected logs with CampaignLabeler (time+IP matching)
- [x] Publish dataset to GitHub Releases and Zenodo (software DOI: 10.5281/zenodo.18810298, dataset DOI: 10.5281/zenodo.18901542)

## Bugs Fixed (2026-02-27)

- [x] Move pyyaml from attacks extra to core dependencies (StreamComposer import)
- [x] Fix BSD syslog timestamp year inference in log collector
- [x] Fix timezone mismatch — collector now auto-detects target UTC offset via `date +%z`
- [x] Fix timezone over-correction for web_access/web_error parsers (only adjust BSD syslog parsers)
- [x] Route Log4Shell campaigns through nginx (:80) instead of direct (:8080)
- [x] Use `sudo -n` for ausearch in campaign configs (prevent paramiko TTY hang)
- [x] Set channel timeout on paramiko stdout/stderr reads

## Phase 5b — New Attack Campaigns ✅

- [x] Set password for researcher account on Isildur for post-auth module
- [x] Run credential stuffing campaign: 361 events (197 malicious)
- [x] Run post-auth execution campaign: 591 events (237 malicious)
- [x] Run full kill chain campaign: 1,156 events (562 malicious)
- [x] Import benign logs from 3 servers into `data/benign.db` (1.45M events)
- [x] Scrub identifying hostnames/domains/emails from benign.db and campaigns.db
- [x] Fix composition config DB paths (relative to config parent dir: `../data/`)
- [x] Add 365-day realistic internet-facing server composition config
- [x] Re-compose all experiment streams with new attack types and scrubbed data

## Phase 9 — eBPF / v2 Data Collection ✅

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
- [x] Re-compose experiment streams from v2 databases (7d: 26k, 30d: 510k, 90d: 475k, 365d: 1.64M events)

## Examples & Baselines ✅

- [x] Create `examples/random_agent.py` — random policy baseline (performance floor)
- [x] Create `examples/threshold_agent.py` — rule-based fail2ban-style heuristic agent
- [x] Create `examples/streaming_demo.py` — SecurityGymStream usage (batch, iter, gym modes)
- [x] Create `examples/benchmark.py` — runs all baselines and prints comparison table
- [x] Add baselines section to README with metrics table
- [ ] Run benchmarks on v4 streams and fill in exact numbers in README

## Phase 6 — Experiments (Ready)

v4 experiment streams ready. rlsecd has `--gym <db>` mode validated on v2 streams.

- [ ] Run rlsecd on v4 streams (exp_7d_brute_v4.db, exp_30d_heavy_v4.db) — validate eBPF-heavy data
- [ ] Benchmark v1 (text) vs v2 (hybrid) env on exp_7d_brute_v4.db with rlsecd
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

## Phase 10 — Benign Data Rebuild (v3)

- [x] Create `scripts/build_benign.py` (renamed from `build_benign.py`) — generic build tool for any server log tarballs
- [x] Malicious traffic filtering (SSH brute force, scanner probes, SQLi/XSS/JNDI, exploit paths)
- [x] PII scrubbing — case-insensitive replacements, all sources mapped to campaign target (`isildur` / `192.168.2.201`), domains → `.internal` TLD
- [x] Update composition configs (`benign_v2.db` → `benign_v3.db`)
- [x] RFI attack filter (`auto_prepend_file`, `auto_append_file`, `allow_url_include`)
- [x] Temporal sort stage — re-orders events by timestamp after multi-server merge (eliminates temporal order violations)
- [x] Run build from 4 servers (can, dallas, isildur, sak): 7,915,858 events (4.96 GB), all checks PASS
- [x] Re-compose experiment streams from benign_v3.db + campaigns_v2.db (4 streams, all validated PASS)
- [x] Publish v3 dataset to Zenodo (DOI: 10.5281/zenodo.18901542)
- [x] Update README / CITATION.cff with new DOI

## Phase 9b — Redis CVE-2022-0543

- [x] Create `redis_lua_escape` attack module (3-stage: enum, exploit, post-exploit)
- [x] Implement RESP protocol helpers (raw TCP, no new deps)
- [x] Add 6 command profiles (system_info, user_enum, network_enum, redis_enum, persistence, full_recon)
- [x] Create `campaigns/redis_exploit_only.yaml` (standalone campaign)
- [x] Create `campaigns/redis_killchain.yaml` (recon → Redis → SSH pivot)
- [x] Add tests (registration, RESP encoding, profiles, dry-run, mocked execute, YAML loading)
- [x] Update `scripts/run_all_campaigns.sh` (7 → 9 campaigns)
- [x] Document Redis setup in `server/BUILD.md`
- [x] Install Redis on Isildur (apt install, bind 0.0.0.0, protected-mode no)
- [x] Create ISILDUR_READY_V3 snapshot on Frodo
- [x] Run `redis_exploit_only` and `redis_killchain` campaigns — campaigns_v2.db now 60,468 events (30,436 malicious)
- [x] Labels validated: 5 PASS, 1 SKIP, 3 FAIL (all pre-existing/expected)
- [x] Update campaign YAML interfaces from `en0` (macOS) to `enp3s0` (Hopper/Linux)
- [x] Re-compose experiment streams with Redis attack data — done in Phase 10 (Redis campaigns in campaigns_v2.db labeled as web_exploit/execution/discovery)

## Phase 9c — Multi-Server Benign eBPF Collection

24-hour collection complete on all 3 servers (2026-03-22). benign_v4.db built, experiment streams composed and validated.

- [x] `collect_ebpf_baseline.py` — standalone DB support (no `--source` required), `--ssh-port` param
- [x] `build_benign.py` — `MaliciousFilter` IP accumulation from filtered auth/web events
- [x] `build_benign.py` — eBPF network event filtering by malicious IP during carryover
- [x] `build_benign.py` — multiple `--ebpf-source` support (`action="append"`)
- [x] `build_benign.py` — `ebpf_events_filtered` in build report
- [x] Tests: 13 new (IP tracking, carryover filtering, multiple sources, fresh DB)
- [x] `server/BUILD.md` — Debian 13 eBPF setup documentation
- [x] Install BCC on 9600baud, hopper, frodo (Debian 13.4, `apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)`)
- [x] Configure sudoers on each server (`/etc/sudoers.d/ebpf_collector`)
- [x] Smoke test collector on each server (deploy via scp, 10s run)
- [x] Run 24-hour collection on all 3 servers — 3,243,383 total eBPF events
  - frodo: 2,355,832 events (`data/ebpf_frodo.db`)
  - 9600baud: 785,473 events (`data/ebpf_9600baud.db`)
  - hopper: 102,078 events (`data/ebpf_hopper.db`)
- [x] Rename `build_benign_v3.py` → `build_benign.py` (version-agnostic), add `--base-db` mode
- [x] Build benign_v4.db: 11,159,241 events (7.9M logs + 3.24M eBPF), all checks PASS
- [x] Compose and validate all 4 v4 experiment streams (4.9M / 21.5M / 63.2M / 257.7M events)
- [x] Update CLAUDE.md data versions with new eBPF event counts
- [ ] Publish v4 dataset to Zenodo (new version of DOI 10.5281/zenodo.18901542): benign_v4.db.zst, campaigns_v2.db.zst, 4 v4 experiment streams, DATASET_README.md
- [ ] Update CITATION.cff and CLAUDE.md with new Zenodo version DOI

## Phase 13a — Structured eBPF Observation Channels

Convert eBPF text channels to fixed-width numeric arrays. See ROADMAP.md Phase 13 for full design.

Phase 13a implementation complete (see ROADMAP.md).

## Phase 13b — eBPF LSM Hooks

Add BPF LSM security decision signals. Requires kernel config on Isildur.

- [ ] SSH to Isildur: `cat /boot/config-$(uname -r) | grep BPF_LSM` — check if BPF LSM is compiled in
- [ ] If disabled: add `lsm=lockdown,yama,bpf` to GRUB cmdline, reboot, verify with `cat /sys/kernel/security/lsm`
- [ ] Create ISILDUR_READY_V4 snapshot on Frodo
- [ ] Add P0 LSM hooks to `server/ebpf_collector.py`: `bprm_check_security`, `file_open`, `socket_connect`
- [ ] Add `lsm_event_t` C struct and `BPF_LSM` program string
- [ ] Add `_on_lsm` callback and LSM event formatter (structured output, not text)
- [ ] Create `src/security_gym/parsers/ebpf_lsm.py` parser
- [ ] Add `ebpf_lsm` source type to EventStore
- [ ] Add `lsm_events` structured channel to v2 env
- [ ] Re-run campaigns with LSM collection → campaigns_v3.db
- [ ] Collect 24h benign LSM baseline
- [ ] Add P1 hooks: `ptrace_access_check`, `capable`
- [ ] Enforcement map prototype: `BPF_HASH(blocked_pids)` readable by LSM hooks, writable from userspace
- [ ] Tests: LSM obs space, hook enum, enforcement map

## Housekeeping

- [x] Add campaign YAML files for Log4Shell and recon-only scenarios
- [x] Comprehensive README with quick start, feature docs, dataset download
- [x] `security-gym` CLI for dataset download from GitHub Releases
- [x] Zenodo DOI badge and archive
- [x] Code quality pass — ruff auto-fixes (unused imports, f-string), mypy type annotations (scan_stream buffers, collect_numpy return type, float cast in reward), all zero errors
- [x] Update default `db_path` fallback in `attacks/config.py` from `campaigns.db` to `campaigns_v2.db`
- [ ] Document dataset schema and labeling methodology
