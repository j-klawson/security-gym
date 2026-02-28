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

- [ ] Set password for researcher account on Isildur (or create test user) for post-auth module
- [ ] Run credential stuffing campaign (`campaigns/credential_stuffing_only.yaml`)
- [ ] Run post-auth execution campaign (`campaigns/post_auth_only.yaml`)
- [ ] Run full kill chain campaign (`campaigns/full_killchain.yaml`)
- [ ] Re-compose experiment streams with new attack types (credential_stuffing + execution data)

## Phase 6 — Experiments

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

## Housekeeping

- [x] Add campaign YAML files for Log4Shell and recon-only scenarios
- [x] Comprehensive README with quick start, feature docs, dataset download
- [x] `security-gym` CLI for dataset download from GitHub Releases
- [x] Zenodo DOI badge and archive
- [ ] Document dataset schema and labeling methodology
- [ ] Investigate auditd timeout through paramiko (2-minute hang on `ausearch --raw`)
