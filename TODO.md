# TODO

Current action items for security-gym development.

## Phase 5 — Data Collection

- [ ] Run SSH brute force campaign against Isildur (`campaigns/ssh_brute_only.yaml`)
- [ ] Run Log4Shell campaign against Isildur
- [ ] Run recon (SYN scan) campaign against Isildur
- [ ] Run combined multi-phase campaign
- [ ] Collect logs from Isildur via SSH/SFTP (LogCollector)
- [ ] Label collected logs with CampaignLabeler (time+IP matching)
- [ ] Validate labeled data in EventStore — spot-check label accuracy
- [ ] Verify auditd ground truth matches campaign execution windows
- [ ] Publish dataset to `data/` (or external host)

## Phase 6 — Experiments

- [ ] Wire SecurityGymStream into alberta-framework's `run_multi_head_learning_loop()`
- [ ] Run baseline experiment: LMS on event features (24-dim)
- [ ] Run IDBD and Autostep comparisons
- [ ] Compare feature representations (event vs. hashed vs. session)
- [ ] Evaluate wrapper combinations (Windowed, DecayingTrace)

## Housekeeping

- [x] Add campaign YAML files for Log4Shell and recon-only scenarios
- [ ] Document dataset schema and labeling methodology
