# TODO

Current action items for security-gym development.

## CI Lint Failure — Ruff Rule-Set Drift ✅ (2026-08-08)

The `lint` job failed on all seven pushes from 2026-07-26 onward (188 errors) while `test` and `security` passed. Cause: no rule selection declared in `pyproject.toml` plus an unbounded `ruff>=0.4.0` dev pin, so CI picked up ruff 0.16.1, which widened the implicit default rule set. Fix is configuration-only; no source changed. Detail in ROADMAP.md "CI Correction — Ruff Default Rule-Set Drift".

- [x] Reproduce under the CI ruff version (0.16.1) and confirm `--select E4,E7,E9,F` is clean, isolating drift from regression
- [x] Declare `[tool.ruff.lint] select = ["E4", "E7", "E9", "F"]` explicitly in `pyproject.toml`
- [x] Bound the dev pin to `ruff>=0.16.1,<0.17`; upgrade the local venv (0.15.4 → 0.16.2) so local matches CI
- [x] Verify clean under both 0.16.1 and 0.16.2
- [ ] Decide whether to adopt the `I` and `UP` rule families (94 findings, all safe-autofixable; `UP017` `timezone.utc` → `datetime.UTC` accounts for 67). `BLE001` and `RUF059` are not recommended: they flag the intentional broad excepts in the attack modules and unused tuple unpacking in tests
- [ ] Housekeeping unrelated to this fix: the working tree carries deletions of `data/build_benign_report.json` and the two `data/provenance/` C11 artifacts, plus an untracked `data.old/`. Decide whether the deletions are intended before they are swept into an unrelated commit

## V4 Published-Archive Remediation (2026-07-26)

Read-only validation on hopper (report: `data/provenance/V4_ARCHIVE_STALENESS_20260726.md`, commit 842a3c3) proved the 7d/30d/90d stream archives published to Zenodo 10.5281/zenodo.19482383 and HuggingFace `j-klawson/security-gym-v4` are stale morning-of-2026-03-22 compositions (140,315 / 1,103,255 / 1,996,031 events versus the live 4,891,541 / 21,511,208 / 63,212,997). The 365d archive is very likely genuine. Live DBs are correct. Remediation executed 2026-07-26 (report Section 9): all three archives regenerated from the live DBs with `zstd -T0 -19 --long=27` and round-trip verified (decompress-and-count, exact match); published `benign_v4.db.zst`/`campaigns_v2.db.zst` downloaded from Zenodo, MD5-matched, content-verified, and retained in `data/`; `croissant.json` now carries real checksums for all six entries.

- [x] Validate the staleness claim end-to-end on local disk (hashes vs Zenodo MD5 + HF LFS SHA-256; decompress-and-count vs live DBs; filesystem timeline)
- [x] Recompress 7d/30d/90d archives from the live v4 DBs; verify each by decompress-and-count (expect 4,891,541 / 21,511,208 / 63,212,997 events) before upload (2026-07-26; fresh sizes 163,895,433 / 719,156,975 / 2,122,545,681 bytes; hashes in provenance report Section 9.1)
- [x] Publish corrected dataset version under concept DOI 10.5281/zenodo.18901541 (the 18901627 DOI in earlier notes was wrong — it was the software v0.3.3 record, see CHANGELOG). Published 2026-08-03 as version 4.1, DOI 10.5281/zenodo.21763493, superseding 19482383. Draft assembled 2026-08-02: five archives + DATASET_README uploaded and MD5-verified against the manifest, description with version note, keywords (with `cybersecurity` typo fixed from the 4.0 record), related works incl. `Obsoletes -> 19482383`. Steps (web UI):
  - [x] Open record 19482383 → "New version" (draft created 2026-08-02)
  - [x] Remove all files carried over from 19482383 (decision 2026-08-02: re-upload all six archives fresh from `data/` on hopper rather than carry any over, as an end-to-end identity check; draft file list confirmed to contain fresh uploads only)
  - [x] Fresh 365d recompress complete and verified (2026-08-02): `zstd -T0 -19 --long=27` from the live DB, then streaming byte-identity (`zstd -d -c | cmp`) against the live DB — BYTE-IDENTICAL (live DB count-verified at 257,654,256 events, so the archive is verified by construction). Fresh archive: 8,667,436,107 B, MD5 `493fb4d1254b4aedf39450205a09631e`, SHA-256 `6cbc777304c5c79a78dd4959228a7d46a258a966d820b73dccf8af9f3f47fd42`. The MD5 does not match the published `1392292d...` (13.68 GB vs 8.67 GB — the original was compressed with different settings), so the determinism check is inconclusive and the superseded 19482383 copy keeps its "very likely genuine" status. croissant.json and DATASET_README.md updated to the fresh size/hashes
  - [ ] Upload all six archives plus the updated `DATASET_README.md` (corrected sizes and `exp_90d` name). Zenodo must display exactly (local MD5s re-confirmed 2026-08-02; any mismatch → do not publish): `exp_7d_brute_v4.db.zst` `338a73eced346420ceea1eab9b3cce94` (163,895,433 B); `exp_30d_heavy_v4.db.zst` `0494284aec6f3f7b3440e3a39ae13b1d` (719,156,975 B); `exp_90d_v4.db.zst` `61c9df3a3ea29f3c96a30e805f063e16` (2,122,545,681 B); `exp_365d_realistic_v4.db.zst` `493fb4d1254b4aedf39450205a09631e` (8,667,436,107 B); `benign_v4.db.zst` `97d9078a84850b1f7dcd86311c21fd43` (454,519,591 B, must equal the 19482383 deposit MD5); `campaigns_v2.db.zst` `cf5cda14876b2c8a16258a1afd62c2c6` (4,392,329 B, must equal the 19482383 deposit MD5). Status 2026-08-02: five of six archives plus `DATASET_README.md` (md5 `06217626bd9442d8ed39b83c2012dc37`, matches commit f578085 copy) uploaded; all displayed MD5s verified against this manifest; 365d verified and ready to upload. NOTE: the uploaded `DATASET_README.md` predates the fresh 365d size fix (12.7 GB → 8.1 GB) — replace it in the draft with the updated copy (md5 `7c75092f847c06e7ddef1f73f4c36252`) before publishing
  - [x] Naming decision resolved 2026-08-02: publish under `exp_90d_v4.db.zst`. Local files renamed `exp01_` → `exp_` (bytes/MD5 unchanged); HF mirror file renamed via server-side LFS copy (commit c301d90b, API-verified sha256 `0749e549...` and size match); `data/croissant.json` (`@id`, `name`, `contentUrl`) and `data/DATASET_README.md` updated and uploaded to HF in the same commit. The old `exp01_90d_v4.db.zst` name survives only in the superseded Zenodo record 19482383 and historical records (provenance report, run logs)
  - [x] In the version description, note that this version corrects the stale 7d/30d/90d archives of 19482383 (2026-08-02: corrected description with version note, event counts, `exp_90d_v4.db.zst` filename, and provenance-report pointer added to the draft)
  - [x] Publish; record the new version DOI in TODO.md, CLAUDE.md, and ROADMAP.md (2026-08-03: live at https://zenodo.org/records/21763493; all seven server-side MD5s verified against the manifest; concept-DOI redirect to the new record verified)
- [x] Update version-DOI references to 21763493 (2026-08-03): `data/croissant.json` (citeAs incl. version 4.1, sameAs, three contentUrls, maintenance plan, both `version` fields), `data/DATASET_README.md` (citation block and concept-DOI line), README.md (stale concept DOI 18901627 → 18901541; mirror/deposit sizes corrected to 2.8 GB / 11.3 GB); revised `croissant.json` and dataset card re-uploaded to HuggingFace (commit ed46e035). Verified no-ops: CITATION.cff cites only the software DOI; neither paper draft references a Zenodo DOI. Deposit-internal caveat: the published DATASET_README.md BibTeX still cites 19482383/version 4.0 (uploaded before the DOI update); correct it in the next version's file set
- [x] Replace the three stale LFS objects in HuggingFace `j-klawson/security-gym-v4`; upload corrected `croissant.json` and dataset card README (2026-07-26, HF commit fd4bcfb6; API-verified LFS sha256 match for all three archives)
- [x] Verify the corrected release's 365d stream at content level (2026-08-02: fresh recompress is byte-identical to the count-verified live DB — see the sub-item above). The superseded 19482383 copy itself remains "very likely genuine" but content-unverified; confirming it would require downloading its 13.68 GB archive from Zenodo for a decompress-and-count, relevant only to the downstream-consumer audit
- [x] Hash-verify `benign_v4.db.zst` and `campaigns_v2.db.zst` against the published deposit when assembling the corrected release (2026-07-26: downloaded from Zenodo, MD5 match, decompress-and-count match — 11,159,241 / 60,468 events; verified copies kept in `data/`)
- [x] Fill the six `"sha256": "TBD"` placeholders in `data/croissant.json` from the regenerated archives (2026-07-26; also corrected `contentSize` for the three regenerated entries)
- [ ] Audit downstream consumers of the published 7d/30d/90d archives (they received 3–5% of the intended streams)

## Companion-Paper Citation Correction ✅ (2026-08-08)

The HuggingFace card cited the companion paper as "NeurIPS 2026 Evaluations & Datasets Track"; that submission was withdrawn. The paper was accepted at the Continual Reinforcement Learning Workshop at RLC 2026 (Montreal, 2026-08-15), which is non-archival — no proceedings, no DOI, and therefore not citable as a conference publication.

- [x] Audit every published surface for the withdrawn attribution. Found only in the hub card; the Zenodo 4.1 record description and related identifiers, `croissant.json` (hub and local), `data/DATASET_README.md`, `README.md`, and `CITATION.cff` were all checked and clean
- [x] Correct the card: Lawson and Malik byline, workshop venue and date, OpenReview PDF link, explicit non-archival statement, dataset citations redirected to the v4.1 DOI (HF commit c0b9543b). Dropped the "Section 6.1 of the companion paper" pointer, unverifiable against the camera-ready
- [x] Remove the `paperswithcode_id: security-gym` frontmatter field (HF commit c8916bad); Papers With Code is retired and the slug resolves to nothing. Absence verified in both the raw card and the hub API `cardData`
- [x] Track the card in-repo at `data/HF_DATASET_CARD.md` (commit bea63f5) so the hub copy stops being the only copy. Workflow: edit that file, upload as `README.md` via `huggingface_hub`
- [ ] Deposit the camera-ready PDF somewhere under project control (GitHub repo or the Zenodo software record) and link it from the card as a fallback. OpenReview note IDs are stable, but post-event reader visibility is a venue setting; the non-archival status preserves the right to self-host. Blocked locally: OpenReview serves a bot challenge to non-browser clients (API and direct PDF both 403), so the file must be downloaded manually
- [ ] Decide whether the workshop paper warrants an arXiv preprint for a durable, indexable copy

## Phase 14 — eBPF Benign-Data Validity (BLOCKED, 2026-06-05)

**STATUS: BLOCKED.** A separate bug (found 2026-06-05) must be fixed before this work resumes. The bug was not yet described in session; record its specifics here once provided. [TODO: detail the gating bug.]

Investigation prompted by the question of whether an RL agent can learn from eBPF events. The current benign-eBPF pipeline does not support this as intended. Three distinct defects were identified with code evidence. Log-only results (session F1 0.979) are not implicated; the exposure is specific to the eBPF ablation that anchors the kernel-telemetry contribution (Exp 13: 60% MAE reduction, Cohen's d=2.577).

Defects:

1. Sessionization asymmetry (label leakage). The eBPF parser emits no `session_id` (`src/security_gym/parsers/ebpf.py:91`; defaults to `None` via `parsers/base.py:24`). The composer fabricates a session only for attack events: `_enrich_ebpf_fields` assigns `f"{dominant_ip}:ebpf_{cid}"` to eBPF events that share a campaign with log events (`src/security_gym/data/composer.py:226-237`). Benign eBPF stays NULL. Process and file events carry no `src_ip` (only network events derive one, `parsers/ebpf.py:82-89`), so under the documented fallback NULL to src_ip to "unknown" (`features/session.py:118-123`) the entire benign process/file stream collapses into one pseudo-session, while each attack burst gets a per-campaign session tagged with the attacker IP. Session-level scorers (rlsecd session EMA) can separate the two on key structure alone.

   Measured 2026-08-07 (full-table scans of the live v4 DBs on hopper), the consequence is broader than session-level scoring: the fabricated `session_id` decides which events reach the learner at all. rlsecd steps `predict`/`update` only on session-mapped events (`tracking/session_tracker.py:60-62`, `daemon.py:234-236`, `experiments/experiment15.py:181-187`), so this column is the learning schedule. Every `ebpf_file` and `ebpf_process` event that passes that gate is malicious, in both streams without exception: 7d 23,976 file + 613 process, 30d 499,084 file + 16,841 process, all `is_malicious=1`. Benign file and process events never pass, having neither `session_id` nor `src_ip`. `ebpf_network` is the control case: it derives a real `src_ip`, so its benign events do pass (364,000 of 374,261 in the 30d). In `exp_30d_heavy_v4.db`, 9 synthetic `{ip}:ebpf_{cid}` sessions, out of 14,248 distinct session IDs, carry 526,186 events, 37.6% of the 1,398,498 events that reach the learner, and the malicious share of learner steps is 38.4% against a 2.83% (609,520 / 21,511,208) stream base rate. Gate-passing totals: 1,398,498 of 21,511,208 (6.50%) for the 30d, 225,114 of 4,891,541 (4.60%) for the 7d. Cross-referenced in rlsecd `TODO.md`, "Learner Cadence vs eBPF Resolution".

2. Cross-server ancestry breakage. `scripts/build_benign.py` carries `pid`/`ppid` verbatim from frodo, hopper, and 9600baud into one table without namespacing. Raw `pid`/`ppid` feed the observation (`envs/ebpf_encoding.py:120-121`); `tree_depth` is computed from a single `_pid_depth` dict keyed on raw pid (`envs/log_stream_env_hybrid.py:167-170`), so cross-server PID collisions corrupt the one ancestry feature for benign events while attack campaigns (single-host Isildur) retain valid chains. Any "ancestry helps" effect is confounded with host-of-origin.

3. Distributional realism. Three heterogeneous hosts stacked and timestamp-cycled (`composer._cycle_source`) do not reproduce any single host's kernel-event distribution; the benign baseline is a statistical chimera.

Two further defects were found 2026-08-09 while auditing the `campaigns_v2.db` label split. Both are in the collector, not the composer, so they are present in every eBPF collection to date (Isildur campaigns and the frodo/9600baud/hopper baselines alike) and would be reproduced by a re-collection running the current daemon.

4. Byte-reversed IPv4 addresses on `connect` events. `_ip_str` (`server/ebpf_collector.py:226-227`) does `struct.pack("!I", addr)`, but BCC decodes the `u32 daddr` in host byte order, so the network-byte-order address read from `sin->sin_addr` (`:148`) comes out reversed. The port on the same line is correct because it uses the compensating idiom (`struct.unpack("!H", struct.pack("H", event.dport))`, `:300`). Evidence in `campaigns_v2.db`: `connect ... comm=nginx dst=3.0.18.172:8080` is the Log4Shell container at `172.18.0.3` (port correct, address reversed); `113.2.168.192` is `192.168.2.113`. Six of eight distinct connect addresses are reversed; `0.0.0.0` and `8.8.8.8` are invariant under reversal and mask the defect. `parsers/ebpf.py:87-89` derives `src_ip` from this field, so the corruption reaches the column used by time-plus-IP labeling and by the environment's IP-keyed blocklist (`envs/log_stream_env.py:437-449`), meaning a block issued against an IP seen in auth.log cannot match that host's network eBPF events.

5. `accept` events carry no peer address. `sys_enter_accept4` submits `pid`/`uid`/`comm` only and never reads `upeer_sockaddr` (`server/ebpf_collector.py:156-166`); `_on_accept` emits no `dst=` (`:306-312`). At syscall entry the kernel has not yet populated the peer address, so the fix needs an entry/exit probe pair with the pointer stashed in a `BPF_HASH` keyed on `pid_tgid`. Measured in `campaigns_v2.db`: all 619 malicious `ebpf_network` events are `accept` with NULL `src_ip`; all 603 addressed events are `connect` and benign. Inbound connections, the direction carrying attacker identity, are the direction with no address, so every malicious network label rests on time-window matching alone and no IP-keyed block can suppress one. This qualifies the "`ebpf_network` is the control case" statement under defect 1: benign network events do pass the learner gate, but on a byte-reversed address.

Proposed fix and its limits: a single-host collect-with-attacks (e.g., 30 days on Isildur) directly fixes (2) and removes the eBPF-transplant path that manufactures (1)'s artifact. It is a precondition but not sufficient for (1): kernel events still require a defined session (process-tree rooted at the session leader, sshd, or login). It does not address (3) unless the host carries realistic workload; Isildur is a frozen, near-idle Debian 11 VM, so a long idle collection trades the chimera problem for a workload-poverty problem (attacks trivially separable from a near-silent background). Coherence versus workload-realism is the central tension.

Recommended sequencing (diagnose before re-collecting):

- [ ] Namespace eBPF `pid`/`ppid` per source (collection host) so ancestry does not collide across the merge.
- [ ] Replace the synthetic per-campaign eBPF session with a process-tree-rooted session applied symmetrically to benign and attack eBPF. This also removes the label correlation from rlsecd's learner-step schedule, which keys on the same `session_id` (see the measured evidence under defect 1); pairs with the rlsecd-side cadence fix, either alone leaves a defect.
- [ ] Re-run Exp 13 on the corrected corpus and measure how much of the 60% MAE reduction survives. Survival implies the current data is salvageable and re-collection is a realism upgrade; collapse mandates re-collection, and the collapse is itself a finding.

Collector fixes (defects 4 and 5; independent of the re-collection decision, and prerequisites for it):

- [ ] Fix `_ip_str` byte order in `server/ebpf_collector.py` (`struct.pack("<I", addr)` or `socket.inet_ntoa(struct.pack("I", addr))`). Add a unit test with a known non-palindromic address; `8.8.8.8` and `0.0.0.0` are invariant under reversal and will pass either way.
- [ ] Capture the `accept4` peer address: stash `upeer_sockaddr` at `sys_enter_accept4` in a `BPF_HASH` keyed on `pid_tgid`, read it at `sys_exit_accept4`, emit `src=` on the accept line. Extend `parsers/ebpf.py` to populate `src_ip` from it.
- [ ] Redeploy the corrected collector to Isildur and the three baseline hosts; bump the ISILDUR_READY snapshot.
- [ ] Decide the remediation path for existing collections: re-collect, or apply a documented byte-reversal pass to `ebpf_network` `connect` addresses in `campaigns_v2.db` and `benign_v4.db`. A reversal pass cannot recover the missing `accept` addresses, so it is a partial fix and must be disclosed as such if the v4 corpus is retained.
- [ ] Re-check whether any published result or claim depends on `ebpf_network` addresses. The 619 malicious network events are labeled by time window alone, so the labeling is not wrong, but claims about IP-level attribution or blocking efficacy on the network channel are not supported by this data.
- [ ] Assess dataset blast radius: the v4.1 deposit (DOI 10.5281/zenodo.21763493) ships both defects inside the eBPF events. Decide whether this warrants a dataset erratum or a corrected version, and coordinate with the downstream-consumer audit already open under "V4 Published-Archive Remediation".

Open decisions (deferred until the blocker is cleared):

- [ ] Sequencing: diagnose-first, commit to re-collection now, or both in parallel.
- [ ] Target host/workload if re-collecting: Isildur plus synthetic realistic workload (preserves auditd ground truth, vuln services, ISILDUR_READY snapshots), a new dedicated realistic target VM, or (rejected) a real production server (PII plus attacking production).
- [ ] Collection duration and the specific non-stationarity required (diurnal/weekly cycles, Poisson campaign base rate); whether a shorter genuinely-continuous collection plus disclosure suffices.
- [ ] Paper/dataset blast radius: whether this supersedes the v4 streams and Zenodo version (now v4.1, DOI 10.5281/zenodo.21763493). The NeurIPS submission that previously set this deadline was withdrawn; the companion paper is now the non-archival RLC 2026 workshop paper, so no proceedings deadline gates this work. Any future archival submission would re-impose one.

## Block recovery — `block_visibility` + `block_ttl` ✅ (v0.5.0, 2026-06-06)

Fixed the block→unblock catch-22 in `SecurityLogStreamEnv`: a blocked IP's events were dropped 100% and never re-surfaced, while `unblock` only targets the current event's `src_ip`, so an `unblock` on a blocked IP was unreachable.

- [x] `block_visibility="deny_log"` (opt-in; default `"drop"`): surface blocked events as ground-truth-blind `"[FIREWALL DENY] "` lines so `unblock` becomes reachable; no `is_malicious` leak into the observation.
- [x] `block_ttl` (opt-in; default `None`): fail2ban-style auto-expiry; composes with `deny_log`.
- [x] Reward double-count avoidance (denied steps contribute consequence only; action/risk zeroed); byte-for-byte backward compatibility under defaults.
- [x] 11 new tests (deny_log loop, unblock-during-attack, GT-blind render, TTL resurface/reblock/compose, drop-mode byte-identical + permanent-block, hybrid mirrors); ruff/mypy/bandit clean.
- Note: this resolves a block-behaviour observability defect. If it is the bug referenced as gating Phase 14 (2026-06-05), confirm before treating Phase 14 as unblocked — the Phase 14 work is eBPF-data-validity, logically independent of the block dynamics.

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
- [x] Run benchmarks on v4 streams and fill in exact numbers in README (7d full + 30d 1M steps)

## Phase 6 — Experiments (Ready)

v4 experiment streams validated with rlsecd. eBPF features cut is_malicious MAE by 60% (Exp 13: 30 seeds, 90d v4, Cohen's d=2.577).

- [x] Run rlsecd on v4 streams — Exp 8 (7d), Exp 12 (365d stability), Exp 13 (90d eBPF ablation, 63.2M events)
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
- [x] Publish v4 dataset to Zenodo (DOI: 10.5281/zenodo.19482383): benign_v4.db.zst, campaigns_v2.db.zst, 4 v4 experiment streams, DATASET_README.md

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

## Phase 13c — Agent-side string encoding (representation neutrality)

Hybrid mode currently pre-hashes string fields (command, IP, path) into the observation via MurmurHash3 in `src/security_gym/envs/ebpf_encoding.py` (`hash_string`, type-keyed seeds). On a real server, string→number encoding is an agent-side perception choice, not something the host does; pre-hashing is lossy and irreversible, so a Hybrid-mode agent cannot try alternative encodings (learned embeddings, char-level, n-grams). Flagged by self-review during the RLC submission (2026-05-29) and noted as a limitation in the RLC paper (§3.1, §7.3 "Text vs. Hybrid encoding").

- [ ] Add a raw-structured observation mode that emits string fields as raw tokens/IDs (or short byte sequences) instead of hashes, leaving encoding to the agent
- [ ] Keep the current Hybrid (pre-hashed) mode as a clearly-documented convenience option
- [ ] Offer the MurmurHash3 hashing as an optional agent-side wrapper (the `features/hasher.py` utility already exists); env emits raw, agent opts in
- [ ] Re-run baselines under raw-structured mode to confirm parity with the pre-hashed convenience path

## Open Questions

- [ ] Revisit the `true_risk` score (the GVF-like auxiliary risk target, `_RISK_MAP`/`_ground_truth_risk` → risk-score MSE reward term). `include_risk_reward` now defaults to `False` (commit a5ceae9), so the risk-prediction head is effectively dormant. Decide whether `true_risk` should be removed entirely (ground-truth field, `Box(1)` risk_score action component, `risk_reward` term, and the label-validator range check) or retained as an opt-in auxiliary task. Touch points: `envs/log_stream_env.py`, `envs/log_stream_env_hybrid.py`, `adapters/scan_stream.py`, `scripts/validate_labels.py`, and tests in `tests/test_env.py` / `tests/test_scan_stream.py`.

## Campaign Corpus Documentation (2026-08-09)

Audit of `campaigns_v2.db` prompted by the question of why only half its events are labeled malicious. The answer (campaign collection captures the whole host inside the window; the labeler marks only time-plus-IP matches) was undocumented, as were several corpus properties a reader would reasonably assume otherwise.

- [x] README: added "Campaign Configurations" section enumerating all 9 configs with phase sequences; corrected "Two kill chain campaigns" to three (`recon_ssh_log4shell` was omitted); stated the 60,468 / 30,436 split and that the remainder is host background, not a benign baseline.
- [x] DATASET_README: added a "Campaigns" section with the per-campaign table (10 runs, 9 configs, aborted `recon_only` run flagged), a "Label composition" subsection explaining the benign half, and a "Known limitations" list (75-minute total capture, deterministic exploit outcomes, timer-driven phase progression, the TA0043 mislabel, the two eBPF network collector defects).
- [x] CLAUDE.md: added a "Campaign Corpus Characteristics" entry with the same facts.
- [ ] Decide the ATT&CK tactic correction. `full_killchain.yaml` and `redis_killchain.yaml` tag the recon phase `TA0043` (Reconnaissance); `recon_only` and `recon_ssh_log4shell` tag the identical T1046 SYN scan `TA0007` (Discovery). T1046 (Network Service Discovery) is a Discovery technique, so the two kill-chain configs are wrong and the README table is right. Fixing the YAML is one line each, but it desynchronizes the configs from the `mitre_tactics` values already written into `campaigns_v2.db` and shipped in the v4.1 deposit, so it carries the same re-collect-or-document choice as the collector defects (Phase 14 items 4 and 5). Options: fix YAML and document the DB discrepancy, fix both via a migration on the DB, or defer until a re-collection.
- [ ] Fold the new DATASET_README limitations into the next dataset version. The file ships inside the Zenodo deposit, so the current 4.1 record (DOI 10.5281/zenodo.21763493) still lacks them; pair this with the known BibTeX self-citation flaw already logged under "V4 Published-Archive Remediation".
- [ ] Mirror the campaign documentation into `data/HF_DATASET_CARD.md` and upload, so the hub card does not drift from the repo again.

## Housekeeping

- [x] Add campaign YAML files for Log4Shell and recon-only scenarios
- [x] Comprehensive README with quick start, feature docs, dataset download
- [x] `security-gym` CLI for dataset download from GitHub Releases
- [x] Zenodo DOI badge and archive
- [x] Code quality pass — ruff auto-fixes (unused imports, f-string), mypy type annotations (scan_stream buffers, collect_numpy return type, float cast in reward), all zero errors
- [x] Update default `db_path` fallback in `attacks/config.py` from `campaigns.db` to `campaigns_v2.db`
- [x] Document dataset schema and labeling methodology (DATASET_README.md)
- [x] Docs sync (2026-04-22): route all generic dataset links to concept DOI 10.5281/zenodo.18901627 (README.md badges + Zenodo links, CLAUDE.md, DATASET_README.md citation); keep version-specific DOIs (v3 18901542, v4 19482383) for reproducibility citations
- [x] Sync paper §5.2 event counts (2026-04-22): updated `research-assistant/mypapers/security-gym/drafts/v3.md` to match authoritative DB counts in DATASET_README.md (7d 4,891,541 / 25,980; 30d 21,511,208 / 609,520; 90d 63,212,997 / 549,787; 365d 257,654,256 / 1,857,178). DATASET_README confirmed canonical via direct sqlite COUNT on shipped v4 DBs.
