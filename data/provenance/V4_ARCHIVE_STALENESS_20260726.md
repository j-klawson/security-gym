# V4 Archive Staleness Validation: Local and Published `.db.zst` Archives versus the Live v4 Streams

Date: 2026-07-26.
Scope: A concurrent analysis session on another machine concluded that the four v4 experiment-stream archives (`exp_7d_brute_v4.db.zst`, `exp_30d_heavy_v4.db.zst`, `exp01_90d_v4.db.zst`, `exp_365d_realistic_v4.db.zst`) were compressed on the morning of 2026-03-22, before the evening recomposition that produced the final v4 databases, and that the stale archives were uploaded to Zenodo (version DOI 10.5281/zenodo.19482383) and HuggingFace (`j-klawson/security-gym-v4`). This report documents an independent, read-only verification performed on hopper, the machine holding the canonical `data/` directory, on the morning of 2026-07-26 (EDT). All measurements were taken before the local archives were deleted later the same day (Section 7). No database was modified; temporary decompression artifacts were removed after measurement. Tools: zstd 1.5.7, SQLite 3.46.1; all live-database queries used read-only URIs (`file:...?mode=ro`).

## 1. The Claim Under Test

The claim has three parts: (a) the local 7d, 30d, and 90d archives contain a small morning-of-2026-03-22 composition (approximately 140,315 / 1,103,255 / 1,996,031 events, timestamps starting 2012-12-30) rather than the final v4 streams (4,891,541 / 21,511,208 / 63,212,997 events); (b) the published Zenodo and HuggingFace copies are byte-identical to those stale local archives; (c) the 365d archive may or may not share the defect. Verdict vocabulary: STALE (archive matches the published copy and does not contain the live database contents), FRESH (archive contents match the live database), INDETERMINATE (evidence insufficient).

An explicit alternate hypothesis was also under test: that only the 7d archive and the published copies were bad, while the local 30d and 90d archives were fresh. That hypothesis is refuted (Section 5).

## 2. Evidence Inventory

| # | Evidence | Source | Bears on |
|---|----------|--------|----------|
| E1 | `stat` metadata (size, mtime, ctime, inode birth) for all four archives | `data/`, measured 2026-07-26 | Timeline |
| E2 | MD5 and SHA-256 of all four archives, compared against the Zenodo deposit MD5s and the HuggingFace LFS SHA-256s | `data/`, measured 2026-07-26 | Published-copy identity |
| E3 | `zstd -l` frame headers (exact decompressed sizes) | `data/`, measured 2026-07-26 | Content-size mismatch |
| E4 | Full decompression of the 7d/30d/90d archives and `SELECT count(*), max(id), min(timestamp), max(timestamp) FROM events` on each | temporary directory on hopper, removed after measurement | Stale contents |
| E5 | The same query, read-only, on all four live v4 databases | `data/`, measured 2026-07-26 | Fresh contents |
| E6 | The same query on the v3-era stream databases (`exp_7d_brute.db`, `exp_30d_heavy.db`, `exp01_90d.db`), plus MD5 of `exp_7d_brute.db` | `data/`, measured 2026-07-26 | Diagnosis (Section 6) |
| E7 | Ownership and mtimes of the live v4 databases (root-owned, evening of 2026-03-22) and the `benign_v4.db` build completion mtime (09:06:00 EDT) | `data/` | Timeline |
| E8 | zstd mtime-preservation signature: the 365d archive mtime equals the live 365d database mtime to the nanosecond; `benign_v4.db.zst` and `campaigns_v2.db.zst` showed the same signature against their sources | `data/` | 365d freshness |
| E9 | Negative searches: `~/.bash_history` retains 2,000 lines (file mtime 2026-07-26 07:01), oldest entries long postdating March 2026, with no zstd, Zenodo, HuggingFace, compose, or upload commands; the repository contains no compression or upload script | machine-wide | Absence of command-level record |

## 3. Measurements

### 3.1 Archive metadata

| Archive | Size (bytes) | mtime (EDT) | Inode birth / ctime (EDT) |
|---------|-------------:|-------------|---------------------------|
| exp_7d_brute_v4.db.zst | 8,902,418 | 2026-03-22 09:07:19.131915226 | 2026-03-22 09:36:45.8 / 09:36:46.0 |
| exp_30d_heavy_v4.db.zst | 67,038,936 | 2026-03-22 09:08:25.730968107 | 2026-03-22 09:36:45.8 / 09:36:46.9 |
| exp01_90d_v4.db.zst | 121,631,440 | 2026-03-22 09:10:05.959563294 | 2026-03-22 09:36:45.8 / 09:36:47.5 |
| exp_365d_realistic_v4.db.zst | 13,683,361,323 | 2026-03-23 10:19:15.245162392 | 2026-04-08 20:16:32.3 / 20:21:05.1 |

zstd preserves the source file's mtime on the compressed output, so each archive mtime records when its source database was last written, not when compression ran. The three small archives share one inode birth timestamp (09:36:45.812657822) with strictly increasing ctimes, consistent with a single copy operation placing them in `data/` at 09:36 on 2026-03-22. The 365d archive materialized on hopper on 2026-04-08.

### 3.2 Hashes

| Archive | MD5 | SHA-256 |
|---------|-----|---------|
| exp_7d_brute_v4.db.zst | 24033d31b63cf94090dfaa0e5e9e9290 | d67c5dd3813acadea2c9977e02a7d337ef78e3a035dfadfc46ad7b30a7e097bd |
| exp_30d_heavy_v4.db.zst | eafcdcc4d6f44e8c52f7c95f6853a67f | b5b4b68e9db41eb49eba17a05d4dd982a2a9807a2fa74c9faa4ea7859f8c6a16 |
| exp01_90d_v4.db.zst | e399ff6476075e7e8d088e3bcdfa3243 | 3984497cdf6fe188d788b6a67c38079e67f7145d4710ed3ea4e4fd147253d5e8 |
| exp_365d_realistic_v4.db.zst | 1392292d134f3871bbf20bb12e14dd7e | ff0e5923dc34f97c874a3661e14264df27e652a52913fe28280e79f081fef220 |

### 3.3 Frame-reported decompressed sizes versus live database sizes

| Stream | Frame decompressed (bytes) | Live database (bytes) | Match |
|--------|---------------------------:|----------------------:|-------|
| 7d | 105,881,600 | 2,020,184,064 | no (5.2%) |
| 30d | 725,250,048 | 9,088,700,416 | no (8.0%) |
| 90d | 1,423,323,136 | 26,501,332,992 | no (5.4%) |
| 365d | 108,418,490,368 | 108,418,490,368 | yes, byte-identical |

### 3.4 Archive contents versus live databases

Query: `SELECT count(*), max(id), min(timestamp), max(timestamp) FROM events;`

| Stream | Source | count(*) | max(id) | min(timestamp) | max(timestamp) |
|--------|--------|---------:|--------:|----------------|----------------|
| 7d | archive | 140,315 | 140,315 | 2012-12-30T06:26:07-05:00 | 2013-01-06T06:25:57-05:00 |
| 7d | live DB | **4,891,541** | 4,891,541 | 2012-12-30T06:26:07-05:00 | 2013-01-06T06:26:06.893556-05:00 |
| 30d | archive | 1,103,255 | 1,103,255 | 2012-12-30T06:26:07-05:00 | 2013-02-02T20:21:27.304464-05:00 |
| 30d | live DB | **21,511,208** | 21,511,208 | 2012-12-30T06:26:07-05:00 | 2013-02-02T20:21:27.304464-05:00 |
| 90d | archive | 1,996,031 | 1,996,031 | 2012-12-30T06:26:07-05:00 | 2013-04-03T07:38:02.377498-05:00 |
| 90d | live DB | **63,212,997** | 63,212,997 | 2012-12-30T06:26:07-05:00 | 2013-04-03T07:38:02.377498-05:00 |
| 365d | archive | not decompressed (Section 3.5) | | | |
| 365d | live DB | **257,654,256** | 257,654,256 | 2012-12-30T06:26:07-05:00 | 2014-01-01T01:49:45.161295-05:00 |

The archive-side counts reproduce the claimed stale values exactly. The live-side counts reproduce the documented final v4 stream sizes exactly.

### 3.5 The 365d archive

Full decompression was skipped because free disk (76 GB) was below the 110 GB required for the 101 GiB payload. Three independent signals nevertheless indicate freshness: the frame-reported decompressed size is byte-identical to the live database (Section 3.3); the archive mtime equals the live database mtime to the nanosecond (2026-03-23 10:19:15.245162392, the zstd mtime-preservation signature, E8), so it was compressed from the final file; and the MD5 matches the Zenodo deposit (Section 4). A full decompress-and-count remains outstanding (Section 8).

## 4. Hash Comparison Against the Published Copies

| Stream | Local MD5 = Zenodo MD5 | Local SHA-256 = HuggingFace LFS SHA-256 |
|--------|:----------------------:|:---------------------------------------:|
| 7d | yes | yes |
| 30d | yes | yes |
| 90d | yes | yes |
| 365d | yes | no reference value available |

Every local archive is byte-identical to its published Zenodo copy, and the three small archives are additionally byte-identical to their HuggingFace LFS objects. Staleness of the local archives therefore transfers directly to both published mirrors, with no network transfer or SMB pathway involved in the proof. No HuggingFace SHA-256 was available for the 365d file; its HuggingFace status is inferred only insofar as the repository is expected to mirror the Zenodo deposit.

## 5. Verdicts

| Archive | Verdict | Basis |
|---------|---------|-------|
| exp_7d_brute_v4.db.zst | **STALE** | Matches both published copies; decompresses to 140,315 events versus 4,891,541 live |
| exp_30d_heavy_v4.db.zst | **STALE** | Matches both published copies; decompresses to 1,103,255 events versus 21,511,208 live |
| exp01_90d_v4.db.zst | **STALE** | Matches both published copies; decompresses to 1,996,031 events versus 63,212,997 live |
| exp_365d_realistic_v4.db.zst | **FRESH** (high confidence) | Zenodo MD5 match; frame size byte-identical to live DB; nanosecond-identical mtime; full count deferred |

The alternate hypothesis (only the 7d archive bad, local 30d/90d fresh) is refuted: all three small archives are stale, and all three stale archives are exactly what was published. Zenodo record 19482383 and the HuggingFace repository consequently serve 2.9%, 5.1%, and 3.2% of the intended 7d, 30d, and 90d streams respectively. Results produced on this machine from the live databases (the Exp 13 eBPF ablation, the rule-agent benchmarks of the C11 validation, and the rlsecd runs) are unaffected; only consumers of the published archives are affected.

## 6. Timeline Reconstruction and Diagnosis

1. 2026-03-22 09:06:00 EDT: the `benign_v4.db` build completes (file mtime).
2. 09:07:19 to 09:10:05: a morning composition run writes small 7d/30d/90d v4 databases (the mtimes preserved inside the archives). The three outputs complete within 166 seconds of one another, beginning about one minute after the benign build finished; the evening full-scale recomposition of the same three streams spanned at least 33 minutes. The morning run therefore cannot have been a full-scale composition.
3. 09:36:45 to 09:36:47: the three archives are placed in `data/` in a single copy operation (E1).
4. Between 2026-03-22 and the v4 release, the morning archives are uploaded to Zenodo and HuggingFace (hash identity, Section 4). No command-level record of the upload survives (E9).
5. 20:19:21, 20:28:06, 20:52:34 EDT: the recomposition, running as root, rewrites the three databases at full scale. The archives are never regenerated.
6. 2026-03-23 10:19:15 EDT: the 365d composition completes. The 365d archive is later compressed from that exact file and materializes on hopper on 2026-04-08 (E1, E8).
7. 2026-07-26: this verification. The local `.zst` files are deleted after measurement.

Diagnosis of the stale contents (E6). The stale 7d archive contents are indistinguishable from the v3-era `exp_7d_brute.db` still on disk: identical event count (140,315), max(id), boundary timestamps, and decompressed byte size (105,881,600). A checksum of the decompressed stale 7d payload was not captured before the archives were deleted, so byte-level identity is highly probable but unconfirmed; the MD5 of `exp_7d_brute.db` is recorded here for any future comparison against the Zenodo copy: `3743327301d64f04bbbbe8fd96e392a8`. The stale 30d and 90d contents are not the v3 streams (1,103,255 versus 1,003,075 events; 1,996,031 versus 1,921,159) but terminate at exactly the final v4 maximum timestamps, consistent with the deterministic composer producing the same campaign schedule as the evening run while nearly all event volume (the final streams are roughly 93% eBPF events) is absent. The precise defect in the morning composition (wrong benign source, or benign eBPF carryover not yet available at 09:07) is not recoverable from surviving artifacts and does not affect the verdicts.

## 7. State of the Local Directory After This Validation

All `.zst` archives in `data/` were deleted on 2026-07-26 after the measurements above were taken. This includes the four v4 stream archives examined here and also `benign_v3.db.zst`, `benign_v4.db.zst`, `campaigns_v2.db.zst`, and the four v1/v3-era stream archives, which were not part of this validation. `benign_v4.db.zst` and `campaigns_v2.db.zst` carried the fresh-compression mtime signature (nanosecond-identical to their source databases, E8) but were never hash-compared against the published deposit. The live databases are intact and unmodified.

## 8. Recommended Follow-Up (outside the scope of this validation)

1. Recompress the 7d, 30d, and 90d archives from the live databases, and verify each by decompress-and-count against the live-DB row of Section 3.4 before any upload.
2. Publish a corrected dataset version under the concept DOI 10.5281/zenodo.18901627 (new version DOI) and replace the three LFS objects in `j-klawson/security-gym-v4`. The deposit checksums will change; any document citing the version DOI 10.5281/zenodo.19482383 for the three affected files should be pointed at the corrected version.
3. Complete the deferred 365d decompress-and-count before treating the published 365d file as verified. The local archive no longer exists, so this must run against the Zenodo-hosted copy or a fresh recompression of the live database (expected: 257,654,256 events, max timestamp 2014-01-01T01:49:45.161295-05:00).
4. When assembling the corrected deposit, hash-verify `benign_v4.db.zst` and `campaigns_v2.db.zst` against the published copies as well, since the local evidence for their freshness (E8) is now unrecoverable.
5. `data/croissant.json` carries `"sha256": "TBD"` placeholders for six file entries; fill them from the regenerated archives at re-release.
6. Audit downstream use: any third-party experiment that downloaded the published 7d, 30d, or 90d v4 archives operated on 3 to 5% of the intended streams.

## 9. Remediation (2026-07-26)

Executed on hopper on the afternoon of 2026-07-26 (EDT), the same day as the validation above. Tools: zstd 1.5.7 (`zstd -T0 -19 --long=27`), SQLite 3.46.1.

### 9.1 Regenerated archives

The three stale archives were recompressed from the live v4 databases in `data/`. Each fresh archive was round-trip verified before acceptance: decompressed in full to a temporary file, queried with `SELECT count(*), max(id) FROM events`, compared against the live-database values of Section 3.4, and the temporary copy deleted. All three match exactly (4,891,541 / 21,511,208 / 63,212,997 events; `max(id)` equal to the count in each case).

| Archive | Size (bytes) | MD5 | SHA-256 |
|---------|-------------:|-----|---------|
| exp_7d_brute_v4.db.zst | 163,895,433 | 338a73eced346420ceea1eab9b3cce94 | d06590723dea52c4e3f8776c6af841c78ff9fd35ea41c49be2137c68cfe7c652 |
| exp_30d_heavy_v4.db.zst | 719,156,975 | 0494284aec6f3f7b3440e3a39ae13b1d | 4e903e2ba8d50945070c23109079388fa318db8f995ce1c3958e1447082f8824 |
| exp01_90d_v4.db.zst | 2,122,545,681 | 61c9df3a3ea29f3c96a30e805f063e16 | 0749e549aa377680c4204fe329ddd1ce0d9d0bb80c751c53b0b5f560448a433d |

The fresh archives are 18x, 10.7x, and 17.5x the size of their stale counterparts (Section 3.1), consistent with the stale copies containing 2.9 to 5.1% of the intended event volume. This closes follow-up item 1 (Section 8).

### 9.2 Verification of the published base archives

Follow-up item 4 is also closed. `benign_v4.db.zst` and `campaigns_v2.db.zst` were downloaded from Zenodo record 19482383, and each matched the deposit MD5 (97d9078a84850b1f7dcd86311c21fd43 and cf5cda14876b2c8a16258a1afd62c2c6 respectively). Both were then content-verified by full decompression and event count against the live databases: benign_v4 contains 11,159,241 events and campaigns_v2 contains 60,468 events, both matching their live counterparts exactly. The published base archives are therefore genuine, upgrading the earlier mtime-only evidence (E8) to content-level proof. Their SHA-256 values, computed here for `croissant.json`, are a8fc9447f6f754474497d08e5b8e54a29de1e53e59976610958d8fafe3718b3d (benign_v4) and 1ddf8f09cf54ebf53563782006c625f191250c1240c6f0c86fb64dd6487ff53e (campaigns_v2). The downloaded archives are retained in `data/` as verified copies of the published artifacts.

### 9.3 Metadata corrections

`data/croissant.json` now carries real checksums for all six distribution entries (follow-up item 5 closed): fresh size, MD5, and SHA-256 for the three regenerated archives; the published SHA-256 and MD5 for the 365d archive (Section 3.2); and the deposit MD5 plus newly computed SHA-256 for the two base archives. `data/DATASET_README.md` compressed-size figures were updated to the fresh archive sizes (156 MB / 686 MB / 2.0 GB; HuggingFace mirror total now approximately 2.8 GB).

### 9.4 Publication status

Remaining steps, tracked in TODO.md: replace the three stale LFS objects on HuggingFace (`j-klawson/security-gym-v4`) with the regenerated archives and upload the corrected `croissant.json` and dataset card; publish a corrected Zenodo version under the concept DOI 10.5281/zenodo.18901627 carrying over the four verified files and the three fresh archives; complete the deferred 365d decompress-and-count (follow-up item 3); update version-DOI citations; audit downstream consumers (follow-up item 6).
