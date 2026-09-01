# V3 Deposit Archive Staleness: The Published v3 Stream Archives Contain the v2-Era Streams

Date: 2026-08-31 (pre-deletion audit of `data.old/`) and 2026-09-01 (published-copy decompress-and-count).
Scope: A pre-deletion audit of `data.old/` (the pre-v4 `data/` directory, renamed aside when the v4 working set was assembled) was performed on lappy, the MacBook holding `/Users/keith/repos/research/security-gym`, to verify that every file was replicated in `data/`, in git, or in a published deposit before the directory was deleted. The audit found that the four experiment-stream archives in the v3 dataset deposit (Zenodo record 18901542, version field `v0.3.3`) do not contain the final v3 streams. This is the same defect class documented for the v4 deposit in `V4_ARCHIVE_STALENESS_20260726.md`, predating that incident by eighteen days and undocumented until this audit. Follow-up measurements on 2026-09-01 downloaded the published archives and identified their contents. Tools: zstd 1.5.7, SQLite 3.51.0, curl against the Zenodo records API. All database queries used read-only URIs (`file:...?mode=ro`, with `immutable=1` where no WAL sidecars were present); temporary downloads and decompression artifacts were removed after measurement.

## 1. The Claim Under Test

The audit's original question was replication: does anything in `data.old/` exist nowhere else? In answering it, a staleness claim emerged with three parts: (a) the four stream archives in the v3 deposit were compressed before the afternoon-of-2026-03-04 recomposition that produced the final v3 stream databases, so the deposit does not contain the final v3 streams; (b) the stream databases in `data.old/` are the final v3 streams and are the only surviving copies; (c) the two base archives (`benign_v3.db.zst`, `campaigns_v2.db.zst`) are genuine. Verdict vocabulary follows the v4 report: STALE (the published archive does not contain the final v3 contents), GENUINE (it does), NOT EXAMINED.

## 2. Evidence Inventory

| # | Evidence | Source | Bears on |
|---|----------|--------|----------|
| E1 | `ls -la` inventory of `data.old/` (sizes, minute-resolution mtimes) | lappy, 2026-08-31, before deletion | Timeline |
| E2 | MD5 of all six `.zst` archives in `data.old/`, compared against the Zenodo record 18901542 file checksums (records API) | lappy, 2026-08-31 | Published-copy identity |
| E3 | `zstd -lv` frame headers (exact decompressed sizes) of all six archives | lappy, 2026-08-31 | Content-size mismatch |
| E4 | Streaming decompression of `benign_v3.db.zst` and MD5 comparison against the local `benign_v3.db` | lappy, 2026-08-31 | Base-archive freshness |
| E5 | SHA-256 of `campaigns_v2.db` and `campaigns_v2.db.zst` in both `data.old/` and `data/` (the `data/` copies were Zenodo-downloaded and content-verified on 2026-07-26, v4 report Section 9.2) | lappy, 2026-08-31 | Base-archive freshness |
| E6 | `SELECT count(*), max(id), min(timestamp), max(timestamp) FROM events` on the four final v3 stream databases (moved to `data/`) and on the v1 `campaigns.db` | lappy, 2026-08-31 and 2026-09-01 | Final v3 contents |
| E7 | Download of the four published stream archives from record 18901542, MD5-verified against the record, decompressed, and queried as in E6; payload sizes and MD5s recorded | lappy, 2026-09-01 | Stale contents |
| E8 | MD5 of `data/exp_7d_brute.db` compared against the value recorded in the v4 report Section 6 | lappy, 2026-08-31 | Chain of custody since 2026-07-26 |
| E9 | Download of the stale v4 7d archive from record 19482383, MD5-verified, decompressed, payload MD5 compared against `data/exp_7d_brute.db` | lappy, 2026-09-01 | Closes the v4 report's open comparison |
| E10 | Documented event counts of the v2-era stream recomposition (TODO.md Phase 9: "7d: 26k, 30d: 510k, 90d: 475k, 365d: 1.64M events") and the 2026-03-04 recompose entry ("Bugs Fixed (2026-03-04)") | repository history | Diagnosis |

A limitation relative to the v4 report: `data.old/` was deleted on 2026-08-31 after the audit, before nanosecond-resolution `stat` capture, so mtimes below are minute-resolution from E1. The same-minute source/archive mtime pairs observed for `benign_v3` and `campaigns_v2` are consistent with the zstd mtime-preservation signature established as E8 in the v4 report.

## 3. Measurements

### 3.1 Archive identity against the published record

Zenodo record 18901542 lists seven files. Local MD5s were measured in `data.old/` on 2026-08-31.

| File | Size (bytes) | Zenodo MD5 | Local MD5 match | mtime (local, 2026) |
|------|-------------:|------------|:---:|---------------------|
| benign_v3.db.zst | 370,574,991 | a151d5a49a2f630e001c5d626c4bb647 | yes | Mar 4 13:51 |
| campaigns_v2.db.zst | 4,392,329 | cf5cda14876b2c8a16258a1afd62c2c6 | yes | Mar 7 08:06 |
| exp_7d_brute.db.zst | 1,382,779 | d026c4600af2d63442316db092df7f19 | yes | Mar 4 08:01 |
| exp_30d_heavy.db.zst | 28,822,424 | 1ed990ec146863a49ee0a1a787295287 | yes | Mar 4 08:01 |
| exp01_90d.db.zst | 26,084,197 | 3563f400c5618ff86e2c9faf6f1eb208 | yes | Mar 4 08:02 |
| exp_365d_realistic.db.zst | 90,648,481 | f928555a299b76c082df0dcd0c763bcb | yes | Mar 4 08:02 |
| DATASET_README.md | 5,003 | e59fa2fa619323d9e71cae777f9583db | not examined | |

Every local archive is byte-identical to its published copy, so any property measured on the local archives transfers to the deposit, and conversely the 2026-09-01 downloads (MD5-matched to the record) stand in for the deleted local copies. The archives were also SHA-256 hashed from the downloads for future cross-referencing: 7d `a547de647fc72728cd50ab115d48cdf3bb22b1ee40bd1601d07bf3391d9fb4f1`, 30d `4ed53f1eb901e6ddc5b913819343724aa733460e551e4ec9fd77d4e60393e5e9`, 90d `333266e3679848b488661f92af9d2a9c6920ea476adae49f1a7b068664b040b8`, 365d `c6374fc4195498bae97aefaea4b072bda55d3c846f3ad4a78afc994c4bc91421`.

### 3.2 Frame-reported decompressed sizes versus the final v3 databases

| Stream | Frame decompressed (bytes) | Final v3 database (bytes) | mtime of DB (2026) | Match |
|--------|---------------------------:|--------------------------:|--------------------|-------|
| benign_v3 | 5,202,800,640 | 5,202,800,640 | Mar 4 13:51 | yes, byte count identical |
| campaigns_v2 | 42,721,280 | 42,721,280 | Mar 7 08:06 | yes, byte count identical |
| 7d | 13,819,904 | 105,881,600 | Mar 4 13:54 | no (13.1%) |
| 30d | 281,206,784 | 673,599,488 | Mar 4 14:58 | no (41.7%) |
| 90d | 254,820,352 | 1,385,906,176 | Mar 4 14:59 | no (18.4%) |
| 365d | 890,892,288 | 6,925,238,272 | Mar 4 15:05 | no (12.9%) |

### 3.3 Base archives: content-level verification

`benign_v3.db.zst` was streaming-decompressed (`zstd -d -c | md5`) on 2026-08-31; the payload MD5 `db08ea929f3488ed304bb9c930900a48` equals the MD5 of the local `benign_v3.db`, so the published base archive is byte-for-byte the local database. `campaigns_v2.db` and `campaigns_v2.db.zst` in `data.old/` are SHA-256 identical to the copies in `data/` (`9f125354822b1c121ec93c72b7efc9a3771e5ea854371b9354b1e00a608369c1` and `1ddf8f09cf54ebf53563782006c625f191250c1240c6f0c86fb64dd6487ff53e` respectively); the `data/` copies were downloaded from Zenodo record 19482383 and content-verified at 60,468 events on 2026-07-26 (v4 report Section 9.2). The archive MD5 `cf5cda14876b2c8a16258a1afd62c2c6` is identical across the v3 record, the v4 record 19482383, and the v4.1 manifest, so one byte-identical `campaigns_v2.db.zst` has shipped in every dataset version.

### 3.4 Stream contents: published archives versus the final v3 databases

Query: `SELECT count(*), max(id), min(timestamp), max(timestamp) FROM events;`. Archive rows were measured on the decompressed 2026-09-01 downloads; database rows on the final v3 databases now in `data/`. In every row `max(id)` equals `count(*)`.

| Stream | Source | count(*) | min(timestamp) | max(timestamp) | Payload bytes | Payload MD5 |
|--------|--------|---------:|----------------|----------------|--------------:|-------------|
| 7d | archive | 26,178 | 2023-07-24T13:54:31+00:00 | 2023-07-31T12:07:28+00:00 | 13,819,904 | cc2229691deeb38dd465a9d4939d45ce |
| 7d | final v3 DB | **140,315** | 2012-12-30T06:26:07-05:00 | 2013-01-06T06:25:57-05:00 | 105,881,600 | 3743327301d64f04bbbbe8fd96e392a8 |
| 30d | archive | 509,542 | 2023-07-24T13:54:31+00:00 | 2023-08-23T14:23:46.437091+00:00 | 281,206,784 | a7842a937998ac1e45e6252f29000cd1 |
| 30d | final v3 DB | **1,003,075** | 2012-12-30T06:26:07-05:00 | 2013-01-29T06:55:22.437091-05:00 | 673,599,488 | |
| 90d | archive | 475,125 | 2023-07-24T13:54:31+00:00 | 2023-10-22T11:11:36.011842+00:00 | 254,820,352 | 6a6d695b759cc80ef587ad25298b059f |
| 90d | final v3 DB | **1,921,159** | 2012-12-30T06:26:07-05:00 | 2013-03-30T06:25:20-05:00 | 1,385,906,176 | |
| 365d | archive | 1,644,222 | 2023-07-24T13:54:31+00:00 | 2024-07-23T13:06:02.107955+00:00 | 890,892,288 | 1afade24b6a6e78ff1f300211e8917ac |
| 365d | final v3 DB | **9,410,946** | 2012-12-30T06:26:07-05:00 | 2013-12-30T05:37:38.107955-05:00 | 6,925,238,272 | |

The final v3 counts for the 7d, 30d, and 90d streams reproduce the v4 report's E6 values exactly, and the MD5 of `exp_7d_brute.db` matches the value that report recorded (E8), so the final v3 streams are unchanged since the 2026-07-26 measurements. The 365d count (9,410,946) had not previously been recorded anywhere.

## 4. Diagnosis: the published stream archives are the v2-era streams

The archive contents are not a truncation of the v3 streams; they are a different data generation. Three independent signals converge:

1. The archive event counts (26,178 / 509,542 / 475,125 / 1,644,222) match the documented sizes of the streams recomposed from the v2 databases (TODO.md Phase 9: "7d: 26k, 30d: 510k, 90d: 475k, 365d: 1.64M events", E10) at full precision under rounding.
2. All four archives share the base timestamp 2023-07-24T13:54:31+00:00, the benign_v2 epoch, whereas all four final v3 streams share the base timestamp 2012-12-30T06:26:07-05:00, the benign_v3 epoch.
3. The archives' preserved mtimes (2026-03-04 08:01 to 08:02) sit hours before the final v3 stream databases' mtimes (13:54 to 15:05 the same day), and the repository log records a stream recomposition from the v2 databases on exactly 2026-03-04 ("Bugs Fixed (2026-03-04)": re-compose to pick up the event_type and session-enrichment parser fixes).

The reconstruction is therefore: on the morning of 2026-03-04 the four stream databases were rewritten from `benign_v2.db` + `campaigns_v2.db` (mtimes 08:01 to 08:02); the four archives were compressed from those files at some point before the afternoon run overwrote them (zstd preserves the source mtime, and the contents are the morning files); at 13:51 the `benign_v3.db` build completed and was archived (same-minute source/archive mtimes); between 13:54 and 15:05 the streams were recomposed from `benign_v3.db` + `campaigns_v2.db` (Phase 10), overwriting the four stream databases; the stream archives were never regenerated; on or after 2026-03-07 (the `campaigns_v2.db` mtime and the v0.3.3 release date) the deposit was published with two genuine base archives and four pre-recomposition stream archives. This is operationally identical to the v4 incident of 2026-03-22: a compose-archive-recompose sequence in which the archives were cut between the two compositions. The v3 occurrence came first, which reclassifies the v4 incident from a one-off error to a repeat of an established failure mode.

One consequence deserves emphasis. The v2-era stream databases no longer exist on disk anywhere (the morning files were overwritten the same day); their only surviving copies are the four published archives, whose payload MD5s are recorded in Section 3.4. Conversely, the final v3 streams exist only as the four uncompressed databases preserved in `data/` (Section 6); the deposit cannot reproduce them.

A second consequence requires assessment rather than emphasis. `benign_v3.db` is documented as a clean rebuild specifically excluding sources that the v2 benign base contained (CLAUDE.md: "a clean rebuild from personal server logs (no hospital PII)"). The published stream archives are composed from `benign_v2.db`, the generation that rebuild replaced. The v1-era import was scrubbed of identifying hostnames, domains, and emails (Phase 5b), but whether the published v2-era streams contain any material the v3 rebuild was intended to exclude was not assessed in this audit and is the first follow-up item (Section 7).

## 5. Verdicts

| Deposit file | Verdict | Basis |
|--------------|---------|-------|
| benign_v3.db.zst | **GENUINE** | Payload MD5 equals the local `benign_v3.db` (content-level proof, E4) |
| campaigns_v2.db.zst | **GENUINE** | Byte-identical to the copy content-verified on 2026-07-26; MD5 constant across all three deposit generations (E5) |
| exp_7d_brute.db.zst | **STALE** | v2-era stream: 26,178 events versus 140,315 final; wrong epoch (Section 3.4) |
| exp_30d_heavy.db.zst | **STALE** | v2-era stream: 509,542 events versus 1,003,075 final; wrong epoch |
| exp01_90d.db.zst | **STALE** | v2-era stream: 475,125 events versus 1,921,159 final; wrong epoch |
| exp_365d_realistic.db.zst | **STALE** | v2-era stream: 1,644,222 events versus 9,410,946 final; wrong epoch |
| DATASET_README.md | NOT EXAMINED | |

Record 18901542 therefore serves 18.7%, 50.8%, 24.7%, and 17.5% of the final v3 event volumes for the 7d, 30d, 90d, and 365d streams respectively, and, more importantly, serves them from the wrong data generation: a downloader received internally coherent v2-composed streams labeled as v3. Exposure is confined to downloaders of the stream archives. No local result is implicated: the published experiments (Exp 8, 12, 13, the rule-agent benchmarks, the rlsecd runs) all used the v4 streams, and the v3 base archives, which the v4 lineage builds on, are genuine.

## 6. Disposition of `data.old/` (2026-08-31)

Sole-copy artifacts moved into `data/` by same-volume rename before deletion:

| File | Size (bytes) | Identity |
|------|-------------:|----------|
| exp_7d_brute.db (+`-shm`/`-wal`) | 105,881,600 | final v3 7d stream, 140,315 events; MD5 `3743327301d64f04bbbbe8fd96e392a8` |
| exp_30d_heavy.db (+`-shm`/`-wal`) | 673,599,488 | final v3 30d stream, 1,003,075 events |
| exp01_90d.db | 1,385,906,176 | final v3 90d stream, 1,921,159 events |
| exp_365d_realistic.db | 6,925,238,272 | final v3 365d stream, 9,410,946 events |
| campaigns.db (+`-shm`/`-wal`) | 1,019,711,488 | v1 campaign database, 1,451,175 events; never published in any deposit |
| exp01_90d.cache_h256.npz | 2,934,373,740 | feature cache for the deprecated v0 extractors, derived from `exp01_90d.db` |

All WAL sidecars were zero bytes (no pending writes). `data/build_benign_report.json`, deleted from the working tree by the original `data/` to `data.old/` rename, was restored from git; the `data.old/` copy was SHA-256 identical to the git copy (`e1646f4f307e46c598592fcdeac4f8a909b849d84fc39a29079f36b9b55c5322`). Everything else in `data.old/` was verified replicated before deletion: `benign_v3.db` and the six archives per Sections 3.1 and 3.3, `campaigns_v2.db` per E5, and the May-era `croissant.json` and `DATASET_README.md` as superseded versions of git-tracked files. A stray `.claude/settings.local.json` was discarded. `data.old/` was deleted on 2026-08-31.

## 7. Closure of the v4 Report's Open Comparison

The v4 report (Section 6) found the stale v4 7d archive's contents indistinguishable from the v3-era `exp_7d_brute.db` at the summary level (identical count, `max(id)`, boundary timestamps, and decompressed size) and recorded that database's MD5 for a future byte-level comparison, byte identity being "highly probable but unconfirmed". That comparison was run on 2026-09-01 (E9): the stale v4 7d archive was downloaded from record 19482383 (archive MD5 `24033d31b63cf94090dfaa0e5e9e9290`, matching the v4 report Section 3.2), decompressed to 105,881,600 bytes, and re-queried (140,315 events, boundaries identical to `data/exp_7d_brute.db`). Its payload MD5 is `6d070139ca9ee8adc8906cbe18464c77`, which does not equal `3743327301d64f04bbbbe8fd96e392a8`. Byte identity is refuted; summary-level indistinguishability is confirmed. The two files are consistent with separate composition runs producing logically equivalent output with different physical page layout; a full logical diff was not performed, and the v4 report's verdicts are unaffected.

## 8. Recommended Follow-Up (outside the scope of this audit)

1. Assess the published v2-era streams for content the v3 rebuild was intended to exclude (Section 4). This is the priority item, since its outcome determines whether the disposition of record 18901542 is a documentation matter or a takedown-and-replace matter.
2. Recompress the four final v3 stream databases from `data/` (with round-trip decompress-and-count against the Section 3.4 final-DB rows) so the final v3 corpus regains a durable compressed form; record the hashes here or in a successor report.
3. Decide the disposition of record 18901542: an erratum note on the record, a corrected v3.1 version under the concept DOI, or repository-side documentation only, informed by item 1 and by the fact that v4.1 already supersedes v3 for all current use.
4. Extend the downstream-consumer audit (open under "V4 Published-Archive Remediation" in TODO.md) to cover v3 stream-archive downloaders, who received v2-generation streams.
5. Check whether any published surface (README.md, the HuggingFace card, either paper) cites the v3 stream archives specifically, as opposed to the v3 base databases; the base archives are genuine, so citations of `benign_v3` need no correction.
