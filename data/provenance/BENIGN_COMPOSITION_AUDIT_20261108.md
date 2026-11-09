# Benign Composition Audit: Native Span, Window Anchoring, and Surface-Format Separability

Date: 2026-11-08. Scope: `benign_v4.db` (benign corpus), `exp_7d_brute_v4.db` and `exp_30d_heavy_v4.db` (v4 composed streams), read-only from the local copies in `~/repos/research/security-gym/data/` on `lappy`. `exp_365d_realistic_v4.db` (108 GB) was not scanned; its figures below are extrapolated from the per-source spans and the composer's cycling arithmetic and are marked as such. Every count is an exhaustive enumeration, so no inferential statistics apply. This note is the log-side counterpart of `KERNEL_LABEL_AUDIT_20261107.md` and is the evidence behind spec register entries D16 and D17 and the retirement of the three-host benign merge under D3.

## 1. Summary

1. The benign corpus's eleven million events are dominated by a single source: 7.9 million `web_access` lines, 97.8% of them from calendar year 2013. The remaining log sources are small (3,737 `auth_log`, 13,599 `syslog`, 66 `web_error`) and the three kernel sources together span 27.7 hours.
2. The composer anchors each source at its own earliest timestamp and uses events in order until the stream duration is filled (`_cycle_source`, `src/security_gym/data/composer.py:257-287`). For a source whose span exceeds the stream, this selects the earliest window regardless of density. The 30-day stream's benign `syslog` is therefore 325 lines from May 2025 (a Debian installer log), 2.4% of the syslog corpus, while the dense December 2025 to February 2026 period (12,392 lines) is unused; the 2024 and 2026 `web_access` data (131,493 lines) is never used in any stream.
3. The kernel baseline is downsampled once to 24.2% by a hash keyed on the source timestamp (`composer.py:180`) before cycling (`:577`), so the same subset is repeated verbatim: about 26 times in the 30-day stream and about 316 times in the 365-day stream (extrapolated).
4. The `syslog` observation channel is perfectly separable by surface format in the 30-day stream. All 26,459 `journal` events are malicious and are rendered as journald JSON export lines; the corpus holds no benign `journal` event. Among `syslog`-source lines, 0 of 325 benign lines carry a hostname token and 256 of 256 malicious lines do. The channel holds 26,715 malicious against 325 benign events (98.8%).
5. Neither shipped detector reads the format leak directly: the keyword baseline uses semantic regexes and rlsecd's twelve log features are per-address authentication statistics. The detection problem they were scored on is nonetheless easy by construction: the `auth_log` channel is 64.0% malicious in the 30-day stream and 49.9% in the 7-day stream, and benign authentication activity is 120 events per day because the benign build filtered real scanner traffic.

## 2. Native span of the benign corpus by source

`SELECT source, MIN(timestamp), MAX(timestamp), COUNT(*) FROM events GROUP BY source` on `benign_v4.db`:

| Source | Events | Earliest | Latest | Span |
|---|---:|---|---|---|
| `auth_log` | 3,737 | 2025-12-01T11:27:26Z | 2026-02-27T06:28:06Z | 88 days |
| `syslog` | 13,599 | 2025-05-20T19:08:27Z | 2026-02-27T06:28:06Z | 283 days |
| `web_access` | 7,898,456 | 2012-12-30T06:26:07-05:00 | 2026-03-04T07:57:27-05:00 | 13.2 years |
| `web_error` | 66 | 2024-01-13T00:06:12Z | 2024-01-27T16:13:20Z | 14 days |
| `ebpf_file` | 3,019,300 | 2026-03-20T16:16:03Z | 2026-03-21T19:59:56Z | 27.7 hours |
| `ebpf_process` | 144,752 | 2026-03-20T16:16:03Z | 2026-03-21T19:59:56Z | 27.7 hours |
| `ebpf_network` | 79,331 | 2026-03-20T16:16:05Z | 2026-03-21T19:59:56Z | 27.7 hours |
| `journal` | 0 | | | |

Totals: 7,915,858 log events and 3,243,383 kernel events, 11,159,241 in all, matching the documented build. The 27.7-hour kernel span is the union of three overlapping 24-hour collections (frodo, 9600baud, hopper).

Distribution within the long-span sources:

| `web_access` by year | Events | | `auth_log` by month | Events | | `syslog` by month | Events |
|---|---:|---|---|---:|---|---|---:|
| 2012 | 39,954 | | 2025-12 | 3,614 | | 2025-05 | 325 |
| 2013 | 7,726,980 | | 2026-01 | 12 | | 2025-08 | 882 |
| 2018 | 3 | | 2026-02 | 111 | | 2025-12 | 5,328 |
| 2023 | 26 | | | | | 2026-01 | 4,180 |
| 2024 | 21,311 | | | | | 2026-02 | 2,884 |
| 2026 | 110,182 | | | | | | |

## 3. What the composed streams contain

`SELECT source, is_malicious, COUNT(*) FROM events GROUP BY source, is_malicious`:

| Source | 7-day benign | 7-day malicious | 30-day benign | 30-day malicious |
|---|---:|---:|---:|---:|
| `auth_log` | 403 | 401 | 3,614 | 6,424 |
| `syslog` | 325 | 0 | 325 | 256 |
| `journal` | 0 | 696 | 0 | 26,459 |
| `web_access` | 114,335 | 0 | 493,735 | 4,501 |
| `web_error` | 23 | 0 | 134 | 0 |
| `ebpf_process` | 213,964 | 613 | 917,943 | 17,116 |
| `ebpf_network` | 117,798 | 294 | 504,918 | 10,261 |
| `ebpf_file` | 4,418,713 | 23,976 | 18,981,019 | 544,503 |

`composition_meta` for the 30-day stream: seed 99, duration 2,592,000 s, `campaigns_per_day` 10.0, five attack types at 0.20 each, benign `configs/../data/benign_v4.db`, attack `configs/../data/campaigns_v2.db`, composed 2026-03-23T00:20:59Z.

Reading the counts against the spans:

- `auth_log` benign in the 30-day stream is exactly the 3,614 December 2025 events (the first 30 days from the source's earliest timestamp). In the 365-day stream the 88-day span cycles about four times (extrapolated).
- `syslog` benign is 325 in both the 7-day and 30-day streams: the May 2025 events, which are Debian installer output (`clock-setup`, `main-menu`). The anchor rule discards the remaining 97.6% of the syslog corpus for any stream shorter than seven months.
- `web_access` benign in the 30-day stream (493,735) is the window 2012-12-30 to 2013-01-29. In the 365-day stream the window is essentially calendar 2013 (7.77 million events), used once; this is the only benign source with a genuine year-scale span. The 2024 and 2026 web events lie beyond any stream's window and are never used.
- Kernel benign in the 30-day stream (20,403,880) equals 3,243,383 × 0.242 × about 26 cycles. The downsample key is `f"{timestamp}|{source}|{raw_line}"` on the source timestamp and runs before `_stream_compose_to_db`, so every cycle carries the identical subset.

Resulting class balance per observation channel (30-day stream): `web_log` 0.90% malicious; `auth_log` 64.0%; `syslog` channel (sources `syslog` and `journal`) 98.8%. Journal events are 70.3% of all malicious log events in the stream (26,459 of 37,640).

## 4. Surface-format separability in the `syslog` channel

`journal` events are routed to the `syslog` channel (`src/security_gym/envs/log_stream_env.py:123`). Two tests on the 30-day stream:

Hostname token (`raw_line LIKE '% isildur %'`):

| Source | Label | With token | Without token |
|---|---|---:|---:|
| `auth_log` | benign | 3,614 | 0 |
| `auth_log` | malicious | 6,424 | 0 |
| `syslog` | benign | 0 | 325 |
| `syslog` | malicious | 256 | 0 |
| `journal` | malicious | 0 | 26,459 |
| `web_access` | benign | 0 | 493,735 |
| `web_access` | malicious | 0 | 4,501 |

JSON-format lines (`raw_line LIKE '{%'`): `journal` malicious 26,459 of 26,459; `syslog` benign 0 of 325; `syslog` malicious 0 of 256.

Samples. Benign syslog: `May 20 19:08:27 clock-setup: rdate: adjust local clock by 75235016.224164 seconds`. Malicious syslog: `Mar  1 17:17:01 isildur CRON[1365]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)`. Malicious journal: `{"SYSLOG_IDENTIFIER":"audit","_AUDIT_TYPE":"1112",...,"_HOSTNAME":"isildur",...}`.

The `auth_log` scrub is symmetric (both classes carry the hostname); the `syslog` scrub is not (benign lines lack it, malicious lines have it). Every benign line in the channel is a BSD-format line without a hostname; every malicious line is either a JSON export or a BSD line with `isildur`. A rule reading the first character of a line and the fourth whitespace-delimited token classifies the channel without error.

## 5. Did the shipped detectors read the leak?

- `examples/keyword_agent.py:40-82`: regexes on semantic content (`Failed password for`, `authentication failure`, `\$\{jndi:`, `execve.*parent_comm=`, and others). None matches JSON structure or a hostname token.
- rlsecd `src/rlsecd/tracking/state_builder.py:15-21`: twelve features (`ip_reputation`, `auth_attempts_1min`, `auth_attempts_5min`, `unique_usernames`, `password_vs_key`, `known_user`, four time-of-day and day-of-week terms, `session_count_24h`, `success_rate`), derived from parsed `event_type`, not from line text.

Neither read the format directly, so the published log-only figures are not products of this leak. They were produced on channels whose class balance (Section 3) and filtered benign background make the detection problem easy; the caveat that the scored population is the attributed 6.5% of events still applies. Any text-mode agent, including an LLM, would see the leak on first inspection.

## 6. Implications

1. Statements that the corpus's non-stationarity "comes from the data" and that the long streams offer "a year of telemetry" hold only for the `web_access` channel of the 365-day stream. The kernel channels are periodic by construction; a null plasticity result on them is uninterpretable.
2. The `syslog` channel leak is the same defect class as eBPF address presence and the asymmetric session (a source or format present in one class only), reached directly through the observation rather than indirectly through the target slate.
3. The benign `auth_log` background is unrealistically quiet because `MaliciousFilter` removed real scanner traffic during the benign build; the campaigns then supply the only failed logins.
4. The window-anchoring rule is a composer design flaw independent of the data and is fixable with a window-selection policy (register D16).
5. Journal and hostname symmetry are resolved by construction if benign and attack telemetry are collected on the same host through the same journald and scrub (register D3, D17); for the legacy corpus they are not fixable without re-scrubbing.

## 7. Recommended checks for the validator

A per-source class-presence check (no source present in only one class) and a per-source surface-format report by class (line prefix class, hostname token presence, JSON prefix) would have caught journal, hostname, and eBPF address presence alike. These belong beside the semantic kernel-label checks (H5) of the kernel-label audit.

## 8. Limitations

- The 365-day stream was not scanned; cycle counts for it are arithmetic from the spans (`duration / (span + 1 s)`).
- Hostname detection used the literal token ` isildur `; journald JSON carries the hostname as `"_HOSTNAME":"isildur"` and is counted separately under the JSON test.
- Whether other text-mode agents or experiments outside this repository consumed the `syslog` channel was not checked.

## 9. Reproduction

```sql
-- Native span and count by source (benign_v4.db)
SELECT source, MIN(timestamp), MAX(timestamp), COUNT(*) FROM events GROUP BY source;
-- Distribution of long-span sources
SELECT substr(timestamp,1,4) y, COUNT(*) FROM events WHERE source='web_access' GROUP BY y ORDER BY y;
SELECT source, substr(timestamp,1,7) m, COUNT(*) FROM events
  WHERE source IN ('auth_log','syslog') GROUP BY source, m ORDER BY source, m;
-- Composed stream contents by source and label (exp_7d_brute_v4.db, exp_30d_heavy_v4.db)
SELECT source, is_malicious, COUNT(*) FROM events GROUP BY source, is_malicious ORDER BY source, is_malicious;
SELECT * FROM composition_meta;
-- Surface-format tests (exp_30d_heavy_v4.db)
SELECT source, is_malicious,
       SUM(CASE WHEN raw_line LIKE '% isildur %' THEN 1 ELSE 0 END) AS with_host,
       SUM(CASE WHEN raw_line LIKE '% isildur %' THEN 0 ELSE 1 END) AS without_host
  FROM events WHERE source IN ('auth_log','syslog','journal','web_access')
  GROUP BY source, is_malicious;
SELECT source, is_malicious, SUM(CASE WHEN raw_line LIKE '{%' THEN 1 ELSE 0 END), COUNT(*)
  FROM events WHERE source IN ('syslog','journal') GROUP BY source, is_malicious;
-- Benign journal in the corpus (benign_v4.db)
SELECT COUNT(*) FROM events WHERE source='journal';
```

Code references: `src/security_gym/data/composer.py:257-287` (`_cycle_source`), `:156-185` (`_downsample_ebpf`, hash key at `:180`), `:577` (downsample precedes composition), `:380-416` (`_stream_compose_to_db`, per-source generators); `src/security_gym/envs/log_stream_env.py:115-124` (`_SOURCE_TO_CHANNEL`).
