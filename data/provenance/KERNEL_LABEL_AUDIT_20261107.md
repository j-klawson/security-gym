# Kernel-Event Label Audit: Window-Based Labeling Misattributes eBPF Events in Both Directions

Date: 2026-11-07; updated 2026-11-08 for handoff to the gym refactoring session. Scope: `campaigns_v2.db` (source campaigns) and `exp_30d_heavy.db` (v3 composed stream). The measurements in Sections 1 to 7 change no artifact. Recommendations appear only in the Handoff Brief, and every decision in it remains with the author.

## Handoff Brief

Status: the audit is complete and no source code, database, or published artifact has been modified. The branch `feat/test-scripts` holds this note and `scripts/gym_usage_demo.py` only. The databases are in `~/repos/research/security-gym/data/` on the MacBook (`lappy`); the v4 streams are on `hopper` and were not scanned.

### H1. Established (verified against data or code in this session)

1. The labeling rule is time-window plus attacker-address membership, with address-less events labeled on the window alone (`attacks/collection/labeler.py:120-127`; the isolation premise is stated at line 40).
2. The composer loads only `is_malicious = 1` rows from a campaign database (`src/security_gym/data/composer.py:142`), so any attack-caused event labeled benign never reaches a composed stream. The same module copies the attacker `src_ip` and a synthetic `session_id` onto attack eBPF events only (lines 199 to 237), which is Phase 14 defects 1 and 6.
3. The parser derives `src_ip` for `connect` events from the `dst=` field (`src/security_gym/parsers/ebpf.py:87-89`), so the byte-reversed destination (defect 4) becomes the event address that the labeler tests.
4. Counts in Sections 3 and 4, and the log-channel finding in H2 below.

### H2. New log-channel finding (not in Sections 3 to 4)

Five `web_access` events in `campaign_220423a6360f` (ids 29535 to 29539, all at 2026-03-01T22:52:24Z, from attacker addresses 192.168.2.111, .112, .115, two of them carrying a `${jndi:ldap://...}` string) are labeled benign, against 345 labeled malicious across the two Log4Shell campaigns (345 + 5 = 350, which matches the 350 Log4Shell requests recorded in the byte-order note). The attacker address is a member of the phase set, so the address test passes; the likely cause is the event falling just after the phase `end_time`, but the phase window was not inspected. This is a 1.43% mislabel rate on the Log4Shell web channel (5 of 350). It qualifies the statement that log-only results are unaffected: the effect is small but not zero.

### H3. Not established

1. Process-level attribution of the "system service reaction" tier (22.70% to 47.56% of malicious kernel events by channel). This needs a pid and parent-pid join and has not been run.
2. Whether the 80 Java callbacks satisfy the time test as well as the address test.
3. What the 166 `sshd` `connect` events to `0.0.0.0:22` are. They occur in every campaign, including recon-only runs.
4. Whether the `tmux:` events are the experimenter's own terminal (measurement apparatus) or host activity.
5. Direction 2 shares on the v4 streams (run on `hopper`).
6. The cause of the 5 labeled-benign Log4Shell requests in H2.

### H4. Recommended work, in order (author decides each)

1. Decide the corpus policy first, because it fixes what the remaining items must produce. The options are relabel in place, drop the affected events with documentation, or document as a known limitation. This note does not choose.
2. If relabeling or dropping, replace the address test with a process-ancestry test: events are attack-caused when their pid descends from a process the campaign started (the attacker `sshd` child, then `bash`, then the command), plus connections whose destination is in the attacker set under either octet order for pre-2026-08-28 data. This removes dependence on `src_ip` for kernel events and addresses the 80 callbacks, the 6 `wget` lookups, and the time-window inheritance of unrelated background.
3. Treat the third-party connection case (8.8.8.8:53 from a `wget` the attacker ran) as an ancestry result, not an address result; byte-order correction does not help it.
4. Inspect the phase windows for `campaign_220423a6360f` and decide whether to pad window ends; this resolves H2.
5. Make `StreamComposer` carry attack-caused events regardless of label once the labeler is correct (`composer.py:142` currently filters on the label).
6. Add a semantic kernel-label check to `scripts/validate_labels.py`, using the acceptance checks in H5.
7. Recompose and rerun the diagnostic for Exp 13 only after items 2 to 5 land, since label noise compounds defects 1 and 6.

### H5. Acceptance checks for any fix (run against `campaigns_v2.db`)

1. The 80 `comm=java` `connect` events to port 1389 are labeled malicious.
2. The 6 `comm=wget` `connect` events to `8.8.8.8:53` in `campaign_e269a921f580` are labeled malicious.
3. The 5 `web_access` events ids 29535 to 29539 are labeled malicious.
4. The 54 `cron`, 33 `systemd-udevd`, and 29 `tmux:` `ebpf_file` events and the 1 `cron` `ebpf_process` event are not labeled malicious.
5. No regression on log events: the 308 malicious `auth_log`, 1,336 malicious `journal`, and 345 (or 350, after check 3) malicious `web_access` rows keep their labels.
6. Re-running the Section 4 tier script (Appendix A) reports the unrelated-background tier at zero.

### H6. Replaying the observations with the demo script

`scripts/gym_usage_demo.py` shows what the agent receives. Event id N is loop step N - 1; use `--start-at` three steps before the target.

```bash
# first malicious event in the 7-day v3 stream (id 10820, sshd opening libcrypt)
python3 scripts/gym_usage_demo.py ~/repos/research/security-gym/data/exp_7d_brute.db --show-obs --start-at 10816 --steps 12
# full post-auth session in the 30-day v3 stream (ids 2745 to 3770, ends in the failed wget)
python3 scripts/gym_usage_demo.py ~/repos/research/security-gym/data/exp_30d_heavy.db --show-obs --start-at 3727 --steps 25
# first Log4Shell sequence in the 30-day v3 stream (ids 411 to 642; no Java callback present)
python3 scripts/gym_usage_demo.py ~/repos/research/security-gym/data/exp_30d_heavy.db --show-obs --start-at 407 --steps 20
```

The demo script reads labels from `info["ground_truth"]` only for display; the agent observation carries none. After a labeler or composer change, the composed streams are stale, so these step numbers will move.

## 1. Summary

The ground-truth labels on eBPF kernel events are assigned by a time-window rule that is correct for log events and unreliable for kernel events. Two failure directions are measured.

1. Attack-caused kernel events labeled benign. At least 86 `ebpf_network` `connect` events (80 Log4Shell JNDI callbacks and 6 payload-download DNS lookups) are labeled benign in `campaigns_v2.db`. A further 350 nginx proxy connections into the vulnerable container are labeled benign and are arguably attack-caused. None of the 602 addressed `ebpf_network` events in scope is labeled malicious.
2. Unrelated or only indirectly related kernel events labeled malicious. In `campaigns_v2.db`, 116 of 26,946 malicious `ebpf_file` events (0.43%) and 1 of 864 malicious `ebpf_process` events come from background processes (`cron`, `tmux`, `systemd-udevd`) that no campaign started. A further 22.70% of malicious `ebpf_file` events and 43.62% of malicious `ebpf_network` events come from system services (`systemd`, `systemd-journal`, `systemd-logind`, `dbus-daemon`) whose attribution cannot be settled by process name alone.

The counts are exhaustive enumerations of the databases, not samples, so no inferential statistics apply; all shares are descriptive.

## 2. Labeling Rule

`attacks/collection/labeler.py`, `CampaignLabeler._event_matches_window` (line 120) labels an event malicious when its timestamp lies inside a phase window and, if the event carries a `src_ip`, that address belongs to the phase's attacker set (lines 125 to 127). An event with no `src_ip` is labeled on the time window alone. The class docstring (line 40) justifies the benign default by stating that the target host is isolated, so non-attack events are known-benign by construction.

Two consequences follow for kernel events.

- Events without an address (`openat`, `execve`, `exit`, `accept`) inherit the label of whatever campaign window contains them, regardless of which process produced them. Any host activity in the window, including activity unrelated to the campaign, is labeled malicious.
- Events with an address are labeled malicious only if the address is an attacker address. An attack-caused connection to any other address (a container, a DNS resolver, an attacker callback whose octets are reversed by Phase 14 defect 4) is labeled benign.

The isolation premise is false for `cron`, `tmux`, `systemd-udevd`, and the measurement apparatus itself.

## 3. Direction 1: Attack-Caused Events Labeled Benign

Source: `campaigns_v2.db`, excluding the aborted campaign `campaign_f1e3fd24735f` (1 event). All benign `ebpf_network` events with a destination address, grouped by process and destination (the full benign set is 699 events; the remaining 97 are addressless `accept` events from `systemd` (64), `dbus-daemon` (32), and `nginx` (1), and are outside this table).

| Process | Destination as recorded | Destination after octet reversal | Events | Campaign context | Attack-caused |
|---|---|---|---:|---|---|
| `java` | `111.2.168.192:1389` and four siblings | `192.168.2.111:1389` and siblings (attacker LDAP listeners) | 80 | Log4Shell Only (32); Full Recon, SSH, Log4Shell (48) | Yes (JNDI callback) |
| `wget` | `8.8.8.8:53` | unchanged (palindromic) | 6 | Full Kill Chain, post-auth phase | Yes (payload download lookup) |
| `nginx` | `3.0.18.172:8080` | `172.18.0.3:8080` (Log4Shell container) | 350 | Both Log4Shell campaigns | Arguably (proxy hop for each exploit request) |
| `sshd` | `0.0.0.0:22` | unchanged | 166 | all campaigns | Not determined |

Total addressed `ebpf_network` events in scope: 602 (80 + 6 + 350 + 166), all benign; the database as a whole holds 603 because the aborted run adds one further `sshd` event. Unambiguously attack-caused and benign-labeled: 86 of 602 (14.29%). Including the nginx proxy hop: 436 of 602 (72.43%). The 166 `sshd` rows are `connect` events to `0.0.0.0:22` spread across every campaign including recon-only runs; they are not classified here.

Observations that bear on cause.

- The `java` destinations are the attacker addresses with octets reversed. No `ebpf_network` event anywhere in the database has an unreversed attacker address in `src_ip`, so no event could satisfy the address test. Whether the 80 callbacks would also satisfy the time test was not separately checked.
- The `wget` lookups carry a correctly ordered address (`8.8.8.8` is invariant under reversal). They are labeled benign because 8.8.8.8 is not an attacker address. Byte order is therefore not the only cause; the rule cannot label any outbound connection to a third party.
- In `exp_30d_heavy.db` there are 0 events with `comm=java`. The composer transplants malicious-labeled sessions only, so the 80 callbacks never reach the composed stream. The composed Log4Shell stage retains the `web_access` JNDI requests and addressless nginx `accept` events, with no kernel evidence of exploitation.

Replay of a Log4Shell excerpt (`campaigns_v2.db`, 22:22:21 to 22:22:24 UTC on 2026-03-01):

```
22:22:21.965  ebpf_network  benign     connect pid=738 comm=java dst=111.2.168.192:1389
22:22:22.792  ebpf_network  malicious  accept  pid=878 comm=nginx
22:22:22.993  ebpf_network  benign     connect pid=878 comm=nginx dst=3.0.18.172:8080
22:22:23.395  ebpf_network  benign     connect pid=738 comm=java dst=114.2.168.192:1389
```

## 4. Direction 2: Events Labeled Malicious by Window Membership

Malicious kernel events grouped by process name (`comm=`) into three tiers. The tier sets are a heuristic chosen for this audit, not a ground truth:

- Unrelated background: `cron`, `CRON`, `tmux:`, `systemd-udevd`.
- System service reaction: `systemd`, `systemd-journal`, `systemd-logind`, `dbus-daemon`. These respond to attacker-created sessions (for example `systemd-journal` records login metadata) but also act on all other host activity in the window; attribution needs a pid-level join that was not performed.
- Attributable by process name: everything else (`sshd`, `bash`, `sh`, `env`, `run-parts`, the enumeration binaries, `nginx`, `redis-server`, `java`, `wget`).

`exit` lines carry no `comm=` and cannot be tiered.

`campaigns_v2.db` (excluding the aborted campaign):

| Channel | Malicious events | Attributable | System service reaction | Unrelated background | No `comm` (exit) |
|---|---:|---:|---:|---:|---:|
| `ebpf_process` | 864 | 391 (45.25%) | 0 | 1 (0.12%) | 472 (54.63%) |
| `ebpf_file` | 26,946 | 20,712 (76.86%) | 6,118 (22.70%) | 116 (0.43%) | 0 |
| `ebpf_network` | 619 | 349 (56.38%) | 270 (43.62%) | 0 | 0 |

`exp_30d_heavy.db` (v3 composed stream):

| Channel | Malicious events | Attributable | System service reaction | Unrelated background | No `comm` (exit) |
|---|---:|---:|---:|---:|---:|
| `ebpf_process` | 14,751 | 6,280 (42.57%) | 0 | 13 (0.09%) | 8,458 (57.34%) |
| `ebpf_file` | 448,583 | 329,623 (73.48%) | 116,673 (26.01%) | 2,287 (0.51%) | 0 |
| `ebpf_network` | 11,534 | 6,048 (52.44%) | 5,486 (47.56%) | 0 | 0 |

Detail for the unrelated-background tier: `cron` (54), `systemd-udevd` (33), `tmux:` (29) in the source database; `systemd-udevd` (928), `cron` (702), `tmux:` (657) in the composed stream. The `tmux:` events are most plausibly the experimenter's own terminal session during collection, which would make them measurement apparatus rather than host background; this was not verified. In the composed stream the `ebpf_network` "system service reaction" rows are all addressless `accept` events from `systemd` (5,295) and `dbus-daemon` (191).

The unrelated-background share is small (at most 0.51% of any channel). The system-service share is large (22.70% to 47.56%), and its correct attribution is the open question for any kernel-channel result.

## 5. Interaction With Other Phase 14 Defects

- Defect 4 (byte-reversed IPv4): directly causes the 80 `java` callbacks to fail the address test. It does not explain the 6 `wget` lookups or the 350 nginx hops.
- Defect 5 (`accept` carries no peer address): leaves all 619 malicious `ebpf_network` events addressless, so they are labeled by time alone. Together with Direction 1, the malicious network class contains no correctly addressed event and the benign class contains the attack-caused connections.
- Defect 1 and 6 (sessionization and address-presence asymmetry): independent of this audit, and compounding. A label-noise estimate does not remove the separability of attack from benign eBPF by key structure.
- The label validator (`scripts/validate_labels.py`) passes both databases because its checks test internal consistency (label coherence, campaign boundaries, temporal order, session coherence). None tests whether a labeled event is semantically part of the attack.

## 6. Limitations

- Process names are a coarse proxy for attribution. A pid and parent-pid join against the labeled `execve` chain would sharpen Direction 2 and was not done.
- Direction 1 counts only events visible in the database. Attack-caused kernel events that the collector did not record (for example container-internal activity, or a `connect` that did not fire) cannot be counted.
- The composed stream `exp_30d_heavy.db` is the v3 stream. The v4 streams (`exp_*_v4.db`) were not scanned; they compose from the same `campaigns_v2.db`, so Direction 1 carries over, and the Direction 2 shares should be close but are not measured.
- `sshd` `connect` events to `0.0.0.0:22` (166 in scope) are left unclassified.
- The attacker IP set was taken from malicious `auth_log` and `web_access` events (25 addresses), not from the campaign YAML or `AttackResult.source_ips`.

## 7. Reproduction

Counts in Section 3 were produced against `data/campaigns_v2.db` opened read-only. Core queries:

```sql
-- Addressed vs addressless benign ebpf_network events, by process and destination
SELECT campaign_id, raw_line FROM events
WHERE source='ebpf_network' AND is_malicious=0 AND campaign_id != 'campaign_f1e3fd24735f';

-- Java callbacks and other port-1389 connections
SELECT is_malicious, COUNT(*) FROM events
WHERE source='ebpf_network' AND raw_line LIKE '%:1389' GROUP BY 1;

-- Nginx proxy hops into the Log4Shell container
SELECT is_malicious, COUNT(*) FROM events
WHERE source='ebpf_network' AND raw_line LIKE '%3.0.18.172:8080' GROUP BY 1;
```

Section 4 tiers were computed by extracting the `comm=` token from `raw_line` for every row with `is_malicious=1` in each of `ebpf_process`, `ebpf_file`, and `ebpf_network`, and assigning it to the tier sets in Section 4.

## 8. Open Items

Superseded by H3 and H4 in the Handoff Brief; retained for the original wording.

- Decide whether Direction 1 events should be relabeled, dropped from the corpus, or documented as a known limitation. This note does not recommend one.
- Perform the pid-ancestry attribution to resolve the system-service tier.
- Repeat the Section 4 scan on the v4 streams on `hopper`.
- Add a semantic label check (or a documented exclusion) so the validator reflects kernel-event attribution.

## Appendix A. Tier Script

Reproduces the Section 4 tables. Adjust `DATA` and the database list; the first entry excludes the aborted recon run.

```python
import collections
import re
import sqlite3

DATA = "/Users/keith/repos/research/security-gym/data"
BG = {"cron", "CRON", "tmux:", "systemd-udevd"}
SVC = {"systemd", "systemd-journal", "systemd-logind", "dbus-daemon"}


def tier(comm: str | None) -> str:
    if comm is None:
        return "exit (no comm)"
    if comm in BG:
        return "unrelated background"
    if comm in SVC:
        return "system service reaction"
    return "attributable by comm"


for name, excl in [("campaigns_v2.db", "campaign_f1e3fd24735f"), ("exp_30d_heavy.db", None)]:
    db = sqlite3.connect(f"file:{DATA}/{name}?mode=ro", uri=True)
    for src in ("ebpf_process", "ebpf_file", "ebpf_network"):
        sql = "SELECT raw_line FROM events WHERE is_malicious=1 AND source=?"
        args: tuple[str, ...] = (src,)
        if excl:
            sql += " AND campaign_id != ?"
            args += (excl,)
        counts: collections.Counter[str] = collections.Counter()
        rows = db.execute(sql, args).fetchall()
        for (raw,) in rows:
            m = re.search(r" comm=(\S+)", raw)
            counts[tier(m.group(1) if m else None)] += 1
        print(name, src, len(rows), dict(counts))
```
