---
id: D20
title: Attribution policy for shared processes, system reactions, and background
status: open
affects: [SPEC-CORPUS 6, SPEC-CORPUS 12, SPEC-CORPUS 13, SPEC-ENV 8, SPEC-BENCH 5]
related: [D1, D9, D10, D12, D13, D19]
---
# D20. Attribution policy for shared processes, system reactions, and background

## Context

Under the 2026-11-09 capture architecture, every traffic generator registers with the recorder before it acts; when `accept4` returns a registered connection the accepting process (or thread) is marked, marks are inherited at `fork`, and log lines join to marks through their process ID (web lines through the registered client address and port). Capture-time marks settle which process an event came from. Three cases are not settled by that mechanism.

1. **Shared server processes.** `java` (Log4Shell) and `redis-server` serve benign and attack requests in one long-lived process; nginx workers and thread pools behave similarly. Process-level marks cannot divide work done inside such a process; thread-level marks help only where the accepting thread also handles the request.
2. **System reactions.** `systemd-logind`, `journald`, and `dbus-daemon` act because of an attack without descending from it. In the legacy corpus the system-service tier is 22.70% to 47.56% of malicious kernel events per channel (`data/provenance/KERNEL_LABEL_AUDIT_20261107.md` Section 4; the range spans `campaigns_v2.db` and the v3 30-day stream).
3. **Background.** Activity no generator registered (`cron`, systemd timers, kernel threads) has no owner. In the legacy corpus unrelated background is at most 0.51% of any channel (audit Section 4).

How these are classed affects the binary `is_malicious` contract of the environment, the reward tables (SPEC-ENV 8), and the control metrics (SPEC-BENCH 5).

## Options

Two decisions belong to the author.

**Definition of malicious.**

| Definition | Log4Shell `java` JNDI callback | `systemd-logind` creating the attacker's login session | `cron` job during an attack |
|---|---|---|---|
| Executes attacker-controlled code (descendants of the attacker's process) | benign | benign | benign |
| Would not have occurred without the attack (counterfactual) | malicious | malicious | benign |
| Tiered (direct, induced, unrelated), binary label derived per protocol | induced | induced | unrelated |

The tiered option records more in the corpus and defers the scoring choice to the protocol, so the corpus need not be re-recorded if the scoring rule changes; the other two fix the scoring choice at capture.

**Scoring of classes that are neither attack nor benign.** Induced, ambiguous, or background events may be scored as benign, scored as malicious, or excluded from reward and metrics. This interacts with D9 and D10 and may be settled there.

**Facts the agent can gather before the decision** (fact-finding, not decisions):

1. Process model of each service on the reference target: fork per connection (`sshd`), prefork pool (php-fpm), thread pool (the Log4Shell application), event loop (nginx workers, `redis-server`). This determines the size of the ambiguous class. Readable from `server/docker-compose.yml` and the images.
2. The process and parent-process join on `campaigns_v2.db` left undone by the kernel-label audit (open item H3.1), sizing direct descendants, reactions, and unrelated events.
3. Whether the Isildur kernel exposes the audit login-session identifier (`task->sessionid`, set by `pam_loginuid` and inherited across fork). If so, every process in an attacker's SSH session shares a kernel-assigned identifier, and `logind`'s "New session N" can be joined to it, which moves SSH reactions from the ambiguous case to the clean one. Requires the kernel configuration of Isildur (`CONFIG_AUDIT`).
4. Once benign drivers exist, the share of activity with no registered owner; drivers that install their own cron jobs own them, which shrinks the background class.

## Recommendation

None yet. The analysis proposes running the fact-finding in items 1 to 3 so that the definition of malicious is chosen against measured class sizes rather than examples.

## Decision

Open.

## Consequences

Gates the label schema of the corrected corpus (SPEC-CORPUS 12), the separability gate's class set (SPEC-CORPUS 13), and the control metrics' treatment of non-binary classes (SPEC-BENCH 5). Must be decided before the first recording is captured.
