#!/usr/bin/env python3
"""Validate label accuracy in EventStore databases.

Runs 9 checks against any EventStore DB and produces a PASS/FAIL report.
Catches labeling errors before they corrupt experiment results.

Usage:
    python scripts/validate_labels.py data/campaigns.db
    python scripts/validate_labels.py data/exp01_90d.db --spot-check 20 --verbose
    python scripts/validate_labels.py data/benign.db --check no_unlabeled_events --check label_consistency
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path


# ── Result tracking ──────────────────────────────────────────────────

class CheckResult:
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"

    def __init__(self, name: str, status: str, detail: str = ""):
        self.name = name
        self.status = status
        self.detail = detail

    def __str__(self) -> str:
        tag = f"[{self.status}]"
        s = f"{tag:6s} {self.name}"
        if self.detail:
            s += "\n" + self.detail
        return s


# ── Individual checks ────────────────────────────────────────────────

def check_label_consistency(conn: sqlite3.Connection, verbose: bool) -> CheckResult:
    """1. Every is_malicious=1 must have attack_type, attack_stage, severity.
    Every is_malicious=0 must have attack_type=NULL and attack_stage=NULL."""
    name = "1. Label Consistency"

    # Malicious missing labels
    row = conn.execute(
        """SELECT COUNT(*) FROM events
           WHERE is_malicious = 1
             AND (attack_type IS NULL OR attack_stage IS NULL OR severity IS NULL)"""
    ).fetchone()
    mal_missing = row[0]

    # Benign with labels
    row = conn.execute(
        """SELECT COUNT(*) FROM events
           WHERE is_malicious = 0
             AND (attack_type IS NOT NULL OR attack_stage IS NOT NULL)"""
    ).fetchone()
    benign_labeled = row[0]

    issues = []
    if mal_missing:
        issues.append(f"  {mal_missing} malicious events missing attack_type/attack_stage/severity")
    if benign_labeled:
        issues.append(f"  {benign_labeled} benign events have attack_type or attack_stage set")

    if issues:
        return CheckResult(name, CheckResult.FAIL, "\n".join(issues))
    return CheckResult(name, CheckResult.PASS)


def check_raw_line_spot_checks(
    conn: sqlite3.Connection, verbose: bool, spot_check_n: int,
) -> CheckResult:
    """2. Sample malicious events per attack type and regex-match raw lines."""
    name = f"2. Raw Line Spot-Checks ({spot_check_n}/type)"

    # Expected patterns per attack type
    patterns = {
        "brute_force": [
            r"(?i)Failed password",
            r"(?i)Invalid user",
            r"(?i)res=failed",
            r"(?i)authentication failure",
            r"(?i)Connection closed.*preauth",
            r"(?i)Disconnected from",
        ],
        "credential_stuffing": [
            r"(?i)Failed password",
            r"(?i)Invalid user",
            r"(?i)res=failed",
            r"(?i)authentication failure",
            r"(?i)Accepted password",
            r"(?i)Connection closed.*preauth",
            r"(?i)Disconnected from",
            r"(?i)systemd",
            r"(?i)session opened",
            r"(?i)pam_unix",
        ],
        "web_exploit": [
            r"\$\{jndi:",
            r"(?i)jndi:ldap://",
            r"(?i)python-requests",
            r"(?i)/\?x=",
        ],
        "discovery": [
            r"(?i)systemd",
            r"(?i)session opened",
            r"(?i)Accepted password",
            r"(?i)pam_unix",
            r"(?i)SYN",
            r"(?i)connection",
        ],
        "execution": [
            r"(?i)Accepted password",
            r"(?i)session opened",
            r"(?i)Started User",
            r"(?i)pam_unix",
            r"(?i)New session",
            # Journal JSON events from post-auth execution
            r"(?i)_AUDIT_TYPE",
            r"(?i)_CMDLINE",
            r"(?i)EXECVE",
            r"(?i)session_finalize",
            r"(?i)User Runtime Directory",
            r"(?i)user-\d+\.slice",
            r"(?i)research_exploit",
            r"(?i)\"MESSAGE\"",
            r"(?i)session-\d+\.scope",
        ],
    }

    # Get attack types present in the DB
    rows = conn.execute(
        "SELECT DISTINCT attack_type FROM events WHERE is_malicious = 1 AND attack_type IS NOT NULL"
    ).fetchall()
    attack_types = [r[0] for r in rows]

    if not attack_types:
        return CheckResult(name, CheckResult.SKIP, "  No malicious events found")

    detail_lines = []
    all_pass = True
    any_fail = False

    for atype in sorted(attack_types):
        if atype not in patterns:
            detail_lines.append(f"  {atype}: no patterns defined (skipped)")
            continue

        regexes = [re.compile(p) for p in patterns[atype]]

        samples = conn.execute(
            "SELECT raw_line FROM events WHERE is_malicious = 1 AND attack_type = ? ORDER BY RANDOM() LIMIT ?",
            (atype, spot_check_n),
        ).fetchall()

        matches = 0
        for (raw_line,) in samples:
            if any(rx.search(raw_line) for rx in regexes):
                matches += 1

        total = len(samples)
        pct = (matches / total * 100) if total else 0
        status_tag = ""
        if pct < 60:
            any_fail = True
            status_tag = " [FAIL]"
        elif pct < 80:
            all_pass = False
            status_tag = " [WARN]"

        detail_lines.append(f"  {atype}: {matches}/{total} ({pct:.0f}%){status_tag}")

        if verbose and matches < total:
            # Show some non-matching lines
            for (raw_line,) in samples:
                if not any(rx.search(raw_line) for rx in regexes):
                    detail_lines.append(f"    unmatched: {raw_line[:120]}")

    detail = "\n".join(detail_lines)
    if any_fail:
        return CheckResult(name, CheckResult.FAIL, detail)
    if not all_pass:
        return CheckResult(name, CheckResult.WARN, detail)
    return CheckResult(name, CheckResult.PASS, detail)


def check_campaign_boundaries(conn: sqlite3.Connection, verbose: bool) -> CheckResult:
    """3. Malicious events with campaign_id must fall within campaign start/end times."""
    name = "3. Campaign Boundary Events"

    # Check if campaigns table has data
    count = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    if count == 0:
        return CheckResult(name, CheckResult.SKIP, "  No campaigns table data (composed stream)")

    # Events outside their campaign's time range
    row = conn.execute(
        """SELECT COUNT(*) FROM events e
           JOIN campaigns c ON e.campaign_id = c.id
           WHERE e.is_malicious = 1
             AND (e.timestamp < c.start_time
                  OR (c.end_time IS NOT NULL AND e.timestamp > c.end_time))"""
    ).fetchone()
    out_of_bounds = row[0]

    if out_of_bounds:
        detail = f"  {out_of_bounds} malicious events fall outside their campaign's time range"
        if verbose:
            rows = conn.execute(
                """SELECT e.id, e.timestamp, e.campaign_id, c.start_time, c.end_time
                   FROM events e JOIN campaigns c ON e.campaign_id = c.id
                   WHERE e.is_malicious = 1
                     AND (e.timestamp < c.start_time
                          OR (c.end_time IS NOT NULL AND e.timestamp > c.end_time))
                   LIMIT 5"""
            ).fetchall()
            for r in rows:
                detail += f"\n    event {r[0]}: ts={r[1]}, campaign={r[2]} ({r[3]} to {r[4]})"
        return CheckResult(name, CheckResult.FAIL, detail)
    return CheckResult(name, CheckResult.PASS)


def check_campaign_type_crossval(conn: sqlite3.Connection, verbose: bool) -> CheckResult:
    """4. Events' attack_type must match their campaign's declared attack_type.

    Multi-phase campaigns may have comma-separated attack_type (e.g.
    "discovery, brute_force, web_exploit"). An event matches if its type
    appears anywhere in the campaign's type list.
    """
    name = "4. Campaign Type Cross-Validation"

    count = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    if count == 0:
        return CheckResult(name, CheckResult.SKIP, "  No campaigns table data (composed stream)")

    # Build a set of allowed types per campaign
    campaigns = conn.execute("SELECT id, attack_type FROM campaigns").fetchall()
    campaign_types: dict[str, set[str]] = {}
    for cid, ctype in campaigns:
        campaign_types[cid] = {t.strip() for t in ctype.split(",")}

    # Check each malicious event with a campaign_id
    rows = conn.execute(
        """SELECT e.id, e.attack_type, e.campaign_id
           FROM events e
           WHERE e.is_malicious = 1 AND e.campaign_id IS NOT NULL"""
    ).fetchall()

    mismatched = []
    for eid, etype, cid in rows:
        allowed = campaign_types.get(cid)
        if allowed is None:
            # campaign_id references a campaign not in the table — flag it
            mismatched.append((eid, etype, cid, "unknown campaign"))
        elif etype not in allowed:
            mismatched.append((eid, etype, cid, ", ".join(sorted(allowed))))

    if mismatched:
        detail = f"  {len(mismatched)} events have attack_type not in their campaign's type list"
        if verbose:
            for eid, etype, cid, allowed in mismatched[:5]:
                detail += f"\n    event {eid}: type={etype}, campaign allows [{allowed}] (campaign {cid})"
        return CheckResult(name, CheckResult.FAIL, detail)
    return CheckResult(name, CheckResult.PASS)


def check_target_array_consistency(
    conn: sqlite3.Connection, verbose: bool, db_path: Path, sample_size: int,
) -> CheckResult:
    """5. Load via SecurityGymStream.collect_numpy() and verify NaN masking."""
    name = "5. Target Array Consistency"

    try:
        from security_gym.adapters.scan_stream import SecurityGymStream
    except ImportError:
        return CheckResult(name, CheckResult.SKIP, "  security_gym not installed")

    stream = SecurityGymStream(db_path)
    _, ground_truths = stream.collect_numpy(limit=sample_size)

    if len(ground_truths) == 0:
        return CheckResult(name, CheckResult.SKIP, "  No events to check")

    issues = []
    n = len(ground_truths)

    n_malicious = sum(1 for gt in ground_truths if gt["is_malicious"])
    n_benign = n - n_malicious

    # Benign events should have no attack_type or attack_stage
    benign_with_type = sum(
        1 for gt in ground_truths
        if not gt["is_malicious"] and gt.get("attack_type") is not None
    )
    if benign_with_type > 0:
        issues.append(f"  {benign_with_type} benign events have non-null attack_type")

    benign_with_stage = sum(
        1 for gt in ground_truths
        if not gt["is_malicious"] and gt.get("attack_stage") is not None
    )
    if benign_with_stage > 0:
        issues.append(f"  {benign_with_stage} benign events have non-null attack_stage")

    # Malicious events should have attack_type and attack_stage
    mal_no_type = sum(
        1 for gt in ground_truths
        if gt["is_malicious"] and gt.get("attack_type") is None
    )
    if mal_no_type > 0:
        issues.append(f"  {mal_no_type} malicious events missing attack_type")

    mal_no_stage = sum(
        1 for gt in ground_truths
        if gt["is_malicious"] and gt.get("attack_stage") is None
    )
    if mal_no_stage > 0:
        issues.append(f"  {mal_no_stage} malicious events missing attack_stage")

    # true_risk should be in [0.0, 10.0]
    out_of_range = sum(
        1 for gt in ground_truths
        if not (0.0 <= gt.get("true_risk", 0.0) <= 10.0)
    )
    if out_of_range > 0:
        issues.append(f"  {out_of_range} events have true_risk outside [0.0, 10.0]")

    detail = f"  Checked {n} events ({n_malicious} malicious, {n_benign} benign)"

    if issues:
        detail += "\n" + "\n".join(issues)
        return CheckResult(name, CheckResult.FAIL, detail)
    return CheckResult(name, CheckResult.PASS, detail)


def check_attack_type_distribution(conn: sqlite3.Connection, verbose: bool) -> CheckResult:
    """6. Compare actual attack type proportions against composition_meta.distribution."""
    name = "6. Attack Type Distribution"

    # Check if this is a composed stream
    row = conn.execute(
        "SELECT value FROM composition_meta WHERE key = 'distribution'"
    ).fetchone()
    if row is None:
        return CheckResult(name, CheckResult.SKIP, "  No composition_meta.distribution (not a composed stream)")

    expected_dist = json.loads(row[0])

    # Actual counts
    rows = conn.execute(
        """SELECT attack_type, COUNT(*) FROM events
           WHERE is_malicious = 1 AND attack_type IS NOT NULL
           GROUP BY attack_type"""
    ).fetchall()

    if not rows:
        return CheckResult(name, CheckResult.SKIP, "  No malicious events in composed stream")

    actual_counts = {r[0]: r[1] for r in rows}
    total_actual = sum(actual_counts.values())

    missing_types: list[str] = []
    skewed: list[str] = []
    detail_lines = []

    for atype, expected_prop in sorted(expected_dist.items()):
        actual_count = actual_counts.get(atype, 0)
        actual_prop = actual_count / total_actual if total_actual else 0

        # 2x tolerance — event counts depend on pool sizes, session sampling
        lower = expected_prop / 2.0
        upper = min(expected_prop * 2.0, 1.0)

        status = ""
        if actual_count == 0 and expected_prop > 0:
            missing_types.append(atype)
            status = " [FAIL]"
        elif actual_prop < lower or actual_prop > upper:
            skewed.append(atype)
            status = " [WARN]"

        detail_lines.append(
            f"  {atype}: {actual_count} events ({actual_prop:.1%}), expected ~{expected_prop:.1%}{status}"
        )

    # Only FAIL for completely missing types. Proportion skew is expected
    # because campaigns produce very different event counts per type
    # (brute_force ~800 events/campaign vs discovery ~18).
    detail = "\n".join(detail_lines)
    if missing_types:
        detail += f"\n  Missing types: {', '.join(missing_types)}"
        return CheckResult(name, CheckResult.FAIL, detail)
    if skewed:
        detail += f"\n  Skewed types (expected — campaign weights control frequency, not event count): {', '.join(skewed)}"
        return CheckResult(name, CheckResult.WARN, detail)
    return CheckResult(name, CheckResult.PASS, detail)


def check_temporal_order(conn: sqlite3.Connection, verbose: bool) -> CheckResult:
    """7. Events ordered by id must have monotonically non-decreasing timestamps."""
    name = "7. Temporal Order"

    row = conn.execute(
        """SELECT COUNT(*) FROM (
               SELECT id, timestamp,
                      LAG(timestamp) OVER (ORDER BY id) AS prev_ts
               FROM events
           ) WHERE prev_ts IS NOT NULL AND timestamp < prev_ts"""
    ).fetchone()
    violations = row[0]

    if violations:
        detail = f"  {violations} events have timestamps earlier than their predecessor"
        if verbose:
            rows = conn.execute(
                """SELECT id, timestamp, prev_ts FROM (
                       SELECT id, timestamp,
                              LAG(timestamp) OVER (ORDER BY id) AS prev_ts
                       FROM events
                   ) WHERE prev_ts IS NOT NULL AND timestamp < prev_ts
                   LIMIT 5"""
            ).fetchall()
            for r in rows:
                detail += f"\n    event {r[0]}: {r[1]} < prev {r[2]}"
        return CheckResult(name, CheckResult.FAIL, detail)
    return CheckResult(name, CheckResult.PASS)


def check_no_unlabeled_events(conn: sqlite3.Connection, verbose: bool) -> CheckResult:
    """8. Every event must have is_malicious = 0 or 1 (not NULL)."""
    name = "8. No Unlabeled Events"

    row = conn.execute(
        "SELECT COUNT(*) FROM events WHERE is_malicious IS NULL"
    ).fetchone()
    unlabeled = row[0]

    if unlabeled:
        detail = f"  {unlabeled} events have is_malicious = NULL"
        if verbose:
            rows = conn.execute(
                "SELECT id, source, timestamp FROM events WHERE is_malicious IS NULL LIMIT 5"
            ).fetchall()
            for r in rows:
                detail += f"\n    event {r[0]}: source={r[1]}, ts={r[2]}"
        return CheckResult(name, CheckResult.FAIL, detail)
    return CheckResult(name, CheckResult.PASS)


def check_session_coherence(conn: sqlite3.Connection, verbose: bool) -> CheckResult:
    """9. All events sharing the same session_id must have the same is_malicious label."""
    name = "9. Session Coherence"

    rows = conn.execute(
        """SELECT session_id, COUNT(DISTINCT is_malicious) AS n_labels
           FROM events
           WHERE session_id IS NOT NULL
           GROUP BY session_id
           HAVING n_labels > 1"""
    ).fetchall()

    if rows:
        detail = f"  {len(rows)} sessions have mixed is_malicious labels"
        if verbose:
            for r in rows[:5]:
                sid = r[0]
                counts = conn.execute(
                    "SELECT is_malicious, COUNT(*) FROM events WHERE session_id = ? GROUP BY is_malicious",
                    (sid,),
                ).fetchall()
                label_str = ", ".join(f"is_malicious={c[0]}: {c[1]}" for c in counts)
                detail += f"\n    session {sid}: {label_str}"
        return CheckResult(name, CheckResult.FAIL, detail)
    return CheckResult(name, CheckResult.PASS)


# ── Registry ─────────────────────────────────────────────────────────

ALL_CHECKS = {
    "label_consistency": check_label_consistency,
    "raw_line_spot_checks": check_raw_line_spot_checks,
    "campaign_boundaries": check_campaign_boundaries,
    "campaign_type_crossval": check_campaign_type_crossval,
    "target_array_consistency": check_target_array_consistency,
    "attack_type_distribution": check_attack_type_distribution,
    "temporal_order": check_temporal_order,
    "no_unlabeled_events": check_no_unlabeled_events,
    "session_coherence": check_session_coherence,
}


# ── Main ─────────────────────────────────────────────────────────────

def run_validation(
    db_path: Path,
    checks: list[str] | None = None,
    spot_check_n: int = 10,
    sample_size: int = 10000,
    verbose: bool = False,
) -> list[CheckResult]:
    """Run validation checks against an EventStore DB."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    # Header stats
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    malicious = conn.execute(
        "SELECT COUNT(*) FROM events WHERE is_malicious = 1"
    ).fetchone()[0]
    benign = conn.execute(
        "SELECT COUNT(*) FROM events WHERE is_malicious = 0"
    ).fetchone()[0]

    print("=" * 48)
    print(f"  Label Validation: {db_path}")
    print(f"  Events: {total:,} | Malicious: {malicious:,} | Benign: {benign:,}")
    print("=" * 48)
    print()

    checks_to_run = checks or list(ALL_CHECKS.keys())
    results: list[CheckResult] = []

    for check_name in checks_to_run:
        func = ALL_CHECKS[check_name]

        # Checks with extra args
        if check_name == "raw_line_spot_checks":
            result = func(conn, verbose, spot_check_n)
        elif check_name == "target_array_consistency":
            result = func(conn, verbose, db_path, sample_size)
        else:
            result = func(conn, verbose)

        results.append(result)
        print(result)

    conn.close()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate label accuracy in EventStore databases.",
    )
    parser.add_argument("db_path", type=Path, help="Path to EventStore SQLite database")
    parser.add_argument(
        "--spot-check", type=int, default=10, metavar="N",
        help="Number of samples per attack type for raw line checks (default: 10)",
    )
    parser.add_argument(
        "--sample-size", type=int, default=10000, metavar="N",
        help="Max events for target array consistency check (default: 10000)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--check", action="append", metavar="NAME", dest="checks",
        help=f"Run only specified checks (repeatable). Available: {', '.join(ALL_CHECKS)}",
    )

    args = parser.parse_args()

    if not args.db_path.exists():
        print(f"Error: {args.db_path} not found")
        sys.exit(1)

    # Validate check names
    if args.checks:
        for name in args.checks:
            if name not in ALL_CHECKS:
                print(f"Error: unknown check {name!r}. Available: {', '.join(ALL_CHECKS)}")
                sys.exit(1)

    results = run_validation(
        db_path=args.db_path,
        checks=args.checks,
        spot_check_n=args.spot_check,
        sample_size=args.sample_size,
        verbose=args.verbose,
    )

    # Summary
    counts = {CheckResult.PASS: 0, CheckResult.FAIL: 0, CheckResult.WARN: 0, CheckResult.SKIP: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print()
    parts = []
    if counts[CheckResult.PASS]:
        parts.append(f"{counts[CheckResult.PASS]} PASS")
    if counts[CheckResult.WARN]:
        parts.append(f"{counts[CheckResult.WARN]} WARN")
    if counts[CheckResult.SKIP]:
        parts.append(f"{counts[CheckResult.SKIP]} SKIP")
    if counts[CheckResult.FAIL]:
        parts.append(f"{counts[CheckResult.FAIL]} FAIL")
    print(f"Summary: {' | '.join(parts)}")

    if counts[CheckResult.FAIL] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
