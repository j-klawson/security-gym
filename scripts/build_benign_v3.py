#!/usr/bin/env python3
"""Build a reproducible benign dataset from server log tarballs.

Produces a clean EventStore database from raw log archives with malicious
traffic filtered out and PII scrubbed. Designed for building benign baseline
datasets for security-gym experiment composition.

Pipeline stages:
  0. Prep     — Record git SHA, create fresh DB
  1. Extract  — Untar each source to temp dirs, inventory files
  2. Parse    — Route files to parsers (reuse ParserRegistry)
  3. Filter   — Remove malicious traffic (MaliciousFilter)
  4. Scrub    — Replace PII (PIIScrubber)
  5. Insert   — Batch insert into output DB (is_malicious=0)
  6. eBPF     — Carry over eBPF events from prior DB (if available)
  7. Verify   — Automated PII/attack/sanity checks
  8. Report   — Write build report JSON

Supported log formats (auto-detected from file paths in tarballs):
  - auth.log (+ rotated .1, .2.gz, etc.)    → auth_log parser
  - syslog   (+ rotated)                     → syslog parser
  - nginx/access.log, nginx/error.log        → web_access / web_error
  - apache2/access.log, apache2/error.log    → web_access / web_error
  - apache2/*_access.log, *_error.log        → web_access / web_error (vhosts)

Usage — process your own server logs:

  # Basic: one server
  python scripts/build_benign_v3.py \\
      --source myserver:/path/to/myserver-var-log.tar \\
      --output data/benign.db

  # Multiple servers
  python scripts/build_benign_v3.py \\
      --source web1:/path/to/web1_logs.tar \\
      --source db1:/path/to/db1_logs.tar \\
      --source mail:/path/to/mail_logs.tar \\
      --output data/benign.db

  # With PII scrubbing (custom config)
  python scripts/build_benign_v3.py \\
      --source web1:/path/to/web1_logs.tar \\
      --scrub-config my_scrub.json \\
      --output data/benign.db

  # With eBPF carryover from multiple servers
  python scripts/build_benign_v3.py \\
      --source web1:/path/to/web1_logs.tar \\
      --ebpf-source data/ebpf_server1.db \\
      --ebpf-source data/ebpf_server2.db \\
      --ebpf-source data/ebpf_server3.db \\
      --output data/benign.db

  # Build + update composition configs + re-compose experiment streams
  python scripts/build_benign_v3.py \\
      --source web1:/path/to/web1_logs.tar \\
      --output data/benign_v3.db \\
      --compose

Scrub config JSON format:

  {
    "replacements": [
      ["real-hostname.example.com", "server1.example.com"],
      ["10.0.1.50", "198.51.100.1"]
    ],
    "hostname_regexes": [
      {
        "pattern": "(\\\\d{2}:\\\\d{2}:\\\\d{2}) myhostname ",
        "replacement": "\\\\1 server1 ",
        "label": "myhostname→server1"
      }
    ],
    "verify_patterns": ["real-hostname", "10.0.1.50"]
  }

  - replacements:      Ordered (old, new) pairs. Specific before generic.
                        Applied to raw_line, parsed JSON, and src_ip fields.
  - hostname_regexes:  For hostnames that are common words (e.g. "can", "web").
                        Only matches in syslog header position after timestamp.
  - verify_patterns:   Strings to search for after scrubbing. Any remaining
                        matches cause the PII verification check to FAIL.
  - Default config maps all sources to the campaign target server
    (isildur / 192.168.2.201) so benign + attack data appears as one host.
  - For custom configs, use RFC 1918 private IPs (e.g. 192.168.x.x)
    and .internal domains for realistic anonymous replacements.
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import re
import sqlite3
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Ensure parsers are registered before use
import security_gym  # noqa: F401
from security_gym.data.event_store import EventStore
from security_gym.parsers.base import ParsedEvent
from security_gym.parsers.registry import ParserRegistry

logger = logging.getLogger(__name__)

BATCH_SIZE = 5000

# ── File routing (extends attacks/collection/import_logs.py) ──────────────

FILE_ROUTES: list[tuple[str, str]] = [
    ("auth.log", "auth_log"),
    ("syslog", "syslog"),
    ("nginx/access.log", "web_access"),
    ("apache2/access.log", "web_access"),
    ("nginx/error.log", "web_error"),
    ("apache2/error.log", "web_error"),
]

SKIP_NAMES = {"journal", "btmp", "wtmp", "lastlog", "faillog"}


def _route_file(rel_path: str) -> str | None:
    """Return parser name for a file, or None to skip."""
    name = Path(rel_path).name

    if name in SKIP_NAMES:
        return None
    if "/journal/" in rel_path or rel_path.startswith("journal/"):
        return None

    for pattern, parser_name in FILE_ROUTES:
        if pattern in rel_path:
            return parser_name

    # Apache vhost-named logs (cod_access.log, ssl_access.log, ds_access.log, etc.)
    if "apache2/" in rel_path:
        if "_access.log" in name or "access.log" in name:
            return "web_access"
        if "_error.log" in name or "error.log" in name:
            return "web_error"

    return None


def _open_log_file(path: Path):
    """Open a log file, handling .gz compression transparently."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")  # noqa: SIM115


def _parse_file(path: Path, parser_name: str) -> list[ParsedEvent]:
    """Parse a single log file and return events."""
    parser = ParserRegistry.get(parser_name)
    events: list[ParsedEvent] = []
    errors = 0

    with _open_log_file(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue
            try:
                event = parser.parse_line(line)
                if event is not None:
                    events.append(event)
            except Exception:
                errors += 1
                if errors <= 5:
                    logger.debug("Parse error in %s line %d", path.name, line_num)

    if errors:
        logger.warning("%d parse errors in %s", errors, path.name)

    return events


# ── Malicious traffic filter ──────────────────────────────────────────────

# Case-insensitive patterns for web access log filtering
WEB_FILTER_RULES: dict[str, list[str]] = {
    "path_traversal": ["../", "..%2f", "..%252f"],
    "sqli": ["union select", "union+select", "' or", "1=1", "' and", "or+1=1"],
    "xss": ["<script", "javascript:", "%3cscript"],
    "jndi": ["${jndi:", "${lower:", "%24%7bjndi"],
    "shell_access": ["/etc/passwd", "/bin/sh", "cmd.exe", "powershell"],
    "rfi": ["auto_prepend_file", "auto_append_file", "allow_url_include"],
    "exploit_paths": [
        "/wp-login", "/.env", "/.git/", "/phpmyadmin",
        "/actuator", "/xmlrpc.php", "/cgi-bin/", "/wp-admin/",
        "/wp-content/", "/wp-includes/",
    ],
    "scanner_ua": [
        "nikto", "sqlmap", "nmap", "masscan", "zmeu",
        "dirbuster", "nuclei", "hydra", "gobuster",
    ],
    "suspicious_method": ["connect ", "trace ", "propfind "],
}

# Auth log filter patterns (case-insensitive substrings)
AUTH_FILTER_RULES: dict[str, list[str]] = {
    "failed_password": ["failed password"],
    "invalid_user": ["invalid user"],
    "auth_failure": ["authentication failure"],
    "preauth_close": ["[preauth]"],
    "max_auth": ["maximum authentication attempts"],
    "input_userauth_invalid": ["input_userauth_request: invalid user"],
}


@dataclass
class MaliciousFilter:
    """Filter malicious events. Returns (keep, rule_name) per event.

    Also accumulates source IPs from filtered events so that eBPF network
    events from the same attackers can be filtered during carryover.
    """

    hit_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    malicious_ips: set[str] = field(default_factory=set)

    def check(self, event: ParsedEvent) -> tuple[bool, str | None]:
        """Return (keep: bool, rule_name | None). False = filtered out."""
        source = event.source
        raw = event.raw_line.lower()

        if source == "web_access":
            for rule, patterns in WEB_FILTER_RULES.items():
                for pat in patterns:
                    if pat.lower() in raw:
                        self._count(source, rule)
                        self._track_ip(event)
                        return False, rule
            return True, None

        if source == "web_error":
            # Apply same web filters to error logs
            for rule, patterns in WEB_FILTER_RULES.items():
                for pat in patterns:
                    if pat.lower() in raw:
                        self._count(source, rule)
                        self._track_ip(event)
                        return False, rule
            return True, None

        if source == "auth_log":
            for rule, patterns in AUTH_FILTER_RULES.items():
                for pat in patterns:
                    if pat in raw:
                        self._count(source, rule)
                        self._track_ip(event)
                        return False, rule
            return True, None

        # syslog, ebpf_* — keep everything
        return True, None

    def _track_ip(self, event: ParsedEvent) -> None:
        """Record source IP from a filtered event for eBPF cross-reference."""
        if event.src_ip:
            self.malicious_ips.add(event.src_ip)

    def _count(self, source: str, rule: str) -> None:
        if source not in self.hit_counts:
            self.hit_counts[source] = {}
        self.hit_counts[source][rule] = self.hit_counts[source].get(rule, 0) + 1


# ── PII scrubber ──────────────────────────────────────────────────────────

@dataclass
class ScrubConfig:
    """PII scrubbing configuration loaded from JSON or built-in defaults."""
    replacements: list[tuple[str, str]]
    hostname_regexes: list[dict[str, str]]  # {pattern, replacement, label}
    verify_patterns: list[str]

    @classmethod
    def from_json(cls, path: Path) -> ScrubConfig:
        """Load scrub config from a JSON file."""
        data = json.loads(path.read_text())
        return cls(
            replacements=[(r[0], r[1]) for r in data.get("replacements", [])],
            hostname_regexes=data.get("hostname_regexes", []),
            verify_patterns=data.get("verify_patterns", []),
        )

    @classmethod
    def default(cls) -> ScrubConfig:
        """Built-in scrub config used to build the published benign_v3.db."""
        return cls(
            replacements=[
                # All sources mapped to match campaign target: isildur / 192.168.2.201
                # === sak server (Linode VPS) ===
                ("blog.9600baud.net", "blog.isildur.internal"),
                ("bsky-feeds.9600baud.net", "feeds.isildur.internal"),
                ("insights.9600baud.net", "insights.isildur.internal"),
                ("9600baud.net", "isildur.internal"),
                ("9600baud", "isildur"),  # catch URL paths like /images/9600baud-favicon.png
                ("keithlawson.me", "isildur.internal"),
                ("nowhere.ca", "isildur.internal"),
                ("172-105-102-54.cprapid.com", "isildur.internal"),
                ("172-105-102-54.ip.linodeusercontent.com", "isildur.internal"),
                ("172.105.102.54", "192.168.2.201"),
                # === dallas server ===
                ("198.58.109.204", "192.168.2.201"),
                # === can server ===
                ("can.libertas-tech.com", "isildur.internal"),
                ("libertas-tech.com", "isildur.internal"),
                # (isildur hostname/IP kept as-is — no replacement needed)
            ],
            hostname_regexes=[
                {
                    "pattern": r"(\d{2}:\d{2}:\d{2}) can ",
                    "replacement": r"\1 isildur ",
                    "label": "can→isildur (syslog header)",
                },
                {
                    "pattern": r"(\d{2}:\d{2}:\d{2}) dallas ",
                    "replacement": r"\1 isildur ",
                    "label": "dallas→isildur (syslog header)",
                },
            ],
            verify_patterns=[
                "9600baud", "keithlawson", "nowhere.ca", "libertas-tech",
                "172.105.102.54", "198.58.109.204",
            ],
        )

    @classmethod
    def empty(cls) -> ScrubConfig:
        """No-op scrub config — no replacements, no verification."""
        return cls(replacements=[], hostname_regexes=[], verify_patterns=[])


@dataclass
class PIIScrubber:
    """Ordered text replacements on raw_line + parsed JSON fields."""

    config: ScrubConfig
    counts: dict[str, int] = field(default_factory=dict)
    _compiled_regexes: list[tuple[re.Pattern, str, str]] = field(
        default_factory=list, init=False, repr=False,
    )

    def __post_init__(self) -> None:
        for entry in self.config.hostname_regexes:
            self._compiled_regexes.append((
                re.compile(entry["pattern"]),
                entry["replacement"],
                entry.get("label", entry["pattern"]),
            ))

    def scrub_event(self, event: ParsedEvent) -> ParsedEvent:
        """Return a new event with PII scrubbed from raw_line and fields."""
        raw = event.raw_line
        fields = dict(event.fields) if event.fields else {}
        fields_json = json.dumps(fields) if fields else ""

        # Apply ordered string replacements (case-insensitive)
        for old, new in self.config.replacements:
            ci_pattern = re.compile(re.escape(old), re.IGNORECASE)
            if ci_pattern.search(raw):
                raw = ci_pattern.sub(new, raw)
                self._count(f"{old}→{new}")
            if ci_pattern.search(fields_json):
                fields_json = ci_pattern.sub(new, fields_json)

        # Apply regex replacements (for hostnames that are common words)
        for compiled, replacement, label in self._compiled_regexes:
            if compiled.search(raw):
                raw = compiled.sub(replacement, raw)
                self._count(label)
            if compiled.search(fields_json):
                fields_json = compiled.sub(replacement, fields_json)

        # Rebuild fields from JSON
        if fields_json:
            fields = json.loads(fields_json)

        # Scrub structured fields
        src_ip = event.src_ip
        if src_ip:
            for old, new in self.config.replacements:
                if old == src_ip:
                    src_ip = new
                    break

        return ParsedEvent(
            timestamp=event.timestamp,
            source=event.source,
            raw_line=raw,
            event_type=event.event_type,
            fields=fields,
            src_ip=src_ip,
            username=event.username,
            service=event.service,
            session_id=event.session_id,
            pid=event.pid,
        )

    def _count(self, key: str) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1


# ── Verification ──────────────────────────────────────────────────────────

# Attack content that should NOT appear (spot-check)
ATTACK_CHECK_PATTERNS = [
    "Failed password", "Invalid user", "${jndi:",
    "UNION+SELECT", "../../../", "wp-login.php",
]


def _verify_db(db_path: Path, scrub_config: ScrubConfig) -> dict[str, str]:
    """Run verification checks on the final database. Returns check → PASS/FAIL."""
    results: dict[str, str] = {}
    conn = sqlite3.connect(str(db_path))

    # 1. PII absence — check scrub config's verify_patterns
    pii_clean = True
    if scrub_config.verify_patterns:
        for pattern in scrub_config.verify_patterns:
            count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE raw_line LIKE ? OR parsed LIKE ?",
                (f"%{pattern}%", f"%{pattern}%"),
            ).fetchone()[0]
            if count:
                logger.warning("PII check: %d rows still contain %r", count, pattern)
                pii_clean = False
        results["pii_absence"] = "PASS" if pii_clean else "FAIL"
    else:
        results["pii_absence"] = "SKIP (no verify_patterns configured)"

    # 2. No attack content
    attack_clean = True
    for pattern in ATTACK_CHECK_PATTERNS:
        count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE raw_line LIKE ?",
            (f"%{pattern}%",),
        ).fetchone()[0]
        if count:
            logger.warning("Attack check: %d rows contain %r", count, pattern)
            attack_clean = False
    results["no_attacks"] = "PASS" if attack_clean else "FAIL"

    # 3. Source distribution
    sources = [row[0] for row in conn.execute("SELECT DISTINCT source FROM events ORDER BY source")]
    results["source_distribution"] = "PASS"
    logger.info("Sources present: %s", sources)

    # 4. Temporal order (spot-check — count violations)
    violations = conn.execute(
        "SELECT COUNT(*) FROM events e1 "
        "JOIN events e2 ON e2.id = e1.id + 1 "
        "WHERE e1.timestamp > e2.timestamp"
    ).fetchone()[0]
    results["temporal_order"] = "PASS" if violations == 0 else f"WARN ({violations} violations)"
    if violations:
        logger.warning("Temporal order: %d violations", violations)

    # 5. All benign
    malicious = conn.execute(
        "SELECT COUNT(*) FROM events WHERE is_malicious != 0"
    ).fetchone()[0]
    results["all_benign"] = "PASS" if malicious == 0 else f"FAIL ({malicious} malicious)"

    # 6. Event count
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    results["event_count"] = str(total)

    conn.close()
    return results


# ── Builder ───────────────────────────────────────────────────────────────

@dataclass
class SourceConfig:
    """A tarball source to import."""
    name: str
    tarball: Path


@dataclass
class SourceStats:
    """Stats for a single source tarball."""
    tarball: str
    name: str
    files_parsed: int = 0
    events_parsed: int = 0
    events_filtered: int = 0
    events_kept: int = 0


class BenignV3Builder:
    """Orchestrates the full pipeline. Produces BuildReport."""

    def __init__(
        self,
        sources: list[SourceConfig],
        output_path: Path,
        scrub_config: ScrubConfig,
        ebpf_sources: list[Path] | None = None,
    ):
        self.sources = sources
        self.output_path = output_path
        self.scrub_config = scrub_config
        self.ebpf_sources = ebpf_sources or []
        self.mal_filter = MaliciousFilter()
        self.scrubber = PIIScrubber(config=scrub_config)
        self.source_stats: list[SourceStats] = []
        self.events_by_source: dict[str, int] = {}
        self.total_events = 0
        self.ebpf_events = 0
        self.ebpf_events_filtered = 0

    def build(self) -> dict:
        """Run full pipeline and return build report dict."""
        # Stage 0: Prep
        logger.info("Stage 0: Prep")
        git_sha = self._get_git_sha()
        if self.output_path.exists():
            self.output_path.unlink()
        logger.info("  Git SHA: %s", git_sha)
        logger.info("  Output: %s", self.output_path)

        # Stages 1-5: Extract → Parse → Filter → Scrub → Insert
        with EventStore(self.output_path, mode="w") as store:
            for source in self.sources:
                self._process_source(source, store)

        # Stage 6: eBPF carryover
        self._carryover_ebpf()

        # Stage 6b: Sort by timestamp (fix temporal order from multi-server merge)
        logger.info("Stage 6b: Sorting events by timestamp...")
        self._sort_by_timestamp()

        # Stage 7: Verify
        logger.info("Stage 7: Verify")
        verification = _verify_db(self.output_path, self.scrub_config)
        for check, result in verification.items():
            status = "PASS" if result == "PASS" else result
            logger.info("  %s: %s", check, status)

        # Stage 8: Report
        logger.info("Stage 8: Report")
        report = self._build_report(git_sha, verification)

        # Compact
        logger.info("VACUUMing database...")
        conn = sqlite3.connect(str(self.output_path))
        conn.execute("VACUUM")
        conn.close()

        return report

    def _process_source(self, source: SourceConfig, store: EventStore) -> None:
        """Process a single tarball: extract, parse, filter, scrub, insert."""
        stats = SourceStats(tarball=source.tarball.name, name=source.name)

        logger.info("Stage 1-5: Processing %s (%s)", source.name, source.tarball.name)

        with tempfile.TemporaryDirectory(prefix=f"benign_v3_{source.name}_") as tmp_dir:
            # Stage 1: Extract
            logger.info("  Extracting %s ...", source.tarball.name)
            with tarfile.open(source.tarball) as tf:
                while True:
                    try:
                        member = tf.next()
                    except tarfile.ReadError:
                        logger.warning("  Truncated tar archive, processing what was read")
                        break
                    if member is None:
                        break
                    if not member.isfile():
                        continue
                    try:
                        tf.extract(member, tmp_dir, filter="data")  # noqa: S202
                    except (tarfile.LinkOutsideDestinationError, tarfile.ReadError) as exc:
                        logger.debug("  Skipping tar member %s: %s", member.name, exc)

            root = Path(tmp_dir)

            # Stage 2: Route files to parsers
            file_plan: list[tuple[Path, str, str]] = []
            skipped = 0
            for file_path in sorted(root.rglob("*")):
                if not file_path.is_file():
                    continue
                rel = str(file_path.relative_to(root))
                parser_name = _route_file(rel)
                if parser_name is None:
                    skipped += 1
                    continue
                file_plan.append((file_path, rel, parser_name))

            logger.info("  Found %d parseable files (%d skipped)", len(file_plan), skipped)

            # Stages 2-5: Parse → Filter → Scrub → Insert (batched)
            batch: list[ParsedEvent] = []

            for file_path, rel, parser_name in file_plan:
                logger.info("  Parsing: %s → %s", rel, parser_name)
                events = _parse_file(file_path, parser_name)
                stats.files_parsed += 1
                stats.events_parsed += len(events)

                for event in events:
                    # Stage 3: Filter
                    keep, rule = self.mal_filter.check(event)
                    if not keep:
                        stats.events_filtered += 1
                        continue

                    # Stage 4: Scrub
                    event = self.scrubber.scrub_event(event)

                    batch.append(event)
                    stats.events_kept += 1

                    # Stage 5: Batch insert
                    while len(batch) >= BATCH_SIZE:
                        self._flush_batch(store, batch[:BATCH_SIZE])
                        batch = batch[BATCH_SIZE:]

            # Final partial batch
            if batch:
                self._flush_batch(store, batch)

        logger.info(
            "  %s: parsed=%d, filtered=%d, kept=%d",
            source.name, stats.events_parsed, stats.events_filtered, stats.events_kept,
        )
        self.source_stats.append(stats)

    def _flush_batch(self, store: EventStore, batch: list[ParsedEvent]) -> None:
        """Sort batch by timestamp and insert with benign labels."""
        batch.sort(key=lambda e: e.timestamp)
        ground_truths = [{"is_malicious": 0}] * len(batch)
        store.bulk_insert(batch, ground_truths)
        count = len(batch)
        self.total_events += count

        # Track per-source counts
        for event in batch:
            src = event.source
            self.events_by_source[src] = self.events_by_source.get(src, 0) + 1

        logger.debug("  Inserted batch of %d events (total: %d)", count, self.total_events)

    def _carryover_ebpf(self) -> None:
        """Stage 6: Carry over eBPF events from prior databases if available.

        Filters ebpf_network events whose src_ip matches IPs accumulated
        from malicious log events during stages 1-5. Process and file events
        pass through unfiltered.
        """
        logger.info("Stage 6: eBPF carryover")

        if not self.ebpf_sources:
            logger.info("  No eBPF sources specified, skipping")
            return

        if self.mal_filter.malicious_ips:
            logger.info("  Will filter ebpf_network events from %d known malicious IPs",
                        len(self.mal_filter.malicious_ips))

        for ebpf_source in self.ebpf_sources:
            self._carryover_single_ebpf(ebpf_source)

        logger.info("  eBPF totals: %d carried over, %d filtered",
                     self.ebpf_events, self.ebpf_events_filtered)

    def _carryover_single_ebpf(self, source_path: Path) -> None:
        """Carry over eBPF events from a single source DB."""
        ebpf_path = source_path
        temp_path = None

        # Handle .zst compressed source
        if ebpf_path.suffix == ".zst":
            if not ebpf_path.exists():
                logger.warning("  eBPF source not found: %s", ebpf_path)
                return
            logger.info("  Decompressing %s ...", ebpf_path.name)
            fd, temp_str = tempfile.mkstemp(suffix=".db", prefix="ebpf_src_")
            os.close(fd)
            temp_path = Path(temp_str)
            try:
                subprocess.run(
                    ["zstd", "-d", str(ebpf_path), "-o", str(temp_path)],
                    check=True, capture_output=True,
                )
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                logger.warning("  Failed to decompress: %s", exc)
                if temp_path.exists():
                    temp_path.unlink()
                return
            ebpf_path = temp_path

        if not ebpf_path.exists():
            logger.warning("  eBPF source not found: %s", ebpf_path)
            return

        try:
            # Read eBPF events from source
            src_conn = sqlite3.connect(str(ebpf_path))
            src_conn.row_factory = sqlite3.Row
            rows = src_conn.execute(
                "SELECT * FROM events "
                "WHERE source IN ('ebpf_process', 'ebpf_network', 'ebpf_file') "
                "AND is_malicious = 0"
            ).fetchall()
            src_conn.close()

            if not rows:
                logger.warning("  No eBPF events found in %s", source_path.name)
                return

            # Insert into output DB, filtering malicious IPs from network events
            dst_conn = sqlite3.connect(str(self.output_path))
            dst_conn.execute("PRAGMA journal_mode=WAL")

            inserted = 0
            filtered = 0
            for row in rows:
                # Filter ebpf_network events from known malicious IPs
                if (row["source"] == "ebpf_network"
                        and row["src_ip"]
                        and row["src_ip"] in self.mal_filter.malicious_ips):
                    filtered += 1
                    continue

                dst_conn.execute(
                    """INSERT INTO events
                       (timestamp, source, raw_line, parsed,
                        is_malicious, campaign_id, attack_type, attack_stage, severity,
                        session_id, src_ip, username, service)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        row["timestamp"], row["source"], row["raw_line"], row["parsed"],
                        0, None, None, None, None,
                        row["session_id"], row["src_ip"], row["username"], row["service"],
                    ),
                )
                inserted += 1

            dst_conn.commit()
            dst_conn.close()

            self.ebpf_events += inserted
            self.ebpf_events_filtered += filtered
            self.total_events += inserted

            # Track per-source counts
            for row in rows:
                if (row["source"] == "ebpf_network"
                        and row["src_ip"]
                        and row["src_ip"] in self.mal_filter.malicious_ips):
                    continue
                src = row["source"]
                self.events_by_source[src] = self.events_by_source.get(src, 0) + 1

            logger.info("  %s: %d eBPF events carried over (%d filtered)",
                        source_path.name, inserted, filtered)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink()

    def _sort_by_timestamp(self) -> None:
        """Re-order events table by timestamp so IDs follow temporal order."""
        conn = sqlite3.connect(str(self.output_path))
        conn.execute("PRAGMA journal_mode=WAL")

        count_before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        logger.info("  Sorting %d events by timestamp...", count_before)

        conn.executescript("""
            CREATE TABLE events_sorted AS
                SELECT timestamp, source, raw_line, parsed,
                       is_malicious, campaign_id, attack_type, attack_stage, severity,
                       session_id, src_ip, username, service
                FROM events
                ORDER BY timestamp, id;

            DROP TABLE events;

            CREATE TABLE events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                source        TEXT NOT NULL,
                raw_line      TEXT NOT NULL,
                parsed        TEXT,
                is_malicious  INTEGER,
                campaign_id   TEXT,
                attack_type   TEXT,
                attack_stage  TEXT,
                severity      INTEGER,
                session_id    TEXT,
                src_ip        TEXT,
                username      TEXT,
                service       TEXT
            );

            INSERT INTO events (timestamp, source, raw_line, parsed,
                               is_malicious, campaign_id, attack_type, attack_stage, severity,
                               session_id, src_ip, username, service)
                SELECT * FROM events_sorted;

            DROP TABLE events_sorted;
        """)

        count_after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert count_after == count_before, (
            f"Row count mismatch after sort: {count_before} → {count_after}"
        )

        conn.close()
        logger.info("  Done — %d events sorted", count_after)

    def _get_git_sha(self) -> str:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "unknown"

    def _build_report(self, git_sha: str, verification: dict) -> dict:
        """Build the audit report dict."""
        return {
            "build_date": datetime.now(timezone.utc).isoformat(),
            "git_sha": git_sha,
            "sources": [
                {
                    "tarball": s.tarball,
                    "name": s.name,
                    "files_parsed": s.files_parsed,
                    "events_parsed": s.events_parsed,
                    "events_filtered": s.events_filtered,
                    "events_kept": s.events_kept,
                }
                for s in self.source_stats
            ],
            "ebpf_events_carried_over": self.ebpf_events,
            "ebpf_events_filtered": self.ebpf_events_filtered,
            "filter_stats": dict(self.mal_filter.hit_counts),
            "scrub_stats": dict(self.scrubber.counts),
            "verification": verification,
            "final_counts": dict(self.events_by_source),
            "total_events": self.total_events,
        }


# ── CLI ───────────────────────────────────────────────────────────────────

def _parse_source(value: str) -> SourceConfig:
    """Parse a NAME:PATH source argument."""
    if ":" not in value:
        # Bare path — use tarball stem as name
        path = Path(value)
        name = path.stem.removesuffix("_logs").removesuffix("-logs").removesuffix("-var-log")
        return SourceConfig(name=name, tarball=path)

    name, path_str = value.split(":", 1)
    return SourceConfig(name=name, tarball=Path(path_str))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a reproducible benign dataset from server log tarballs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # Single server, no scrubbing
  %(prog)s --source myserver:/path/to/logs.tar --output data/benign.db --no-scrub

  # Multiple servers with custom scrub config
  %(prog)s --source web1:web1.tar --source db1:db1.tar --scrub-config scrub.json

  # Bare paths (name inferred from filename)
  %(prog)s --source /path/to/webserver_logs.tar --source /path/to/mailserver_logs.tar

supported log formats (auto-detected from paths inside tarballs):
  auth.log, syslog, nginx/{access,error}.log, apache2/{access,error}.log,
  apache2/*_{access,error}.log (vhosts), plus .gz rotated variants
""",
    )
    parser.add_argument(
        "--source", action="append", required=True, metavar="NAME:PATH",
        help="Server log tarball to import. NAME is a label for reporting "
             "(e.g. 'webserver'). PATH is the tarball. Can be repeated. "
             "If NAME: prefix is omitted, name is inferred from filename.",
    )
    parser.add_argument(
        "--scrub-config", type=Path, default=None, metavar="JSON",
        help="JSON file with PII scrubbing config (replacements, hostname "
             "regexes, verify patterns). See script docstring for format. "
             "If omitted, uses built-in defaults from the published dataset build.",
    )
    parser.add_argument(
        "--no-scrub", action="store_true",
        help="Disable PII scrubbing entirely. Use when your logs contain "
             "no PII or you'll scrub separately.",
    )
    parser.add_argument(
        "--ebpf-source", action="append", type=Path, default=[],
        help="Path to an EventStore DB (or .db.zst) containing eBPF kernel "
             "events to carry over. Can be repeated for multiple sources.",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("data/benign_v3.db"),
        help="Output database path (default: data/benign_v3.db)",
    )
    parser.add_argument(
        "--report", type=Path, default=None,
        help="Report JSON path (default: <output_dir>/build_benign_report.json)",
    )
    parser.add_argument(
        "--compose", action="store_true",
        help="After building, update composition configs to point at the new "
             "DB and re-compose all experiment streams.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    # Parse sources
    sources = [_parse_source(s) for s in args.source]

    # Validate inputs
    for src in sources:
        if not src.tarball.exists():
            parser.error(f"Source tarball not found: {src.tarball}")

    # Load scrub config
    if args.no_scrub:
        scrub_config = ScrubConfig.empty()
        logger.info("PII scrubbing disabled (--no-scrub)")
    elif args.scrub_config:
        scrub_config = ScrubConfig.from_json(args.scrub_config)
        logger.info("Loaded scrub config from %s (%d replacements, %d regexes, %d verify patterns)",
                     args.scrub_config, len(scrub_config.replacements),
                     len(scrub_config.hostname_regexes), len(scrub_config.verify_patterns))
    else:
        scrub_config = ScrubConfig.default()
        logger.info("Using built-in scrub config (for published dataset)")

    builder = BenignV3Builder(
        sources=sources,
        output_path=args.output,
        scrub_config=scrub_config,
        ebpf_sources=args.ebpf_source,
    )

    report = builder.build()

    # Write report
    report_path = args.report or args.output.parent / "build_benign_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    logger.info("Report written to %s", report_path)

    # Summary
    logger.info("─── Build Summary ───")
    logger.info("Total events:  %d", report["total_events"])
    for source, count in sorted(report["final_counts"].items()):
        logger.info("  %-15s %d", source, count)
    logger.info("Database:      %s", args.output)
    logger.info("Database size: %.1f MB", args.output.stat().st_size / 1_048_576)

    # Optional: update configs and re-compose
    if args.compose:
        _update_configs_and_compose(args.output)


def _update_configs_and_compose(output_db: Path) -> None:
    """Update composition configs to point at the new benign DB and re-compose."""
    config_dir = Path("configs")
    db_name = output_db.name
    configs = [
        "stream_7d_brute_only.yaml",
        "stream_30d_heavy.yaml",
        "stream_90d_mixed.yaml",
        "stream_365d_realistic.yaml",
    ]

    for config_name in configs:
        config_path = config_dir / config_name
        if not config_path.exists():
            logger.warning("Config not found: %s", config_path)
            continue

        text = config_path.read_text()
        # Replace any benign_v*.db reference with the new DB name
        import re as _re
        new_text = _re.sub(r"benign_v\d+\.db", db_name, text)
        if new_text != text:
            config_path.write_text(new_text)
            logger.info("Updated %s → %s", config_name, db_name)

    # Re-compose each stream
    for config_name in configs:
        config_path = config_dir / config_name
        if not config_path.exists():
            continue
        logger.info("Composing %s ...", config_name)
        subprocess.run(
            ["python3", "-m", "attacks", "compose", str(config_path)],
            check=True,
        )
        logger.info("  Done.")


if __name__ == "__main__":
    main()
