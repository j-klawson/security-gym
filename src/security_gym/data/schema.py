"""SQLite schema for security-gym event storage."""

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    source        TEXT NOT NULL,
    raw_line      TEXT NOT NULL,
    parsed        TEXT,

    -- Ground truth (NULL for unlabeled/benign)
    is_malicious  INTEGER,
    campaign_id   TEXT,
    attack_type   TEXT,
    attack_stage  TEXT,
    severity      INTEGER,

    -- Session linkage
    session_id    TEXT,
    src_ip        TEXT,
    username      TEXT,
    service       TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);

CREATE TABLE IF NOT EXISTS campaigns (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    start_time    TEXT NOT NULL,
    end_time      TEXT,
    attack_type   TEXT NOT NULL,
    mitre_tactics TEXT,
    description   TEXT,
    parameters    TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    src_ip        TEXT NOT NULL,
    start_time    TEXT NOT NULL,
    end_time      TEXT,
    service       TEXT,
    is_malicious  INTEGER,
    campaign_id   TEXT REFERENCES campaigns(id),
    event_count   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""
