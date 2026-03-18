"""eBPF event field extraction and numeric encoding for structured channels.

Converts parsed JSON fields from eBPF kernel events into fixed-width float32
rows suitable for StructuredRingBuffer / Box observation spaces.
"""

from __future__ import annotations

import math

import mmh3
import numpy as np

# ── Syscall enum ────────────────────────────────────────────────────────

SYSCALL_MAP: dict[str, int] = {
    "execve": 1,
    "exit": 2,
    "fork": 3,
    "connect": 4,
    "accept": 5,
    "bind": 6,
    "close": 7,
    "open": 8,
    "write": 9,
    "unlink": 10,
}

# ── Per-field hash seeds (prevent cross-channel aliasing) ───────────────

SEED_COMM = 0
SEED_IP = 1
SEED_PATH = 2

# ── Flag bitmask mapping ───────────────────────────────────────────────

_FLAG_BITS: dict[str, int] = {
    "O_RDONLY": 0,
    "O_WRONLY": 1,
    "O_RDWR": 2,
    "O_CREAT": 64,
    "O_EXCL": 128,
    "O_TRUNC": 512,
    "O_APPEND": 1024,
    "O_NONBLOCK": 2048,
}

# ── Channel widths ──────────────────────────────────────────────────────

PROCESS_COLS = 8
NETWORK_COLS = 7
FILE_COLS = 6


# ── Encoding helpers ────────────────────────────────────────────────────

def hash_string(s: str, seed: int = 0) -> np.float32:
    """Hash a string to an unsigned float32 via mmh3."""
    h = mmh3.hash(s, seed=seed, signed=False)
    return np.float32(h)


def encode_syscall(event_type: str | None) -> float:
    """Map event_type string to syscall enum integer."""
    if event_type is None:
        return 0.0
    return float(SYSCALL_MAP.get(event_type, 0))


def parse_ip_port(addr: str | None) -> tuple[np.float32, float]:
    """Parse 'ip:port' string into (ip_hash, port_float).

    Returns (0.0, 0.0) for None or malformed input.
    """
    if not addr:
        return np.float32(0.0), 0.0
    parts = addr.rsplit(":", 1)
    if len(parts) != 2:
        return hash_string(addr, seed=SEED_IP), 0.0
    ip_str, port_str = parts
    ip_hash = hash_string(ip_str, seed=SEED_IP)
    try:
        port = float(port_str)
    except ValueError:
        port = 0.0
    return ip_hash, port


def encode_flags(flags_str: str | None) -> float:
    """Encode pipe-separated flags string to bitmask integer.

    Example: "O_WRONLY|O_CREAT" → float(1 | 64) = 65.0
    """
    if not flags_str:
        return 0.0
    result = 0
    for flag in flags_str.split("|"):
        flag = flag.strip()
        result |= _FLAG_BITS.get(flag, 0)
    return float(result)


def log_delta(dt_seconds: float) -> float:
    """Log-scaled timestamp delta: log(1 + dt) for stable gradients."""
    return math.log1p(max(0.0, dt_seconds))


# ── Row extraction functions ────────────────────────────────────────────

def extract_process_row(
    parsed: dict, ts_delta: float, depth: int = 0,
) -> np.ndarray:
    """Extract (8,) float32 row from parsed process event.

    Schema: [log_delta, pid, ppid, uid, syscall_type, comm_hash,
             parent_comm_hash, tree_depth]
    """
    row = np.zeros(PROCESS_COLS, dtype=np.float32)
    row[0] = log_delta(ts_delta)
    row[1] = float(parsed.get("pid", 0))
    row[2] = float(parsed.get("ppid", 0))
    row[3] = float(parsed.get("uid", 0))
    row[4] = encode_syscall(parsed.get("event_type"))
    comm = parsed.get("comm")
    row[5] = hash_string(comm, seed=SEED_COMM) if comm else np.float32(0.0)
    parent_comm = parsed.get("parent_comm")
    row[6] = hash_string(parent_comm, seed=SEED_COMM) if parent_comm else np.float32(0.0)
    row[7] = float(depth)
    return row


def extract_network_row(parsed: dict, ts_delta: float) -> np.ndarray:
    """Extract (7,) float32 row from parsed network event.

    Schema: [log_delta, pid, uid, syscall_type, dst_ip_hash, dst_port,
             comm_hash]
    """
    row = np.zeros(NETWORK_COLS, dtype=np.float32)
    row[0] = log_delta(ts_delta)
    row[1] = float(parsed.get("pid", 0))
    row[2] = float(parsed.get("uid", 0))
    row[3] = encode_syscall(parsed.get("event_type"))
    ip_hash, port = parse_ip_port(parsed.get("dst"))
    row[4] = ip_hash
    row[5] = port
    comm = parsed.get("comm")
    row[6] = hash_string(comm, seed=SEED_COMM) if comm else np.float32(0.0)
    return row


def extract_file_row(parsed: dict, ts_delta: float) -> np.ndarray:
    """Extract (6,) float32 row from parsed file event.

    Schema: [log_delta, pid, uid, syscall_type, flags_int, path_hash]
    """
    row = np.zeros(FILE_COLS, dtype=np.float32)
    row[0] = log_delta(ts_delta)
    row[1] = float(parsed.get("pid", 0))
    row[2] = float(parsed.get("uid", 0))
    row[3] = encode_syscall(parsed.get("event_type"))
    row[4] = encode_flags(parsed.get("flags"))
    path = parsed.get("path")
    row[5] = hash_string(path, seed=SEED_PATH) if path else np.float32(0.0)
    return row
