#!/usr/bin/env python3
"""Multi-channel keyword heuristic agent for SecurityLogStream-Text-v0.

A stronger rule-based agent that scans ALL text channels for suspicious
patterns — not just auth_log. Represents what a well-tuned SIEM rule set
achieves without learning.

Detection rules (applied per-step to all channels):
  - auth_log: failed SSH auth, invalid user, preauth disconnect
  - web_log: JNDI injection, SQL injection, path traversal, scanner UAs
  - process_events: suspicious parent→child (sshd→bash, redis-server→sh),
    known attack tools (nmap, wget from unusual parents, curl pipes)
  - network_events: connections from non-daemon UIDs to unusual ports
  - file_events: access to sensitive paths (/etc/shadow, /etc/passwd,
    /proc/*/cmdline from server processes)

Scoring: each rule hit increments a per-step threat score. If the score
exceeds --alert-threshold, alert. If it exceeds --block-threshold, block.

Usage:
    python examples/keyword_agent.py data/exp_7d_brute_v4.db
    python examples/keyword_agent.py data/exp_30d_heavy_v4.db --max-steps 1000000
"""

from __future__ import annotations

import argparse
import re
import time

import gymnasium as gym
import numpy as np

import security_gym  # noqa: F401 — registers envs

# ── Detection rules per channel ─────────────────────────────────────

# auth_log: SSH brute force, credential stuffing, preauth failures
_AUTH_RULES = [
    (re.compile(r"Failed password for"), 2),
    (re.compile(r"Invalid user"), 2),
    (re.compile(r"Connection closed by.*\[preauth\]"), 1),
    (re.compile(r"authentication failure"), 2),
    (re.compile(r"maximum authentication attempts exceeded"), 3),
    (re.compile(r"Bad protocol version"), 1),
]

# web_log: injection attacks, scanners, exploit attempts
_WEB_RULES = [
    (re.compile(r"\$\{jndi:", re.IGNORECASE), 5),       # Log4Shell
    (re.compile(r"UNION\s+SELECT", re.IGNORECASE), 4),  # SQLi
    (re.compile(r"\.\./\.\./"), 3),                       # path traversal
    (re.compile(r"(?:nmap|nikto|sqlmap|masscan)", re.IGNORECASE), 3),  # scanner UAs
    (re.compile(r'"\s*(?:4\d{2})\s'), 1),                # 4xx errors (probing)
    (re.compile(r"(?:etc/passwd|etc/shadow|proc/self)"), 4),  # file inclusion
]

# process_events: suspicious execve chains and attack tools
_PROCESS_RULES = [
    # Server process spawning a shell — strong signal for RCE
    (re.compile(r"execve.*parent_comm=(?:redis-server|nginx|apache2|java)"), 5),
    # sshd spawning interactive commands (post-auth execution)
    (re.compile(r"execve.*parent_comm=sshd.*comm=(?:bash|sh|dash|wget|curl|python)"), 3),
    # Known recon/attack tools
    (re.compile(r"execve.*comm=(?:nmap|masscan|nikto|sqlmap|hydra|john)"), 4),
    # Suspicious download from a server process
    (re.compile(r"execve.*comm=(?:wget|curl).*parent_comm=(?:redis-server|nginx|java)"), 5),
    # Exit code 255 (SSH auth failure)
    (re.compile(r"exit.*code=255"), 1),
]

# network_events: unusual connections
_NETWORK_RULES = [
    # Accepts on unusual ports (not 22, 80, 443, 6379) from non-root
    (re.compile(r"connect.*uid=(?!0\b)\d+.*comm=(?!(?:apt|curl|wget)\b)"), 1),
]

# file_events: access to sensitive files from server processes
_FILE_RULES = [
    (re.compile(r"open.*comm=(?:redis-server|nginx|java).*path=/etc/(?:passwd|shadow)"), 4),
    (re.compile(r"open.*comm=(?:redis-server|nginx|java).*path=/proc/\d+/cmdline"), 3),
    (re.compile(r"unlink"), 1),  # file deletion — mildly suspicious
]

_CHANNEL_RULES = {
    "auth_log": _AUTH_RULES,
    "web_log": _WEB_RULES,
    "process_events": _PROCESS_RULES,
    "network_events": _NETWORK_RULES,
    "file_events": _FILE_RULES,
}

# Map event source to observation channel (same as env)
_SOURCE_TO_CHANNEL = {
    "auth_log": "auth_log",
    "syslog": "syslog",
    "web_access": "web_log",
    "web_error": "web_log",
    "ebpf_process": "process_events",
    "ebpf_network": "network_events",
    "ebpf_file": "file_events",
    "journal": "syslog",
}


def score_current_event(obs: dict[str, str], source: str) -> float:
    """Score only the most recent line in the relevant channel."""
    channel = _SOURCE_TO_CHANNEL.get(source, "syslog")
    rules = _CHANNEL_RULES.get(channel)
    if not rules:
        return 0.0
    text = obs.get(channel, "")
    if not text:
        return 0.0
    # Only check the last line (most recent event in ring buffer)
    last_line = text.rsplit("\n", 1)[-1]
    total = 0.0
    for pattern, weight in rules:
        if pattern.search(last_line):
            total += weight
    return total


def run(
    db_path: str,
    alert_threshold: float = 2.0,
    block_threshold: float = 5.0,
    max_steps: int | None = None,
    seed: int = 42,
) -> dict:
    """Run the keyword heuristic agent and return metrics."""
    env = gym.make("SecurityLogStream-Text-v0", db_path=db_path)
    obs, info = env.reset(seed=seed)

    total_reward = 0.0
    steps = 0
    tp = fp = tn = fn = 0
    blocked_ips: set[str] = set()

    t0 = time.perf_counter()

    while True:
        gt = info["ground_truth"]
        is_mal = gt["is_malicious"]
        src_ip = info.get("src_ip")

        source = info.get("source", "")
        threat_score = score_current_event(obs, source)

        # Decision
        if threat_score >= block_threshold and src_ip:
            action_id = 3  # block_source
            blocked_ips.add(src_ip)
            risk = min(10.0, threat_score)
        elif threat_score >= alert_threshold:
            action_id = 1  # alert
            risk = min(10.0, threat_score)
        else:
            action_id = 0  # pass
            risk = min(10.0, threat_score)

        action = {
            "action": action_id,
            "risk_score": np.array([risk], dtype=np.float32),
        }

        obs, reward, terminated, truncated, info = env.step(action)
        total_reward += reward
        steps += 1

        acted = action_id in (1, 2, 3, 5)
        if is_mal and acted:
            tp += 1
        elif is_mal and not acted:
            fn += 1
        elif not is_mal and acted:
            fp += 1
        else:
            tn += 1

        if truncated or (max_steps and steps >= max_steps):
            break

    elapsed = time.perf_counter() - t0
    env.close()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "agent": f"keyword(a={alert_threshold},b={block_threshold})",
        "steps": steps,
        "total_reward": total_reward,
        "mean_reward": total_reward / steps if steps else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "elapsed_s": elapsed,
        "events_per_s": steps / elapsed if elapsed > 0 else 0.0,
        "ips_blocked": len(blocked_ips),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-channel keyword heuristic agent")
    parser.add_argument("db_path", help="Path to experiment stream DB")
    parser.add_argument("--alert-threshold", type=float, default=2.0,
                        help="Threat score to trigger alert (default: 2.0)")
    parser.add_argument("--block-threshold", type=float, default=5.0,
                        help="Threat score to trigger block (default: 5.0)")
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    results = run(args.db_path, args.alert_threshold, args.block_threshold,
                  args.max_steps, args.seed)

    print(f"\n{'Keyword Heuristic Agent':=^60}")
    print(f"  Config:      alert={args.alert_threshold}, block={args.block_threshold}")
    print(f"  Steps:       {results['steps']:,}")
    print(f"  Elapsed:     {results['elapsed_s']:.1f}s ({results['events_per_s']:,.0f} evt/s)")
    print(f"  Total reward: {results['total_reward']:,.1f}")
    print(f"  Mean reward:  {results['mean_reward']:.4f}")
    print(f"  Precision:   {results['precision']:.4f}")
    print(f"  Recall:      {results['recall']:.4f}")
    print(f"  F1:          {results['f1']:.4f}")
    print(f"  TP={results['tp']:,}  FP={results['fp']:,}  TN={results['tn']:,}  FN={results['fn']:,}")
    print(f"  IPs blocked: {results['ips_blocked']}")


if __name__ == "__main__":
    main()
