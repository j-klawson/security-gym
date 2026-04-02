#!/usr/bin/env python3
"""Threshold heuristic agent for SecurityLogStream-v1.

A rule-based agent that parses auth_log text to detect SSH brute force
patterns and blocks source IPs after repeated failures. Represents what
a simple fail2ban-style policy achieves without any learning.

Rules:
  1. Track failed SSH auth attempts per source IP (pattern matching on
     "Failed password" / "Invalid user" in the auth_log channel).
  2. After `--threshold` failures from the same IP within `--window`
     seconds, block the IP.
  3. Set risk_score proportional to recent failure rate.
  4. For non-auth events, pass.

Usage:
    python examples/threshold_agent.py data/exp_7d_brute_v4.db
    python examples/threshold_agent.py data/exp_7d_brute_v4.db --threshold 5 --window 300
"""

from __future__ import annotations

import argparse
import collections
import re
import time

import gymnasium as gym
import numpy as np

import security_gym  # noqa: F401 — registers envs

# Patterns that indicate a failed SSH authentication attempt
_FAIL_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
    re.compile(r"Invalid user (\S+) from (\S+)"),
    re.compile(r"authentication failure.*rhost=(\S+)"),
    re.compile(r"Connection closed by (\S+).*\[preauth\]"),
]

# Patterns for successful auth (to set low risk)
_SUCCESS_PATTERNS = [
    re.compile(r"Accepted \S+ for \S+ from (\S+)"),
    re.compile(r"session opened for user"),
]


def extract_failures(auth_text: str) -> list[str]:
    """Extract source IPs from failed auth lines in the auth_log channel."""
    ips = []
    for line in auth_text.split("\n"):
        for pat in _FAIL_PATTERNS:
            m = pat.search(line)
            if m:
                # Last group is always the IP
                ips.append(m.group(m.lastindex))
                break
    return ips


def run(
    db_path: str,
    threshold: int = 5,
    window: float = 300.0,
    max_steps: int | None = None,
    seed: int = 42,
) -> dict:
    """Run the threshold agent and return metrics."""
    env = gym.make("SecurityLogStream-v1", db_path=db_path)
    obs, info = env.reset(seed=seed)

    # Per-IP failure timestamps (for windowed counting)
    ip_failures: dict[str, collections.deque] = collections.defaultdict(
        lambda: collections.deque()
    )
    blocked_ips: set[str] = set()

    total_reward = 0.0
    steps = 0
    tp = fp = tn = fn = 0

    t0 = time.perf_counter()

    while True:
        src_ip = info.get("src_ip")
        ts_str = info.get("timestamp", "")
        gt = info["ground_truth"]
        is_mal = gt["is_malicious"]

        # Parse new auth failures from the current auth_log text.
        # We use the full channel text — the ring buffer contains recent lines.
        auth_text = obs["auth_log"]
        # Only look at lines we haven't seen (simple: check last N chars)
        new_failures = extract_failures(auth_text)

        # Record failure timestamps
        try:
            now = float(time.mktime(time.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S")))
        except (ValueError, TypeError):
            now = 0.0

        for fail_ip in new_failures:
            ip_failures[fail_ip].append(now)
            # Expire old entries outside window
            while ip_failures[fail_ip] and (now - ip_failures[fail_ip][0]) > window:
                ip_failures[fail_ip].popleft()

        # Decision: should we act on the current event's source IP?
        action_id = 0  # default: pass
        risk = 0.0

        if src_ip and src_ip in blocked_ips:
            # Already blocked — pass (env handles the drop)
            action_id = 0
            risk = 8.0
        elif src_ip and len(ip_failures.get(src_ip, [])) >= threshold:
            # Threshold exceeded — block
            action_id = 3  # block_source
            blocked_ips.add(src_ip)
            risk = 9.0
        elif src_ip and len(ip_failures.get(src_ip, [])) >= threshold // 2:
            # Approaching threshold — alert
            action_id = 1  # alert
            risk = 5.0
        else:
            action_id = 0
            risk = 1.0 if new_failures else 0.0

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
        "agent": f"threshold(t={threshold},w={window:.0f})",
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
    parser = argparse.ArgumentParser(description="Threshold heuristic agent")
    parser.add_argument("db_path", help="Path to experiment stream DB")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts before blocking (default: 5)")
    parser.add_argument("--window", type=float, default=300.0,
                        help="Time window in seconds (default: 300)")
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    results = run(args.db_path, args.threshold, args.window, args.max_steps, args.seed)

    print(f"\n{'Threshold Agent Baseline':=^60}")
    print(f"  Config:      threshold={args.threshold}, window={args.window:.0f}s")
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
