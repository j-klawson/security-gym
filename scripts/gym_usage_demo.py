#!/usr/bin/env python3
"""Runnable walkthrough of the basic Gymnasium usage shown in README.md.

Opens ``SecurityLogStream-Text-v0`` on an EventStore database, prints the
spaces and a sample observation, steps through the stream, and prints one line
per step (timestamp, ground truth, reward) followed by an episode summary.

Usage:
    python scripts/gym_usage_demo.py                       # data/exp_7d_brute_v4.db
    python scripts/gym_usage_demo.py path/to/stream.db     # any EventStore DB
    python scripts/gym_usage_demo.py --steps 100           # print more steps
    python scripts/gym_usage_demo.py --policy heuristic    # block on SSH failures
    python scripts/gym_usage_demo.py --show-obs            # also print the log lines delivered
    python scripts/gym_usage_demo.py --show-obs --start-at 5000   # skip ahead before printing
    python scripts/gym_usage_demo.py --synthetic           # no dataset needed

``--synthetic`` builds a small auth_log stream in a temporary directory (benign
logins plus one brute-force burst) so the script runs without downloading the
published streams. The synthetic stream is for exercising the API only; it is
not representative of the released corpus.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import gymnasium as gym
import numpy as np

import security_gym  # noqa: F401 — registers envs
from security_gym.data.event_store import EventStore
from security_gym.parsers.base import ParsedEvent

DEFAULT_DB = "data/exp_7d_brute_v4.db"
ENV_ID = "SecurityLogStream-Text-v0"

ACTION_NAMES = ("pass", "alert", "throttle", "block_source", "unblock", "isolate")
ACTION_PASS = 0
ACTION_BLOCK = 3
TARGET_CURRENT_EVENT = 0
FAILURE_MARKERS = ("Failed password", "Invalid user")


def build_synthetic_db(path: Path, n_benign: int = 120, n_attack: int = 60) -> Path:
    """Write a small mixed auth_log stream: benign logins, then a brute-force burst."""
    start = datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc)
    store = EventStore(path, mode="w")
    benign_ip, attacker_ip = "10.0.0.5", "203.0.113.50"

    def stamp(sec: int) -> str:
        t = start + timedelta(seconds=sec)
        return t.strftime("%b %d %H:%M:%S")

    # Interleave: the attack burst begins after the first third of the benign events.
    attack_begin = n_benign // 3
    sec = 0
    attack_i = 0
    for i in range(n_benign + n_attack):
        in_burst = attack_begin <= i < attack_begin + n_attack
        sec += 1
        if in_burst:
            ip, user, event_type = attacker_ip, "root", "auth_failure"
            raw = (f"{stamp(sec)} myhost sshd[200]: Failed password for root "
                   f"from {ip} port {40000 + attack_i} ssh2")
            gt: dict[str, Any] = {
                "is_malicious": 1, "campaign_id": "demo-campaign",
                "attack_type": "brute_force", "attack_stage": "initial_access",
                "severity": 2,
            }
            attack_i += 1
        else:
            ip, user, event_type = benign_ip, "admin", "auth_success"
            raw = (f"{stamp(sec)} myhost sshd[100]: Accepted password for admin "
                   f"from {ip} port {50000 + i} ssh2")
            gt = {"is_malicious": 0, "severity": 0}
        store.insert_event(
            ParsedEvent(
                timestamp=start + timedelta(seconds=sec),
                source="auth_log",
                raw_line=raw,
                event_type=event_type,
                fields={"event_type": event_type, "auth_method": "password"},
                src_ip=ip,
                username=user,
                service="sshd",
                session_id=f"{ip}:{sec}",
            ),
            gt,
        )
    store.flush()
    store.close()
    return path


def choose_action(policy: str, obs: dict[str, Any]) -> dict[str, Any]:
    """Return an action dict for the chosen policy.

    ``pass`` is the README baseline. ``heuristic`` blocks the current event's
    source whenever the newest auth_log line looks like an SSH failure; it
    exists to show a defensive action taking effect, not to be a good agent.
    """
    action = ACTION_PASS
    risk = 0.0
    if policy == "heuristic":
        lines = obs["auth_log"].splitlines()
        if lines and any(m in lines[-1] for m in FAILURE_MARKERS):
            action, risk = ACTION_BLOCK, 8.0
    return {
        "action": action,
        "risk_score": np.array([risk], dtype=np.float32),
        "target": TARGET_CURRENT_EVENT,
    }


TEXT_CHANNELS = ("auth_log", "syslog", "web_log", "process_events", "network_events", "file_events")
OBS_LINE_WIDTH = 200


def print_new_lines(prev: dict[str, str], obs: dict[str, Any]) -> None:
    """Print the newest line of each text channel whose ring buffer changed this step.

    The agent receives the whole ring buffer (the last ``tail_lines`` lines per
    channel); only the final line is new, so that is the one shown here. An
    event dropped by the defense layer leaves every channel unchanged.
    """
    changed = False
    for ch in TEXT_CHANNELS:
        text = obs[ch]
        if text != prev.get(ch, "") and text:
            line = text.splitlines()[-1]
            if len(line) > OBS_LINE_WIDTH:
                line = line[:OBS_LINE_WIDTH] + "..."
            print(f"    [{ch}] {line}")
            changed = True
        prev[ch] = text
    if not changed:
        print("    (no channel changed: event dropped by the defense layer or evicted from view)")


def run(
    db_path: str,
    steps_to_print: int,
    policy: str,
    max_steps: int | None,
    seed: int,
    show_obs: bool = False,
    start_at: int = 0,
) -> None:
    env = gym.make(ENV_ID, db_path=db_path)
    obs, info = env.reset(seed=seed)

    print(f"Environment : {ENV_ID}")
    print(f"Database    : {db_path}")
    print(f"Policy      : {policy}")
    print(f"Action space: {env.action_space}")
    print(f"Channels    : {', '.join(obs.keys())}")

    print("\n--- Initial observation ---")
    print("auth_log (first 200 chars):")
    print(obs["auth_log"][:200] or "(empty)")
    print(f"system_stats [load_avg, mem_used, disk_used]: {obs['system_stats']}")

    print(f"\n--- Stepping ({steps_to_print} steps printed, after skipping {start_at}) ---")
    total_reward = 0.0
    steps = 0
    malicious_seen = 0
    actions_taken = [0] * len(ACTION_NAMES)
    prev_obs: dict[str, str] = {ch: obs[ch] for ch in TEXT_CHANNELS}

    while True:
        action = choose_action(policy, obs)
        obs, reward, terminated, truncated, info = env.step(action)

        gt = info["ground_truth"]
        total_reward += float(reward)
        steps += 1
        malicious_seen += int(bool(gt["is_malicious"]))
        actions_taken[action["action"]] += 1

        printing = start_at < steps <= start_at + steps_to_print
        if not printing and show_obs:
            for ch in TEXT_CHANNELS:
                prev_obs[ch] = obs[ch]
        if printing:
            print(f"{info['timestamp']} | {ACTION_NAMES[action['action']]:<12} | "
                  f"malicious={gt['is_malicious']} | risk={gt['true_risk']:.1f} | "
                  f"reward={reward:.2f}")
            if show_obs:
                print_new_lines(prev_obs, obs)

        if truncated or terminated or (max_steps is not None and steps >= max_steps):
            break

    env.close()

    print("\n--- Summary ---")
    print(f"Steps taken      : {steps}")
    print(f"Ended by         : {'end of data' if truncated else 'step limit'}")
    print(f"Malicious events : {malicious_seen} ({malicious_seen / steps:.2%})")
    print(f"Total reward     : {total_reward:.2f}")
    print(f"Mean reward      : {total_reward / steps:.4f}")
    print("Action counts    : " + ", ".join(
        f"{n}={c}" for n, c in zip(ACTION_NAMES, actions_taken) if c))


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("db_path", nargs="?", default=DEFAULT_DB,
                        help=f"EventStore database (default: {DEFAULT_DB})")
    parser.add_argument("--steps", type=int, default=25,
                        help="number of per-step lines to print (default: 25)")
    parser.add_argument("--max-steps", type=int, default=2000,
                        help="stop after this many steps; 0 runs to end of data (default: 2000)")
    parser.add_argument("--policy", choices=("pass", "heuristic"), default="pass",
                        help="pass = README baseline; heuristic = block on SSH failures")
    parser.add_argument("--show-obs", action="store_true",
                        help="also print the newest log line delivered on each channel per step")
    parser.add_argument("--start-at", type=int, default=0,
                        help="skip this many steps (silently, with pass) before printing")
    parser.add_argument("--synthetic", action="store_true",
                        help="generate a tiny synthetic stream instead of reading a dataset")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    max_steps = args.max_steps or None
    if max_steps is not None:
        max_steps = max(max_steps, args.start_at + args.steps)
    if args.synthetic:
        with tempfile.TemporaryDirectory() as tmp:
            db = build_synthetic_db(Path(tmp) / "synthetic_demo.db")
            run(str(db), args.steps, args.policy, max_steps, args.seed, args.show_obs, args.start_at)
        return 0

    if not Path(args.db_path).exists():
        print(f"error: {args.db_path} not found. Download the data (see README.md, "
              "'Dataset') or rerun with --synthetic.", file=sys.stderr)
        return 1
    run(args.db_path, args.steps, args.policy, max_steps, args.seed, args.show_obs, args.start_at)
    return 0


if __name__ == "__main__":
    sys.exit(main())
