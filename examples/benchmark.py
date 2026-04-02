#!/usr/bin/env python3
"""Benchmark all baseline agents and print a comparison table.

Runs the random and threshold agents on a given experiment stream DB
and prints a formatted results table suitable for README / paper inclusion.

Usage:
    python examples/benchmark.py data/exp_7d_brute_v4.db
    python examples/benchmark.py data/exp_7d_brute_v4.db --max-steps 100000
"""

from __future__ import annotations

import argparse
import time

import gymnasium as gym
import numpy as np

import security_gym  # noqa: F401

from random_agent import run as run_random
from threshold_agent import run as run_threshold


def format_table(results: list[dict]) -> str:
    """Format results as a markdown table."""
    lines = [
        "| Agent | Steps | Mean Reward | Precision | Recall | F1 | evt/s |",
        "|-------|------:|------------:|----------:|-------:|---:|------:|",
    ]
    for r in results:
        lines.append(
            f"| {r['agent']} "
            f"| {r['steps']:,} "
            f"| {r['mean_reward']:.4f} "
            f"| {r['precision']:.4f} "
            f"| {r['recall']:.4f} "
            f"| {r['f1']:.4f} "
            f"| {r['events_per_s']:,.0f} |"
        )
    return "\n".join(lines)


def run_pass_only(db_path: str, max_steps: int | None, seed: int) -> dict:
    """Run a pass-only agent (never acts)."""
    env = gym.make("SecurityLogStream-v1", db_path=db_path)
    obs, info = env.reset(seed=seed)
    total_reward = 0.0
    steps = 0
    tn = fn = 0
    t0 = time.perf_counter()
    while True:
        action = {"action": 0, "risk_score": np.array([0.0], dtype=np.float32)}
        obs, reward, terminated, truncated, info = env.step(action)
        total_reward += reward
        steps += 1
        gt = info["ground_truth"]
        if gt["is_malicious"]:
            fn += 1
        else:
            tn += 1
        if truncated or (max_steps and steps >= max_steps):
            break
    elapsed = time.perf_counter() - t0
    env.close()
    return {
        "agent": "pass-only",
        "steps": steps,
        "total_reward": total_reward,
        "mean_reward": total_reward / steps if steps else 0.0,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "elapsed_s": elapsed,
        "events_per_s": steps / elapsed if elapsed > 0 else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark baseline agents")
    parser.add_argument("db_path", help="Path to experiment stream DB")
    parser.add_argument("--max-steps", type=int, default=None,
                        help="Max steps per agent (default: full stream)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    results = []

    print(f"Benchmarking on: {args.db_path}")
    if args.max_steps:
        print(f"Max steps: {args.max_steps:,}")
    print()

    # --- Pass-only agent ---
    print("Running pass-only agent ...")
    r = run_pass_only(args.db_path, args.max_steps, args.seed)
    results.append(r)
    print(f"  done ({r['elapsed_s']:.1f}s)")

    # --- Random agent ---
    print("Running random agent ...")
    r = run_random(args.db_path, args.max_steps, args.seed)
    results.append(r)
    print(f"  done ({r['elapsed_s']:.1f}s)")

    # --- Threshold agents (vary threshold) ---
    for threshold in (3, 5, 10):
        print(f"Running threshold agent (t={threshold}) ...")
        r = run_threshold(args.db_path, threshold, 300.0, args.max_steps, args.seed)
        results.append(r)
        print(f"  done ({r['elapsed_s']:.1f}s)")

    # --- Print results ---
    print(f"\n{'Baseline Results':=^60}\n")
    print(format_table(results))
    print()


if __name__ == "__main__":
    main()
