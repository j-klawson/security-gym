#!/usr/bin/env python3
"""Streaming adapter demo for SecurityGymStream.

Shows three ways to consume security-gym data:

1. Batch mode — load everything into memory (small datasets)
2. Iterator mode — constant-memory streaming in batches
3. Gymnasium mode — full env with actions and rewards

Usage:
    python examples/streaming_demo.py data/exp_7d_brute_v4.db
    python examples/streaming_demo.py data/exp_7d_brute_v4.db --mode batch
    python examples/streaming_demo.py data/exp_7d_brute_v4.db --mode iter --batch-size 500
    python examples/streaming_demo.py data/exp_7d_brute_v4.db --mode gym --max-steps 100
"""

from __future__ import annotations

import argparse
import time

import numpy as np


def demo_batch(db_path: str, max_events: int = 1000) -> None:
    """Load events into memory — good for small datasets or analysis."""
    from security_gym.adapters.scan_stream import SecurityGymStream

    print(f"Loading up to {max_events:,} events from {db_path} ...")
    stream = SecurityGymStream(db_path)
    observations, ground_truths = stream.collect_numpy(limit=max_events)

    n_mal = sum(1 for gt in ground_truths if gt.get("is_malicious"))
    print(f"  Loaded {len(observations):,} events ({n_mal:,} malicious)")

    # Show a sample
    if observations:
        obs = observations[0]
        gt = ground_truths[0]
        print("\n  First event:")
        print(f"    auth_log:  {obs['auth_log'][:120]}...")
        print(f"    malicious: {gt.get('is_malicious')}")
        print(f"    type:      {gt.get('attack_type')}")


def demo_iter(db_path: str, batch_size: int = 1000, max_batches: int = 5) -> None:
    """Stream events in constant-memory batches."""
    from security_gym.adapters.scan_stream import SecurityGymStream

    print(f"Streaming from {db_path} (batch_size={batch_size}) ...")
    stream = SecurityGymStream(db_path)

    total = 0
    t0 = time.perf_counter()

    for i, (obs_batch, gt_batch) in enumerate(stream.iter_batches(size=batch_size)):
        n_mal = sum(1 for gt in gt_batch if gt.get("is_malicious"))
        total += len(obs_batch)
        print(f"  Batch {i}: {len(obs_batch):,} events, {n_mal:,} malicious")

        if i + 1 >= max_batches:
            break

    elapsed = time.perf_counter() - t0
    print(f"\n  Processed {total:,} events in {elapsed:.2f}s "
          f"({total / elapsed:,.0f} evt/s)")


def demo_gym(db_path: str, max_steps: int = 20) -> None:
    """Full Gymnasium loop with a pass-only agent."""
    import gymnasium as gym
    import security_gym  # noqa: F401

    print(f"Running Gymnasium env for {max_steps} steps ...")
    env = gym.make("SecurityLogStream-v1", db_path=db_path, render_mode="ansi")
    obs, info = env.reset(seed=42)

    for step in range(max_steps):
        action = {
            "action": 0,  # pass — monitor only
            "risk_score": np.array([0.0], dtype=np.float32),
        }
        obs, reward, terminated, truncated, info = env.step(action)

        gt = info["ground_truth"]
        source = info["source"]
        ts = info["timestamp"][:19]
        mal = "MAL" if gt["is_malicious"] else "   "
        print(f"  [{ts}] {mal} {source:<15} reward={reward:+.2f}  "
              f"risk={gt['true_risk']:.0f}")

        if truncated:
            print("  (end of stream)")
            break

    env.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SecurityGymStream demo")
    parser.add_argument("db_path", help="Path to experiment stream DB")
    parser.add_argument("--mode", choices=["batch", "iter", "gym"], default="gym",
                        help="Demo mode (default: gym)")
    parser.add_argument("--max-steps", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=1000)
    args = parser.parse_args()

    if args.mode == "batch":
        demo_batch(args.db_path, max_events=args.max_steps)
    elif args.mode == "iter":
        demo_iter(args.db_path, batch_size=args.batch_size)
    else:
        demo_gym(args.db_path, max_steps=args.max_steps)


if __name__ == "__main__":
    main()
