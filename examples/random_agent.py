#!/usr/bin/env python3
"""Random agent baseline for SecurityLogStream-Text-v0.

Selects actions uniformly at random and predicts a random risk score.
This establishes the performance floor — any useful agent should beat this.

Usage:
    python examples/random_agent.py data/exp_7d_brute_v4.db
    python examples/random_agent.py data/exp_7d_brute_v4.db --max-steps 50000
"""

from __future__ import annotations

import argparse
import time

import gymnasium as gym
import numpy as np

import security_gym  # noqa: F401 — registers envs


def run(db_path: str, max_steps: int | None = None, seed: int = 42) -> dict:
    """Run a random agent and return metrics."""
    env = gym.make("SecurityLogStream-Text-v0", db_path=db_path)
    obs, info = env.reset(seed=seed)
    rng = np.random.default_rng(seed)

    total_reward = 0.0
    steps = 0

    # Confusion matrix counts
    tp = fp = tn = fn = 0

    t0 = time.perf_counter()

    while True:
        action = {
            "action": int(rng.integers(0, 6)),
            "risk_score": rng.uniform(0, 10, size=(1,)).astype(np.float32),
        }

        obs, reward, terminated, truncated, info = env.step(action)
        total_reward += reward
        steps += 1

        gt = info["ground_truth"]
        is_mal = gt["is_malicious"]
        acted = action["action"] in (1, 2, 3, 5)  # alert/throttle/block/isolate

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
        "agent": "random",
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
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Random agent baseline")
    parser.add_argument("db_path", help="Path to experiment stream DB")
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    results = run(args.db_path, args.max_steps, args.seed)

    print(f"\n{'Random Agent Baseline':=^60}")
    print(f"  Steps:       {results['steps']:,}")
    print(f"  Elapsed:     {results['elapsed_s']:.1f}s ({results['events_per_s']:,.0f} evt/s)")
    print(f"  Total reward: {results['total_reward']:,.1f}")
    print(f"  Mean reward:  {results['mean_reward']:.4f}")
    print(f"  Precision:   {results['precision']:.4f}")
    print(f"  Recall:      {results['recall']:.4f}")
    print(f"  F1:          {results['f1']:.4f}")
    print(f"  TP={results['tp']:,}  FP={results['fp']:,}  TN={results['tn']:,}  FN={results['fn']:,}")


if __name__ == "__main__":
    main()
