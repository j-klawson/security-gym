"""Reward alignment: which event is an action graded against?

``step(action)`` applies ``action`` to the event the agent was shown, advances
to the next visible event, and then grades the action term (and the risk term)
against that *next* event's label. These tests state the intended alignment,
that an action is graded on the event it was chosen for, and are marked
``xfail(strict=True)`` so that the fix flips them to a hard failure until the
markers are removed. See TODO.md, "Reward alignment (off-by-one)".

Fixture layouts (tests/conftest.py):
  tmp_db              events 0-4 benign 10.0.0.1, 5-9 malicious 192.168.1.50
                      (initial_access), 10-12 unlabeled
  single_ip_mixed_db  events 0-3 benign 10.9.9.9, 4-7 malicious 10.9.9.9
  single_ip_malicious_db  events 0-7 malicious 10.9.9.9
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pytest

from security_gym.envs.log_stream_env import (
    ACTION_ALERT,
    ACTION_BLOCK_SOURCE,
    ACTION_PASS,
    ACTION_THROTTLE,
    SecurityLogStreamEnv,
)
from security_gym.envs.log_stream_env_hybrid import SecurityLogStreamHybridEnv

ENV_CLASSES = [SecurityLogStreamEnv, SecurityLogStreamHybridEnv]

OFF_BY_ONE = pytest.mark.xfail(
    strict=True,
    reason="step() grades the action on the next event's label, not the observed event's",
)


def _act(action: int, risk: float = 0.0, target: int = 0) -> dict[str, Any]:
    return {
        "action": action,
        "risk_score": np.array([risk], dtype=np.float32),
        "target": target,
    }


def _advance_to(env: SecurityLogStreamEnv, index: int) -> dict[str, Any]:
    """Reset and pass until event ``index`` is the one on screen; return its info."""
    _, info = env.reset(seed=0)
    for _ in range(index):
        _, _, _, _, info = env.step(_act(ACTION_PASS))
    return info


@pytest.mark.parametrize("env_cls", ENV_CLASSES)
def test_alert_within_a_label_run_is_graded_correctly(env_cls, tmp_db) -> None:
    """Control: away from a label boundary the shift is invisible."""
    env = env_cls(db_path=tmp_db)
    info = _advance_to(env, 6)
    assert info["ground_truth"]["is_malicious"] is True
    _, reward, *_ = env.step(_act(ACTION_ALERT))
    assert reward == pytest.approx(0.5)
    env.close()


@OFF_BY_ONE
@pytest.mark.parametrize("env_cls", ENV_CLASSES)
def test_alert_on_last_benign_event_is_graded_benign(env_cls, tmp_db) -> None:
    """Alert on benign event 4; event 5 (malicious) is what the code grades."""
    env = env_cls(db_path=tmp_db)
    info = _advance_to(env, 4)
    assert info["ground_truth"]["is_malicious"] is False
    _, reward, *_ = env.step(_act(ACTION_ALERT))
    assert reward == pytest.approx(-0.3)  # observed: +0.5
    env.close()


@OFF_BY_ONE
@pytest.mark.parametrize("env_cls", ENV_CLASSES)
def test_blocking_a_benign_host_is_penalized(env_cls, tmp_db) -> None:
    """Block benign 10.0.0.1 at event 4 (target 0): effective, so -1.0 is due."""
    env = env_cls(db_path=tmp_db)
    _advance_to(env, 4)
    _, reward, _, _, info = env.step(_act(ACTION_BLOCK_SOURCE))
    assert info["action_effective"] is True
    assert info["action_target"] == "10.0.0.1"
    assert reward == pytest.approx(-1.0)  # observed: +1.0
    env.close()


@OFF_BY_ONE
@pytest.mark.parametrize("env_cls", ENV_CLASSES)
def test_risk_prediction_is_graded_on_observed_event(env_cls, tmp_db) -> None:
    """A correct risk of 0 for benign event 4 should cost nothing."""
    env = env_cls(db_path=tmp_db, reward_config={"include_risk_reward": True})
    _advance_to(env, 4)
    _, reward, *_ = env.step(_act(ACTION_PASS, risk=0.0))
    assert reward == pytest.approx(0.0)  # observed: -3.0 (pass graded as missed attack, -0.5; risk 0.1 * 5.0**2, -2.5)
    env.close()


@OFF_BY_ONE
@pytest.mark.parametrize("env_cls", ENV_CLASSES)
def test_explicit_target_uses_only_labels_already_observed(
    env_cls, single_ip_mixed_db,
) -> None:
    """Throttle slot 1 (10.9.9.9) at event 3, whose last observed label is benign.

    ``_observe_address`` records event 4's malicious label before
    ``_compute_reward`` runs, so the docstring's causality claim ("uses only a
    label the agent has already been shown") does not hold.
    """
    env = env_cls(db_path=single_ip_mixed_db, throttle_drop_rate=0.0)
    info = _advance_to(env, 3)
    assert info["ground_truth"]["is_malicious"] is False
    _, reward, _, _, info = env.step(_act(ACTION_THROTTLE, target=1))
    assert info["action_target_explicit"] is True
    assert info["action_effective"] is True
    assert reward == pytest.approx(-0.5)  # observed: +0.75
    env.close()


@OFF_BY_ONE
@pytest.mark.parametrize("env_cls", ENV_CLASSES)
def test_final_action_is_graded_on_final_event(env_cls, single_ip_malicious_db) -> None:
    """At exhaustion the code grades against a synthetic benign label."""
    env = env_cls(db_path=single_ip_malicious_db)
    info = _advance_to(env, 7)
    assert info["ground_truth"]["is_malicious"] is True
    _, reward, _, truncated, _ = env.step(_act(ACTION_ALERT))
    assert truncated is True
    assert reward == pytest.approx(0.5)  # observed: -0.3
    env.close()


@pytest.mark.xfail(
    strict=True,
    reason="re-blocking an already-blocked address counts as effective and is paid in full",
)
@pytest.mark.parametrize("env_cls", ENV_CLASSES)
def test_repeat_block_of_controlled_address_is_not_paid(env_cls, tmp_db) -> None:
    """Block 192.168.1.50 once, then name its pinned slot again on a benign step.

    ``_apply_action`` sets ``_target_effective = True`` for throttle and block
    whether or not the address was already controlled, and the slate grades the
    explicit target on its last observed label (malicious, and frozen there
    because drop visibility hides the host thereafter). A policy that repeats the
    block collects +1.0 on every step.
    """
    env = env_cls(db_path=tmp_db)
    _advance_to(env, 6)  # malicious 192.168.1.50 on screen; slate slot 2
    env.step(_act(ACTION_BLOCK_SOURCE, target=2))
    _, reward, _, _, info = env.step(_act(ACTION_BLOCK_SOURCE, target=2))
    assert info["ground_truth"]["is_malicious"] is False
    assert info["action_effective"] is False
    assert reward == pytest.approx(0.0)  # observed: +1.0
    env.close()
