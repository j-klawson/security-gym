"""Tests for target builder + NaN masking."""

import numpy as np

from security_gym.targets.builder import N_HEADS, TargetBuilder


class TestTargetBuilder:
    def setup_method(self):
        self.builder = TargetBuilder()

    def test_none_input_all_nan(self):
        targets = self.builder.build_targets(None)
        assert targets.shape == (N_HEADS,)
        assert np.all(np.isnan(targets))

    def test_empty_dict_all_nan(self):
        targets = self.builder.build_targets({})
        assert np.all(np.isnan(targets))

    def test_benign_event(self):
        targets = self.builder.build_targets({
            "is_malicious": 0,
            "severity": 0,
        })
        assert targets[0] == 0.0  # is_malicious
        assert np.isnan(targets[1])  # attack_type unknown
        assert np.isnan(targets[2])  # attack_stage unknown
        assert targets[3] == 0.0  # severity
        assert np.isnan(targets[4])  # session_value unknown

    def test_malicious_event(self):
        targets = self.builder.build_targets({
            "is_malicious": 1,
            "attack_type": "brute_force",
            "attack_stage": "initial_access",
            "severity": 2,
        })
        assert targets[0] == 1.0  # is_malicious
        assert 0.0 <= targets[1] <= 1.0  # attack_type normalized
        assert 0.0 <= targets[2] <= 1.0  # attack_stage normalized
        assert 0.0 <= targets[3] <= 1.0  # severity normalized
        assert np.isnan(targets[4])  # session_value not set

    def test_attack_type_string_mapping(self):
        targets = self.builder.build_targets({
            "is_malicious": 1,
            "attack_type": "exfiltration",
        })
        assert not np.isnan(targets[1])
        # exfiltration = 7, normalized = 7/7 = 1.0
        assert abs(targets[1] - 1.0) < 1e-5

    def test_session_value(self):
        targets = self.builder.build_targets({
            "is_malicious": 1,
            "session_value": 50.0,
        })
        # Default scale = 100.0, so 50/100 = 0.5
        assert abs(targets[4] - 0.5) < 1e-5

    def test_output_dtype(self):
        targets = self.builder.build_targets({"is_malicious": 1})
        assert targets.dtype == np.float32
