"""Tests for feature extraction."""

import numpy as np

from security_gym.features.extractors import EventFeatureExtractor, FEATURE_DIM
from security_gym.features.hasher import FeatureHasher
from tests.conftest import SAMPLE_EVENTS


class TestEventFeatureExtractor:
    def setup_method(self):
        self.extractor = EventFeatureExtractor()

    def test_output_shape(self):
        event, _ = SAMPLE_EVENTS[0]
        vec = self.extractor.extract(event)
        assert vec.shape == (FEATURE_DIM,)
        assert vec.dtype == np.float32

    def test_feature_dim_attribute(self):
        assert self.extractor.feature_dim == FEATURE_DIM

    def test_source_onehot(self):
        event, _ = SAMPLE_EVENTS[0]
        vec = self.extractor.extract(event)
        # auth_log is index 0 in SOURCE_TYPES
        assert vec[0] == 1.0
        assert sum(vec[:5]) == 1.0  # exactly one source active

    def test_event_type_onehot(self):
        event, _ = SAMPLE_EVENTS[0]  # auth_success
        vec = self.extractor.extract(event)
        # event_type one-hot starts at offset 5
        assert sum(vec[5:18]) == 1.0

    def test_cyclic_features_bounded(self):
        event, _ = SAMPLE_EVENTS[0]
        vec = self.extractor.extract(event)
        # sin/cos values should be in [-1, 1]
        for i in range(18, 22):
            assert -1.0 <= vec[i] <= 1.0

    def test_has_ip_and_username(self):
        event, _ = SAMPLE_EVENTS[0]
        vec = self.extractor.extract(event)
        assert vec[22] == 1.0  # has_ip
        assert vec[23] == 1.0  # has_username

    def test_different_events_different_features(self):
        benign, _ = SAMPLE_EVENTS[0]  # auth_success
        malicious, _ = SAMPLE_EVENTS[5]  # auth_failure
        v1 = self.extractor.extract(benign)
        v2 = self.extractor.extract(malicious)
        assert not np.array_equal(v1, v2)


class TestFeatureHasher:
    def setup_method(self):
        self.hasher = FeatureHasher(dim=128)

    def test_output_shape(self):
        vec = self.hasher.hash("Feb 17 10:15:30 myhost sshd[1234]: test")
        assert vec.shape == (128,)
        assert vec.dtype == np.float32

    def test_l2_normalized(self):
        vec = self.hasher.hash("Feb 17 10:15:30 myhost sshd[1234]: test message")
        norm = np.linalg.norm(vec)
        assert abs(norm - 1.0) < 1e-5

    def test_empty_string(self):
        vec = self.hasher.hash("")
        assert np.all(vec == 0.0)

    def test_deterministic(self):
        line = "Feb 17 10:15:30 myhost sshd[1234]: Failed password for admin"
        v1 = self.hasher.hash(line)
        v2 = self.hasher.hash(line)
        np.testing.assert_array_equal(v1, v2)

    def test_different_lines_different_hashes(self):
        v1 = self.hasher.hash("Accepted password for admin from 10.0.0.1")
        v2 = self.hasher.hash("Failed password for root from 192.168.1.1")
        assert not np.array_equal(v1, v2)

    def test_tokenize(self):
        tokens = self.hasher.tokenize("sshd[1234]: Failed password for admin")
        assert "sshd" in tokens
        assert "1234" in tokens
        assert "Failed" in tokens

    def test_default_dim(self):
        h = FeatureHasher()
        assert h.dim == 1024
