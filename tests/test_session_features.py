"""Tests for session feature extractor."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import numpy as np

from security_gym.features.session import (
    SESSION_FEATURE_DIM,
    SessionFeatureExtractor,
    _subnet_entropy,
)
from security_gym.parsers.base import ParsedEvent


def _make_event(
    event_type: str = "other",
    src_ip: str | None = "10.0.0.1",
    username: str | None = None,
    session_id: str | None = None,
    timestamp: datetime | None = None,
    source: str = "auth_log",
) -> ParsedEvent:
    if timestamp is None:
        timestamp = datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc)
    return ParsedEvent(
        timestamp=timestamp,
        source=source,
        raw_line="test line",
        event_type=event_type,
        fields={},
        src_ip=src_ip,
        username=username,
        session_id=session_id,
    )


class TestSessionFeatureExtractor:
    def setup_method(self):
        self.extractor = SessionFeatureExtractor()

    def test_output_shape(self):
        event = _make_event()
        vec = self.extractor.extract(event)
        assert vec.shape == (SESSION_FEATURE_DIM,)
        assert vec.dtype == np.float32

    def test_event_count_increments(self):
        for i in range(3):
            vec = self.extractor.extract(_make_event(session_id="s1"))
        assert vec[0] == 3.0  # event_count

    def test_auth_success_counted(self):
        vec = self.extractor.extract(_make_event(event_type="auth_success"))
        assert vec[1] == 1.0  # auth_success_count

    def test_auth_failure_counted(self):
        vec = self.extractor.extract(_make_event(event_type="auth_failure"))
        assert vec[2] == 1.0  # auth_failure_count

    def test_auth_failure_ratio(self):
        self.extractor.extract(_make_event(event_type="auth_failure"))
        self.extractor.extract(_make_event(event_type="auth_failure"))
        vec = self.extractor.extract(_make_event(event_type="auth_success"))
        # 2 failures / 3 total auth attempts
        assert abs(vec[13] - 2.0 / 3.0) < 1e-6

    def test_unique_usernames(self):
        self.extractor.extract(_make_event(username="alice"))
        self.extractor.extract(_make_event(username="bob"))
        vec = self.extractor.extract(_make_event(username="alice"))
        assert vec[10] == 2.0  # unique usernames

    def test_unique_ips(self):
        self.extractor.extract(_make_event(src_ip="10.0.0.1", session_id="s1"))
        vec = self.extractor.extract(_make_event(src_ip="10.0.0.2", session_id="s1"))
        assert vec[11] == 2.0  # unique IPs

    def test_session_duration(self):
        t0 = datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc)
        self.extractor.extract(_make_event(timestamp=t0))
        vec = self.extractor.extract(
            _make_event(timestamp=t0 + timedelta(seconds=120))
        )
        assert abs(vec[14] - 120.0) < 1e-6  # session_duration

    def test_mean_inter_event_dt(self):
        t0 = datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc)
        self.extractor.extract(_make_event(timestamp=t0))
        self.extractor.extract(_make_event(timestamp=t0 + timedelta(seconds=10)))
        vec = self.extractor.extract(
            _make_event(timestamp=t0 + timedelta(seconds=30))
        )
        # dt1=10, dt2=20 -> mean=15
        assert abs(vec[15] - 15.0) < 1e-6

    def test_hour_encoding(self):
        # Test at hour 6 (sin should be 1.0 for 6/24 cycle)
        t = datetime(2026, 2, 17, 6, 0, 0, tzinfo=timezone.utc)
        vec = self.extractor.extract(_make_event(timestamp=t))
        expected_sin = math.sin(2 * math.pi * 6.0 / 24.0)
        expected_cos = math.cos(2 * math.pi * 6.0 / 24.0)
        assert abs(vec[16] - expected_sin) < 1e-6
        assert abs(vec[17] - expected_cos) < 1e-6

    def test_day_encoding(self):
        # 2026-02-17 is a Tuesday (weekday=1)
        t = datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc)
        vec = self.extractor.extract(_make_event(timestamp=t))
        expected_sin = math.sin(2 * math.pi * 1.0 / 7.0)
        expected_cos = math.cos(2 * math.pi * 1.0 / 7.0)
        assert abs(vec[18] - expected_sin) < 1e-6
        assert abs(vec[19] - expected_cos) < 1e-6

    def test_subnet_entropy_single_ip(self):
        """Single IP -> entropy 0."""
        self.extractor.extract(_make_event(src_ip="10.0.0.1"))
        vec = self.extractor.extract(_make_event(src_ip="10.0.0.1"))
        assert vec[12] == 0.0

    def test_subnet_entropy_multiple_subnets(self):
        """Multiple /24 subnets -> positive entropy."""
        self.extractor.extract(_make_event(src_ip="10.0.0.1", session_id="s1"))
        self.extractor.extract(_make_event(src_ip="10.0.1.1", session_id="s1"))
        vec = self.extractor.extract(_make_event(src_ip="10.0.2.1", session_id="s1"))
        # 3 distinct /24s, uniform -> entropy = log2(3)
        expected = math.log2(3)
        assert abs(vec[12] - expected) < 1e-6

    def test_reset_clears_state(self):
        self.extractor.extract(_make_event())
        self.extractor.reset()
        vec = self.extractor.extract(_make_event())
        assert vec[0] == 1.0  # count reset to 1

    def test_separate_sessions(self):
        """Events with different session IDs are tracked independently."""
        self.extractor.extract(_make_event(session_id="s1", event_type="auth_failure"))
        vec = self.extractor.extract(
            _make_event(session_id="s2", event_type="auth_success")
        )
        # s2 should have 1 event, 0 failures, 1 success
        assert vec[0] == 1.0
        assert vec[1] == 1.0
        assert vec[2] == 0.0

    def test_session_key_fallback_to_ip(self):
        """When no session_id, falls back to src_ip."""
        self.extractor.extract(_make_event(session_id=None, src_ip="1.2.3.4"))
        vec = self.extractor.extract(
            _make_event(session_id=None, src_ip="1.2.3.4")
        )
        assert vec[0] == 2.0  # same session

    def test_http_counts(self):
        self.extractor.extract(_make_event(event_type="http_request"))
        vec = self.extractor.extract(_make_event(event_type="http_error"))
        assert vec[7] == 1.0  # http_request_count
        assert vec[8] == 1.0  # http_error_count


class TestSubnetEntropy:
    def test_empty(self):
        from collections import Counter
        assert _subnet_entropy(Counter()) == 0.0

    def test_single(self):
        from collections import Counter
        assert _subnet_entropy(Counter({"10.0.0": 5})) == 0.0

    def test_uniform_two(self):
        from collections import Counter
        e = _subnet_entropy(Counter({"10.0.0": 1, "10.0.1": 1}))
        assert abs(e - 1.0) < 1e-6  # log2(2) = 1.0
