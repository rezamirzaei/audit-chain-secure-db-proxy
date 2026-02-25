from __future__ import annotations

from database_server.server.runtime import InMemoryRateLimiter


def test_rate_limiter_enforces_max_attempts_within_window():
    now = 1000.0
    limiter = InMemoryRateLimiter(window_seconds=10, max_attempts=2, now_fn=lambda: now)

    assert limiter.is_limited("login", "1.2.3.4") is False
    limiter.record_failure("login", "1.2.3.4")
    assert limiter.is_limited("login", "1.2.3.4") is False
    limiter.record_failure("login", "1.2.3.4")
    assert limiter.is_limited("login", "1.2.3.4") is True


def test_rate_limiter_prunes_attempts_outside_window():
    now_holder = {"now": 1000.0}
    limiter = InMemoryRateLimiter(window_seconds=10, max_attempts=1, now_fn=lambda: now_holder["now"])

    limiter.record_failure("login", "ip")
    assert limiter.is_limited("login", "ip") is True

    now_holder["now"] = 1011.0
    assert limiter.is_limited("login", "ip") is False
