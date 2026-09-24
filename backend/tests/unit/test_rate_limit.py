from app.core.rate_limit import SlidingWindowRateLimiter


def test_allows_up_to_the_limit_then_blocks() -> None:
    limiter = SlidingWindowRateLimiter(max_events=3, window_seconds=60)
    assert [limiter.allow("ip", now=float(i)) for i in range(4)] == [True, True, True, False]


def test_window_expiry_frees_capacity() -> None:
    limiter = SlidingWindowRateLimiter(max_events=2, window_seconds=60)
    assert limiter.allow("ip", now=0.0)
    assert limiter.allow("ip", now=1.0)
    assert not limiter.allow("ip", now=2.0)
    assert limiter.allow("ip", now=61.5)


def test_keys_are_independent() -> None:
    limiter = SlidingWindowRateLimiter(max_events=1, window_seconds=60)
    assert limiter.allow("a", now=0.0)
    assert not limiter.allow("a", now=1.0)
    assert limiter.allow("b", now=1.0)
