"""app/fx.py: the one outbound request to the Bank of Canada, always through a fake opener here."""
import json
import urllib.request
from decimal import Decimal
from pathlib import Path

import pytest

from app import fx

FIX = Path(__file__).parent / "fixtures" / "valet_fxusdcad.json"


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def read(self, n=-1):
        return self.body if n < 0 else self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, body: bytes | None = None, error: Exception | None = None):
        self.body = body if body is not None else FIX.read_bytes()
        self.error = error
        self.requests: list[tuple[urllib.request.Request, float]] = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return FakeResponse(self.body)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_parse_recorded_valet_shape():
    rate = fx.parse(json.loads(FIX.read_text()))
    assert rate == fx.Rate(Decimal("1.2500"), "2024-01-02")
    assert rate.block() == {"pair": "USDCAD", "rate": "1.2500", "date": "2024-01-02", "source": "Bank of Canada"}


@pytest.mark.parametrize("payload", [
    {},
    {"observations": []},
    {"observations": [{"d": "2024-01-02"}]},
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "abc"}}]},
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "1250"}}]},  # absurd rate
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "-1.25"}}]},
    {"observations": [{"d": "<b>", "FXUSDCAD": {"v": "1.25"}}]},
    {"observations": "nope"},
])
def test_parse_rejects_bad_shapes(payload):
    with pytest.raises(ValueError):
        fx.parse(payload)


def test_fetch_is_a_plain_get_to_the_fixed_url_with_timeout():
    opener = FakeOpener()
    assert fx.fetch(opener=opener).rate == Decimal("1.2500")
    (request, timeout), = opener.requests
    assert request.full_url == fx.VALET_URL and request.get_method() == "GET" and request.data is None
    assert timeout == fx.TIMEOUT == 5
    # nothing about the owner is sent: no cookies, no auth, no custom identifying headers
    assert {k.lower() for k in request.headers} <= {"accept", "user-agent"}


@pytest.mark.parametrize("url", [
    "https://evil.example/valet/observations/FXUSDCAD/json?recent=1",
    "http://www.bankofcanada.ca/valet/observations/FXUSDCAD/json?recent=1",
    "https://www.bankofcanada.ca.evil.example/valet",
    "https://user@www.bankofcanada.ca:444/valet",
    "https://bankofcanada.ca/valet",
])
def test_host_allow_list(url):
    opener = FakeOpener()
    with pytest.raises(ValueError):
        fx.fetch(url, opener=opener)
    assert opener.requests == []


def test_redirects_are_refused():
    handler = fx._NoRedirect()
    req = urllib.request.Request(fx.VALET_URL)
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/")


def test_oversized_body_is_rejected():
    with pytest.raises(ValueError):
        fx.fetch(opener=FakeOpener(b"{" + b" " * (fx.MAX_BYTES + 10) + b"}"))


def test_source_caches_for_twelve_hours():
    opener, clock = FakeOpener(), Clock()
    source = fx.FxSource(fetcher=lambda: fx.fetch(opener=opener), clock=clock)
    assert source.rate().rate == Decimal("1.2500") and source.rate() is not None
    assert len(opener.requests) == 1
    clock.now += fx.TTL - 1
    source.rate()
    assert len(opener.requests) == 1
    clock.now += 2
    source.rate()
    assert len(opener.requests) == 2
    assert fx.TTL == 12 * 3600


def test_source_failure_returns_none_and_is_retried_later():
    opener, clock = FakeOpener(error=OSError("down")), Clock()
    source = fx.FxSource(fetcher=lambda: fx.fetch(opener=opener), clock=clock)
    assert source.rate() is None and source.rate() is None
    assert len(opener.requests) == 1  # a failure is remembered briefly, so tool calls don't each wait on a timeout
    clock.now += fx.RETRY_AFTER + 1
    opener.error = None
    assert source.rate().rate == Decimal("1.2500") and len(opener.requests) == 2


def test_source_keeps_a_stale_rate_when_a_refresh_fails():
    opener, clock = FakeOpener(), Clock()
    source = fx.FxSource(fetcher=lambda: fx.fetch(opener=opener), clock=clock)
    first = source.rate()
    clock.now += fx.TTL + 1
    opener.error = OSError("down")
    assert source.rate() == first  # the dated rate is still the best public figure; its date is shown


def test_disabled_source_never_fetches():
    calls = []
    source = fx.FxSource(fetcher=lambda: calls.append(1), enabled=False)
    assert source.rate() is None and not source.enabled and calls == []


def test_tests_cannot_reach_the_network():
    with pytest.raises(RuntimeError):
        fx.fetch()
