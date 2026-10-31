"""app/fx.py: the one outbound request to the Bank of Canada, always through a fake opener here."""
import io
import json
import urllib.request
from decimal import Decimal
from pathlib import Path

import pytest

from app import fx

FIX = Path(__file__).parent / "fixtures" / "valet_fxusdcad.json"


class FakeResponse:
    def __init__(self, body: bytes, on_read=None):
        self.stream, self.on_read = io.BytesIO(body), on_read

    def read(self, n=-1):
        if self.on_read:
            self.on_read()
        return self.stream.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, body: bytes | None = None, error: Exception | None = None, on_read=None):
        self.body = body if body is not None else FIX.read_bytes()
        self.error, self.on_read = error, on_read
        self.requests: list[tuple[urllib.request.Request, float]] = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return FakeResponse(self.body, self.on_read)


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
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": 1.25}}]},  # a number, not Valet's string
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "1.25e0"}}]},
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "1.123456789"}}]},  # more than 8 decimals
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": " 1.25"}}]},
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "3.5000"}}]},  # outside 0.5 to 3
    {"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "0.4000"}}]},
])
def test_parse_rejects_bad_shapes(payload):
    with pytest.raises(ValueError):
        fx.parse(payload)


def test_rate_is_quantized_to_four_decimals():
    rate = fx.parse({"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": "1.23456789"}}]})
    assert format(rate.rate, "f") == "1.2346"


def test_giant_digit_rate_is_rejected():
    giant = "1." + "2" * 60000  # inside the range, but it would bloat every response
    body = json.dumps({"observations": [{"d": "2024-01-02", "FXUSDCAD": {"v": giant}}]}).encode()
    with pytest.raises(ValueError):
        fx.parse(json.loads(body))
    with pytest.raises(ValueError):  # too large for the response cap as well
        fx.fetch(opener=FakeOpener(body))


def test_slow_response_hits_the_total_deadline():
    clock = iter(range(0, 1000, 5))  # each read takes 5 s
    opener = FakeOpener(b" " * (fx.CHUNK * 3) + FIX.read_bytes())
    with pytest.raises(TimeoutError):
        fx.fetch(opener=opener, clock=lambda: next(clock))


def test_real_opener_ignores_environment_proxies(monkeypatch):
    built = []
    monkeypatch.setattr(fx.urllib.request, "build_opener", lambda *h: built.append(h) or pytest.fail("built"))
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    with pytest.raises(pytest.fail.Exception):
        fx._open_direct(urllib.request.Request(fx.VALET_URL), 5)
    proxies = [h for h in built[0] if isinstance(h, urllib.request.ProxyHandler)]
    assert len(proxies) == 1 and proxies[0].proxies == {}


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
