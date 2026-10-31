"""The public USD/CAD rate from the Bank of Canada Valet API, used only to estimate cash in investment accounts.

This is the server's one outbound request besides Plaid: a GET to one fixed URL on one allow-listed host, with no
parameters, cookies or credentials, so nothing about the owner is sent. Proxies from the environment and redirects
are ignored, the response is capped in size and time, the rate must look like one (a few decimals, 0.5 to 3), and
it is cached in memory for TTL. A failure returns None (the caller omits its estimates with a note) and is
remembered for RETRY_AFTER, so tool calls don't each wait on a timeout. FX_ENABLED=false turns it off.
"""
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Callable

VALET_URL = "https://www.bankofcanada.ca/valet/observations/FXUSDCAD/json?recent=1"
ALLOWED_HOST = "www.bankofcanada.ca"
SERIES = "FXUSDCAD"
TIMEOUT = 5  # seconds, per socket operation
DEADLINE = 8  # seconds for the whole read, so a slow server can't hold the cache lock for long
CHUNK = 8192
TTL = 12 * 3600  # seconds
RETRY_AFTER = 600  # seconds between attempts after a failure
MAX_BYTES = 64 * 1024
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# Valet publishes four decimals; a bounded shape stops a hostile or broken response from putting a huge number
# into every tool result
RATE_RE = re.compile(r"\d\.\d{1,8}")
STEP = Decimal("0.0001")
# a sanity range, wider than USD/CAD has ever moved; anything outside it is a parse problem, not a rate
LOW, HIGH = Decimal("0.5"), Decimal("3")


@dataclass(frozen=True)
class Rate:
    rate: Decimal  # CAD per USD
    date: str

    def block(self) -> dict:
        return {"pair": "USDCAD", "rate": format(self.rate, "f"), "date": self.date, "source": "Bank of Canada"}


def parse(payload: dict) -> Rate:
    """The latest observation of a Valet observations response. Raises ValueError on any unexpected shape."""
    try:
        obs = payload["observations"][-1]
        day, raw = obs["d"], obs[SERIES]["v"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("unexpected Valet response") from exc
    if not isinstance(day, str) or not DATE_RE.fullmatch(day) or not isinstance(raw, str) or not RATE_RE.fullmatch(raw):
        raise ValueError("unexpected Valet response")
    try:
        rate = Decimal(raw).quantize(STEP)
    except InvalidOperation as exc:
        raise ValueError("unexpected Valet response") from exc
    if not LOW < rate < HIGH:
        raise ValueError("unexpected Valet response")
    return Rate(rate, day)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could point anywhere; refuse it rather than follow it off the allow-listed host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _open_direct(request: urllib.request.Request, timeout: float):
    # ProxyHandler({}) ignores proxy environment variables: the request goes straight to the allow-listed host
    handlers = [urllib.request.ProxyHandler({}), _NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    return urllib.request.build_opener(*handlers).open(request, timeout=timeout)


_urlopen = _open_direct  # the opener fetch uses; tests replace it with one that raises


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != ALLOWED_HOST or parts.port or parts.username or parts.password:
        raise ValueError("FX URL is not on the allow-listed host")


def fetch(url: str = VALET_URL, opener: Callable | None = None,
          clock: Callable[[], float] = time.monotonic) -> Rate:
    """One GET to the Valet API. Raises on any network, HTTP, size, deadline or parse failure."""
    _check_url(url)
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    start = clock()
    body = b""
    with (opener or _urlopen)(request, timeout=TIMEOUT) as resp:
        while chunk := resp.read(CHUNK):
            body += chunk
            if len(body) > MAX_BYTES:
                raise ValueError("Valet response too large")
            if clock() - start > DEADLINE:
                raise TimeoutError("Valet response too slow")
    return parse(json.loads(body))


class FxSource:
    """Thread-safe, in-memory cache around fetch(). rate() never raises."""

    def __init__(self, fetcher: Callable[[], Rate] | None = None, clock: Callable[[], float] = time.monotonic,
                 enabled: bool = True):
        self.fetcher = fetcher or fetch
        self.clock = clock
        self.enabled = enabled
        self._rate: Rate | None = None
        self._fetched_at = 0.0
        self._failed_at: float | None = None
        self._lock = threading.Lock()

    def rate(self) -> Rate | None:
        if not self.enabled:
            return None
        with self._lock:
            now = self.clock()
            if self._rate and now - self._fetched_at < TTL:
                return self._rate
            if self._failed_at is not None and now - self._failed_at < RETRY_AFTER:
                return self._rate  # the last good (dated) rate, if any
            try:
                rate = self.fetcher()
                if not isinstance(rate, Rate):
                    raise ValueError("fetcher returned no rate")
            except Exception:  # network, HTTP, TLS or parse: only "no rate" reaches the caller
                self._failed_at = now
                return self._rate
            self._rate, self._fetched_at, self._failed_at = rate, now, None
            return rate

    def clear(self) -> None:
        with self._lock:
            self._rate, self._fetched_at, self._failed_at = None, 0.0, None
