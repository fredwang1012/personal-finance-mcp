"""The public USD/CAD rate from the Bank of Canada Valet API, used only to estimate cash in investment accounts.

This is the server's one outbound request besides Plaid: a GET to one fixed URL on one allow-listed host, with no
parameters, cookies or credentials, so nothing about the owner is sent. Redirects are refused, the response is capped,
and the rate is cached in memory for TTL. A failure returns None (the caller omits its estimates with a note) and is
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
TIMEOUT = 5  # seconds
TTL = 12 * 3600  # seconds
RETRY_AFTER = 600  # seconds between attempts after a failure
MAX_BYTES = 64 * 1024
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# a sanity range, far wider than USD/CAD has ever moved; anything outside it is a parse problem, not a rate
LOW, HIGH = Decimal("0.5"), Decimal("5")


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
        rate = Decimal(str(raw))
    except (KeyError, IndexError, TypeError, InvalidOperation) as exc:
        raise ValueError("unexpected Valet response") from exc
    if not isinstance(day, str) or not DATE_RE.fullmatch(day) or not rate.is_finite() or not LOW < rate < HIGH:
        raise ValueError("unexpected Valet response")
    return Rate(rate, day)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could point anywhere; refuse it rather than follow it off the allow-listed host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _urlopen(request: urllib.request.Request, timeout: float):
    handlers = [_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    return urllib.request.build_opener(*handlers).open(request, timeout=timeout)


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != ALLOWED_HOST or parts.port or parts.username or parts.password:
        raise ValueError("FX URL is not on the allow-listed host")


def fetch(url: str = VALET_URL, opener: Callable | None = None) -> Rate:
    """One GET to the Valet API. Raises on any network, HTTP or parse failure."""
    _check_url(url)
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    with (opener or _urlopen)(request, timeout=TIMEOUT) as resp:
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("Valet response too large")
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
