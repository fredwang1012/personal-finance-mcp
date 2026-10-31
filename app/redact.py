"""Shared redaction helpers for anything that is printed or becomes model context."""
import hashlib
import re
import unicodedata

MAX_TEXT = 120
BULLETS = "•••"
DIGIT_RUN = re.compile(r"\d(?:[ -]?\d){5,}")
# links and e-mail addresses in institution text (e-Transfer memos, display messages) are never useful to the model
# and are the easiest carrier for injected instructions, so they are replaced outright
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def short_hash(value: str) -> str:
    """8-character stand-in for an id (Plaid item or account id, CSV account key) that must not be shown."""
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def last4(number: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", number)[-4:]


def _mask(match: re.Match) -> str:
    return BULLETS + re.sub(r"\D", "", match.group())[-4:]


def clean_text(raw: str, number: str = "") -> str:
    """Free text that may reach model context: drop control chars, replace links and e-mail addresses, mask account
    numbers, cap the length."""
    out = "".join(ch for ch in raw if not unicodedata.category(ch).startswith("C")).strip()
    if len(number) >= 4:
        out = out.replace(number, BULLETS + last4(number))
    out = EMAIL_RE.sub("[email]", URL_RE.sub("[link]", out))
    out = DIGIT_RUN.sub(_mask, out)
    return out[:MAX_TEXT]


def cut(text: str | None, limit: int) -> str | None:
    """Shorten already-cleaned text for display."""
    if not text or len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
