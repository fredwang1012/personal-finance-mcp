"""Sealed transfer of Plaid secrets from the laptop to the server (export-bundle --to KEY / import-bundle).

The server makes a one-time X25519 keypair (`bundle-key`) and prints only the public half. The laptop seals the
bundle to it: an ephemeral X25519 key agreement, HKDF-SHA256 for the key, AES-256-GCM for the data. Only ciphertext
leaves the laptop, so it is harmless on a terminal, in scrollback or in a file. The server's private half is a
secret in the configured backend and is deleted after a successful import.
"""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PUB_PREFIX = "pfmcp-pub-1:"
SEALED_PREFIX = "pfmcp-sealed-1:"
_INFO = b"personal-finance-mcp bundle v1"
_RAW = serialization.Encoding.Raw


class BundleError(ValueError):
    """Bad key or ciphertext; the message never contains key material or plaintext."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise BundleError("not valid base64") from None


def generate_keypair() -> tuple[str, str]:
    """(private, public) as text; only the public half is ever printed."""
    private = X25519PrivateKey.generate()
    priv = private.private_bytes(_RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = private.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
    return _b64(priv), PUB_PREFIX + _b64(pub)


def _key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO + eph_pub + recipient_pub).derive(shared)


def seal(public_key: str, plaintext: bytes) -> str:
    public_key = public_key.strip()
    if not public_key.startswith(PUB_PREFIX):
        raise BundleError(f"the key must start with {PUB_PREFIX} (printed by bundle-key on the server)")
    recipient_raw = _unb64(public_key[len(PUB_PREFIX):])
    if len(recipient_raw) != 32:
        raise BundleError("the key has the wrong length")
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
    key = _key(eph.exchange(X25519PublicKey.from_public_bytes(recipient_raw)), eph_pub, recipient_raw)
    nonce = os.urandom(12)
    return SEALED_PREFIX + _b64(eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, SEALED_PREFIX.encode()))


def open_sealed(private_key: str, sealed: str) -> bytes:
    sealed = sealed.strip()
    if not sealed.startswith(SEALED_PREFIX):
        raise BundleError("input is not a sealed bundle")
    blob = _unb64(sealed[len(SEALED_PREFIX):])
    if len(blob) < 32 + 12 + 16:
        raise BundleError("sealed bundle is truncated")
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    private = X25519PrivateKey.from_private_bytes(_unb64(private_key.strip()))
    recipient_pub = private.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
    key = _key(private.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, recipient_pub)
    try:
        return AESGCM(key).decrypt(nonce, ct, SEALED_PREFIX.encode())
    except InvalidTag:
        raise BundleError("could not decrypt: wrong key (run bundle-key again and re-export) or damaged input") from None
