"""Agent keys: Ed25519 key pairs in NATS nkey encoding (SPEC.md 4).

An agent's identity is an Ed25519 key pair. Its public key, written as a NATS
user nkey (``U`` followed by 55 base32 characters), is its agent ID and its
address on the mesh. Its seed (``SU...``) is the private key: whoever holds the
seed IS the agent, so keep it secret and keep it safe.

The nkey encoding is small enough to write out here rather than take another
dependency: a prefix byte, the 32 key bytes, a CRC-16 (XMODEM) checksum in
little-endian order, all in unpadded RFC 4648 base32. Ed25519 itself comes from
PyNaCl (libsodium).
"""

from __future__ import annotations

import base64
import os
import stat
import sys
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

__all__ = [
    "KeyPair",
    "create_agent_identity",
    "is_agent_id",
    "verify_signature",
    "load_seed",
    "save_seed",
    "load_or_create_seed",
    "b64url_encode",
    "b64url_decode",
]

# nkey prefix bytes (nats-io/nkeys): the high 5 bits of the first byte.
_PREFIX_SEED = 18 << 3  # 'S'
_PREFIX_PRIVATE = 15 << 3  # 'P'
_PREFIX_USER = 20 << 3  # 'U'
_PREFIX_NAMES = {
    14 << 3: "operator",  # 'O'
    0: "account",  # 'A'
    20 << 3: "user",  # 'U'
    13 << 3: "server",  # 'N'
    2 << 3: "cluster",  # 'C'
}


def _crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def _b32encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32decode(text: str) -> bytes:
    pad = "=" * ((8 - len(text) % 8) % 8)
    return base64.b32decode(text + pad)


def _encode(prefix: bytes, payload: bytes) -> str:
    body = prefix + payload
    return _b32encode(body + _crc16(body).to_bytes(2, "little"))


def _decode(text: str) -> bytes:
    try:
        raw = _b32decode(text)
    except Exception as exc:  # binascii.Error, ValueError
        raise ValueError("not an nkey: bad base32") from exc
    if len(raw) < 4:
        raise ValueError("not an nkey: too short")
    body, crc = raw[:-2], int.from_bytes(raw[-2:], "little")
    if _crc16(body) != crc:
        raise ValueError("not an nkey: checksum does not match")
    return body


def _encode_public(prefix_byte: int, public: bytes) -> str:
    return _encode(bytes([prefix_byte]), public)


def _encode_seed(prefix_byte: int, seed: bytes) -> str:
    b1 = _PREFIX_SEED | (prefix_byte >> 5)
    b2 = (prefix_byte & 31) << 3
    return _encode(bytes([b1, b2]), seed)


def _decode_seed(seed: str) -> tuple[int, bytes]:
    body = _decode(seed.strip())
    if len(body) != 34:
        raise ValueError("not an nkey seed: wrong length")
    b1, b2 = body[0], body[1]
    if (b1 & 0xF8) != _PREFIX_SEED:
        raise ValueError("not an nkey seed: it does not start with S")
    prefix_byte = ((b1 & 7) << 5) | ((b2 & 0xF8) >> 3)
    if prefix_byte not in _PREFIX_NAMES:
        raise ValueError("not an nkey seed: unknown key type")
    return prefix_byte, body[2:]


def _decode_public(public: str) -> tuple[int, bytes]:
    body = _decode(public.strip())
    if len(body) != 33:
        raise ValueError("not an nkey public key: wrong length")
    prefix_byte = body[0]
    if prefix_byte not in _PREFIX_NAMES:
        raise ValueError("not an nkey public key: unknown key type")
    return prefix_byte, body[1:]


def b64url_encode(data: bytes) -> str:
    """Unpadded base64url, the encoding of an envelope ``sig``."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


class KeyPair:
    """An Ed25519 key pair with nkey encoding.

    ``KeyPair.create()`` makes a fresh user key (an agent identity);
    ``KeyPair.from_seed("SU...")`` loads one. ``public_key`` is the agent ID.
    The seed is never included in ``repr()``.
    """

    __slots__ = ("_signing", "_prefix")

    def __init__(self, signing_key: SigningKey, prefix_byte: int = _PREFIX_USER):
        self._signing = signing_key
        self._prefix = prefix_byte

    @classmethod
    def create(cls) -> "KeyPair":
        return cls(SigningKey.generate(), _PREFIX_USER)

    @classmethod
    def from_seed(cls, seed: str | bytes) -> "KeyPair":
        if isinstance(seed, (bytes, bytearray)):
            seed = bytes(seed).decode("ascii")
        prefix_byte, raw = _decode_seed(seed)
        return cls(SigningKey(raw), prefix_byte)

    @property
    def public_key(self) -> str:
        return _encode_public(self._prefix, bytes(self._signing.verify_key))

    @property
    def seed(self) -> str:
        return _encode_seed(self._prefix, bytes(self._signing))

    def sign(self, data: bytes) -> bytes:
        """Detached Ed25519 signature (64 bytes)."""
        return self._signing.sign(bytes(data)).signature

    def verify(self, data: bytes, signature: bytes) -> bool:
        return verify_signature(self.public_key, data, signature)

    def __repr__(self) -> str:
        return f"KeyPair(public_key={self.public_key!r})"


def verify_signature(public_key: str, data: bytes, signature: bytes) -> bool:
    """True when ``signature`` is ``public_key``'s Ed25519 signature over ``data``.

    Never raises: a malformed key or signature is simply not a valid signature.
    """
    try:
        _, raw = _decode_public(public_key)
        VerifyKey(raw).verify(bytes(data), bytes(signature))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
    except Exception:
        return False


def is_agent_id(value: object) -> bool:
    """True for a well-formed user nkey (an agent ID), checksum included."""
    if not isinstance(value, str) or len(value) != 56 or not value.startswith("U"):
        return False
    try:
        prefix, _ = _decode_public(value)
    except ValueError:
        return False
    return prefix == _PREFIX_USER


def create_agent_identity() -> tuple[str, str]:
    """A fresh agent identity: ``(public_key, seed)``. Persist the seed."""
    kp = KeyPair.create()
    return kp.public_key, kp.seed


# ── seed files ──────────────────────────────────────────────────────────────


def save_seed(path: str | os.PathLike[str], seed: str) -> Path:
    """Write a seed to ``path`` readable by the owner only.

    On POSIX the file is created with mode 0600 before any byte is written, so
    there is no moment where another user could read it. On Windows, file
    permissions follow the folder's access list; keep seed files in your own
    profile folder.
    """
    KeyPair.from_seed(seed)  # refuse to write something that is not a seed
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(p, flags, 0o600)
    try:
        os.write(fd, (seed.strip() + "\n").encode("ascii"))
    finally:
        os.close(fd)
    if sys.platform != "win32":
        os.chmod(p, 0o600)
    return p


def load_seed(path: str | os.PathLike[str], *, strict_permissions: bool = True) -> str:
    """Read a seed file written by :func:`save_seed` (or by hand).

    On POSIX, a file that group or others can read is refused while
    ``strict_permissions`` is on, the same rule ssh applies to private keys: a
    seed anyone else could read is a seed anyone else may already hold.
    """
    p = Path(path)
    if strict_permissions and sys.platform != "win32":
        mode = p.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(
                f"{p} is readable by other users (mode {oct(mode & 0o777)}). "
                f"Run: chmod 600 {p}"
            )
    seed = p.read_text(encoding="ascii").strip()
    KeyPair.from_seed(seed)
    return seed


def load_or_create_seed(path: str | os.PathLike[str]) -> str:
    """Load the seed at ``path``, or make a new identity and save it there."""
    p = Path(path)
    if p.exists():
        return load_seed(p)
    _, seed = create_agent_identity()
    save_seed(p, seed)
    return seed
