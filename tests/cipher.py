"""A deliberately trivial cipher for tests: XOR with a keystream, and a tag.

The standard library has no AES, ChaCha20 or GCM, and ``CLAUDE.md`` forbids
reaching for one, so a real cipher is always the caller's to register. This is
enough to exercise every path one would: parameters from fields and from the
document, a tag that does not verify on the wrong key, and a failure whose
message a caller's code controls. It is not encryption.

Layout of a sealed payload: the XORed plaintext, then a four-byte tag.
"""

from __future__ import annotations

import hashlib
import zlib

TAG = 4


def _keystream(key: bytes, nonce: bytes, size: int) -> bytes:
    """Return ``size`` bytes of keystream for this key and nonce."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:size])


def _tag(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return zlib.crc32(key + nonce + plaintext).to_bytes(TAG, "big")


def seal(plaintext: bytes, *, key: bytes, nonce: bytes) -> bytes:
    """Encrypt and tag ``plaintext``: what a test puts on the wire."""
    stream = _keystream(key, nonce, len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, stream, strict=True)) + _tag(
        key, nonce, plaintext
    )


def xor_open(data: bytes, *, limit: int, key: bytes, nonce: bytes) -> bytes:
    """Open a sealed payload: the transform a test registers.

    Raises ``ValueError`` on a tag that does not verify, with the key in its
    message, exactly the kind of text kober must never write out.
    """
    if len(data) < TAG:
        msg = "sealed payload shorter than its tag"
        raise ValueError(msg)
    body, tag = data[:-TAG], data[-TAG:]
    if len(body) > limit:
        msg = "plaintext longer than the limit"
        raise ValueError(msg)
    stream = _keystream(key, nonce, len(body))
    plaintext = bytes(a ^ b for a, b in zip(body, stream, strict=True))
    if _tag(key, nonce, plaintext) != tag:
        msg = f"tag mismatch under key {key.hex()}"
        raise ValueError(msg)
    return plaintext
