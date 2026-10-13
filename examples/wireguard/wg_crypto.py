"""ChaCha20-Poly1305 (RFC 8439) in the standard library, for the WireGuard example.

**This is the example's cipher, not kober's.** kober ships no cryptography and
never will: a cipher is always the code of whoever runs the spec, registered as
a transform. That is the point of the example. This file is what such code
looks like, and it is shared by the two things that need it: the transform
that opens a transport message (``wg_transforms.py``) and the tunnel wrapper
that seals one when traffic is generated.

It is written to be read against the RFC, section by section, and checked
against the RFC's own test vectors (``tests/test_wireguard_example.py``). It is
not written to be fast, about 6 ms for a full-size packet, and it is not
hardened against timing: use a reviewed library for anything that protects
data. A test decoding a few hundred packets does not care.

WireGuard's transport messages use exactly this AEAD, with an empty AAD and a
nonce of four zero bytes and the message's 64-bit counter, little-endian
(:func:`transport_nonce`).
"""

from __future__ import annotations

import hmac
import struct

#: ChaCha20's key, nonce and Poly1305 tag sizes, in bytes.
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

#: The first four words of every ChaCha20 state: "expand 32-byte k" (§2.3).
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK32 = 0xFFFFFFFF
#: The Poly1305 prime, 2^130 - 5 (§2.5).
_P = (1 << 130) - 5
#: The bits of r that §2.5's clamp keeps.
_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


class AuthenticationError(ValueError):
    """A sealed message's tag does not verify: corrupted, or under another key."""


def _rotl(value: int, count: int) -> int:
    return ((value << count) & _MASK32) | (value >> (32 - count))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    """Apply §2.1's quarter round to four words of ``state``, in place."""
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Return one 64-byte ChaCha20 keystream block (§2.3).

    Args:
        key: 32 bytes.
        counter: The 32-bit block counter.
        nonce: 12 bytes.

    Returns:
        The block.

    """
    initial = [
        *_CONSTANTS,
        *struct.unpack("<8I", key),
        counter & _MASK32,
        *struct.unpack("<3I", nonce),
    ]
    state = list(initial)
    for _ in range(10):  # 20 rounds: a column round and a diagonal round, ten times
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *((word + start) & _MASK32 for word, start in zip(state, initial, strict=True))
    )


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt ``data`` with ChaCha20, from block ``counter`` (§2.4).

    Args:
        key: 32 bytes.
        counter: The first block's counter.
        nonce: 12 bytes.
        data: The bytes to XOR with the keystream.

    Returns:
        ``data`` XORed with the keystream: the ciphertext of a plaintext, and
        the plaintext of a ciphertext.

    """
    out = bytearray()
    for block, at in enumerate(range(0, len(data), 64)):
        stream = chacha20_block(key, counter + block, nonce)
        out += bytes(a ^ b for a, b in zip(data[at : at + 64], stream, strict=False))
    return bytes(out)


def poly1305(key: bytes, message: bytes) -> bytes:
    """Return the 16-byte Poly1305 tag of ``message`` under a one-time ``key`` (§2.5).

    Args:
        key: 32 bytes, r then s.
        message: What to authenticate.

    Returns:
        The tag.

    """
    r = int.from_bytes(key[:16], "little") & _CLAMP
    s = int.from_bytes(key[16:32], "little")
    accumulator = 0
    for at in range(0, len(message), 16):
        block = int.from_bytes(message[at : at + 16] + b"\x01", "little")
        accumulator = (accumulator + block) * r % _P
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def poly1305_key(key: bytes, nonce: bytes) -> bytes:
    """Return the one-time Poly1305 key for a ChaCha20 key and nonce (§2.6).

    Args:
        key: 32 bytes.
        nonce: 12 bytes.

    Returns:
        32 bytes: the first half of block 0's keystream.

    """
    return chacha20_block(key, 0, nonce)[:32]


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    """Return what the tag is computed over: §2.8's padded AAD, ciphertext and lengths."""

    def pad16(data: bytes) -> bytes:
        return b"\x00" * (-len(data) % 16)

    lengths = struct.pack("<QQ", len(aad), len(ciphertext))
    return aad + pad16(aad) + ciphertext + pad16(ciphertext) + lengths


def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate ``plaintext`` (§2.8): the ciphertext, then the tag.

    Args:
        key: 32 bytes.
        nonce: 12 bytes, never used twice under one key.
        plaintext: What to seal.
        aad: Data authenticated but not encrypted.

    Returns:
        The ciphertext followed by its 16-byte tag.

    """
    ciphertext = chacha20(key, 1, nonce, plaintext)
    return ciphertext + poly1305(poly1305_key(key, nonce), _mac_data(aad, ciphertext))


def open_sealed(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Verify and decrypt what :func:`seal` produced (§2.8).

    The tag is checked before anything is decrypted, and compared in constant
    time.

    Args:
        key: 32 bytes.
        nonce: 12 bytes, as it was sealed with.
        sealed: The ciphertext followed by its tag.
        aad: The data it was authenticated with.

    Returns:
        The plaintext.

    Raises:
        AuthenticationError: If ``sealed`` is shorter than a tag, or its tag
            does not verify.

    """
    if len(sealed) < TAG_SIZE:
        msg = "shorter than a Poly1305 tag"
        raise AuthenticationError(msg)
    ciphertext, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]
    expected = poly1305(poly1305_key(key, nonce), _mac_data(aad, ciphertext))
    if not hmac.compare_digest(expected, tag):
        msg = "the tag does not verify"
        raise AuthenticationError(msg)
    return chacha20(key, 1, nonce, ciphertext)


def transport_nonce(counter: int) -> bytes:
    """Return the nonce a WireGuard transport message is sealed with.

    Four zero bytes, then the message's counter as a 64-bit little-endian
    integer: the same eight bytes the message carries in its counter field.

    Args:
        counter: The message's counter.

    Returns:
        12 bytes.

    """
    return b"\x00" * 4 + counter.to_bytes(8, "little")
