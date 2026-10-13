"""WireGuard's handshake, Noise IK, both sides of it, for the WireGuard example.

Written against https://www.wireguard.com/protocol/, step for step: the page's
``HASH``, ``HMAC``, ``MAC`` and ``AEAD`` are :func:`blake2s`, :func:`hmac_blake2s`,
:func:`keyed_mac` and :func:`aead`, and its other names are kept. Two messages,
then both peers hold the same two transport keys, one per direction
(:class:`Session`).

The example needs both sides because the tunnel wrapper (``wg_seal.py``) plays
both peers: it seals what packeteer's client sends and what its server
answers. Reading each message back as the other side would, rather than
handing the keys across, means a fault in one half cannot be cancelled by the
same fault in the other. Wireshark, given the same keys, opens what this
produces; that is the check from outside (``tests/test_wireguard_example.py``).

What it leaves out, being an example: cookies (``mac2`` is always zero, as
when a responder is not under load), a pre-shared key other than none, and
every timer. Like ``wg_crypto.py``, it is not hardened and protects nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from wg_crypto import open_sealed, seal, transport_nonce, x25519, x25519_public

#: The protocol's constants, as the page defines them.
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
#: No pre-shared key: 32 zero bytes, as the page says to use then.
NO_PRESHARED_KEY = b"\x00" * 32

INITIATION_SIZE = 148
RESPONSE_SIZE = 92
#: Where ``mac1`` starts in each message: it covers everything before it.
_INITIATION_MAC1 = 116
_RESPONSE_MAC1 = 60
#: What TAI64N adds to a Unix time: 2^62, and the ten seconds TAI ran ahead of
#: UTC in 1970.
_TAI64_BASE = 0x400000000000000A


class HandshakeError(ValueError):
    """A handshake message that does not read back: wrong peer, or not intact."""


def blake2s(*parts: bytes) -> bytes:
    """Return the protocol's ``HASH``: BLAKE2s-256 of the parts, joined."""
    return hashlib.blake2s(b"".join(parts)).digest()


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    """Return the protocol's ``HMAC``: HMAC-BLAKE2s, 32 bytes."""
    return hmac.new(key, data, hashlib.blake2s).digest()


def keyed_mac(key: bytes, data: bytes) -> bytes:
    """Return the protocol's ``MAC``: keyed BLAKE2s, 16 bytes."""
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def aead(key: bytes, counter: int, plaintext: bytes, auth: bytes) -> bytes:
    """Return the protocol's ``AEAD``: ChaCha20-Poly1305, nonce zeros then the counter."""
    return seal(key, transport_nonce(counter), plaintext, auth)


def tai64n(timestamp: float) -> bytes:
    """Return a TAI64N label for a Unix time: 8 bytes of seconds, 4 of nanoseconds."""
    seconds = int(timestamp)
    nanoseconds = int(round((timestamp - seconds) * 1e9)) % 1_000_000_000
    return struct.pack(">QI", _TAI64_BASE + seconds, nanoseconds)


@dataclass(frozen=True)
class Keypair:
    """A Curve25519 key pair.

    Attributes:
        private: 32 bytes.
        public: 32 bytes, derived from ``private``.

    """

    private: bytes
    public: bytes

    @classmethod
    def from_private(cls, private: bytes) -> Keypair:
        """Return the pair whose private key is ``private``."""
        return cls(private, x25519_public(private))


@dataclass(frozen=True)
class Session:
    """What a completed handshake gives both peers.

    Attributes:
        initiator_index: The index the initiator chose: the receiver of every
            transport message sent to it.
        responder_index: The index the responder chose.
        initiator_to_responder: The key for messages to the responder.
        responder_to_initiator: The key for messages to the initiator.

    """

    initiator_index: int
    responder_index: int
    initiator_to_responder: bytes
    responder_to_initiator: bytes


@dataclass
class _State:
    """A side's ``chaining_key`` and ``hash``, which each step updates."""

    chaining_key: bytes
    hash: bytes

    def mix_key(self, material: bytes) -> bytes:
        """Set ``temp = HMAC(chaining_key, material)`` and the next chaining key; return temp."""
        temp = hmac_blake2s(self.chaining_key, material)
        self.chaining_key = hmac_blake2s(temp, b"\x01")
        return temp

    def mix_hash(self, data: bytes) -> None:
        self.hash = blake2s(self.hash, data)


def _start(responder_public: bytes) -> _State:
    chaining_key = blake2s(CONSTRUCTION)
    return _State(chaining_key, blake2s(blake2s(chaining_key, IDENTIFIER), responder_public))


@dataclass
class Initiated:
    """The initiator's state once its initiation is sent."""

    state: _State
    static: Keypair
    ephemeral: Keypair
    responder_public: bytes
    sender_index: int


@dataclass
class Received:
    """The responder's state once it has read an initiation."""

    state: _State
    static: Keypair
    initiator_public: bytes
    initiator_ephemeral: bytes
    initiator_index: int
    timestamp: bytes


def create_initiation(
    static: Keypair,
    responder_public: bytes,
    ephemeral: Keypair,
    sender_index: int,
    timestamp: float,
) -> tuple[bytes, Initiated]:
    """Build the first message, initiator to responder.

    Args:
        static: The initiator's static key pair.
        responder_public: The responder's static public key.
        ephemeral: This handshake's ephemeral key pair.
        sender_index: The index the initiator chooses for this session.
        timestamp: When it is sent, as a Unix time: encrypted as TAI64N.

    Returns:
        The 148-byte message, and the state to read the response with.

    """
    state = _start(responder_public)
    state.mix_hash(ephemeral.public)
    state.mix_key(ephemeral.public)
    temp = state.mix_key(x25519(ephemeral.private, responder_public))
    key = hmac_blake2s(temp, state.chaining_key + b"\x02")
    encrypted_static = aead(key, 0, static.public, state.hash)
    state.mix_hash(encrypted_static)
    temp = state.mix_key(x25519(static.private, responder_public))
    key = hmac_blake2s(temp, state.chaining_key + b"\x02")
    encrypted_timestamp = aead(key, 0, tai64n(timestamp), state.hash)
    state.mix_hash(encrypted_timestamp)
    body = (
        struct.pack("<B3sI", 1, b"\x00" * 3, sender_index)
        + ephemeral.public
        + encrypted_static
        + encrypted_timestamp
    )
    message = body + keyed_mac(blake2s(LABEL_MAC1, responder_public), body) + b"\x00" * 16
    return message, Initiated(state, static, ephemeral, responder_public, sender_index)


def consume_initiation(static: Keypair, message: bytes) -> Received:
    """Read the first message as the responder, the same steps in reverse.

    Args:
        static: The responder's static key pair.
        message: The initiation.

    Returns:
        The responder's state, holding the initiator's static public key.

    Raises:
        HandshakeError: If the message is not an intact initiation to this
            responder.

    """
    if len(message) != INITIATION_SIZE or message[0] != 1:
        msg = "not a handshake initiation"
        raise HandshakeError(msg)
    if not hmac.compare_digest(
        keyed_mac(blake2s(LABEL_MAC1, static.public), message[:_INITIATION_MAC1]),
        message[_INITIATION_MAC1 : _INITIATION_MAC1 + 16],
    ):
        msg = "mac1 does not verify: not meant for this responder"
        raise HandshakeError(msg)
    (sender_index,) = struct.unpack_from("<I", message, 4)
    ephemeral = message[8:40]
    encrypted_static, encrypted_timestamp = message[40:88], message[88:116]
    state = _start(static.public)
    state.mix_hash(ephemeral)
    state.mix_key(ephemeral)
    temp = state.mix_key(x25519(static.private, ephemeral))
    key = hmac_blake2s(temp, state.chaining_key + b"\x02")
    try:
        initiator_public = open_sealed(key, transport_nonce(0), encrypted_static, state.hash)
        state.mix_hash(encrypted_static)
        temp = state.mix_key(x25519(static.private, initiator_public))
        key = hmac_blake2s(temp, state.chaining_key + b"\x02")
        timestamp = open_sealed(key, transport_nonce(0), encrypted_timestamp, state.hash)
    except ValueError as exc:
        msg = "the initiation does not decrypt"
        raise HandshakeError(msg) from exc
    state.mix_hash(encrypted_timestamp)
    return Received(state, static, initiator_public, ephemeral, sender_index, timestamp)


def _transport_keys(chaining_key: bytes) -> tuple[bytes, bytes]:
    """Return the two transport keys, initiator to responder first."""
    temp1 = hmac_blake2s(chaining_key, b"")
    temp2 = hmac_blake2s(temp1, b"\x01")
    return temp2, hmac_blake2s(temp1, temp2 + b"\x02")


def create_response(
    received: Received, ephemeral: Keypair, sender_index: int
) -> tuple[bytes, Session]:
    """Build the second message, responder to initiator.

    Args:
        received: What :func:`consume_initiation` read.
        ephemeral: The responder's ephemeral key pair.
        sender_index: The index the responder chooses for this session.

    Returns:
        The 92-byte message, and the session as the responder holds it.

    """
    state = received.state
    state.mix_hash(ephemeral.public)
    state.mix_key(ephemeral.public)
    state.mix_key(x25519(ephemeral.private, received.initiator_ephemeral))
    state.mix_key(x25519(ephemeral.private, received.initiator_public))
    temp = hmac_blake2s(state.chaining_key, NO_PRESHARED_KEY)
    state.chaining_key = hmac_blake2s(temp, b"\x01")
    temp2 = hmac_blake2s(temp, state.chaining_key + b"\x02")
    key = hmac_blake2s(temp, temp2 + b"\x03")
    state.mix_hash(temp2)
    encrypted_nothing = aead(key, 0, b"", state.hash)
    state.mix_hash(encrypted_nothing)
    body = (
        struct.pack("<B3sII", 2, b"\x00" * 3, sender_index, received.initiator_index)
        + ephemeral.public
        + encrypted_nothing
    )
    message = body + keyed_mac(blake2s(LABEL_MAC1, received.initiator_public), body) + b"\x00" * 16
    to_responder, to_initiator = _transport_keys(state.chaining_key)
    return message, Session(received.initiator_index, sender_index, to_responder, to_initiator)


def consume_response(initiated: Initiated, message: bytes) -> Session:
    """Read the second message as the initiator, and derive the session.

    Args:
        initiated: What :func:`create_initiation` kept.
        message: The response.

    Returns:
        The session as the initiator holds it.

    Raises:
        HandshakeError: If the message is not an intact response to this
            initiation.

    """
    if len(message) != RESPONSE_SIZE or message[0] != 2:
        msg = "not a handshake response"
        raise HandshakeError(msg)
    if not hmac.compare_digest(
        keyed_mac(blake2s(LABEL_MAC1, initiated.static.public), message[:_RESPONSE_MAC1]),
        message[_RESPONSE_MAC1 : _RESPONSE_MAC1 + 16],
    ):
        msg = "mac1 does not verify: not meant for this initiator"
        raise HandshakeError(msg)
    sender_index, receiver_index = struct.unpack_from("<II", message, 4)
    if receiver_index != initiated.sender_index:
        msg = "the response answers another initiation"
        raise HandshakeError(msg)
    ephemeral, encrypted_nothing = message[12:44], message[44:60]
    state = initiated.state
    state.mix_hash(ephemeral)
    state.mix_key(ephemeral)
    state.mix_key(x25519(initiated.ephemeral.private, ephemeral))
    state.mix_key(x25519(initiated.static.private, ephemeral))
    temp = hmac_blake2s(state.chaining_key, NO_PRESHARED_KEY)
    state.chaining_key = hmac_blake2s(temp, b"\x01")
    temp2 = hmac_blake2s(temp, state.chaining_key + b"\x02")
    key = hmac_blake2s(temp, temp2 + b"\x03")
    state.mix_hash(temp2)
    try:
        open_sealed(key, transport_nonce(0), encrypted_nothing, state.hash)
    except ValueError as exc:
        msg = "the response does not decrypt"
        raise HandshakeError(msg) from exc
    to_responder, to_initiator = _transport_keys(state.chaining_key)
    return Session(initiated.sender_index, sender_index, to_responder, to_initiator)
