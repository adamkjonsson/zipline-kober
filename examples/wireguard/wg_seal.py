r"""Seal generated traffic as WireGuard: a tunnel module for ``packeteer stream``.

packeteer generates the traffic inside the tunnel, a DNS or HTTP conversation
with whatever impairments it is asked for, and calls :meth:`WireGuard.wrap`
once for each inner packet it sends, in the order it sends them. This returns
the WireGuard datagrams that carry it: a real handshake first, then the packet,
sealed. packeteer does no cryptography; this file and ``wg_crypto.py`` do it
all, which is the point of the example::

    packeteer stream --protocol udp --payload dns --protocol-messages dns.json \
        --client-ip 10.8.0.2 --server-ip 10.8.0.1 --server-port 53 --packets 40 \
        --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 51820 \
        --tunnel-module examples/wireguard/wg_seal.py \
        --tunnel-arg keylog=keys.json --tunnel-arg truth=truth.jsonl \
        --tunnel-corruption 0.1 --seed 7 --pcap wg.pcap

The client is the initiator. Every ``rekey_after`` sealed packets a new
handshake starts a new session, with new indices and keys, as WireGuard rekeys
after a time.

``--tunnel-arg`` takes:

- ``keylog``: where to write the key log kober reads, each receiver index to
  its session's key in that direction: ``--param keys=file:keys.json``.
- ``truth``: where to write one JSON line per sealed packet, saying what it
  carried and what went on the wire, for a test to check a decode against.
- ``wireshark_keylog`` (optional): where to write the keys Wireshark needs to
  open the same capture, for a check by a WireGuard implementation that is not
  this one: ``tshark -o wg.keylog_file:wireshark.keys``.
- ``seed`` (default 1): every key and index comes from it, so a seeded capture
  reproduces byte for byte.
- ``initiator_key``, ``responder_key`` (optional): the static private keys, as
  ``hex:…``, when they should be known ones rather than the seed's.
- ``rekey_after`` (default 1000000): sealed packets per session.

The responder sends as soon as the handshake ends, where a real one waits for
the initiator's first transport message. Nothing that reads the capture can
tell, and the example does not try to reproduce WireGuard's timers.
"""

from __future__ import annotations

import base64
import json
import random
import struct
from collections.abc import Mapping, Sequence
from pathlib import Path

from wg_crypto import KEY_SIZE, seal, transport_nonce
from wg_handshake import (
    Keypair,
    Session,
    consume_initiation,
    consume_response,
    create_initiation,
    create_response,
)


def _private(text: str | None, rng: random.Random) -> bytes:
    """Return a private key from ``hex:…``, or the seed's next one."""
    if text is None:
        return rng.randbytes(32)
    form, _, value = text.partition(":")
    if form != "hex" or len(bytes.fromhex(value)) != KEY_SIZE:
        msg = "a key is hex: and 32 bytes"
        raise ValueError(msg)
    return bytes.fromhex(value)


class WireGuard:
    """Both peers of a WireGuard tunnel: the initiator on the client's side.

    Attributes:
        initiator: The initiator's static key pair.
        responder: The responder's static key pair.
        session: The session in use, or ``None`` before the first packet.

    """

    def __init__(
        self,
        *,
        seed: int,
        rekey_after: int,
        keylog: Path,
        truth: Path,
        wireshark_keylog: Path | None = None,
        initiator_key: str | None = None,
        responder_key: str | None = None,
    ) -> None:
        self._rng = random.Random(seed)
        self.initiator = Keypair.from_private(_private(initiator_key, self._rng))
        self.responder = Keypair.from_private(_private(responder_key, self._rng))
        self._rekey_after = rekey_after
        self._keylog, self._truth, self._wireshark = keylog, truth, wireshark_keylog
        self.session: Session | None = None
        self._keys: dict[int, bytes] = {}
        self._counters = {"c2s": 0, "s2c": 0}
        self._sessions = 0
        self._sealed = 0
        truth.write_text("")
        if wireshark_keylog is not None:
            wireshark_keylog.write_text("")

    def wrap(self, inner: bytes, direction: str, timestamp: float) -> Sequence[tuple[str, bytes]]:
        """Return the datagrams that carry ``inner``: a handshake first when one is due.

        Args:
            inner: The inner packet, from its IP header on.
            direction: ``"c2s"`` or ``"s2c"``, the way it travels.
            timestamp: When it is sent, which the handshake encrypts.

        Returns:
            The outer datagrams, each with its direction.

        """
        out: list[tuple[str, bytes]] = []
        if self.session is None or self._sealed % self._rekey_after == 0:
            out += self._handshake(timestamp)
        out.append((direction, self._seal(inner, direction)))
        return out

    def _handshake(self, timestamp: float) -> list[tuple[str, bytes]]:
        """Run one handshake, each side reading the other's message as it would."""
        initiator_ephemeral = Keypair.from_private(self._rng.randbytes(32))
        responder_ephemeral = Keypair.from_private(self._rng.randbytes(32))
        initiator_index, responder_index = self._rng.getrandbits(32), self._rng.getrandbits(32)
        initiation, initiated = create_initiation(
            self.initiator, self.responder.public, initiator_ephemeral, initiator_index, timestamp
        )
        received = consume_initiation(self.responder, initiation)
        response, responder_side = create_response(received, responder_ephemeral, responder_index)
        session = consume_response(initiated, response)
        if session != responder_side:  # pragma: no cover - the two halves disagree
            msg = "the two sides of the handshake derived different keys"
            raise RuntimeError(msg)
        self.session = session
        self._sessions += 1
        self._counters = {"c2s": 0, "s2c": 0}
        self._keys[session.responder_index] = session.initiator_to_responder
        self._keys[session.initiator_index] = session.responder_to_initiator
        self._keylog.write_text(
            json.dumps({str(index): f"hex:{key.hex()}" for index, key in self._keys.items()})
        )
        if self._wireshark is not None:
            self._log_for_wireshark(initiator_ephemeral, responder_ephemeral)
        return [("c2s", initiation), ("s2c", response)]

    def _log_for_wireshark(self, initiator: Keypair, responder: Keypair) -> None:
        """Append what Wireshark needs to open this session, from either side."""

        def line(name: str, key: bytes) -> str:
            return f"{name} = {base64.b64encode(key).decode()}\n"

        assert self._wireshark is not None
        with self._wireshark.open("a") as log:
            for local, remote, ephemeral in (
                (self.initiator, self.responder, initiator),
                (self.responder, self.initiator, responder),
            ):
                log.write(line("LOCAL_STATIC_PRIVATE_KEY", local.private))
                log.write(line("REMOTE_STATIC_PUBLIC_KEY", remote.public))
                log.write(line("LOCAL_EPHEMERAL_PRIVATE_KEY", ephemeral.private))

    def _seal(self, inner: bytes, direction: str) -> bytes:
        """Seal one inner packet as a transport message, and say so in the truth."""
        assert self.session is not None
        if direction == "c2s":
            receiver, key = self.session.responder_index, self.session.initiator_to_responder
        else:
            receiver, key = self.session.initiator_index, self.session.responder_to_initiator
        counter = self._counters[direction]
        self._counters[direction] += 1
        padded = inner + b"\x00" * (-len(inner) % 16)
        message = struct.pack("<B3sIQ", 4, b"\x00" * 3, receiver, counter) + seal(
            key, transport_nonce(counter), padded
        )
        self._sealed += 1
        with self._truth.open("a") as truth:
            truth.write(
                json.dumps(
                    {
                        "session": self._sessions,
                        "direction": direction,
                        "receiver": receiver,
                        "counter": counter,
                        "inner": inner.hex(),
                        "plaintext": padded.hex(),
                        "outer": message.hex(),
                    }
                )
                + "\n"
            )
        return message


def make_wrapper(args: Mapping[str, str]) -> WireGuard:
    """Return the tunnel ``--tunnel-arg`` describes: what packeteer calls."""
    wireshark = args.get("wireshark_keylog")
    return WireGuard(
        seed=int(args.get("seed", "1")),
        rekey_after=int(args.get("rekey_after", "1000000")),
        keylog=Path(args.get("keylog", "keys.json")),
        truth=Path(args.get("truth", "truth.jsonl")),
        wireshark_keylog=None if wireshark is None else Path(wireshark),
        initiator_key=args.get("initiator_key"),
        responder_key=args.get("responder_key"),
    )
