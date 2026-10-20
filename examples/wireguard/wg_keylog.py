r"""Turn a WireGuard key log and a capture into the key log kober reads.

kober opens a transport message with its session's key in its direction,
``keys[receiver]``. A real WireGuard endpoint never writes those keys down: it
derives them in each handshake, from static and ephemeral keys, and drops
them when the session ends. What it can be made to write down is those keys,
the ones Wireshark's WireGuard dissector reads (``wg.keylog_file``), and
wireguard-tools' ``contrib/extract-handshakes`` writes them on Linux, from the
endpoint's kernel, for every handshake it takes part in::

    New handshake session:
      LOCAL_STATIC_PRIVATE_KEY = QChaGDXeH3eQsbFAhueUNWFdq9KfpF3yl+eITjZbXEk=
      REMOTE_STATIC_PUBLIC_KEY = HzgTY6aWXtuSyW/PUquZtg8LB/DyMwEXGkPiEmdSsUU=
      LOCAL_EPHEMERAL_PRIVATE_KEY = UNGdRHuKDeqbFvmiV5FD4wP7a8PqI6v3Xnnz6Jc6NXQ=
      PRESHARED_KEY = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

This replays each handshake the capture holds with those keys, as the side
that logged them did, and writes the transport keys it derives::

    zpfwire convert wg.pcap -o wg.zpf
    python examples/wireguard/wg_keylog.py wg.zpf --wireshark-keylog handshakes.log \
        -o keys.json
    kober run examples/wireguard/wireguard.yaml wg.zpf -o packets.zpf --emit field \
        --load-transforms examples/wireguard/wg_transforms.py --param keys=file:keys.json

One side's keys are enough, either side's, so a log from one endpoint opens
both directions. A derivation is only taken when the capture confirms it: the
initiation must decrypt to the logged static key, and the response must open,
or be rebuilt byte for byte. A handshake no logged key opens is reported, and
its session's transport messages decode as ``decrypt-failed``.

A handshake is only seen if the capture has it: a session that began before
the capture did cannot be opened from it, whatever the log holds.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import zpf
from wg_crypto import KEY_SIZE
from wg_handshake import (
    INITIATION_SIZE,
    LABEL_MAC1,
    NO_PRESHARED_KEY,
    RESPONSE_SIZE,
    HandshakeError,
    Keypair,
    Session,
    blake2s,
    consume_initiation,
    consume_response,
    create_response,
    keyed_mac,
    own_initiation,
)
from zpf.blocks import Record

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

#: The key log lines Wireshark's dissector reads, by what each holds.
STATIC = "LOCAL_STATIC_PRIVATE_KEY"
REMOTE = "REMOTE_STATIC_PUBLIC_KEY"
EPHEMERAL = "LOCAL_EPHEMERAL_PRIVATE_KEY"
PRESHARED = "PRESHARED_KEY"
_KINDS = (STATIC, REMOTE, EPHEMERAL, PRESHARED)

#: Where ``mac1`` starts in each handshake message: it covers everything before.
_INITIATION_MAC1, _RESPONSE_MAC1 = 116, 60


@dataclass
class Logged:
    """Every key a WireGuard key log holds, whichever handshake it came from.

    Attributes:
        statics: Static key pairs, from their private keys.
        remotes: Static public keys of peers.
        ephemerals: Ephemeral key pairs, by public key.
        preshared: Pre-shared keys; none is always tried as well.

    """

    statics: list[Keypair] = field(default_factory=list)
    remotes: set[bytes] = field(default_factory=set)
    ephemerals: dict[bytes, Keypair] = field(default_factory=dict)
    preshared: list[bytes] = field(default_factory=lambda: [NO_PRESHARED_KEY])

    def publics(self) -> set[bytes]:
        """Return every static public key the log names or implies."""
        return self.remotes | {pair.public for pair in self.statics}


def read_wireshark_keylog(lines: Iterable[str]) -> Logged:
    """Read a key log as Wireshark does: ``NAME = base64`` lines, anything else ignored.

    Args:
        lines: The log's lines, ``extract-handshakes``' or Wireshark's own.

    Returns:
        Every key in it.

    Raises:
        ValueError: If a key line's value is not a 32-byte key in base64.

    """
    logged = Logged()
    for number, line in enumerate(lines, 1):
        name, equals, value = line.strip().partition("=")
        name = name.strip()
        if not equals or name not in _KINDS:
            continue
        try:
            key = base64.b64decode(value.strip(), validate=True)
        except binascii.Error:
            key = b""
        if len(key) != KEY_SIZE:
            msg = f"line {number}: {name} is not a 32-byte key in base64"
            raise ValueError(msg)
        if name == STATIC:
            pair = Keypair.from_private(key)
            if pair not in logged.statics:
                logged.statics.append(pair)
        elif name == REMOTE:
            logged.remotes.add(key)
        elif name == EPHEMERAL:
            pair = Keypair.from_private(key)
            logged.ephemerals[pair.public] = pair
        elif key not in logged.preshared:
            logged.preshared.append(key)
    return logged


def handshake_messages(capture: Path) -> tuple[list[bytes], list[bytes]]:
    """Return a converted capture's initiations and responses, each once, in order."""
    initiations: dict[bytes, None] = {}
    responses: dict[bytes, None] = {}
    with zpf.open(capture) as handle:
        for block in handle.blocks():
            if not isinstance(block, Record):
                continue
            payload = bytes(block.payload)
            if len(payload) == INITIATION_SIZE and payload[:4] == b"\x01\x00\x00\x00":
                initiations[payload] = None
            elif len(payload) == RESPONSE_SIZE and payload[:4] == b"\x02\x00\x00\x00":
                responses[payload] = None
    return list(initiations), list(responses)


def _meant_for(public: bytes, message: bytes, mac1: int) -> bool:
    return keyed_mac(blake2s(LABEL_MAC1, public), message[:mac1]) == message[mac1 : mac1 + 16]


def _as_initiator(logged: Logged, initiation: bytes, response: bytes) -> Session | None:
    """Replay a handshake as its initiator would, if the log holds the initiator's keys."""
    ephemeral = logged.ephemerals.get(initiation[8:40])
    if ephemeral is None:
        return None
    for responder in logged.publics():
        if not _meant_for(responder, initiation, _INITIATION_MAC1):
            continue
        for static in logged.statics:
            for preshared in logged.preshared:
                try:
                    initiated = own_initiation(static, responder, ephemeral, initiation)
                    return consume_response(initiated, response, preshared)
                except HandshakeError:
                    continue
    return None


def _as_responder(logged: Logged, initiation: bytes, response: bytes) -> Session | None:
    """Replay a handshake as its responder would, if the log holds the responder's keys."""
    ephemeral = logged.ephemerals.get(response[12:44])
    if ephemeral is None:
        return None
    (sender_index,) = struct.unpack_from("<I", response, 4)
    for static in logged.statics:
        if not _meant_for(static.public, initiation, _INITIATION_MAC1):
            continue
        for preshared in logged.preshared:
            try:
                received = consume_initiation(static, initiation)
            except HandshakeError:
                break
            rebuilt, session = create_response(received, ephemeral, sender_index, preshared)
            if rebuilt[:_RESPONSE_MAC1] == response[:_RESPONSE_MAC1]:
                return session
    return None


@dataclass(frozen=True)
class Derived:
    """What a key log and a capture give.

    Attributes:
        sessions: Every handshake the log opened.
        unopened: Initiations no response opened with the logged keys.

    """

    sessions: list[Session]
    unopened: list[bytes]

    def key_log(self) -> dict[str, str]:
        """Return the key log ``--param keys=file:…`` reads: receiver index to key."""
        keys: dict[str, str] = {}
        for session in self.sessions:
            keys[str(session.responder_index)] = f"hex:{session.initiator_to_responder.hex()}"
            keys[str(session.initiator_index)] = f"hex:{session.responder_to_initiator.hex()}"
        return keys


def derive(logged: Logged, initiations: Sequence[bytes], responses: Sequence[bytes]) -> Derived:
    """Derive each handshake's transport keys, from whichever side's keys the log holds."""
    answers: dict[int, list[bytes]] = {}
    for response in responses:
        answers.setdefault(struct.unpack_from("<I", response, 8)[0], []).append(response)
    sessions, unopened = [], []
    for initiation in initiations:
        (index,) = struct.unpack_from("<I", initiation, 4)
        for response in answers.get(index, []):
            session = _as_initiator(logged, initiation, response) or _as_responder(
                logged, initiation, response
            )
            if session is not None:
                sessions.append(session)
                break
        else:
            unopened.append(initiation)
    return Derived(sessions, unopened)


def main(argv: Sequence[str] | None = None) -> int:
    """Convert from the command line; return the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("capture", type=Path, help="a capture, converted: zpfwire convert")
    parser.add_argument(
        "--wireshark-keylog", type=Path, required=True,
        help="the key log Wireshark reads, as extract-handshakes writes it",
    )
    parser.add_argument("-o", "--output", type=Path, default=Path("keys.json"))
    args = parser.parse_args(argv)
    try:
        logged = read_wireshark_keylog(args.wireshark_keylog.read_text().splitlines())
    except (OSError, ValueError) as exc:
        print(f"wg_keylog: {exc}", file=sys.stderr)
        return 1
    derived = derive(logged, *handshake_messages(args.capture))
    args.output.write_text(json.dumps(derived.key_log(), indent=2) + "\n")
    total = len(derived.sessions) + len(derived.unopened)
    print(f"{len(derived.sessions)} of {total} handshakes opened; wrote {args.output}")
    for initiation in derived.unopened:
        (index,) = struct.unpack_from("<I", initiation, 4)
        print(f"  not opened: the initiation from index {index}", file=sys.stderr)
    return 0 if derived.sessions or not total else 1


if __name__ == "__main__":
    sys.exit(main())
