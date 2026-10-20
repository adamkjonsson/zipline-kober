r"""Pack generated traffic into ``packbits.yaml`` datagrams: a tunnel module for packeteer.

packeteer generates the traffic inside the tunnel and calls
:meth:`PackBitsTunnel.wrap` once for each inner packet it sends, in the order
it sends them; this returns the one datagram that carries it::

    packeteer stream --protocol udp --payload dns \
        --client-ip 10.8.0.2 --server-ip 10.8.0.1 --server-port 53 --packets 40 \
        --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 9999 \
        --tunnel-module examples/packbits/pb_tunnel.py \
        --tunnel-arg truth=truth.jsonl \
        --tunnel-corruption 0.1 --seed 7 --pcap pb.pcap

``--tunnel-arg`` takes one thing, ``truth``: where to write a JSON line per
packed packet, saying what went in and what went on the wire, for a test to
check a decode against. Nothing here is random, so there is no seed: packeteer's
own makes a run reproduce.
"""

from __future__ import annotations

import json
import struct
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from pb_codec import pack

#: The protocol's version, its first byte: ``packbits.yaml`` confirms it.
VERSION = 1

#: What a datagram starts with: version, the packet's length, its CRC-32.
HEADER = struct.Struct(">BHI")


def datagram(packet: bytes) -> bytes:
    """Return the datagram that carries ``packet``."""
    return HEADER.pack(VERSION, len(packet), zlib.crc32(packet)) + pack(packet)


class PackBitsTunnel:
    """One datagram per packet, and a truth line for each."""

    def __init__(self, truth: Path) -> None:
        self._truth = truth
        truth.write_text("")

    def wrap(self, inner: bytes, direction: str, timestamp: float) -> Sequence[tuple[str, bytes]]:
        """Return the datagram that carries one inner packet, and say so in the truth."""
        del timestamp  # every packet is packed the same, whenever it is sent
        outer = datagram(inner)
        with self._truth.open("a") as truth:
            line = {"direction": direction, "inner": inner.hex(), "outer": outer.hex()}
            truth.write(json.dumps(line) + "\n")
        return [(direction, outer)]


def make_wrapper(args: Mapping[str, str]) -> PackBitsTunnel:
    """Return the tunnel ``--tunnel-arg`` describes: what packeteer calls."""
    unknown = set(args) - {"truth"}
    if unknown:
        msg = f"unknown --tunnel-arg {sorted(unknown)}; this tunnel takes only truth"
        raise ValueError(msg)
    return PackBitsTunnel(Path(args.get("truth", "truth.jsonl")))
