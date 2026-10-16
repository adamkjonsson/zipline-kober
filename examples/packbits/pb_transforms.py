r"""Register ``packbits``, so kober can unpack a datagram of ``packbits.yaml``.

Load it beside the spec::

    kober run examples/packbits/packbits.yaml in.zpf -o out.zpf --emit field \
        --load-transforms examples/packbits/pb_transforms.py

No ``--param``: nothing about a run is secret here, and everything the
transform needs, the datagram says.
"""

from __future__ import annotations

import zlib

from pb_codec import unpack

from kober.transforms import register


def packbits(data: bytes, *, limit: int, length: int, crc: int) -> bytes:
    """Unpack one datagram's packet: what ``packbits.yaml`` declares.

    Args:
        data: The packed packet, as the datagram carries it.
        limit: The most bytes the packet may have, from the spec.
        length: The packet's length, from the datagram's header.
        crc: The packet's CRC-32, from the datagram's header.

    Returns:
        The packet.

    Raises:
        ValueError: If the length passes the limit, the bytes do not unpack to
            it, or what unpacks is not what the CRC says. The spec names each
            ``unpack-failed``.

    """
    if length > limit:
        msg = "the length passes the limit"
        raise ValueError(msg)
    packet = unpack(data, length)
    if zlib.crc32(packet) != crc:
        msg = "the packet is not the one its CRC says"
        raise ValueError(msg)
    return packet


register("packbits", packbits)
