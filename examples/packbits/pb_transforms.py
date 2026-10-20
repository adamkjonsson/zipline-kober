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

#: IP's two versions, by a packet's first nibble, and their headers' sizes.
_IPV4, _IPV6 = 4, 6
_IPV4_HEADER, _IPV6_HEADER = 20, 40


def is_one_ip_packet(packet: bytes) -> bool:
    """Return whether ``packet`` is one IP packet, exactly as long as its header says.

    What ``net:ip`` promises of a record, and what nothing downstream checks:
    the format never holds a ``net:`` payload to its label.
    """
    version = packet[0] >> 4 if packet else 0
    if version == _IPV4 and len(packet) >= _IPV4_HEADER:
        return int.from_bytes(packet[2:4], "big") == len(packet)
    if version == _IPV6 and len(packet) >= _IPV6_HEADER:
        return _IPV6_HEADER + int.from_bytes(packet[4:6], "big") == len(packet)
    return False


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
            it, what unpacks is not what the CRC says, or it is not one IP
            packet, which a tunnel's receiver would drop too. The spec names
            each ``unpack-failed``.

    """
    if length > limit:
        msg = "the length passes the limit"
        raise ValueError(msg)
    packet = unpack(data, length)
    if zlib.crc32(packet) != crc:
        msg = "the packet is not the one its CRC says"
        raise ValueError(msg)
    if not is_one_ip_packet(packet):
        msg = "what unpacks is not one IP packet"
        raise ValueError(msg)
    return packet


register("packbits", packbits)
