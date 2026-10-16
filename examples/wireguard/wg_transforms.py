r"""Register ``wg-transport``, so kober can open a WireGuard transport message.

Load it beside the spec::

    kober run examples/wireguard/wireguard.yaml in.zpf -o out.zpf --emit field \
        --load-transforms examples/wireguard/wg_transforms.py \
        --param keys=file:keys.json

This is all the code a protocol of your own needs on kober's side: a function
from the bytes a spec hands it, and the arguments it declares, to the bytes it
produces, and one call to :func:`kober.transforms.register`. Whatever it raises
is a failed transform, named ``decrypt-failed`` where the spec says so, and the
message goes on. kober reports only the exception's class, never its text, so a
key in a message cannot reach the file.
"""

from __future__ import annotations

from wg_crypto import KEY_SIZE, TAG_SIZE, open_sealed, transport_nonce

from kober.transforms import register

#: The two IP versions, and the smallest header each has.
_IPV4, _IPV6 = 4, 6
_IPV4_HEADER, _IPV6_HEADER = 20, 40


def ip_length(packet: bytes) -> int:
    """Return how long the IP packet at the start of ``packet`` says it is.

    What WireGuard reads to drop its padding: an IPv4 header's total length,
    or an IPv6 header's payload length plus its own 40 bytes.

    Args:
        packet: A decrypted plaintext, possibly padded.

    Returns:
        The packet's length, at most ``len(packet)``.

    Raises:
        ValueError: If it does not start with an IP header, or says it is
            longer than what is there.

    """
    version = packet[0] >> 4 if packet else 0
    if version == _IPV4 and len(packet) >= _IPV4_HEADER:
        length = int.from_bytes(packet[2:4], "big")
    elif version == _IPV6 and len(packet) >= _IPV6_HEADER:
        length = _IPV6_HEADER + int.from_bytes(packet[4:6], "big")
    else:
        msg = "not an IP packet"
        raise ValueError(msg)
    if not _IPV4_HEADER <= length <= len(packet):
        msg = "an IP length past the plaintext"
        raise ValueError(msg)
    return length


def wg_transport(data: bytes, *, limit: int, key: bytes, counter: int) -> bytes:
    """Open one transport message's packet: what ``wireguard.yaml`` declares.

    Args:
        data: The encrypted packet and its tag, as the message carries them.
        limit: The most bytes the plaintext may have, from the spec.
        key: The receiver's key for this session, from the spec's ``keys``.
        counter: The message's counter, which is its nonce.

    Returns:
        The IP packet, without the padding WireGuard seals it with, or nothing
        for a keepalive.

    Raises:
        ValueError: If the key, the counter or the length cannot be right, or
            what opens is not an IP packet. WireGuard drops such a packet too,
            and the spec names it ``decrypt-failed``, which is the one case that
            says more than happened: it did decrypt.
        wg_crypto.AuthenticationError: If the tag does not verify.

    """
    if len(key) != KEY_SIZE:
        msg = f"a key is {KEY_SIZE} bytes"
        raise ValueError(msg)
    if not 0 <= counter < 1 << 64:
        msg = "a counter is 64 bits"
        raise ValueError(msg)
    if len(data) - TAG_SIZE > limit:
        msg = "the plaintext would pass the limit"
        raise ValueError(msg)
    plaintext = open_sealed(key, transport_nonce(counter), data)
    return plaintext[: ip_length(plaintext)] if plaintext else plaintext


register("wg-transport", wg_transport)
