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


def wg_transport(data: bytes, *, limit: int, key: bytes, counter: int) -> bytes:
    """Open one transport message's packet: what ``wireguard.yaml`` declares.

    Args:
        data: The encrypted packet and its tag, as the message carries them.
        limit: The most bytes the plaintext may have, from the spec.
        key: The receiver's key for this session, from the spec's ``keys``.
        counter: The message's counter, which is its nonce.

    Returns:
        The plaintext: an IP packet, padded to a multiple of 16 bytes as
        WireGuard pads it, or nothing for a keepalive.

    Raises:
        ValueError: If the key, the counter or the length cannot be right.
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
    return open_sealed(key, transport_nonce(counter), data)


register("wg-transport", wg_transport)
