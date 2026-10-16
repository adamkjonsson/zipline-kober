"""PackBits, the run-length scheme of Apple's Macintosh toolbox and TIFF.

TIFF 6.0 §9 defines it, as compression type 32773, by its unpacking loop: read
a flag-counter byte ``n``; from 0 to 127, copy the next ``n + 1`` bytes as they
are; from -127 to -1, repeat the next byte ``-n + 1`` times; -128 does nothing.
Apple's Technical Note TN1023, *Understanding PackBits*, adds the rule that
makes it usable at all: the packed bytes do not say where they end, so
unpacking needs the unpacked length.

Both sides of a tunnel use this file, the module that packs and the transform
that unpacks, which is why it is a file of its own, and why its tests check it
against TN1023's worked example rather than against itself.
"""

from __future__ import annotations

#: The longest run either kind of record holds.
MAX_RUN = 128

#: The shortest run of one byte worth a replicate record: TN1023's.
MIN_REPEAT = 3

#: The flag-counter byte that does nothing, which PackBits never writes.
NOOP = 0x80


class UnpackError(ValueError):
    """Packed bytes that do not unpack to the length they were said to have."""


def pack(data: bytes) -> bytes:
    """Pack ``data``: a replicate record for three or more equal bytes, literals otherwise.

    It is what Apple's PackBits writes for TN1023's example, and never more than
    one byte longer per 128 than ``data``, as TIFF 6.0 promises of the scheme.
    """
    out = bytearray()
    literal = bytearray()

    def flush() -> None:
        while literal:
            chunk = literal[:MAX_RUN]
            out.append(len(chunk) - 1)
            out.extend(chunk)
            del literal[:MAX_RUN]

    at = 0
    while at < len(data):
        run = 1
        while at + run < len(data) and run < MAX_RUN and data[at + run] == data[at]:
            run += 1
        if run >= MIN_REPEAT:
            flush()
            out.append(257 - run)  # -(run - 1), as an unsigned byte
            out.append(data[at])
            at += run
        else:
            literal.append(data[at])
            at += 1
    flush()
    return bytes(out)


def unpack(packed: bytes, length: int) -> bytes:
    """Unpack exactly ``length`` bytes, from exactly all of ``packed``.

    Args:
        packed: The packed bytes.
        length: How long the unpacked data is: PackBits cannot say.

    Returns:
        The unpacked data.

    Raises:
        UnpackError: If a record runs past ``length``, the packed bytes end
            before it is reached, or bytes are left over after it.

    """
    out = bytearray()
    at = 0
    while len(out) < length:
        if at >= len(packed):
            msg = "the packed bytes end before the length"
            raise UnpackError(msg)
        flag = packed[at]
        at += 1
        if flag == NOOP:
            continue
        if flag < NOOP:
            count, chunk = flag + 1, packed[at : at + flag + 1]
            if len(chunk) < count:
                msg = "a literal record past the packed bytes"
                raise UnpackError(msg)
            at += count
        else:
            count = 257 - flag
            if at >= len(packed):
                msg = "a replicate record with no byte to repeat"
                raise UnpackError(msg)
            chunk = packed[at : at + 1] * count
            at += 1
        if len(out) + count > length:
            msg = "a record runs past the length"
            raise UnpackError(msg)
        out += chunk
    if at != len(packed):
        msg = "packed bytes left over after the length"
        raise UnpackError(msg)
    return bytes(out)
