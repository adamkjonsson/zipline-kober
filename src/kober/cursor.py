"""A bit-level read cursor over a run of bytes.

The cursor **owns the read position**, which is ``DESIGN.md`` §2.1's invariant
in code: nothing author-supplied moves it, and every advance goes through a
method here. That is what keeps coverage honest, because bytes can only be
consumed by being claimed.

Positions are tracked in **bits**, since :attr:`kober.spec.IntType.bits` need
not be a multiple of eight. Citations are still **bytes**: :meth:`Cursor.span`
rounds a bit range outward to the bytes containing it, which is the rule from
§1 — `zpf` spans are byte offsets, and a record citing a bitfield cites the
containing bytes.

**Offsets are absolute.** A cursor is built over one contiguous run and carries
that run's ``base``, so every span it reports is already in the stream's offset
space. That is the translation the decoder phase's Q1 settlement requires: runs
are relative, citations are not.

Bit order is **most significant first**, both within a byte and across a
multi-byte unaligned field, matching Kaitai and the wire layout of every
protocol that packs flags. :attr:`~kober.spec.Endian` applies to whole-byte
reads from an aligned position and is meaningless below that — see
:meth:`Cursor.read_int`.
"""

from __future__ import annotations

from kober.errors import TruncatedRead
from kober.spec import Endian

_BITS_PER_BYTE = 8


class Cursor:
    """A read position over ``data``, measured in bits.

    Args:
        data: The contiguous run to read.
        base: Stream offset of ``data[0]``, so reported spans are absolute.

    """

    __slots__ = ("_base", "_bit", "_data")

    def __init__(self, data: bytes, base: int = 0) -> None:
        self._data = data
        self._base = base
        self._bit = 0

    def __repr__(self) -> str:
        return (
            f"Cursor(bit={self._bit} of {len(self._data) * _BITS_PER_BYTE}, "
            f"base={self._base})"
        )

    # --- position ----------------------------------------------------------

    @property
    def base(self) -> int:
        """Stream offset of the run's first byte."""
        return self._base

    @property
    def size(self) -> int:
        """The run's length in bytes."""
        return len(self._data)

    def tell(self) -> int:
        """Return the current position, in bits from the run's start."""
        return self._bit

    def remaining_bits(self) -> int:
        """Return how many bits are left."""
        return len(self._data) * _BITS_PER_BYTE - self._bit

    def remaining_bytes(self) -> int:
        """Return how many whole bytes are left from the current position."""
        return self.remaining_bits() // _BITS_PER_BYTE

    def at_end(self) -> bool:
        """Whether the run is exhausted."""
        return self.remaining_bits() <= 0

    def is_aligned(self) -> bool:
        """Whether the position sits on a byte boundary."""
        return self._bit % _BITS_PER_BYTE == 0

    def byte_offset(self) -> int:
        """Return the absolute offset of the byte the position is inside."""
        return self._base + self._bit // _BITS_PER_BYTE

    def span(self, mark: int) -> tuple[int, int]:
        """Return the absolute byte range covered since ``mark``.

        Rounded **outward**: a four-bit field inside one byte cites that whole
        byte, which is what §1 requires and what makes overlapping citations —
        a flags word and the bits within it — the normal case rather than a
        special one.

        Args:
            mark: A position previously returned by :meth:`tell`.

        Returns:
            ``(off_start, off_end)``, half-open, in stream offsets.

        """
        low, high = (mark, self._bit) if mark <= self._bit else (self._bit, mark)
        start = self._base + low // _BITS_PER_BYTE
        end = self._base + (high + _BITS_PER_BYTE - 1) // _BITS_PER_BYTE
        return start, end

    def seek(self, bit: int) -> None:
        """Move to an absolute bit position within the run.

        Args:
            bit: The position to move to.

        Raises:
            ValueError: If the position is outside the run.

        """
        if not 0 <= bit <= len(self._data) * _BITS_PER_BYTE:
            msg = f"bit position {bit} is outside the run"
            raise ValueError(msg)
        self._bit = bit

    def align(self) -> int:
        """Advance to the next byte boundary, returning how many bits were skipped.

        The caller is responsible for accounting for those bits — silently
        dropping them is exactly the lie §2 warns about — so this reports the
        count rather than swallowing it.

        Returns:
            Bits skipped, ``0`` when already aligned.

        """
        if self.is_aligned():
            return 0
        skipped = _BITS_PER_BYTE - (self._bit % _BITS_PER_BYTE)
        self._bit += skipped
        return skipped

    # --- reads -------------------------------------------------------------

    def _require(self, bits: int) -> None:
        """Refuse a read that would run past the end of the run."""
        if bits > self.remaining_bits():
            msg = (
                f"read of {bits} bit(s) at offset {self.byte_offset()} runs past "
                f"the end of the available {self.remaining_bits()} bit(s)"
            )
            raise TruncatedRead(msg)

    def read_bits(self, count: int) -> int:
        """Read ``count`` bits, most significant first.

        Args:
            count: How many bits.

        Returns:
            The value.

        Raises:
            TruncatedRead: If fewer than ``count`` bits remain.
            ValueError: If ``count`` is negative.

        """
        if count < 0:
            msg = f"cannot read a negative number of bits ({count})"
            raise ValueError(msg)
        self._require(count)
        value = 0
        for _ in range(count):
            byte = self._data[self._bit // _BITS_PER_BYTE]
            shift = _BITS_PER_BYTE - 1 - (self._bit % _BITS_PER_BYTE)
            value = (value << 1) | ((byte >> shift) & 1)
            self._bit += 1
        return value

    def read_int(self, bits: int, *, signed: bool = False, endian: Endian = Endian.BIG) -> int:
        """Read an integer of ``bits`` width.

        ``endian`` applies only to a whole-byte read from an aligned position.
        Below a byte, or across a byte boundary from an unaligned position,
        bits are taken most significant first and ``endian`` has no meaning —
        byte order is not a property a four-bit field has.

        Args:
            bits: Width in bits.
            signed: Interpret as two's complement.
            endian: Byte order, for aligned whole-byte reads.

        Returns:
            The value.

        Raises:
            TruncatedRead: If the field does not fit in what remains.

        """
        if bits % _BITS_PER_BYTE == 0 and self.is_aligned():
            raw = self.read_bytes(bits // _BITS_PER_BYTE)
            order = "big" if endian is Endian.BIG else "little"
            return int.from_bytes(raw, order, signed=signed)
        value = self.read_bits(bits)
        if signed and bits > 0 and value >= 1 << (bits - 1):
            value -= 1 << bits
        return value

    def read_bytes(self, count: int) -> bytes:
        """Read ``count`` whole bytes from an aligned position.

        Refuses to read from a half-consumed byte rather than aligning first.
        Auto-aligning would drop the remaining bits silently, and unclaimed
        bytes are the failure §2 exists to prevent; a spec that lands here has
        a bug worth reporting, not papering over.

        Args:
            count: How many bytes.

        Returns:
            The bytes.

        Raises:
            TruncatedRead: If fewer than ``count`` bytes remain.
            ValueError: If the position is not byte-aligned, or ``count`` is
                negative.

        """
        if count < 0:
            msg = f"cannot read a negative number of bytes ({count})"
            raise ValueError(msg)
        if not self.is_aligned():
            msg = (
                f"cannot read whole bytes from a position {self._bit % _BITS_PER_BYTE} "
                f"bit(s) into a byte; the preceding bitfields do not add up to a "
                f"whole number of bytes"
            )
            raise ValueError(msg)
        self._require(count * _BITS_PER_BYTE)
        start = self._bit // _BITS_PER_BYTE
        self._bit += count * _BITS_PER_BYTE
        return self._data[start : start + count]

    def read_remaining(self) -> bytes:
        """Read everything left, from an aligned position.

        Returns:
            The remaining bytes.

        Raises:
            ValueError: If the position is not byte-aligned.

        """
        return self.read_bytes(self.remaining_bytes())

    def find(self, delimiter: bytes) -> int | None:
        """Return the byte offset of the next ``delimiter``, relative to the position.

        Searches from the current position without moving it. Requires
        alignment, since a delimiter is a byte sequence.

        Args:
            delimiter: What to search for.

        Returns:
            Bytes from the current position to the delimiter's first byte, or
            ``None`` if it does not occur.

        Raises:
            ValueError: If the position is not byte-aligned, or the delimiter
                is empty.

        """
        if not delimiter:
            msg = "cannot search for an empty delimiter"
            raise ValueError(msg)
        if not self.is_aligned():
            msg = "cannot search for a delimiter from a position inside a byte"
            raise ValueError(msg)
        found = self._data.find(delimiter, self._bit // _BITS_PER_BYTE)
        return None if found < 0 else found - self._bit // _BITS_PER_BYTE
