"""What a generated decoder imports, and the only thing it imports.

The compiler phase's Q3 in code: generated modules depend on **this module and
nothing else** from ``kober``. No spec model, no ``Node``, no YAML, no checker.
A consumer installs ``kober`` and gets a decoder that reads bytes; the machinery
that turned a specification into it stays behind.

That is a real constraint rather than a preference, and it is why some of what is
here looks like a thin wrapper. :func:`read_int_le` exists because
:meth:`kober.cursor.Cursor.read_int` takes a :class:`kober.spec.Endian`, and a
generated module reaching for the spec model in order to read a little-endian
integer would be exactly the dependency this module exists to absorb. The
wrapper is the seam: **the spec-shaped import happens here, once.**

Everything else is re-exported rather than reimplemented. A generated decoder
and the interpreter read bytes through the same cursor, raise the same signals,
and bound a shift the same way — which is what makes the two comparable, and
that comparison is the strongest test this project has.

What generated code raises, and what each becomes in an output file:

- :class:`~kober.errors.TruncatedRead` — the input ended inside a field, and the
  region is ``truncated``. With :class:`~kober.errors.Undecodable` it carries
  *where* the decode stopped, because generated code keeps its read position in
  a local and nothing else can be asked afterwards.
- :class:`~kober.errors.Undecodable` — it was read and made no sense: a
  ``switch`` with no case, a negative size, a ``confirm`` that did not hold.
  The region is ``undecodable``.
- :class:`~kober.errors.EvalError` and ``ZeroDivisionError`` — an expression
  could not answer for this input. Also ``undecodable``: the shorter road to the
  same verdict, since a compiled expression is Python arithmetic and Python
  already refuses to divide by zero.

None of them escapes a decode. The entry point of a generated module catches
each one, accounts for the bytes it did not decode, and returns.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol

from kober.cursor import Cursor
from kober.errors import EvalError, Stopped, TruncatedRead, Undecodable
from kober.expr import shift_left, shift_right
from kober.spec import Endian

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = [
    "PRIM_WIDTHS",
    "TEXT_CONTENT_TYPE",
    "Cursor",
    "EvalError",
    "Sink",
    "Spanned",
    "Stopped",
    "TruncatedRead",
    "Undecodable",
    "cited",
    "normalize_int",
    "prim_int",
    "prim_token",
    "read_int_le",
    "shift_left",
    "shift_right",
    "span",
]


# --- what a record is made of ----------------------------------------------


#: The widths `zpf`'s closed ``prim:`` integer vocabulary can label, in bytes.
PRIM_WIDTHS = (1, 2, 4, 8)

#: How a text field's payload is labelled. Not ``prim:`` — that scheme has no
#: text token — so the format's other fully-specified scheme is used instead.
TEXT_CONTENT_TYPE = "mime:text/plain; charset=utf-8"


def prim_token(bits: int, signed: bool) -> str:
    """Return the ``prim:`` token for an integer of ``bits`` width.

    `zpf`'s ``prim:`` vocabulary is **closed** — 8, 16, 32, and 64 bits, signed
    or not — so a width outside it has no token. Rather than drop to ``dec:``
    and lose the normative typing §4.1 fought to keep, the value is widened to
    the smallest token that holds it: a four-bit field is written as
    ``prim:u8``.

    The payload is *created* rather than copied, so this is honest about the
    value — a ``u4`` holding 5 really is the integer 5 — and any reader gets
    the right number without our registry. What is lost is the field's exact
    width, which the format has nowhere to record anyway; ``cites`` already
    rounds a sub-byte field out to its containing byte for the same reason.

    Args:
        bits: The declared width.
        signed: Whether the field is two's complement.

    Returns:
        A token such as ``"u8"`` or ``"i32"``.

    Raises:
        ValueError: If ``bits`` exceeds the widest token.

    """
    needed = (bits + 7) // 8
    for width in PRIM_WIDTHS:
        if needed <= width:
            return f"{'i' if signed else 'u'}{width * 8}"
    msg = f"no prim: token holds a {bits}-bit integer"
    raise ValueError(msg)


def normalize_int(value: int, bits: int, signed: bool) -> bytes:
    """Encode an integer as its ``prim:`` token requires: little-endian.

    ``prim:`` is little-endian by definition, so a big-endian wire value is
    re-encoded here. That the payload then differs from the bytes it cites is
    fine and **[verified]** — a decode stage's records are created, not copied.

    Args:
        value: The decoded value.
        bits: The declared width, which decides the token's width.
        signed: Whether to encode as two's complement.

    Returns:
        The payload.

    """
    token_bytes = int(prim_token(bits, signed)[1:]) // 8
    return value.to_bytes(token_bytes, "little", signed=signed)


def prim_int(value: int) -> tuple[bytes, str]:
    """Return the payload and content type for an integer of no declared width.

    A ``computed:`` integer is the one value nothing declares a width for, so it
    is sized by its magnitude: the narrowest token that holds it, signed only if
    it is negative. Both implementations have to agree about that, and a
    generated decoder cannot work it out at compile time — the value is not
    known until the message is.

    Args:
        value: The computed value.

    Returns:
        The payload, and the ``prim:`` content type labelling it.

    Example:
        >>> prim_int(300)[1]
        'prim:u16'

    """
    bits = max(8, abs(value).bit_length() + 1)
    signed = value < 0
    return normalize_int(value, bits, signed), f"prim:{prim_token(bits, signed)}"


def cited(ranges: Sequence[tuple[int, int]], default: tuple[int, int]) -> tuple[int, int]:
    """Return the range a computed value's inputs cover.

    ``DESIGN.md`` §3.2: a computed value consumed nothing, so citing its own
    position would claim an empty range and say nothing about where the value
    came from. It cites the fields its expression read instead. Which fields
    those are is settled when the spec is compiled; whether each of them read
    anything is not, so the empty ones are dropped here.

    Args:
        ranges: The byte ranges of the fields the expression read.
        default: What to cite if none of them read anything.

    Returns:
        ``(off_start, off_end)``, half-open.

    """
    spoken = [(start, end) for start, end in ranges if end > start]
    if not spoken:
        return default
    return min(start for start, _ in spoken), max(end for _, end in spoken)


def read_int_le(cur: Cursor, bits: int, *, signed: bool = False) -> int:
    """Read a little-endian integer of ``bits`` width.

    Byte order is only meaningful for a whole-byte read from an aligned
    position, and the cursor decides that — below a byte, bits are taken most
    significant first and this behaves exactly like a big-endian read. Passing
    the choice through unexamined is deliberate: the two implementations must
    agree about the awkward cases as much as the ordinary ones.

    Args:
        cur: The cursor to read from.
        bits: Width in bits.
        signed: Interpret as two's complement.

    Returns:
        The value.

    Raises:
        TruncatedRead: If the field does not fit in what remains.

    """
    return cur.read_int(bits, signed=signed, endian=Endian.LITTLE)


class Sink(Protocol):
    """Where a generated decoder's records and undecoded regions go.

    The compiler phase's Q1 as an interface. Its two calls are
    :class:`kober.emit.Emission` and :class:`kober.emit.Unclaimed` written as
    method signatures, deliberately: a generated decoder is a *second producer*
    for the contract the interpreter's emitter already has, so what the two
    write can be compared record for record. That comparison is this project's
    strongest test, and it only exists because both speak the same vocabulary.

    Both are called in decode order, and a sink is handed the same byte twice
    only as an overlapping **citation** — a sub-byte field and the byte holding
    it — never as a citation and a region.
    """

    def record(
        self,
        payload: bytes,
        content_type: str,
        off_start: int,
        off_end: int,
        comment: str | None,
    ) -> None:
        """Write one record citing ``[off_start, off_end)``.

        Args:
            payload: The bytes to write, already normalized for the type.
            content_type: The label.
            off_start: First input byte this is evidence about.
            off_end: One past the last.
            comment: The field path, or ``None``.

        """

    def undecoded(self, off_start: int, off_end: int, reason: str) -> None:
        """Mark ``[off_start, off_end)`` as not decoded, and say why.

        Args:
            off_start: First byte.
            off_end: One past the last.
            reason: One of `zpf`'s ``reason=`` strings.

        """


class Spanned(Protocol):
    """An object that knows which bytes it and its fields came from.

    Attributes:
        __spans__: This object's own extent, then one ``(start, end)`` pair per
            attribute in declaration order.
        __span_index__: Attribute name to its position among the pairs.

    """

    __spans__: tuple[int, ...]
    __span_index__: ClassVar[Mapping[str, int]]


def span(obj: Spanned, name: str | None = None) -> tuple[int, int]:
    """Return the byte range ``obj`` — or one of its fields — was decoded from.

    The compiler phase's Q2 from the consumer's side. A decoded field is a plain
    ``int`` or ``str``, because a wrapper per field is the allocation the whole
    phase exists to remove; provenance lives beside the values instead, in one
    flat tuple per object, and this reads it back by name.

    Args:
        obj: Any object a generated decoder produced.
        name: A field of it, or ``None`` for the object's own extent.

    Returns:
        ``(off_start, off_end)``, half-open, in the stream's offset space.

    Raises:
        KeyError: If ``name`` is not a field of ``obj``.

    Example:
        >>> span(message, "id")
        (0, 2)

    """
    at = 0 if name is None else 2 * obj.__span_index__[name] + 2
    return obj.__spans__[at], obj.__spans__[at + 1]
