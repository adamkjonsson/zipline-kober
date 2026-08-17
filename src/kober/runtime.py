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
  region is ``truncated``.
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
from kober.errors import EvalError, TruncatedRead, Undecodable
from kober.expr import shift_left, shift_right
from kober.spec import Endian

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "Cursor",
    "EvalError",
    "Spanned",
    "TruncatedRead",
    "Undecodable",
    "read_int_le",
    "shift_left",
    "shift_right",
    "span",
]


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
