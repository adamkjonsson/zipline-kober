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

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Protocol

from kober import transforms
from kober.cursor import Cursor
from kober.errors import (
    EvalError,
    ParameterError,
    Refused,
    Stopped,
    TransformError,
    TruncatedRead,
    Undecodable,
)
from kober.expr import shift_left, shift_right, to_int
from kober.spec import Endian

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from kober.expr import ExprValue
    from kober.transforms import Transformer

__all__ = [
    "PRIM_WIDTHS",
    "TEXT_CONTENT_TYPE",
    "Cursor",
    "EvalError",
    "Held",
    "Output",
    "Refused",
    "Sink",
    "Spanned",
    "Stopped",
    "TransformError",
    "TransformFailed",
    "TruncatedRead",
    "Undecodable",
    "bind_transforms",
    "cited",
    "concat",
    "document_params",
    "first_failed",
    "normalize_int",
    "params_digest",
    "prim_int",
    "prim_token",
    "read_int_le",
    "run_transform",
    "take_over",
    "shift_left",
    "shift_right",
    "span",
    "to_int",
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


def prim_int(value: int) -> tuple[bytes, str] | None:
    """Return the payload and content type for an integer of no declared width.

    A ``computed:`` integer is the one value nothing declares a width for, so it
    is sized by its magnitude: the narrowest token that holds it, signed only if
    it is negative. Both implementations have to agree about that, and neither
    can work it out ahead of time — the value is not known until the message is.

    **``None`` when no token holds it.** ``prim:`` stops at 64 bits and a
    computed value does not: ``1 << n`` with ``n`` off the wire is a perfectly
    ordinary expression and a perfectly enormous number. There is nothing
    dishonest to write for it, so nothing is written — the value is still in the
    decoded object, and the bytes it *cites* are the fields it read, which have
    records of their own. Coverage is untouched, because a computed field
    consumed nothing.

    Args:
        value: The computed value.

    Returns:
        The payload and its ``prim:`` content type, or ``None``.

    Example:
        >>> prim_int(300)[1]
        'prim:u16'
        >>> prim_int(1 << 200) is None
        True

    """
    bits = max(8, abs(value).bit_length() + 1)
    if bits > PRIM_WIDTHS[-1] * 8:
        return None
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
        role: str | None,
    ) -> None:
        """Write one record citing ``[off_start, off_end)``.

        Args:
            payload: The bytes to write, already normalized for the type.
            content_type: The label.
            off_start: First input byte this is evidence about.
            off_end: One past the last.
            role: The field path, or ``None`` — what this record *is*, where
                ``content_type`` says what kind it is.

        """

    def undecoded(self, off_start: int, off_end: int, reason: str) -> None:
        """Mark ``[off_start, off_end)`` as not decoded, and say why.

        Args:
            off_start: First byte.
            off_end: One past the last.
            reason: One of `zpf`'s ``reason=`` strings.

        """


class Held:
    """A sink that keeps what a unit writes until it is decided what stands.

    A generated module writes each record as it reads the field. Two things
    are only decided later in the unit: whether its ``confirm`` or ``reject``
    holds, and whether a ``transform`` takes over a field it already wrote. So
    such a unit writes through one of these, and the wrapper around it releases
    the records into the real sink when the unit decoded, or when it failed
    some other way, since what it read before a truncation is real. It drops
    them only when the guard refused, which is ``DESIGN.md`` §3.1's promise: no
    field tree for a guess that did not hold up. A transform takes back its
    source's record with :meth:`retract`, so the order of what stays is the
    order it was read in.

    Args:
        sink: Where the records go once released.

    """

    __slots__ = ("_sink", "_writes")

    def __init__(self, sink: Sink) -> None:
        self._sink = sink
        #: Every write, in order, tagged ``"record"`` or ``"region"``.
        self._writes: list[tuple[str, tuple[object, ...]]] = []

    def record(
        self,
        payload: bytes,
        content_type: str,
        off_start: int,
        off_end: int,
        role: str | None,
    ) -> None:
        """Keep one record until :meth:`release`."""
        self._writes.append(("record", (payload, content_type, off_start, off_end, role)))

    def undecoded(self, off_start: int, off_end: int, reason: str) -> None:
        """Keep one region until :meth:`release`."""
        self._writes.append(("region", (off_start, off_end, reason)))

    def retract(self, role: str) -> None:
        """Take back the last record kept for ``role``, if there is one.

        What a transform does to its source (the transform plan's *Decided*
        1a): the source was written when it was read, and the transform, later
        in the same unit, speaks for its bytes instead.
        """
        for index in range(len(self._writes) - 1, -1, -1):
            tag, write = self._writes[index]
            if tag == "record" and write[-1] == role:
                del self._writes[index]
                return

    def release(self) -> None:
        """Write everything kept, in the order it was written."""
        for tag, write in self._writes:
            if tag == "record":
                self._sink.record(*write)  # type: ignore[arg-type]
            else:
                self._sink.undecoded(*write)  # type: ignore[arg-type]
        self._writes.clear()


class Output:
    """A sink for what a transform's output decodes to, released only on success.

    Every record read from an output cites the transform's range in the input,
    since the output has no offsets a file can name; and nothing read from it
    becomes a region, for the same reason. A failure anywhere in the output
    fails the whole transform (the plan's *Decided* 1b), so nothing is written
    until :meth:`release`.

    Args:
        sink: Where the records go once released.
        off_start: The first input byte the transform cites.
        off_end: One past the last.

    """

    __slots__ = ("_off_end", "_off_start", "_records", "_sink")

    def __init__(self, sink: Sink, off_start: int, off_end: int) -> None:
        self._sink = sink
        self._off_start = off_start
        self._off_end = off_end
        self._records: list[tuple[bytes, str, str | None]] = []

    def record(
        self,
        payload: bytes,
        content_type: str,
        _off_start: int,
        _off_end: int,
        role: str | None,
    ) -> None:
        """Keep one record, to cite the transform's input range when released.

        The offsets it is given are in the output, and are replaced by the
        transform's range in the input.
        """
        self._records.append((payload, content_type, role))

    def undecoded(self, _off_start: int, _off_end: int, _reason: str) -> None:
        """Drop a region: an output's offsets cannot name input bytes."""

    def release(self) -> None:
        """Write every record kept, citing the transform's input range."""
        for payload, content_type, role in self._records:
            self._sink.record(payload, content_type, self._off_start, self._off_end, role)
        self._records.clear()


@dataclass(frozen=True)
class TransformFailed:
    """What a transform field holds when its transform produced nothing usable.

    Its message still decoded whole (the transform plan's *Decided* 1), so the
    object is returned and this stands where the output would have been, with
    the reason, worded exactly as the interpreter words it.

    Attributes:
        detail: Why, in kober's own words: never a codec's or a cipher's.

    """

    detail: str


def first_failed(value: object) -> str | None:
    """Return the first failed transform's detail in a decoded object, or ``None``.

    Depth first, in field order, which is the order the interpreter's tree
    walk finds one in, so a stream declined for one quotes the same failure.

    Args:
        value: What a generated decoder returned.

    Returns:
        The detail, or ``None`` if every transform in it produced its output.

    """
    if isinstance(value, TransformFailed):
        return value.detail
    if isinstance(value, list):
        for item in value:
            found = first_failed(item)
            if found is not None:
                return found
        return None
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for item in dataclasses.fields(value):
            if item.name.startswith("__"):
                continue
            found = first_failed(getattr(value, item.name))
            if found is not None:
                return found
    return None


def concat(
    elements: Sequence[Spanned] | None,
    member: str,
    default: int,
    *,
    detail: str,
    at: int,
) -> tuple[bytes, tuple[int, int]]:
    """Join one member of every element, and return what the join cites.

    The citation is the members' hull, non-empty members only: an empty one
    cites nothing, which keeps the terminating chunk's size line out of it
    (the transform plan's Stage 1). With none, it cites nothing, at ``default``.

    Args:
        elements: The repetition's decoded elements, or ``None`` if it was
            not decoded.
        member: The attribute joined.
        default: Where the concat stands, for an empty result.
        detail: What to say if ``elements`` is ``None``.
        at: Where the decode stands, for that failure.

    Returns:
        The joined bytes, and ``(off_start, off_end)``.

    Raises:
        Undecodable: If ``elements`` is ``None``.

    """
    if elements is None:
        raise Undecodable(detail, at)
    parts = [getattr(element, member) for element in elements]
    joined = b"".join(part for part in parts if part is not None)
    spans = [span(element, member) for element in elements]
    spans = [(start, end) for start, end in spans if end > start]
    if not spans:
        return joined, (default, default)
    return joined, (spans[0][0], spans[-1][1])


def take_over(
    sink: Held | None,
    value: object,
    *,
    role: str | None = None,
    source: tuple[int, int] | None = None,
    skipped: bool = False,
    record: tuple[str, str | None, tuple[int, int]] | None = None,
) -> None:
    """Write what a transform's outcome says about its source (*Decided* 1).

    The source's own record is taken back, since the outcome speaks for it.
    On failure its bytes are ``undecodable``; with ``emit: none`` they are
    ``skipped`` whatever happened. A type-less output that succeeded is
    written as a record of its own.

    Args:
        sink: The unit's held sink, or ``None`` if nothing is written.
        value: What the transform produced: its output, or a
            :class:`TransformFailed`.
        role: The source's record to take back, if it has one.
        source: The source's range to name, or ``None`` to name nothing —
            a concat's bytes are its members', which keep their records.
        skipped: Whether the transform is ``emit: none``.
        record: For a type-less output: its content type, role and citation.

    """
    if sink is None:
        return
    if role is not None:
        sink.retract(role)
    failed = isinstance(value, TransformFailed)
    if source is not None and source[1] > source[0] and (failed or skipped):
        sink.undecoded(*source, "skipped" if skipped else "undecodable")
    if record is not None and not failed and not skipped:
        content_type, output_role, cite = record
        sink.record(value, content_type, *cite, output_role)


def run_transform(
    name: str,
    transformer: Transformer,
    data: bytes | None,
    *,
    limit: int,
    args: Mapping[str, ExprValue] | TransformFailed | None = None,
    missing: str = "",
    decode: Callable[..., tuple[object, int]] | None = None,
    decode_args: Sequence[object] = (),
    output: Output | None = None,
) -> object:
    """Run one transform and decode its output, for generated code.

    Every way it can fail is contained here, worded as the interpreter words
    it, so the generated code has one line per transform rather than a
    ``try`` per step (the transform plan's *Decided* 1).

    Args:
        name: The transform's name.
        transformer: What it is bound to.
        data: The source's bytes, or ``None`` if it was not decoded.
        limit: The most bytes the output may have.
        args: The spec's ``args``, evaluated, or why evaluating one failed.
        missing: What to say if ``data`` is ``None``.
        decode: The output's unit function, for a typed output; ``None`` to
            keep the output as bytes.
        decode_args: Its arguments after the output's own four.
        output: The :class:`Output` among ``decode_args``, released if the
            whole output decodes; ``None`` when nothing is written.

    Returns:
        The output, or the unit decoded from it, or a :class:`TransformFailed`.

    """
    if data is None:
        return TransformFailed(missing)
    if isinstance(args, TransformFailed):
        return args
    try:
        out = transforms.apply(name, transformer, data, limit=limit, args=args)
    except TransformError as exc:
        return TransformFailed(str(exc))
    if decode is None:
        return out
    try:
        value, end = decode(out, len(out), 0, 0, *decode_args)
    except TruncatedRead:
        # Where inside the output means little to a reader; the interpreter
        # says it the same way.
        return TransformFailed(f"{name} output does not decode: it ends before its type does")
    except Undecodable as exc:
        return TransformFailed(f"{name} output does not decode: {exc}")
    if end != len(out):
        unread = len(out) - end
        return TransformFailed(f"{name} output has {unread} byte(s) its type does not read")
    if output is not None:
        output.release()
    return value


def bind_transforms(names: Sequence[str]) -> Mapping[str, Transformer]:
    """Bind the transforms a generated module uses, when it is imported.

    From :data:`kober.transforms.DEFAULT`, so what a program registers before
    importing the module is what it runs. A name nothing binds fails the import,
    once, rather than every message (the transform plan's Q6).

    Args:
        names: The names the module uses.

    Returns:
        Each name, and what it is bound to.

    """
    return transforms.DEFAULT.bind_names(names)


#: The Python type a document parameter of each declared type holds. ``bool`` is
#: an ``int`` to Python, and is refused where an integer is wanted.
_PARAM_TYPES: Mapping[str, type] = {"int": int, "bool": bool, "str": str, "bytes": bytes}


def document_params(
    spec: str, declared: Mapping[str, str], supplied: Mapping[str, ExprValue]
) -> dict[str, ExprValue]:
    """Check the values supplied for a spec's ``params:``, and return them.

    Every declared parameter must be supplied, nothing undeclared may be, and
    each must be of its declared type. A run missing one could not be
    reproduced, so it never starts. No message quotes a value, since one may be
    a secret. Shared by both backends, so they refuse alike.

    Args:
        spec: The spec's name, for messages.
        declared: Each parameter's name and type, as ``"int"``, ``"bool"``,
            ``"str"`` or ``"bytes"``.
        supplied: The values given.

    Returns:
        The values, checked.

    Raises:
        ParameterError: If one is missing, undeclared, or of the wrong type.

    """
    unknown = sorted(set(supplied) - set(declared))
    if unknown:
        listed = ", ".join(repr(name) for name in unknown)
        msg = f"parameter(s) {listed} are not declared by spec {spec!r}"
        raise ParameterError(msg)
    missing = sorted(set(declared) - set(supplied))
    if missing:
        listed = ", ".join(repr(name) for name in missing)
        msg = f"spec {spec!r} needs parameter(s) {listed}, and none was supplied"
        raise ParameterError(msg)
    for name, value in supplied.items():
        wanted = _PARAM_TYPES[declared[name]]
        if not isinstance(value, wanted) or (wanted is int and isinstance(value, bool)):
            msg = f"parameter {name!r} must be {declared[name]}, got {type(value).__name__}"
            raise ParameterError(msg)
    return dict(supplied)


def params_digest(spec_digest: str, emit: str, params: Mapping[str, ExprValue]) -> str:
    """Return the digest of a decode's configuration, for the Decoder Descriptor.

    Over the spec's own digest (:meth:`kober.spec.Spec.digest`), the
    granularity, and every parameter's value, so the same spec with a different
    key is a different configuration. A secret goes into the hash and nowhere
    else. Shared by both backends, so a compiled module and the interpreter
    write the same one.

    Args:
        spec_digest: The spec's digest.
        emit: The granularity's name.
        params: The parameters' values.

    Returns:
        ``sha256:`` and the hex digest.

    """
    document = {
        "spec": spec_digest,
        "emit": emit,
        "params": [
            [name, {"bytes": value.hex()} if isinstance(value, bytes) else value]
            for name, value in sorted(params.items())
        ],
    }
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


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
