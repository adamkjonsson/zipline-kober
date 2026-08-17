"""What ``kober compile examples/dns.yaml -o dns.py`` should produce.

Stage 1 of the compiler phase is a spike, and this is it: the target, written
out before any generator exists, so that an answer to Q1–Q4 that does not work
is found now rather than after a generator has been built around it. It is
**not** a module anyone maintains by editing — it is the fixture the
generator's output is expected to converge on, and the shape of every decision
in it is meant to be read as a rule about generated code rather than a choice
made for this protocol.

**Two of its blocks are no longer hand-written.** The ``enums`` and ``the typed
model`` sections are exactly what :mod:`kober.pygen` renders, and
``test_pygen.py`` compares them character for character. That is what
convergence means in practice: as each stage lands, the block it generates
replaces the hand-written one, until the file is the generator's output and the
comparison covers all of it.

What it demonstrates, question by question:

**Q1, emission.** One pass, one optional sink. Every field's path, content
type, ``prim:`` token and emission granularity is known when the spec is
compiled, so each is a literal here and nothing generic is walked afterwards.
The sink speaks exactly :func:`kober.emit.plan`'s vocabulary — a payload with a
content type over a byte range, or a byte range with a reason — so the
interpreter and this module have one contract between them, which is what makes
them comparable at all.

**Q2, byte ranges.** Every object carries ``__spans__``: one flat tuple of
ints, its own extent first and then one pair per attribute, in declaration
order. One tuple per object, no wrappers, and :func:`span` reads it back by
name. A repeated field's pair is the whole repetition's extent; each element is
an object with an extent of its own.

**Q3, dependencies.** :class:`~kober.cursor.Cursor` and
:class:`~kober.errors.TruncatedRead`, and nothing else from ``kober`` — no
spec model, no ``Node``, no YAML. The :class:`Sink` and :class:`Spanned`
protocols and :func:`span` belong with them in the ``kober.runtime`` that stage
6 factors out; they are written here because the spike ships no public API.

**Q4, names.** Unit names become classes in ``CamelCase``, field names become
attributes unchanged, and an anonymous field gets no attribute at all — its
bytes are still read, still cited, and still spelled ``_`` in a path, but
nothing can name it. Every identifier this module introduces of its own starts
with an underscore, which is the namespace a backend has to reserve.

**What is not the target: the read path.** Every value here goes through
:class:`~kober.cursor.Cursor`, and that measures 14.0 µs a message against 2.1
for the same objects and the same spans read straight off the buffer. The
cursor is what makes this module comparable to the interpreter today, and it is
the fallback a fast path needs when a bounds check fails, but a generator that
emitted these calls would give back most of the phase. See the plan's Q5.

Compiled at **field** granularity, which is the case worth spiking: message
granularity emits one record and needs no paths at all. :func:`decode_message`
is the entry point the same spec compiles to under ``emit: message``; the rest
of the module is unchanged by the choice apart from the ``sink`` calls, which
is the argument for granularity being a compile-time decision rather than a
runtime one.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Protocol

from kober.cursor import Cursor
from kober.errors import TruncatedRead

if TYPE_CHECKING:
    from collections.abc import Mapping

#: The spec's name and version, for the decode stage's ``decoder=`` field.
NAME = "dns"
VERSION = "1.0"

#: How a whole-message record is labelled under ``emit: message``.
MESSAGE_CONTENT_TYPE = "dec:dns-message"

#: How a text field's payload is labelled. ``prim:`` has no text token.
TEXT_CONTENT_TYPE = "mime:text/plain; charset=utf-8"


# --- enums -----------------------------------------------------------------

# A spec's enums are mappings, not enum.IntEnum subclasses: a value with no
# label is normal on the wire, and a decoder may not raise. A labelled field
# stays an int, and the labels are a lookup beside it.

#: Labels declared as ``opcode``.
OPCODE: Mapping[int, str] = MappingProxyType(
    {0: "query", 1: "iquery", 2: "status", 4: "notify", 5: "update"}
)

#: Labels declared as ``rcode``.
RCODE: Mapping[int, str] = MappingProxyType(
    {0: "noerror", 1: "formerr", 2: "servfail", 3: "nxdomain", 4: "notimp", 5: "refused"}
)

#: Labels declared as ``rrtype``.
RRTYPE: Mapping[int, str] = MappingProxyType(
    {1: "a", 2: "ns", 5: "cname", 6: "soa", 12: "ptr", 15: "mx", 16: "txt", 28: "aaaa", 255: "any"}
)

#: Labels declared as ``rrclass``.
RRCLASS: Mapping[int, str] = MappingProxyType({1: "internet", 3: "chaos", 4: "hesiod", 255: "any"})


# --- the runtime -----------------------------------------------------------


class Sink(Protocol):
    """Where a decode's records and undecoded regions go.

    The two calls are :class:`kober.emit.Emission` and
    :class:`kober.emit.Unclaimed` as method signatures, deliberately: a
    generated decoder is a second producer for the same contract the
    interpreter's emitter already has, so the two can be compared record for
    record.

    Both are called in decode order, and a sink may be handed the same byte
    twice only as an overlapping *citation* — a sub-byte field and the byte
    holding it — never as a citation and a region.
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
        __spans__: This object's extent, then one ``(start, end)`` pair per
            attribute in declaration order.
        __span_index__: Attribute name to its position among the pairs.

    """

    __spans__: tuple[int, ...]
    __span_index__: ClassVar[Mapping[str, int]]


def span(obj: Spanned, name: str | None = None) -> tuple[int, int]:
    """Return the byte range ``obj`` — or one of its fields — was decoded from.

    Args:
        obj: Any object a decode produced.
        name: A field of it, or ``None`` for the object's own extent.

    Returns:
        ``(off_start, off_end)``, half-open, in stream offsets.

    Raises:
        KeyError: If ``name`` is not a field of ``obj``.

    Example:
        >>> span(message, "id")
        (0, 2)

    """
    at = 0 if name is None else 2 * obj.__span_index__[name] + 2
    return obj.__spans__[at], obj.__spans__[at + 1]


# --- the typed model -------------------------------------------------------


@dataclass(slots=True)
class Message:
    """One DNS message.

    Attributes:
        id: Copied into the reply; matches responses to requests.
        flags: One :class:`Flags`.
        qdcount: Number of entries in the question section.
        ancount: A 16-bit unsigned integer.
        nscount: A 16-bit unsigned integer.
        arcount: A 16-bit unsigned integer.
        questions: Each element is one :class:`Question`.
        resource_records: The answer, authority, and additional sections. Left
            undecoded on purpose: an owner name here is usually a compression
            pointer, which this language cannot follow. Marked skipped rather
            than claimed. Present only when ``((ancount + nscount) + arcount) >
            0``.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    id: int
    flags: Flags
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    questions: list[Question]
    resource_records: bytes | None
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType(
        {
            "id": 0,
            "flags": 1,
            "qdcount": 2,
            "ancount": 3,
            "nscount": 4,
            "arcount": 5,
            "questions": 6,
            "resource_records": 7,
        }
    )


@dataclass(slots=True)
class Flags:
    """The 16-bit flags word, MSB first.

    The spec's field at position 7 is anonymous: read and cited, but with no
    attribute here — a field with no name is not something a caller can ask
    for.

    Attributes:
        qr: 0 query, 1 response.
        opcode: A 4-bit unsigned integer. Labelled by :data:`OPCODE`.
        aa: Authoritative answer.
        tc: Truncated.
        rd: Recursion desired.
        ra: Recursion available.
        rcode: A 4-bit unsigned integer. Labelled by :data:`RCODE`.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    rcode: int
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType(
        {"qr": 0, "opcode": 1, "aa": 2, "tc": 3, "rd": 4, "ra": 5, "rcode": 6}
    )


@dataclass(slots=True)
class Question:
    """One decoded ``question``.

    Attributes:
        qname: One :class:`Name`.
        qtype: A 16-bit unsigned integer. Labelled by :data:`RRTYPE`.
        qclass: A 16-bit unsigned integer. Labelled by :data:`RRCLASS`.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    qname: Name
    qtype: int
    qclass: int
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType(
        {"qname": 0, "qtype": 1, "qclass": 2}
    )


@dataclass(slots=True)
class Name:
    """A sequence of length-prefixed labels ending in a zero-length one.

    Attributes:
        labels: Each element is one :class:`Label`.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    labels: list[Label]
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType({"labels": 0})


@dataclass(slots=True)
class Label:
    """One decoded ``label``.

    Attributes:
        length: An 8-bit unsigned integer.
        text: Text, decoded as ``utf-8``.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    length: int
    text: str
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType({"length": 0, "text": 1})


# --- the decoder -----------------------------------------------------------


def _decode_message(cur: Cursor, sink: Sink | None, path: str) -> Message:
    """Decode one ``message``.

    Args:
        cur: The cursor to read from.
        sink: Where records go, or ``None`` to decode without emitting.
        path: This instance's field path.

    Returns:
        The decoded message.

    Raises:
        TruncatedRead: If the input ends inside the message.

    """
    _extent = cur.tell()

    _mark = cur.tell()
    id = cur.read_int(16)
    _s_id, _e_id = cur.span(_mark)
    if sink is not None:
        sink.record(id.to_bytes(2, "little"), "prim:u16", _s_id, _e_id, path + ".id")

    _mark = cur.tell()
    flags = _decode_flags(cur, sink, path + ".flags")
    _s_flags, _e_flags = cur.span(_mark)

    _mark = cur.tell()
    qdcount = cur.read_int(16)
    _s_qdcount, _e_qdcount = cur.span(_mark)
    if sink is not None:
        sink.record(
            qdcount.to_bytes(2, "little"), "prim:u16", _s_qdcount, _e_qdcount, path + ".qdcount"
        )

    _mark = cur.tell()
    ancount = cur.read_int(16)
    _s_ancount, _e_ancount = cur.span(_mark)
    if sink is not None:
        sink.record(
            ancount.to_bytes(2, "little"), "prim:u16", _s_ancount, _e_ancount, path + ".ancount"
        )

    _mark = cur.tell()
    nscount = cur.read_int(16)
    _s_nscount, _e_nscount = cur.span(_mark)
    if sink is not None:
        sink.record(
            nscount.to_bytes(2, "little"), "prim:u16", _s_nscount, _e_nscount, path + ".nscount"
        )

    _mark = cur.tell()
    arcount = cur.read_int(16)
    _s_arcount, _e_arcount = cur.span(_mark)
    if sink is not None:
        sink.record(
            arcount.to_bytes(2, "little"), "prim:u16", _s_arcount, _e_arcount, path + ".arcount"
        )

    # repeat: {count: "qdcount"}. The count is unsigned on the wire, so the
    # interpreter's negative-count check has nothing to catch here, and one
    # `question` always reads at least a label length, so the repetition
    # cannot fail to make progress. Both checks are compiled away.
    _mark = cur.tell()
    questions: list[Question] = []
    for _index in range(qdcount):
        questions.append(_decode_question(cur, sink, f"{path}.questions[{_index}]"))
    _s_questions, _e_questions = cur.span(_mark)

    if ancount + nscount + arcount > 0:
        _mark = cur.tell()
        resource_records = cur.read_remaining()
        _s_records, _e_records = cur.span(_mark)
        if sink is not None and _e_records > _s_records:
            # emit: none. The bytes were deliberately passed over, which is
            # what `skipped` means; saying so is the whole point of §2.
            sink.undecoded(_s_records, _e_records, "skipped")
    else:
        # Absent, not empty: the field read nothing, so it cites nothing.
        resource_records = None
        _s_records = _e_records = cur.byte_offset()

    _s, _e = cur.span(_extent)
    return Message(
        id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
        questions,
        resource_records,
        (
            _s,
            _e,
            _s_id,
            _e_id,
            _s_flags,
            _e_flags,
            _s_qdcount,
            _e_qdcount,
            _s_ancount,
            _e_ancount,
            _s_nscount,
            _e_nscount,
            _s_arcount,
            _e_arcount,
            _s_questions,
            _e_questions,
            _s_records,
            _e_records,
        ),
    )


def _decode_flags(cur: Cursor, sink: Sink | None, path: str) -> Flags:
    """Decode one ``flags``.

    Args:
        cur: The cursor to read from.
        sink: Where records go, or ``None`` to decode without emitting.
        path: This instance's field path.

    Returns:
        The decoded flags word.

    Raises:
        TruncatedRead: If the input ends inside the word.

    """
    _extent = cur.tell()

    _mark = cur.tell()
    qr = cur.read_int(1)
    _s_qr, _e_qr = cur.span(_mark)
    if sink is not None:
        sink.record(qr.to_bytes(1, "little"), "prim:u8", _s_qr, _e_qr, path + ".qr")

    _mark = cur.tell()
    opcode = cur.read_int(4)
    _s_opcode, _e_opcode = cur.span(_mark)
    if sink is not None:
        sink.record(opcode.to_bytes(1, "little"), "prim:u8", _s_opcode, _e_opcode, path + ".opcode")

    _mark = cur.tell()
    aa = cur.read_int(1)
    _s_aa, _e_aa = cur.span(_mark)
    if sink is not None:
        sink.record(aa.to_bytes(1, "little"), "prim:u8", _s_aa, _e_aa, path + ".aa")

    _mark = cur.tell()
    tc = cur.read_int(1)
    _s_tc, _e_tc = cur.span(_mark)
    if sink is not None:
        sink.record(tc.to_bytes(1, "little"), "prim:u8", _s_tc, _e_tc, path + ".tc")

    _mark = cur.tell()
    rd = cur.read_int(1)
    _s_rd, _e_rd = cur.span(_mark)
    if sink is not None:
        sink.record(rd.to_bytes(1, "little"), "prim:u8", _s_rd, _e_rd, path + ".rd")

    _mark = cur.tell()
    ra = cur.read_int(1)
    _s_ra, _e_ra = cur.span(_mark)
    if sink is not None:
        sink.record(ra.to_bytes(1, "little"), "prim:u8", _s_ra, _e_ra, path + ".ra")

    # The spec's field 7 is anonymous: read and cited, but not named.
    _mark = cur.tell()
    _anon7 = cur.read_int(3)
    _s_anon7, _e_anon7 = cur.span(_mark)
    if sink is not None:
        sink.record(_anon7.to_bytes(1, "little"), "prim:u8", _s_anon7, _e_anon7, path + "._")

    _mark = cur.tell()
    rcode = cur.read_int(4)
    _s_rcode, _e_rcode = cur.span(_mark)
    if sink is not None:
        sink.record(rcode.to_bytes(1, "little"), "prim:u8", _s_rcode, _e_rcode, path + ".rcode")

    _s, _e = cur.span(_extent)
    return Flags(
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        rcode,
        (
            _s,
            _e,
            _s_qr,
            _e_qr,
            _s_opcode,
            _e_opcode,
            _s_aa,
            _e_aa,
            _s_tc,
            _e_tc,
            _s_rd,
            _e_rd,
            _s_ra,
            _e_ra,
            _s_rcode,
            _e_rcode,
        ),
    )


def _decode_question(cur: Cursor, sink: Sink | None, path: str) -> Question:
    """Decode one ``question``.

    Args:
        cur: The cursor to read from.
        sink: Where records go, or ``None`` to decode without emitting.
        path: This instance's field path.

    Returns:
        The decoded question.

    Raises:
        TruncatedRead: If the input ends inside the question.

    """
    _extent = cur.tell()

    # A unit-typed field emits no record of its own: its leaves do.
    _mark = cur.tell()
    qname = _decode_name(cur, sink, path + ".qname")
    _s_qname, _e_qname = cur.span(_mark)

    _mark = cur.tell()
    qtype = cur.read_int(16)
    _s_qtype, _e_qtype = cur.span(_mark)
    if sink is not None:
        sink.record(qtype.to_bytes(2, "little"), "prim:u16", _s_qtype, _e_qtype, path + ".qtype")

    _mark = cur.tell()
    qclass = cur.read_int(16)
    _s_qclass, _e_qclass = cur.span(_mark)
    if sink is not None:
        sink.record(
            qclass.to_bytes(2, "little"), "prim:u16", _s_qclass, _e_qclass, path + ".qclass"
        )

    _s, _e = cur.span(_extent)
    return Question(
        qname,
        qtype,
        qclass,
        (_s, _e, _s_qname, _e_qname, _s_qtype, _e_qtype, _s_qclass, _e_qclass),
    )


def _decode_name(cur: Cursor, sink: Sink | None, path: str) -> Name:
    """Decode one ``name``.

    Args:
        cur: The cursor to read from.
        sink: Where records go, or ``None`` to decode without emitting.
        path: This instance's field path.

    Returns:
        The decoded name.

    Raises:
        TruncatedRead: If the input ends inside the name.

    """
    _extent = cur.tell()

    # repeat: {until: "labels.length == 0"} — the clause sees the element just
    # decoded, bound by the field's own name, so it compiles to a test on it.
    _mark = cur.tell()
    labels: list[Label] = []
    _index = 0
    while True:
        _element = _decode_label(cur, sink, f"{path}.labels[{_index}]")
        labels.append(_element)
        if _element.length == 0:
            break
        _index += 1
    _s_labels, _e_labels = cur.span(_mark)

    _s, _e = cur.span(_extent)
    return Name(labels, (_s, _e, _s_labels, _e_labels))


def _decode_label(cur: Cursor, sink: Sink | None, path: str) -> Label:
    """Decode one ``label``.

    Args:
        cur: The cursor to read from.
        sink: Where records go, or ``None`` to decode without emitting.
        path: This instance's field path.

    Returns:
        The decoded label.

    Raises:
        TruncatedRead: If the input ends inside the label.

    """
    _extent = cur.tell()

    _mark = cur.tell()
    length = cur.read_int(8)
    _s_length, _e_length = cur.span(_mark)
    if sink is not None:
        sink.record(length.to_bytes(1, "little"), "prim:u8", _s_length, _e_length, path + ".length")

    # size: {expr: "length"}, and the field it reads is unsigned, so there is
    # no negative size to refuse.
    _mark = cur.tell()
    _raw = cur.read_bytes(length)
    _s_text, _e_text = cur.span(_mark)
    try:
        text = _raw.decode("utf-8")
    except UnicodeDecodeError:
        # A malformed string is a fact about the input, not a failure of the
        # decoder: the bytes are accounted for either way.
        text = _raw.decode("utf-8", errors="replace")
    if sink is not None:
        sink.record(
            text.encode("utf-8", errors="replace"),
            TEXT_CONTENT_TYPE,
            _s_text,
            _e_text,
            path + ".text",
        )

    _s, _e = cur.span(_extent)
    return Label(length, text, (_s, _e, _s_length, _e_length, _s_text, _e_text))


# --- entry points ----------------------------------------------------------


def decode(data: bytes, *, base: int = 0, sink: Sink | None = None) -> Message | None:
    """Decode one message from ``data``, at field granularity.

    ``data`` is one contiguous run holding one message, which is what a
    datagram is. Everything in it is accounted for: what the message decoded is
    cited by the records, and whatever is left over is named.

    Failure returns ``None`` rather than a half-built object. The typed model
    has no half-built state to offer — that is the trade a typed API makes for
    not being a generic tree — and what *was* decoded has already reached the
    sink, which is where provenance lives.

    Args:
        data: The bytes to decode.
        base: Stream offset of ``data[0]``, so spans are absolute.
        sink: Where records and undecoded regions go. ``None`` decodes without
            emitting anything, for a caller that only wants the typed objects.

    Returns:
        The message, or ``None`` if it could not be decoded.

    """
    cur = Cursor(data, base)
    end = base + len(data)
    try:
        message = _decode_message(cur, sink, NAME)
    except TruncatedRead:
        if sink is not None:
            sink.undecoded(_stopped_at(cur, base), end, "truncated")
        return None
    if sink is not None:
        stop = _stopped_at(cur, base)
        if stop < end:
            sink.undecoded(stop, end, "skipped")
    return message


def decode_message(data: bytes, *, base: int = 0, sink: Sink | None = None) -> Message | None:
    """Decode one message from ``data``, at message granularity.

    The entry point the same spec compiles to under ``emit: message``: one
    record for a whole message, and no field paths anywhere. Its payload is a
    copy of the input rather than anything the decode created, which is why a
    ``dec:`` type means "whatever that decoder documents".

    Args:
        data: The bytes to decode.
        base: Stream offset of ``data[0]``, so spans are absolute.
        sink: Where the record and any undecoded regions go.

    Returns:
        The message, or ``None`` if it could not be decoded.

    """
    cur = Cursor(data, base)
    end = base + len(data)
    try:
        message = _decode_message(cur, None, NAME)
    except TruncatedRead:
        if sink is not None:
            # From ``base``, not from where the cursor stopped: only a *whole*
            # message is a message, so nothing here cited the bytes that did
            # decode, and a region no record claims is the only honest thing
            # to say about them. At field granularity those same bytes are
            # cited one by one, which is why that path starts further along.
            sink.undecoded(base, end, "truncated")
        return None
    if sink is not None:
        stop = _stopped_at(cur, base)
        if stop > base:
            sink.record(data[: stop - base], MESSAGE_CONTENT_TYPE, base, stop, None)
        if stop < end:
            sink.undecoded(stop, end, "skipped")
    return message


def _stopped_at(cur: Cursor, base: int) -> int:
    """Return the first byte no field has claimed, in stream offsets.

    Rounded **up**: the cursor can only sit inside a byte because an earlier
    field read part of it, and that field cited the whole byte. Starting an
    undecoded region there would name a byte a record already claims.

    Args:
        cur: The cursor, wherever the decode left it.
        base: Stream offset of the run's first byte.

    Returns:
        The offset the caller's accounting resumes at.

    """
    return base + (cur.tell() + 7) // 8
