"""Decoder for the ``dns`` specification, version 1.0.

DNS messages, header and question section.

Generated from a specification by kober. Do not edit: change the spec and
compile it again.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from kober.runtime import Cursor, EvalError, Sink, TruncatedRead, Undecodable

if TYPE_CHECKING:
    from collections.abc import Mapping

#: The specification this module was generated from.
NAME = "dns"
VERSION = "1.0"

#: How a text field's payload is labelled. Not ``prim:`` — that scheme
#: has no text token — so the format's other fully specified one is used.
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
            than claimed. Present only when ``ancount + nscount + arcount >
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
        sink: Where records go, or ``None`` to decode without
            emitting anything.
        path: This instance's field path, which its records carry.

    Returns:
        The decoded ``message``.

    Raises:
        TruncatedRead: If the input ends inside it.

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

    _mark = cur.tell()
    questions: list[Question] = []
    for _index in range(qdcount):
        _element = _decode_question(cur, sink, f"{path}.questions[{_index}]")
        questions.append(_element)
    _s_questions, _e_questions = cur.span(_mark)

    if ancount + nscount + arcount > 0:
        _mark = cur.tell()
        resource_records = cur.read_remaining()
        _s_resource_records, _e_resource_records = cur.span(_mark)
        if sink is not None and _e_resource_records > _s_resource_records:
            sink.undecoded(_s_resource_records, _e_resource_records, "skipped")
    else:
        # Absent, not empty: it read nothing, so it cites nothing.
        resource_records = None
        _s_resource_records = _e_resource_records = cur.byte_offset()

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
            _s_resource_records,
            _e_resource_records,
        ),
    )


def _decode_flags(cur: Cursor, sink: Sink | None, path: str) -> Flags:
    """Decode one ``flags``.

    Args:
        cur: The cursor to read from.
        sink: Where records go, or ``None`` to decode without
            emitting anything.
        path: This instance's field path, which its records carry.

    Returns:
        The decoded ``flags``.

    Raises:
        TruncatedRead: If the input ends inside it.

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

    _mark = cur.tell()
    _anon6 = cur.read_int(3)
    _s__anon6, _e__anon6 = cur.span(_mark)
    if sink is not None:
        sink.record(_anon6.to_bytes(1, "little"), "prim:u8", _s__anon6, _e__anon6, path + "._")

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
        sink: Where records go, or ``None`` to decode without
            emitting anything.
        path: This instance's field path, which its records carry.

    Returns:
        The decoded ``question``.

    Raises:
        TruncatedRead: If the input ends inside it.

    """
    _extent = cur.tell()

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
        sink: Where records go, or ``None`` to decode without
            emitting anything.
        path: This instance's field path, which its records carry.

    Returns:
        The decoded ``name``.

    Raises:
        TruncatedRead: If the input ends inside it.

    """
    _extent = cur.tell()

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
        sink: Where records go, or ``None`` to decode without
            emitting anything.
        path: This instance's field path, which its records carry.

    Returns:
        The decoded ``label``.

    Raises:
        TruncatedRead: If the input ends inside it.

    """
    _extent = cur.tell()

    _mark = cur.tell()
    length = cur.read_int(8)
    _s_length, _e_length = cur.span(_mark)
    if sink is not None:
        sink.record(length.to_bytes(1, "little"), "prim:u8", _s_length, _e_length, path + ".length")

    _mark = cur.tell()
    _raw = cur.read_bytes(length)
    try:
        text = _raw.decode("utf-8")
    except UnicodeDecodeError:
        # A malformed string is a fact about the input, not a
        # failure of the decoder: §3.2. The bytes are accounted
        # for either way, so the region stays decoded.
        text = _raw.decode("utf-8", errors="replace")
    _s_text, _e_text = cur.span(_mark)
    if sink is not None:
        sink.record(
            text.encode("utf-8", errors="replace"),
            "mime:text/plain; charset=utf-8",
            _s_text,
            _e_text,
            path + ".text",
        )

    _s, _e = cur.span(_extent)
    return Label(length, text, (_s, _e, _s_length, _e_length, _s_text, _e_text))


# --- entry points ----------------------------------------------------------


def decode_from(cur: Cursor, sink: Sink | None = None) -> Message:
    """Decode one ``message`` from wherever ``cur`` stands.

    The driver's entry point. The cursor is left after the last byte read,
    which is how a caller decoding several messages from one run knows where
    the next one starts — and the bytes after it are the driver's to account
    for, since only it knows whether another message follows.

    Args:
        cur: The cursor to read from.
        sink: Where records and undecoded regions go.

    Returns:
        The decoded ``message``.

    Raises:
        TruncatedRead: If the input ends inside the message.
        Undecodable: If it is not what the specification describes.

    """
    return _decode_message(cur, sink, NAME)


def decode(data: bytes, *, base: int = 0, sink: Sink | None = None) -> Message | None:
    """Decode one ``message`` from ``data``, accounting for all of it.

    ``data`` is one contiguous run holding one message, which is what a
    datagram is. Everything in it is accounted for: what the message decoded is
    cited by the records, and whatever is left over is named.

    Failure returns ``None`` rather than a half-built object. The typed model
    has no half-built state to offer — that is the trade it makes for not being
    a generic tree — and what *was* decoded has already reached the sink, which
    is where provenance lives.

    Args:
        data: The bytes to decode.
        base: Stream offset of ``data[0]``, so every byte range is
            absolute.
        sink: Where records and undecoded regions go. ``None`` decodes
            without emitting anything, for a caller who wants only the
            typed objects.

    Returns:
        The message, or ``None`` if it could not be decoded.

    """
    cur = Cursor(data, base)
    _end = base + len(data)
    try:
        _message = decode_from(cur, sink)
    except (EvalError, TruncatedRead, Undecodable, ZeroDivisionError) as _exc:
        if sink is not None:
            # From where the cursor stopped. Whatever this message could
            # account for it has already said; what is left is what was never
            # decoded.
            sink.undecoded(_stopped_at(cur, base), _end, _reason(_exc))
        return None
    if sink is not None:
        # Whatever this message did not claim is this datagram's alone: a
        # following message cannot use it, so it is skipped rather than left.
        _stop = _stopped_at(cur, base)
        if _stop < _end:
            sink.undecoded(_stop, _end, "skipped")
    return _message


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


def _reason(exc: Exception) -> str:
    """Return the `zpf` ``reason=`` a failed decode is marked with.

    Truncation is the only failure that means the bytes were never there.
    Everything else — a switch with no case, a guard that did not hold, an
    expression that could not answer — read the bytes and could not make sense
    of them.

    Args:
        exc: What the decode raised.

    Returns:
        ``"truncated"`` or ``"undecodable"``.

    """
    return "truncated" if isinstance(exc, TruncatedRead) else "undecodable"


