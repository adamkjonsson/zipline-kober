"""Decoder for the ``dns`` specification, version 1.0.

DNS messages, header, question section, and resource records.

Generated from a specification by kober. Do not edit: change the spec and
compile it again.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from kober.runtime import Cursor, Sink, Stopped, TruncatedRead, Undecodable

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
        answers: Each element is one :class:`Rr`.
        authority: Each element is one :class:`Rr`.
        additional: Each element is one :class:`Rr`.
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
    answers: list[Rr]
    authority: list[Rr]
    additional: list[Rr]
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
            "answers": 7,
            "authority": 8,
            "additional": 9,
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
class Rr:
    """One resource record, in the answer, authority, or additional section.

    Attributes:
        name: The owner name, often a pointer.
        type: A 16-bit unsigned integer. Labelled by :data:`RRTYPE`.
        class_: A 16-bit unsigned integer. Labelled by :data:`RRCLASS`.
        ttl: A 32-bit unsigned integer.
        rdlength: A 16-bit unsigned integer.
        rdata: Opaque here; what is inside depends on the record type.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    name: Name
    type: int
    class_: int
    ttl: int
    rdlength: int
    rdata: bytes
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType(
        {"name": 0, "type": 1, "class_": 2, "ttl": 3, "rdlength": 4, "rdata": 5}
    )


@dataclass(slots=True)
class Name:
    """One decoded ``name``.

    A sequence of labels, ending either in a zero-length label or in a
    compression pointer, which is always the last thing in a name.

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

    A length byte, then the rest of the label. The top two bits of the length
    decide which: 00 means that many bytes of text, and 11 means the byte is
    the high half of a compression pointer. 01 and 10 are reserved, and there
    is no default, so a message using one is undecodable rather than guessed
    at.

    Attributes:
        length: An 8-bit unsigned integer.
        rest: Text, decoded as ``utf-8`` or one :class:`Compressed`.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    length: int
    rest: str | Compressed
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType({"length": 0, "rest": 1})


@dataclass(slots=True)
class Compressed:
    """One decoded ``compressed``.

    The second half of a compression pointer: the offset is the low 14 bits of
    the two bytes, counted from the start of the message.

    Attributes:
        low: An 8-bit unsigned integer.
        target: The name already at that offset, read there and returned from.
        __spans__: Byte ranges: this object's own extent first, then one pair
            per attribute above, in order.

    """

    low: int
    target: Name
    __spans__: tuple[int, ...]

    __span_index__: ClassVar[Mapping[str, int]] = MappingProxyType({"low": 0, "target": 1})


# --- the decoder -----------------------------------------------------------


def _decode_message(
    _data: bytes,
    _size: int,
    _at: int,
    _base: int,
    _sink: Sink | None,
    _path: str,
    _depth: int,
    _origin: int,
    _limit: int,
    _hops: int,
) -> tuple[Message, int]:
    """Decode one ``message``.

    Args:
        _data: The run being decoded.
        _size: Its length, passed rather than measured again here.
        _at: Where in it to start, as a byte offset.
        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.
        _sink: Where records go, or ``None`` to decode without
            emitting anything.
        _path: This instance's field path, which its records carry.
        _depth: How many units deep this decode already is.
        _origin: Where the message starts, as an index into ``_data``. A
            pointer offset is measured from here.
        _limit: What a pointer may not reach, or ``-1`` before the first hop.
        _hops: How many hops the chain has taken.

    Returns:
        The decoded ``message``, and the byte offset
        after it.

    Raises:
        TruncatedRead: If the input ends inside it.
        Undecodable: If the input is not what this unit describes.

    """
    if _depth > 64:
        raise Undecodable("unit nesting passed 64 levels", _at)

    _b = _base + _at
    _extent = _b

    _s_id = _b
    if _size - _at < 2:
        raise TruncatedRead("truncated", _at)
    id = int.from_bytes(_data[_at:_at + 2], "big")
    _e_id = _b + 2
    if _sink is not None:
        _sink.record(id.to_bytes(2, "little"), "prim:u16", _s_id, _e_id, _path + ".id")

    _s_flags = _b + 2
    flags, _at = _decode_flags(
        _data, _size, _at + 2, _base, _sink, _path + ".flags", _depth + 1, _origin, _limit, _hops
    )
    _b = _base + _at
    _e_flags = _b

    _s_qdcount = _b
    if _size - _at < 2:
        raise TruncatedRead("truncated", _at)
    qdcount = int.from_bytes(_data[_at:_at + 2], "big")
    _e_qdcount = _b + 2
    if _sink is not None:
        _sink.record(
            qdcount.to_bytes(2, "little"), "prim:u16", _s_qdcount, _e_qdcount, _path + ".qdcount"
        )

    _s_ancount = _b + 2
    if _size - _at < 4:
        raise TruncatedRead("truncated", _at + 2)
    ancount = int.from_bytes(_data[_at + 2:_at + 4], "big")
    _e_ancount = _b + 4
    if _sink is not None:
        _sink.record(
            ancount.to_bytes(2, "little"), "prim:u16", _s_ancount, _e_ancount, _path + ".ancount"
        )

    _s_nscount = _b + 4
    if _size - _at < 6:
        raise TruncatedRead("truncated", _at + 4)
    nscount = int.from_bytes(_data[_at + 4:_at + 6], "big")
    _e_nscount = _b + 6
    if _sink is not None:
        _sink.record(
            nscount.to_bytes(2, "little"), "prim:u16", _s_nscount, _e_nscount, _path + ".nscount"
        )

    _s_arcount = _b + 6
    if _size - _at < 8:
        raise TruncatedRead("truncated", _at + 6)
    arcount = int.from_bytes(_data[_at + 6:_at + 8], "big")
    _e_arcount = _b + 8
    if _sink is not None:
        _sink.record(
            arcount.to_bytes(2, "little"), "prim:u16", _s_arcount, _e_arcount, _path + ".arcount"
        )

    _s_questions = _b + 8
    _at = _at + 8
    _b = _base + _at
    questions: list[Question] = []
    for _index in range(qdcount):
        _element, _at = _decode_question(
            _data,
            _size,
            _at,
            _base,
            _sink,
            f"{_path}.questions[{_index}]",
            _depth + 1,
            _origin,
            _limit,
            _hops,
        )
        _b = _base + _at
        questions.append(_element)
    _e_questions = _b

    _s_answers = _b
    answers: list[Rr] = []
    for _index in range(ancount):
        _element, _at = _decode_rr(
            _data,
            _size,
            _at,
            _base,
            _sink,
            f"{_path}.answers[{_index}]",
            _depth + 1,
            _origin,
            _limit,
            _hops,
        )
        _b = _base + _at
        answers.append(_element)
    _e_answers = _b

    _s_authority = _b
    authority: list[Rr] = []
    for _index in range(nscount):
        _element, _at = _decode_rr(
            _data,
            _size,
            _at,
            _base,
            _sink,
            f"{_path}.authority[{_index}]",
            _depth + 1,
            _origin,
            _limit,
            _hops,
        )
        _b = _base + _at
        authority.append(_element)
    _e_authority = _b

    _s_additional = _b
    additional: list[Rr] = []
    for _index in range(arcount):
        _element, _at = _decode_rr(
            _data,
            _size,
            _at,
            _base,
            _sink,
            f"{_path}.additional[{_index}]",
            _depth + 1,
            _origin,
            _limit,
            _hops,
        )
        _b = _base + _at
        additional.append(_element)
    _e_additional = _b

    _s, _e = _extent, _b
    return Message(
        id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
        questions,
        answers,
        authority,
        additional,
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
            _s_answers,
            _e_answers,
            _s_authority,
            _e_authority,
            _s_additional,
            _e_additional,
        ),
    ), _at


def _decode_flags(
    _data: bytes,
    _size: int,
    _at: int,
    _base: int,
    _sink: Sink | None,
    _path: str,
    _depth: int,
    _origin: int,
    _limit: int,
    _hops: int,
) -> tuple[Flags, int]:
    """Decode one ``flags``.

    Args:
        _data: The run being decoded.
        _size: Its length, passed rather than measured again here.
        _at: Where in it to start, as a byte offset.
        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.
        _sink: Where records go, or ``None`` to decode without
            emitting anything.
        _path: This instance's field path, which its records carry.
        _depth: How many units deep this decode already is.
        _origin: Where the message starts, as an index into ``_data``. A
            pointer offset is measured from here.
        _limit: What a pointer may not reach, or ``-1`` before the first hop.
        _hops: How many hops the chain has taken.

    Returns:
        The decoded ``flags``, and the byte offset
        after it.

    Raises:
        TruncatedRead: If the input ends inside it.
        Undecodable: If the input is not what this unit describes.

    """
    if _depth > 64:
        raise Undecodable("unit nesting passed 64 levels", _at)

    _b = _base + _at
    _extent = _b

    _s_qr = _b
    if _size - _at < 1:
        raise TruncatedRead("truncated", _at)
    qr = (_data[_at] >> 7) & 1
    _e_qr = _b + 1
    if _sink is not None:
        _sink.record(qr.to_bytes(1, "little"), "prim:u8", _s_qr, _e_qr, _path + ".qr")

    _s_opcode = _b
    if _size - _at < 1:
        raise TruncatedRead("truncated", _at + 1)
    opcode = (_data[_at] >> 3) & 15
    _e_opcode = _b + 1
    if _sink is not None:
        _sink.record(
            opcode.to_bytes(1, "little"), "prim:u8", _s_opcode, _e_opcode, _path + ".opcode"
        )

    _s_aa = _b
    if _size - _at < 1:
        raise TruncatedRead("truncated", _at + 1)
    aa = (_data[_at] >> 2) & 1
    _e_aa = _b + 1
    if _sink is not None:
        _sink.record(aa.to_bytes(1, "little"), "prim:u8", _s_aa, _e_aa, _path + ".aa")

    _s_tc = _b
    if _size - _at < 1:
        raise TruncatedRead("truncated", _at + 1)
    tc = (_data[_at] >> 1) & 1
    _e_tc = _b + 1
    if _sink is not None:
        _sink.record(tc.to_bytes(1, "little"), "prim:u8", _s_tc, _e_tc, _path + ".tc")

    _s_rd = _b
    if _size - _at < 1:
        raise TruncatedRead("truncated", _at + 1)
    rd = _data[_at] & 1
    _e_rd = _b + 1
    if _sink is not None:
        _sink.record(rd.to_bytes(1, "little"), "prim:u8", _s_rd, _e_rd, _path + ".rd")

    _s_ra = _b + 1
    if _size - _at < 2:
        raise TruncatedRead("truncated", _at + 1)
    ra = (_data[_at + 1] >> 7) & 1
    _e_ra = _b + 2
    if _sink is not None:
        _sink.record(ra.to_bytes(1, "little"), "prim:u8", _s_ra, _e_ra, _path + ".ra")

    _s__anon6 = _b + 1
    if _size - _at < 2:
        raise TruncatedRead("truncated", _at + 2)
    _anon6 = (_data[_at + 1] >> 4) & 7
    _e__anon6 = _b + 2
    if _sink is not None:
        _sink.record(_anon6.to_bytes(1, "little"), "prim:u8", _s__anon6, _e__anon6, _path + "._")

    _s_rcode = _b + 1
    if _size - _at < 2:
        raise TruncatedRead("truncated", _at + 2)
    rcode = _data[_at + 1] & 15
    _e_rcode = _b + 2
    if _sink is not None:
        _sink.record(rcode.to_bytes(1, "little"), "prim:u8", _s_rcode, _e_rcode, _path + ".rcode")

    _s, _e = _extent, _b + 2
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
    ), _at + 2


def _decode_question(
    _data: bytes,
    _size: int,
    _at: int,
    _base: int,
    _sink: Sink | None,
    _path: str,
    _depth: int,
    _origin: int,
    _limit: int,
    _hops: int,
) -> tuple[Question, int]:
    """Decode one ``question``.

    Args:
        _data: The run being decoded.
        _size: Its length, passed rather than measured again here.
        _at: Where in it to start, as a byte offset.
        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.
        _sink: Where records go, or ``None`` to decode without
            emitting anything.
        _path: This instance's field path, which its records carry.
        _depth: How many units deep this decode already is.
        _origin: Where the message starts, as an index into ``_data``. A
            pointer offset is measured from here.
        _limit: What a pointer may not reach, or ``-1`` before the first hop.
        _hops: How many hops the chain has taken.

    Returns:
        The decoded ``question``, and the byte offset
        after it.

    Raises:
        TruncatedRead: If the input ends inside it.
        Undecodable: If the input is not what this unit describes.

    """
    if _depth > 64:
        raise Undecodable("unit nesting passed 64 levels", _at)

    _b = _base + _at
    _extent = _b

    _s_qname = _b
    qname, _at = _decode_name(
        _data, _size, _at, _base, _sink, _path + ".qname", _depth + 1, _origin, _limit, _hops
    )
    _b = _base + _at
    _e_qname = _b

    _s_qtype = _b
    if _size - _at < 2:
        raise TruncatedRead("truncated", _at)
    qtype = int.from_bytes(_data[_at:_at + 2], "big")
    _e_qtype = _b + 2
    if _sink is not None:
        _sink.record(qtype.to_bytes(2, "little"), "prim:u16", _s_qtype, _e_qtype, _path + ".qtype")

    _s_qclass = _b + 2
    if _size - _at < 4:
        raise TruncatedRead("truncated", _at + 2)
    qclass = int.from_bytes(_data[_at + 2:_at + 4], "big")
    _e_qclass = _b + 4
    if _sink is not None:
        _sink.record(
            qclass.to_bytes(2, "little"), "prim:u16", _s_qclass, _e_qclass, _path + ".qclass"
        )

    _s, _e = _extent, _b + 4
    return Question(
        qname,
        qtype,
        qclass,
        (_s, _e, _s_qname, _e_qname, _s_qtype, _e_qtype, _s_qclass, _e_qclass),
    ), _at + 4


def _decode_rr(
    _data: bytes,
    _size: int,
    _at: int,
    _base: int,
    _sink: Sink | None,
    _path: str,
    _depth: int,
    _origin: int,
    _limit: int,
    _hops: int,
) -> tuple[Rr, int]:
    """Decode one ``rr``.

    Args:
        _data: The run being decoded.
        _size: Its length, passed rather than measured again here.
        _at: Where in it to start, as a byte offset.
        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.
        _sink: Where records go, or ``None`` to decode without
            emitting anything.
        _path: This instance's field path, which its records carry.
        _depth: How many units deep this decode already is.
        _origin: Where the message starts, as an index into ``_data``. A
            pointer offset is measured from here.
        _limit: What a pointer may not reach, or ``-1`` before the first hop.
        _hops: How many hops the chain has taken.

    Returns:
        The decoded ``rr``, and the byte offset
        after it.

    Raises:
        TruncatedRead: If the input ends inside it.
        Undecodable: If the input is not what this unit describes.

    """
    if _depth > 64:
        raise Undecodable("unit nesting passed 64 levels", _at)

    _b = _base + _at
    _extent = _b

    _s_name = _b
    name, _at = _decode_name(
        _data, _size, _at, _base, _sink, _path + ".name", _depth + 1, _origin, _limit, _hops
    )
    _b = _base + _at
    _e_name = _b

    _s_type = _b
    if _size - _at < 2:
        raise TruncatedRead("truncated", _at)
    type = int.from_bytes(_data[_at:_at + 2], "big")
    _e_type = _b + 2
    if _sink is not None:
        _sink.record(type.to_bytes(2, "little"), "prim:u16", _s_type, _e_type, _path + ".type")

    _s_class_ = _b + 2
    if _size - _at < 4:
        raise TruncatedRead("truncated", _at + 2)
    class_ = int.from_bytes(_data[_at + 2:_at + 4], "big")
    _e_class_ = _b + 4
    if _sink is not None:
        _sink.record(
            class_.to_bytes(2, "little"), "prim:u16", _s_class_, _e_class_, _path + ".class"
        )

    _s_ttl = _b + 4
    if _size - _at < 8:
        raise TruncatedRead("truncated", _at + 4)
    ttl = int.from_bytes(_data[_at + 4:_at + 8], "big")
    _e_ttl = _b + 8
    if _sink is not None:
        _sink.record(ttl.to_bytes(4, "little"), "prim:u32", _s_ttl, _e_ttl, _path + ".ttl")

    _s_rdlength = _b + 8
    if _size - _at < 10:
        raise TruncatedRead("truncated", _at + 8)
    rdlength = int.from_bytes(_data[_at + 8:_at + 10], "big")
    _e_rdlength = _b + 10
    if _sink is not None:
        _sink.record(
            rdlength.to_bytes(2, "little"),
            "prim:u16",
            _s_rdlength,
            _e_rdlength,
            _path + ".rdlength",
        )

    _s_rdata = _b + 10
    _want = rdlength
    if _size - (_at + 10) < _want:
        raise TruncatedRead("truncated", _at + 10)
    rdata = _data[_at + 10:_at + 10 + _want]
    _at = _at + 10 + _want
    _b = _base + _at
    _e_rdata = _b
    if _sink is not None:
        _sink.record(rdata, "prim:bytes", _s_rdata, _e_rdata, _path + ".rdata")

    _s, _e = _extent, _b
    return Rr(
        name,
        type,
        class_,
        ttl,
        rdlength,
        rdata,
        (
            _s,
            _e,
            _s_name,
            _e_name,
            _s_type,
            _e_type,
            _s_class_,
            _e_class_,
            _s_ttl,
            _e_ttl,
            _s_rdlength,
            _e_rdlength,
            _s_rdata,
            _e_rdata,
        ),
    ), _at


def _decode_name(
    _data: bytes,
    _size: int,
    _at: int,
    _base: int,
    _sink: Sink | None,
    _path: str,
    _depth: int,
    _origin: int,
    _limit: int,
    _hops: int,
) -> tuple[Name, int]:
    """Decode one ``name``.

    Args:
        _data: The run being decoded.
        _size: Its length, passed rather than measured again here.
        _at: Where in it to start, as a byte offset.
        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.
        _sink: Where records go, or ``None`` to decode without
            emitting anything.
        _path: This instance's field path, which its records carry.
        _depth: How many units deep this decode already is.
        _origin: Where the message starts, as an index into ``_data``. A
            pointer offset is measured from here.
        _limit: What a pointer may not reach, or ``-1`` before the first hop.
        _hops: How many hops the chain has taken.

    Returns:
        The decoded ``name``, and the byte offset
        after it.

    Raises:
        TruncatedRead: If the input ends inside it.
        Undecodable: If the input is not what this unit describes.

    """
    if _depth > 64:
        raise Undecodable("unit nesting passed 64 levels", _at)

    _b = _base + _at
    _extent = _b

    _s_labels = _b
    labels: list[Label] = []
    _index = 0
    while True:
        _element, _at = _decode_label(
            _data,
            _size,
            _at,
            _base,
            _sink,
            f"{_path}.labels[{_index}]",
            _depth + 1,
            _origin,
            _limit,
            _hops,
        )
        _b = _base + _at
        labels.append(_element)
        if _element.length == 0 or _element.length >= 192:
            break
        _index += 1
    _e_labels = _b

    _s, _e = _extent, _b
    return Name(labels, (_s, _e, _s_labels, _e_labels)), _at


def _decode_label(
    _data: bytes,
    _size: int,
    _at: int,
    _base: int,
    _sink: Sink | None,
    _path: str,
    _depth: int,
    _origin: int,
    _limit: int,
    _hops: int,
) -> tuple[Label, int]:
    """Decode one ``label``.

    Args:
        _data: The run being decoded.
        _size: Its length, passed rather than measured again here.
        _at: Where in it to start, as a byte offset.
        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.
        _sink: Where records go, or ``None`` to decode without
            emitting anything.
        _path: This instance's field path, which its records carry.
        _depth: How many units deep this decode already is.
        _origin: Where the message starts, as an index into ``_data``. A
            pointer offset is measured from here.
        _limit: What a pointer may not reach, or ``-1`` before the first hop.
        _hops: How many hops the chain has taken.

    Returns:
        The decoded ``label``, and the byte offset
        after it.

    Raises:
        TruncatedRead: If the input ends inside it.
        Undecodable: If the input is not what this unit describes.

    """
    if _depth > 64:
        raise Undecodable("unit nesting passed 64 levels", _at)

    _b = _base + _at
    _extent = _b

    _s_length = _b
    if _size - _at < 1:
        raise TruncatedRead("truncated", _at)
    length = _data[_at]
    _e_length = _b + 1
    if _sink is not None:
        _sink.record(
            length.to_bytes(1, "little"), "prim:u8", _s_length, _e_length, _path + ".length"
        )

    _s_rest = _b + 1
    _selector = length >> 6
    if _selector == 0:
        _want = length
        if _size - (_at + 1) < _want:
            raise TruncatedRead("truncated", _at + 1)
        _raw = _data[_at + 1:_at + 1 + _want]
        _at = _at + 1 + _want
        _b = _base + _at
        try:
            rest = _raw.decode("utf-8")
        except UnicodeDecodeError:
            # A malformed string is a fact about the input, not a
            # failure of the decoder: §3.2. The bytes are accounted
            # for either way, so the region stays decoded.
            rest = _raw.decode("utf-8", errors="replace")
    elif _selector == 3:
        rest, _at = _decode_compressed(
            _data,
            _size,
            _at + 1,
            _base,
            _sink,
            _path + ".rest",
            length,
            _depth + 1,
            _origin,
            _limit,
            _hops,
        )
        _b = _base + _at
    else:
        raise Undecodable(f"no case for {_selector!r} and no default", _at + 1)
    _e_rest = _b
    if _sink is not None and _selector == 0:
        _sink.record(
            rest.encode("utf-8", errors="replace"),
            "mime:text/plain; charset=utf-8",
            _s_rest,
            _e_rest,
            _path + ".rest",
        )

    _s, _e = _extent, _b
    return Label(length, rest, (_s, _e, _s_length, _e_length, _s_rest, _e_rest)), _at


def _decode_compressed(
    _data: bytes,
    _size: int,
    _at: int,
    _base: int,
    _sink: Sink | None,
    _path: str,
    high: int,
    _depth: int,
    _origin: int,
    _limit: int,
    _hops: int,
) -> tuple[Compressed, int]:
    """Decode one ``compressed``.

    Args:
        _data: The run being decoded.
        _size: Its length, passed rather than measured again here.
        _at: Where in it to start, as a byte offset.
        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.
        _sink: Where records go, or ``None`` to decode without
            emitting anything.
        _path: This instance's field path, which its records carry.
        high: The ``high`` its caller supplies.
        _depth: How many units deep this decode already is.
        _origin: Where the message starts, as an index into ``_data``. A
            pointer offset is measured from here.
        _limit: What a pointer may not reach, or ``-1`` before the first hop.
        _hops: How many hops the chain has taken.

    Returns:
        The decoded ``compressed``, and the byte offset
        after it.

    Raises:
        TruncatedRead: If the input ends inside it.
        Undecodable: If the input is not what this unit describes.

    """
    if _depth > 64:
        raise Undecodable("unit nesting passed 64 levels", _at)

    _b = _base + _at
    _extent = _b

    _s_low = _b
    if _size - _at < 1:
        raise TruncatedRead("truncated", _at)
    low = _data[_at]
    _e_low = _b + 1
    if _sink is not None:
        _sink.record(low.to_bytes(1, "little"), "prim:u8", _s_low, _e_low, _path + ".low")

    _at = _at + 1
    _b = _base + _at
    _p_at = (high & 63) << 8 | low
    _p_end = _at if _limit < 0 else _limit
    _p_to = _origin + _p_at
    if _p_at < 0 or _p_to >= _p_end:
        raise Undecodable(f"pointer target {_p_at} is outside the bytes already decoded", _at)
    if _hops >= 16:
        raise Undecodable("pointer chain passed 16 hops", _at)
    _p_at, _p_size = _at, _size
    _at, _size = _p_to, _p_end
    _b = _base + _at
    _s_target = _b
    try:
        target, _at = _decode_name(
            _data,
            _size,
            _at,
            _base,
            _sink,
            _path + ".target",
            _depth + 1,
            _origin,
            _p_to,
            _hops + 1,
        )
        _b = _base + _at
    except TruncatedRead as _exc:
        raise Undecodable(f"pointer target does not decode: {_exc}", _p_at) from _exc
    except Undecodable as _exc:
        raise Undecodable(str(_exc), _p_at) from _exc
    _e_target = _b
    _at, _size = _p_at, _p_size
    _b = _base + _at

    _s, _e = _extent, _b
    return Compressed(low, target, (_s, _e, _s_low, _e_low, _s_target, _e_target)), _at


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
    _data = cur.data
    _size = len(_data)
    # The cursor owns the position between messages; inside one, the generated
    # code below owns it, because a byte offset in a local is what makes every
    # read an index rather than a call. It is handed back at every exit,
    # including the failures.
    _start = cur.tell() >> 3
    _at = _start
    try:
        _message, _at = _decode_message(_data, _size, _at, cur.base, sink, NAME, 0, _start, -1, 0)
    except Stopped as _exc:
        _at = _start if _exc.at is None else _exc.at
        cur.seek(_at << 3)
        raise
    cur.seek(_at << 3)
    return _message


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
    except Stopped as _exc:
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


