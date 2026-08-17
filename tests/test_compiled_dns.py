"""``compiled_dns.py``: the compiler's output, kept in the repository.

It began as stage 1's spike — the module the compiler *should* produce, written
by hand so the design could be run before a generator existed. It is now
literally what the generator produces, character for character, which is what
"the generator's output converges on the fixture" was always supposed to mean.
`test_pygen.py` asserts that; these tests are the other side of it, and they ask
what a **consumer** gets:

- a typed object whose fields are `int` and `str`, completable in an editor and
  wrong at import time rather than `None` at runtime;
- byte ranges for all of it, through `kober.runtime.span`, without a wrapper per
  field;
- enum labels as a lookup beside the value rather than a type that raises.

What the module *writes* is checked in `test_compiled.py`, against the
interpreter and against `zpf`. Keeping the file in the repository is the point:
generated code is source this project ships, so it should be readable in review
like anything else, and a diff in it is a diff in what every generated decoder
will look like.
"""

from __future__ import annotations

import struct

import compiled_dns
import pytest
from compiled_dns import decode

from kober.runtime import span

# A real query: one question, `example.com`, type A, class IN.
QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

# Its reply. The answer's owner name is the compression pointer 0xc00c, which
# is exactly why `dns.yaml` decodes no further than the question section.
ANSWER = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
RESPONSE = (
    struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
    + ANSWER
)


# --- the typed API ---------------------------------------------------------


def test_a_real_query_decodes_into_typed_objects():
    message = decode(QUERY)
    assert message is not None
    assert message.id == 0x1234
    assert message.qdcount == 1
    assert message.flags.rd == 1
    assert message.flags.qr == 0
    assert [label.text for label in message.questions[0].qname.labels] == ["example", "com", ""]
    assert message.questions[0].qtype == 1


def test_the_typed_api_needs_no_sink():
    """A caller who wants objects and no records passes nothing."""
    assert decode(QUERY) is not None


def test_a_message_that_cannot_be_decoded_is_none():
    assert decode(QUERY[:5]) is None


def test_an_absent_conditional_field_is_none_rather_than_empty():
    message = decode(QUERY)
    assert message is not None
    assert message.resource_records is None
    message = decode(RESPONSE)
    assert message is not None
    assert message.resource_records == ANSWER


def test_an_enum_is_a_lookup_rather_than_a_type():
    """A value with no label is normal on the wire, so the field stays an int."""
    message = decode(QUERY)
    assert message is not None
    assert compiled_dns.OPCODE[message.flags.opcode] == "query"
    assert compiled_dns.RRTYPE[message.questions[0].qtype] == "a"
    assert 3 not in compiled_dns.OPCODE


def test_an_anonymous_field_has_no_attribute():
    """It is read and cited, but a field with no name is not something to ask for."""
    message = decode(QUERY)
    assert message is not None
    assert "_" not in compiled_dns.Flags.__span_index__
    assert not hasattr(message.flags, "_")


# --- provenance ------------------------------------------------------------


def test_every_object_knows_which_bytes_it_came_from():
    message = decode(QUERY)
    assert message is not None
    assert span(message) == (0, len(QUERY))
    assert span(message, "id") == (0, 2)
    assert span(message, "qdcount") == (4, 6)
    question = message.questions[0]
    assert span(question) == (12, 29)
    assert span(question, "qtype") == (25, 27)
    assert span(question.qname.labels[0], "text") == (13, 20)


def test_a_sub_byte_field_cites_the_byte_holding_it():
    """§1: spans are byte offsets, so overlapping citations are the normal case."""
    message = decode(QUERY)
    assert message is not None
    assert span(message, "flags") == (2, 4)
    assert span(message.flags, "qr") == (2, 3)
    assert span(message.flags, "rcode") == (3, 4)


def test_an_absent_field_cites_nothing():
    message = decode(QUERY)
    assert message is not None
    start, end = span(message, "resource_records")
    assert start == end == len(QUERY)


def test_offsets_are_absolute():
    """A run does not begin at zero, and every range says so."""
    message = decode(QUERY, base=1000)
    assert message is not None
    assert span(message, "id") == (1000, 1002)


def test_span_refuses_a_name_that_is_not_a_field():
    message = decode(QUERY)
    assert message is not None
    with pytest.raises(KeyError):
        span(message, "qname")


def test_a_decoded_object_carries_no_dict():
    """The allocation the whole phase exists to remove is not allowed back in."""
    message = decode(QUERY)
    assert message is not None
    assert not hasattr(message, "__dict__")
