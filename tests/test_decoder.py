"""Tests for the decode engine."""

from __future__ import annotations

import struct

import pytest

from kober.decoder import MAX_DEPTH, Decoder
from kober.errors import SpecError
from kober.node import Node, NodeStatus
from kober.spec import Spec

DNS_QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)


def build(fields: str, *, extra_units: str = "", entry: str = "message", **kw: str) -> Spec:
    """Build a one-unit spec from a YAML fields block."""
    head = "\n".join(f"{key}: {value}" for key, value in kw.items())
    document = f"""
name: t
version: "1.0"
entry: {entry}
{head}
units:
  message:
    fields:
{fields}
{extra_units}
"""
    return Spec.from_yaml(document)


def decode(fields: str, data: bytes, *, extra_units: str = "", **kw: str) -> Node:
    return Decoder(build(fields, extra_units=extra_units, **kw)).decode_bytes(data)


# --- integers --------------------------------------------------------------


def test_big_endian_default():
    tree = decode("      - {name: a, type: {int: {bits: 16}}}", b"\x12\x34")
    assert tree.find("a").value == 0x1234
    assert (tree.off_start, tree.off_end) == (0, 2)


def test_little_endian():
    tree = decode("      - {name: a, type: {int: {bits: 16, endian: little}}}", b"\x12\x34")
    assert tree.find("a").value == 0x3412


def test_signed():
    tree = decode("      - {name: a, type: {int: {bits: 16, signed: true}}}", b"\xff\xff")
    assert tree.find("a").value == -1


def test_sub_byte_fields_cite_the_containing_byte():
    fields = """
      - {name: qr, type: {int: {bits: 1}}}
      - {name: opcode, type: {int: {bits: 4}}}
      - {name: rest, type: {int: {bits: 3}}}
"""
    tree = decode(fields, bytes([0b1_0010_110]))
    assert [(n.name, n.value) for n in tree.children] == [
        ("qr", 1),
        ("opcode", 0b0010),
        ("rest", 0b110),
    ]
    # All three cite the same byte: overlapping spans are the normal case.
    assert all((n.off_start, n.off_end) == (0, 1) for n in tree.children)


def test_anonymous_fields_are_decoded_but_unnamed():
    fields = """
      - {name: a, type: {int: {bits: 4}}}
      - {name: null, type: {int: {bits: 4}}}
"""
    tree = decode(fields, b"\xab")
    assert [n.name for n in tree.children] == ["a", None]
    assert tree.children[1].value == 0xB


# --- bytes and strings -----------------------------------------------------


def test_fixed_bytes():
    tree = decode("      - {name: a, type: {bytes: {size: 3}}}", b"abcdef")
    assert tree.find("a").value == b"abc"


def test_size_from_expression():
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: body, type: {bytes: {size: {expr: "n"}}}}
"""
    tree = decode(fields, b"\x03abc")
    assert tree.find("body").value == b"abc"


def test_remaining():
    fields = """
      - {name: a, type: {int: {bits: 8}}}
      - {name: rest, type: {bytes: {size: {remaining: true}}}}
"""
    tree = decode(fields, b"\x01xyz")
    assert tree.find("rest").value == b"xyz"


def test_terminated_consumes_by_default():
    fields = '      - {name: a, type: {string: {size: {terminated: {delimiter: "\\0"}}}}}\n'
    fields += "      - {name: b, type: {int: {bits: 8}}}"
    tree = decode(fields, b"host\x00\x07")
    assert tree.find("a").value == "host"
    assert tree.find("b").value == 7


def test_terminated_without_consuming():
    fields = (
        '      - {name: a, type: {bytes: {size: {terminated: '
        '{delimiter: "\\0", consume: false}}}}}\n'
    )
    fields += "      - {name: b, type: {int: {bits: 8}}}"
    tree = decode(fields, b"ab\x00")
    assert tree.find("a").value == b"ab"
    assert tree.find("b").value == 0


def test_missing_required_terminator_is_truncation_not_failure():
    """In STREAM shape the value may continue in a segment we do not hold."""
    fields = '      - {name: a, type: {string: {size: {terminated: {delimiter: "\\0"}}}}}'
    tree = decode(fields, b"unterminated")
    assert tree.status is NodeStatus.TRUNCATED


def test_optional_terminator_takes_the_rest():
    fields = (
        '      - {name: a, type: {bytes: {size: {terminated: '
        '{delimiter: "\\0", required: false}}}}}'
    )
    tree = decode(fields, b"rest")
    assert tree.find("a").value == b"rest"
    assert tree.status is NodeStatus.OK


def test_string_encoding():
    fields = "      - {name: a, type: {string: {size: 2, encoding: ascii}}}"
    assert decode(fields, b"hi").find("a").value == "hi"


def test_bad_encoding_is_recorded_not_raised():
    """A malformed string is a fact about the input, not a decoder failure."""
    fields = "      - {name: a, type: {string: {size: 2}}}"
    tree = decode(fields, b"\xff\xfe")
    node = tree.find("a")
    assert node.status is NodeStatus.OK
    assert "decode error" in node.detail
    assert node.value == "\ufffd\ufffd"


# --- units, params, nesting ------------------------------------------------


def test_nested_unit():
    fields = "      - {name: h, type: {unit: header}}"
    extra = """
  header:
    fields:
      - {name: x, type: {int: {bits: 8}}}
"""
    tree = decode(fields, b"\x05", extra_units=extra)
    assert tree.find("h").find("x").value == 5
    assert tree.find("h").unit == "header"


def test_reference_into_a_nested_unit():
    fields = """
      - {name: h, type: {unit: header}}
      - {name: body, type: {bytes: {size: {expr: "h.n"}}}}
"""
    extra = """
  header:
    fields:
      - {name: n, type: {int: {bits: 8}}}
"""
    tree = decode(fields, b"\x02xy", extra_units=extra)
    assert tree.find("body").value == b"xy"


def test_a_nested_unit_that_failed_part_way_keeps_what_it_decoded():
    """Found by the compiler's differential test, which is what it is for.

    A generated decoder emits as it reads, so it had already reported the two
    fields below by the time the third ran out. The interpreter used to throw
    the whole nested unit away, leaving the emitter to name bytes ``truncated``
    that had in fact been read and understood.
    """
    fields = "      - {name: h, type: {unit: header}}"
    extra = """
  header:
    fields:
      - {name: a, type: {int: {bits: 8}}}
      - {name: b, type: {int: {bits: 8}}}
      - {name: c, type: {int: {bits: 8}}}
"""
    tree = decode(fields, b"\x01\x02", extra_units=extra)
    assert tree.status is NodeStatus.TRUNCATED
    nested = tree.find("h")
    assert nested is not None, "the nested unit was discarded"
    assert nested.status is NodeStatus.TRUNCATED
    assert [child.value for child in nested.children] == [1, 2, None]
    assert (nested.off_start, nested.off_end) == (0, 2)


def test_unit_parameters():
    fields = '      - {name: b, type: {unit: {name: body, args: ["4"]}}}'
    extra = """
  body:
    params: [{name: size, type: int}]
    fields:
      - {name: data, type: {bytes: {size: {expr: "size"}}}}
"""
    tree = decode(fields, b"abcd", extra_units=extra)
    assert tree.find("b").find("data").value == b"abcd"


def test_parent_reference():
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: b, type: {unit: body}}
"""
    extra = """
  body:
    fields:
      - {name: data, type: {bytes: {size: {expr: "parent.n"}}}}
"""
    tree = decode(fields, b"\x02xy", extra_units=extra)
    assert tree.find("b").find("data").value == b"xy"


def test_root_reference():
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: b, type: {unit: body}}
"""
    extra = """
  body:
    fields:
      - {name: data, type: {bytes: {size: {expr: "root.n"}}}}
"""
    tree = decode(fields, b"\x03xyz", extra_units=extra)
    assert tree.find("b").find("data").value == b"xyz"


# --- conditions, switches, computed ---------------------------------------


def test_condition_present():
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: opt, type: {int: {bits: 8}}, condition: "n > 0"}
"""
    tree = decode(fields, b"\x01\x09")
    assert tree.find("opt").value == 9


def test_condition_absent_produces_no_node():
    """An absent field consumes nothing, so it gets no node and no empty span."""
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: opt, type: {int: {bits: 8}}, condition: "n > 0"}
"""
    tree = decode(fields, b"\x00")
    assert tree.find("opt") is None
    assert tree.off_end == 1


def test_switch_selects_a_case():
    fields = """
      - {name: kind, type: {int: {bits: 8}}}
      - name: body
        type:
          switch:
            on: "kind"
            cases:
              1: {int: {bits: 8}}
              2: {bytes: {size: 2}}
            default: {bytes: {size: {remaining: true}}}
"""
    assert decode(fields, b"\x01\x09").find("body").value == 9
    assert decode(fields, b"\x02ab").find("body").value == b"ab"
    assert decode(fields, b"\x09zzz").find("body").value == b"zzz"


def test_switch_without_a_match_is_undecodable():
    """§2: no case and no default means tried and failed."""
    fields = """
      - {name: kind, type: {int: {bits: 8}}}
      - name: body
        type:
          switch: {on: "kind", cases: {1: {int: {bits: 8}}}}
"""
    tree = decode(fields, b"\x09\x09")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "no case for 9" in tree.detail


def test_computed_consumes_nothing():
    fields = """
      - {name: words, type: {int: {bits: 8}}}
      - {name: octets, type: {computed: "words * 4"}}
      - {name: body, type: {bytes: {size: {expr: "octets"}}}}
"""
    tree = decode(fields, b"\x01abcd")
    node = tree.find("octets")
    assert node.value == 4
    assert node.width == 0
    assert tree.find("body").value == b"abcd"


# --- repetition ------------------------------------------------------------


def test_repeat_count():
    fields = '      - {name: xs, type: {int: {bits: 8}}, repeat: {count: "3"}}'
    tree = decode(fields, b"\x01\x02\x03")
    assert [n.value for n in tree.find("xs").children] == [1, 2, 3]


def test_repeat_elements_are_indexed():
    fields = '      - {name: xs, type: {int: {bits: 8}}, repeat: {count: "2"}}'
    tree = decode(fields, b"\x01\x02")
    assert [n.name for n in tree.find("xs").children] == ["xs[0]", "xs[1]"]


def test_repeat_count_from_a_field():
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: xs, type: {int: {bits: 8}}, repeat: {count: "n"}}
"""
    tree = decode(fields, b"\x02\x0a\x0b")
    assert [n.value for n in tree.find("xs").children] == [10, 11]


def test_repeat_to_end():
    fields = "      - {name: xs, type: {int: {bits: 8}}, repeat: {to_end: true}}"
    tree = decode(fields, b"\x01\x02\x03")
    assert len(tree.find("xs").children) == 3


def test_repeat_until_sees_the_element_just_decoded():
    fields = '      - {name: xs, type: {int: {bits: 8}}, repeat: {until: "xs == 0"}}'
    tree = decode(fields, b"\x01\x02\x00\x09")
    assert [n.value for n in tree.find("xs").children] == [1, 2, 0]
    assert tree.off_end == 3


def test_negative_repeat_count_is_undecodable():
    fields = """
      - {name: n, type: {int: {bits: 8, signed: true}}}
      - {name: xs, type: {int: {bits: 8}}, repeat: {count: "n"}}
"""
    tree = decode(fields, b"\xff\x01")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "negative repeat count" in tree.detail


def test_a_repetition_that_consumes_nothing_cannot_spin():
    """A zero-width element under to_end would otherwise loop forever."""
    fields = '      - {name: xs, type: {computed: "1"}, repeat: {to_end: true}}'
    tree = decode(fields, b"\x01\x02")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "cannot terminate" in tree.detail


# --- truncation ------------------------------------------------------------


def test_truncation_stops_the_decode_and_says_how_far_it_got():
    fields = """
      - {name: a, type: {int: {bits: 16}}}
      - {name: b, type: {int: {bits: 16}}}
"""
    tree = decode(fields, b"\x00\x01\x00")
    assert tree.status is NodeStatus.TRUNCATED
    assert tree.find("a").value == 1
    assert tree.off_end == 2, "the tail the driver must account for starts here"


def test_size_past_the_end_is_truncation():
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: body, type: {bytes: {size: {expr: "n"}}}}
"""
    tree = decode(fields, b"\x64ab")
    assert tree.status is NodeStatus.TRUNCATED


# --- failure never escapes -------------------------------------------------


def test_division_by_zero_becomes_undecodable_not_an_exception():
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: body, type: {bytes: {size: {expr: "4 / n"}}}}
"""
    tree = decode(fields, b"\x00ab")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "division by zero" in tree.detail


def test_recursion_is_bounded():
    """Crafted input must not exhaust the interpreter stack."""
    fields = """
      - {name: n, type: {int: {bits: 8}}}
      - {name: next, type: {unit: message}, condition: "n > 0"}
"""
    tree = decode(fields, b"\x01" * (MAX_DEPTH + 10))
    assert tree.status is NodeStatus.UNDECODABLE
    assert "nesting passed" in tree.detail


# --- guards ----------------------------------------------------------------


def test_confirm_that_holds():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    confirm: "magic == 127"
    fields:
      - {name: magic, type: {int: {bits: 8}}}
""")
    assert Decoder(spec).decode_bytes(b"\x7f").status is NodeStatus.OK


def test_confirm_that_does_not_hold_is_undecodable():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    confirm: "magic == 127"
    fields:
      - {name: magic, type: {int: {bits: 8}}}
""")
    tree = Decoder(spec).decode_bytes(b"\x01")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "did not confirm" in tree.detail


def test_reject_abandons_the_unit():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    reject: "magic == 0"
    fields:
      - {name: magic, type: {int: {bits: 8}}}
""")
    tree = Decoder(spec).decode_bytes(b"\x00")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "rejected the input" in tree.detail


# --- construction ----------------------------------------------------------


def test_decoder_checks_the_spec_by_default():
    """Every guarantee the engine relies on is one check() proves."""
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: a, type: {unit: missing}}
""")
    with pytest.raises(SpecError, match="unknown unit 'missing'"):
        Decoder(spec)


def test_checking_can_be_skipped():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: a, type: {unit: missing}}
""")
    assert Decoder(spec, check=False).spec is spec


def test_warnings_do_not_block_construction():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: a, type: {int: {bits: 8}}}
  orphan:
    fields:
      - {name: b, type: {int: {bits: 8}}}
""")
    assert Decoder(spec) is not None


# --- the real thing --------------------------------------------------------

DNS_SPEC = """
name: dns
version: "1.0"
entry: message
enums:
  opcode: {0: query, 1: iquery}
units:
  message:
    fields:
      - {name: id, type: {int: {bits: 16}}}
      - {name: flags, type: {unit: flags}}
      - {name: qdcount, type: {int: {bits: 16}}}
      - {name: ancount, type: {int: {bits: 16}}}
      - {name: nscount, type: {int: {bits: 16}}}
      - {name: arcount, type: {int: {bits: 16}}}
      - {name: questions, type: {unit: question}, repeat: {count: "qdcount"}}
  flags:
    fields:
      - {name: qr, type: {int: {bits: 1}}}
      - {name: opcode, type: {int: {bits: 4, enum: opcode}}}
      - {name: null, type: {int: {bits: 3}}}
      - {name: null, type: {int: {bits: 8}}}
  question:
    fields:
      - {name: qname, type: {bytes: {size: {terminated: {delimiter: "\\0"}}}}}
      - {name: qtype, type: {int: {bits: 16}}}
      - {name: qclass, type: {int: {bits: 16}}}
"""


def test_the_pressure_tests_dns_query_decodes_whole():
    """The 29-byte query every [verified] claim in DESIGN.md was made against."""
    tree = Decoder(Spec.from_yaml(DNS_SPEC)).decode_bytes(DNS_QUERY)
    assert tree.status is NodeStatus.OK
    assert (tree.off_start, tree.off_end) == (0, len(DNS_QUERY))
    assert tree.find("id").value == 0x1234
    assert tree.find("qdcount").value == 1
    flags = tree.find("flags")
    assert flags.find("qr").value == 0
    assert flags.find("opcode").value == 0
    question = tree.find("questions").children[0]
    assert question.find("qname").value == b"\x07example\x03com"
    assert question.find("qtype").value == 1


def test_every_byte_is_covered_by_a_leaf():
    """The property the emitter will depend on: leaves tile the input."""
    tree = Decoder(Spec.from_yaml(DNS_SPEC)).decode_bytes(DNS_QUERY)
    covered: set[int] = set()
    for leaf in tree.leaves():
        covered.update(range(leaf.off_start, leaf.off_end))
    assert covered == set(range(len(DNS_QUERY)))
