"""Tests for the decode engine."""

from __future__ import annotations

import struct
from typing import Any

import pytest

from kober.cursor import Cursor
from kober.decoder import MAX_DEPTH, MAX_POINTER_HOPS, Decoder
from kober.errors import SpecError
from kober.node import Node, NodeStatus
from kober.spec import Field, Select, Spec

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
    """The property the emitter depends on: every byte covered *at least* once.

    This used to assert that leaves **tile** the input — covered exactly once,
    set equality both ways. `Pointer` retired that: a region decoded in place
    and reached again by reference is cited twice, which `zpf` permits and
    §2 now says so explicitly. What the emitter actually needs, and what the
    coverage guarantee actually is, is coverage without contradiction.
    """
    tree = Decoder(Spec.from_yaml(DNS_SPEC)).decode_bytes(DNS_QUERY)
    covered: set[int] = set()
    for leaf in tree.leaves():
        covered.update(range(leaf.off_start, leaf.off_end))
    assert covered >= set(range(len(DNS_QUERY)))


# --- pointers --------------------------------------------------------------

#: A message whose second field points back at the first: `at` is read from
#: `off`, and the target is the byte at that message-relative offset.
POINTER_FIELDS = """\
      - {name: pad, type: {int: {bits: 8}}}
      - {name: pos, type: {int: {bits: 8}}}
      - {name: seen, type: {pointer: {at: "pos", type: {int: {bits: 8}}}}}
"""


def pointer_tree(data: bytes) -> Node:
    return decode(POINTER_FIELDS, data)


def test_a_pointer_reads_at_the_offset_it_names():
    tree = pointer_tree(b"\xaa\x00\xff")
    assert tree.find("seen").value == 0xAA


def test_a_pointer_does_not_move_the_enclosing_cursor():
    """§2.1: the runtime seeks, the reading position does not move."""
    tree = pointer_tree(b"\xaa\x00\xff")
    assert tree.off_end == 2, "the pointer must consume nothing"


def test_a_pointer_cites_the_region_it_read():
    """One contiguous range — the target, not the bytes naming it."""
    seen = pointer_tree(b"\xaa\x00\xff").find("seen")
    assert (seen.off_start, seen.off_end) == (0, 1)


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("past the end", b"\xaa\x7f"),
        ("forward, not yet decoded", b"\xaa\x05\x00\x00\x00\x00"),
        ("at the pointer itself", b"\xaa\x02"),
    ],
)
def test_an_unreachable_target_is_undecodable_and_never_raises(label: str, data: bytes):
    tree = pointer_tree(data)
    assert tree.status is NodeStatus.UNDECODABLE, label
    assert "outside the bytes already decoded" in (tree.detail or "")


def test_a_pointer_target_that_does_not_decode_is_undecodable_not_truncated():
    """`truncated` is hole-class: it would claim the input had a gap.

    The input arrived intact — the spec aimed at bytes that do not decode as
    what it asked for — so the honest reason is `undecodable`, which owes no
    seam under §5.
    """
    tree = decode(
        """\
      - {name: pad, type: {int: {bits: 8}}}
      - {name: pos, type: {int: {bits: 8}}}
      - {name: seen, type: {pointer: {at: "pos", type: {int: {bits: 32}}}}}
""",
        b"\xaa\x00",
    )
    assert tree.status is NodeStatus.UNDECODABLE
    assert "does not decode" in (tree.detail or "")


def test_a_pointer_chain_resolves_while_it_goes_backwards():
    """Two hops, each landing strictly earlier than the last."""
    tree = decode(
        """\
      - {name: value, type: {int: {bits: 8}}}
      - {name: mid, type: {int: {bits: 8}}}
      - {name: hop, type: {int: {bits: 8}}}
      - {name: second, type: {pointer: {at: "hop", type: {unit: inner}}}}
""",
        b"\xaa\xbb\x01",
        extra_units="""\
  inner:
    fields:
      - {name: again, type: {pointer: {at: "0", type: {int: {bits: 8}}}}}
""",
    )
    assert tree.status is NodeStatus.OK
    assert tree.find("second").find("again").value == 0xAA


def test_a_chain_may_not_hop_sideways():
    """Two hops to the same offset is a hop that did not go back."""
    tree = decode(
        """\
      - {name: value, type: {int: {bits: 8}}}
      - {name: hop, type: {int: {bits: 8}}}
      - {name: second, type: {pointer: {at: "hop", type: {unit: inner}}}}
""",
        b"\xaa\x00",
        extra_units="""\
  inner:
    fields:
      - {name: again, type: {pointer: {at: "0", type: {int: {bits: 8}}}}}
""",
    )
    assert tree.status is NodeStatus.UNDECODABLE


def test_a_self_pointer_terminates_rather_than_looping():
    """It cannot even start: each hop must land strictly earlier than the last."""
    tree = decode(
        """\
      - {name: pos, type: {int: {bits: 8}}}
      - {name: loop, type: {pointer: {at: "pos", type: {unit: inner}}}}
""",
        b"\x00\x00",
        extra_units="""\
  inner:
    fields:
      - {name: again, type: {pointer: {at: "0", type: {int: {bits: 8}}}}}
""",
    )
    assert tree.status is NodeStatus.UNDECODABLE


def test_the_offset_is_relative_to_the_message_not_the_run():
    """A run holds many messages; offset 0 means *this* message's first byte."""
    decoder = Decoder(build(POINTER_FIELDS))
    # Two messages of two bytes each: a pointer consumes nothing, so each
    # message is exactly its `pad` and `pos`.
    cursor = Cursor(b"\xaa\x00" + b"\xbb\x00", 0)
    first = decoder.decode_one(cursor)
    second = decoder.decode_one(cursor)
    assert first.find("seen").value == 0xAA
    assert second.find("seen").value == 0xBB, "the second message read the first's bytes"
    assert (second.find("seen").off_start, second.find("seen").off_end) == (2, 3)


def test_a_decode_does_not_depend_on_what_follows_it():
    """The ceiling is the message's high-water mark, not the run's end."""
    message = b"\xaa\x02"
    results = [
        pointer_tree(message + trailing)
        for trailing in (b"", bytes(80), b"\xaa\x00\xff")
    ]
    assert {(t.status, t.detail) for t in results} == {(results[0].status, results[0].detail)}


def test_a_long_chain_stops_at_the_hop_bound():
    """The bound guards recursion depth, not cycles — those cannot be built.

    Each hop lands one byte earlier, so this chain is legal all the way down
    and would simply be deep. `MAX_POINTER_HOPS` is what stops it.
    """
    tree = decode(
        """\
      - {name: filler, type: {bytes: {size: 24}}}
      - name: start
        type:
          pointer:
            at: "20"
            type: {unit: {name: chain, args: ["19"]}}
""",
        bytes(24),
        extra_units="""\
  chain:
    params: [{name: n, type: int}]
    fields:
      - name: down
        type:
          pointer:
            at: "n"
            type: {unit: {name: chain, args: ["n - 1"]}}
""",
    )
    assert tree.status is NodeStatus.UNDECODABLE
    assert f"passed {MAX_POINTER_HOPS} hops" in (tree.detail or "")


def test_a_cycle_is_refused_structurally_rather_than_merely_bounded():
    """A target that reads on, then points back at itself, is the real cycle.

    Each hop's ceiling is the previous hop's *target*, so the second hop is
    refused for landing no earlier — not caught later by the hop bound. The
    detail is the assertion: `MAX_POINTER_HOPS` never gets involved.
    """
    tree = decode(
        """\
      - {name: pos, type: {int: {bits: 8}}}
      - {name: loop, type: {pointer: {at: "pos", type: {unit: inner}}}}
""",
        b"\x00\x00",
        extra_units="""\
  inner:
    fields:
      - {name: first, type: {int: {bits: 8}}}
      - {name: back, type: {pointer: {at: "0", type: {unit: inner}}}}
""",
    )
    assert tree.status is NodeStatus.UNDECODABLE
    assert "outside the bytes already decoded" in (tree.detail or "")
    assert "hops" not in (tree.detail or "")


# --- builtins --------------------------------------------------------------

CHUNK_FIELDS = """\
      - {name: size, type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}}
      - {name: body, type: {bytes: {size: {expr: "to_int(size, 16)"}}}}
"""


def test_a_builtin_sizes_a_field_from_text():
    """§13.2's case: a chunk header is a hexadecimal string, not an integer."""
    tree = decode(CHUNK_FIELDS, b"1a\r\n" + b"x" * 0x1A)
    assert tree.find("size").value == "1a"
    assert tree.find("body").value == b"x" * 0x1A
    assert tree.status is NodeStatus.OK


def test_text_that_is_not_a_number_is_undecodable_not_a_raise():
    """Partial at the value level, total at the decode level.

    The same path a size expression that cannot be evaluated already takes —
    the builtin adds no new failure mode, which is the whole of what makes
    admitting it cheap.
    """
    tree = decode(CHUNK_FIELDS, b"chunked\r\nbody")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "cannot read" in (tree.detail or "")


def test_a_builtin_makes_a_case_insensitive_match_expressible():
    """The other half of §13.2: `Transfer-Encoding` values vary in case."""
    fields = """\
      - {name: value, type: {string: {size: 7}}}
      - name: body
        type: {bytes: {size: {remaining: true}}}
        condition: "lower(value) == 'chunked'"
"""
    for text in (b"chunked", b"CHUNKED", b"Chunked"):
        tree = decode(fields, text + b"rest")
        assert tree.find("body") is not None, text
        assert tree.find("body").value == b"rest"


class _Unimplemented:
    """A field type the engine does not know, for the fall-through test."""


def test_a_field_type_the_engine_does_not_implement_is_undecodable_not_a_raise():
    """The model may gain a type before the engine does; a decode still cannot raise.

    This is not hypothetical: `select` was exactly that between the stage that
    put it in the model and the stage that taught the engine to run it. What the
    checker cannot say — the spec is well formed and valid — the decoder has to,
    and the way it says it is an honest `undecodable` region rather than an
    `AttributeError` out of a decode that promises never to raise.
    """
    spec = build('      - {name: a, type: {int: {bits: 8}}}\n')
    item = spec.unit("message").fields[0]
    object.__setattr__(item, "type", _Unimplemented())
    tree = Decoder(spec, check=False).decode_bytes(b"\x01\x02")
    assert tree.status is NodeStatus.UNDECODABLE
    assert "not implemented" in tree.detail


# --- select ----------------------------------------------------------------


SELECT_ITEM = """\
  item:
    fields:
      - {name: tag, type: {int: {bits: 8}}}
      - {name: body, type: {int: {bits: 8}}}
"""


def select_fields(
    where: str = "items.tag == 7",
    value: str = "items.body",
    default: str = "-1",
    extra: str = "",
) -> str:
    return f"""\
      - {{name: n, type: {{int: {{bits: 8}}}}}}
      - {{name: items, type: {{unit: item}}, repeat: {{count: "n"}}}}
      - name: picked
        type:
          select: {{from: items, where: "{where}", value: "{value}", default: "{default}"}}
{extra}"""


def select(data: bytes, **kw: str) -> Node:
    return decode(select_fields(**kw), data, extra_units=SELECT_ITEM)


def test_select_projects_the_first_match():
    """Two elements match; the *first* wins, which is the documented rule."""
    tree = select(bytes([3, 1, 10, 7, 20, 7, 30]))
    assert tree.find("picked").value == 20


def test_select_falls_back_to_its_default():
    tree = select(bytes([2, 1, 10, 2, 20]))
    assert tree.find("picked").value == -1


def test_select_cites_the_element_it_selected():
    """Q4: the honest evidence is *that* element, not the whole repetition."""
    tree = select(bytes([3, 1, 10, 7, 20, 9, 30]))
    picked = tree.find("picked")
    matched = tree.find("items").children[1]
    assert (picked.off_start, picked.off_end) == (matched.off_start, matched.off_end)
    # And narrower than the repetition, which is the point of the rule.
    items = tree.find("items")
    assert (picked.off_start, picked.off_end) != (items.off_start, items.off_end)


def test_a_default_cites_nothing():
    """Nothing matched, so there is nothing to point at."""
    picked = select(bytes([2, 1, 10, 2, 20])).find("picked")
    assert picked.off_start == picked.off_end


def test_select_over_an_empty_repetition_takes_the_default():
    tree = select(bytes([0]))
    assert tree.find("picked").value == -1
    assert tree.status is NodeStatus.OK


def test_select_reads_no_input_and_moves_no_position():
    """§2.1, asserted where the claim is made rather than inferred from coverage.

    A select that *consumed* would leave coverage whole — the byte it took
    would be covered by whatever followed — so no coverage-shaped invariant
    can catch it. This compares the cursor either side, which does.
    """
    spec = build(select_fields(), extra_units=SELECT_ITEM)
    decoder = Decoder(spec)
    seen: list[tuple[int, int]] = []
    original = Decoder._select

    def watched(
        self: Decoder, item: Field, kind: Select, frame: Any,
        cursor: Cursor, mark: int,
    ) -> Node:
        before = cursor.tell()
        node = original(self, item, kind, frame, cursor, mark)
        seen.append((before, cursor.tell()))
        return node

    Decoder._select = watched
    try:
        for data in (bytes([3, 1, 10, 7, 20, 9, 30]), bytes([2, 1, 10, 2, 20]), bytes([0])):
            cursor = Cursor(data)
            decoder.decode_one(cursor)
    finally:
        Decoder._select = original

    assert len(seen) == 3, "the select did not run"
    assert all(before == after for before, after in seen), seen


def test_the_no_movement_assertion_catches_a_select_that_consumes():
    """The check above must fail against a consuming implementation, or it is worthless."""
    spec = build(select_fields(), extra_units=SELECT_ITEM)
    decoder = Decoder(spec)
    original = Decoder._select

    def greedy(
        self: Decoder, item: Field, kind: Select, frame: Any,
        cursor: Cursor, mark: int,
    ) -> Node:
        node = original(self, item, kind, frame, cursor, mark)
        if cursor.remaining_bytes() > 0:
            cursor.read_bytes(1)
        return node

    seen: list[tuple[int, int]] = []

    def watched(
        self: Decoder, item: Field, kind: Select, frame: Any,
        cursor: Cursor, mark: int,
    ) -> Node:
        before = cursor.tell()
        node = greedy(self, item, kind, frame, cursor, mark)
        seen.append((before, cursor.tell()))
        return node

    Decoder._select = watched
    try:
        cursor = Cursor(bytes([1, 7, 20, 99]))
        decoder.decode_one(cursor)
    finally:
        Decoder._select = original

    assert seen and any(before != after for before, after in seen)


def test_an_unevaluable_predicate_is_undecodable_not_a_silent_default():
    """Reporting the author's default as though it were read is the failure to avoid."""
    tree = decode(
        """\
      - {name: n, type: {int: {bits: 8}}}
      - {name: items, type: {unit: item}, repeat: {count: "n"}}
      - name: picked
        type:
          select:
            from: items
            where: "to_int(items.text) > 100"
            value: "to_int(items.text)"
            default: "0"
""",
        bytes([1]) + b"zz",
        extra_units="""\
  item:
    fields:
      - {name: text, type: {string: {size: 2}}}
""",
    )
    assert tree.status is NodeStatus.UNDECODABLE
    picked = tree.find("picked")
    # The node is kept and says what happened, as any failed field's is. What
    # matters is that it carries no value: a `0` here would be the author's
    # default wearing the input's clothes.
    assert picked.status is NodeStatus.UNDECODABLE
    assert picked.value is None
    assert "to_int()" in tree.detail


def test_an_unevaluable_projection_is_undecodable_too():
    tree = decode(
        """\
      - {name: n, type: {int: {bits: 8}}}
      - {name: items, type: {unit: item}, repeat: {count: "n"}}
      - name: picked
        type:
          select:
            from: items
            where: "items.text == 'zz'"
            value: "to_int(items.text)"
            default: "0"
""",
        bytes([1]) + b"zz",
        extra_units="""\
  item:
    fields:
      - {name: text, type: {string: {size: 2}}}
""",
    )
    assert tree.status is NodeStatus.UNDECODABLE


def test_the_element_binding_is_put_back_after_a_select():
    """A later field must see the repetition, not whichever element was tested."""
    tree = select(
        bytes([2, 1, 10, 7, 20]),
        extra='      - {name: after, type: {computed: "picked + 1"}}\n',
    )
    assert tree.find("picked").value == 20
    assert tree.find("after").value == 21
    assert tree.find("items").is_repetition


def test_a_failed_select_leaves_the_repetition_bound():
    """Even when an expression raises part-way, the name is restored."""
    spec = build(
        """\
      - {name: n, type: {int: {bits: 8}}}
      - {name: items, type: {unit: item}, repeat: {count: "n"}}
      - name: picked
        type:
          select:
            from: items
            where: "to_int(items.text) > 0"
            value: "1"
            default: "0"
""",
        extra_units="""\
  item:
    fields:
      - {name: text, type: {string: {size: 2}}}
""",
    )
    tree = Decoder(spec).decode_bytes(bytes([1]) + b"zz")
    assert tree.status is NodeStatus.UNDECODABLE
    items = tree.find("items")
    assert items is not None and items.is_repetition


def test_a_select_result_can_size_a_later_field():
    """The construct earns its place by framing what comes after it."""
    tree = decode(
        """\
      - {name: n, type: {int: {bits: 8}}}
      - {name: items, type: {unit: item}, repeat: {count: "n"}}
      - name: length
        type:
          select: {from: items, where: "items.tag == 7", value: "items.body", default: "0"}
      - {name: payload, type: {bytes: {size: {expr: "length"}}}}
""",
        bytes([2, 1, 10, 7, 3]) + b"abcdef",
        extra_units=SELECT_ITEM,
    )
    assert tree.find("length").value == 3
    assert tree.find("payload").value == b"abc"


def test_a_boolean_select_is_how_any_is_spelled():
    """`value: "true"` with `default: "false"` is the `any` the language has no word for."""
    for data, expected in ((bytes([2, 1, 10, 7, 20]), True), (bytes([1, 1, 10]), False)):
        tree = select(data, value="true", default="false")
        assert tree.find("picked").value is expected


# --- bounded terminator ----------------------------------------------------


def bounded(data: bytes, *, required: str = "false") -> Node:
    """Decode a header-shaped pair: a bounded name, then the rest of the line."""
    return decode(
        f"""\
      - name: name
        type:
          string:
            size: {{terminated: {{delimiter: ":", within: "\\r\\n", required: {required}}}}}
      - name: value
        type: {{string: {{size: {{terminated: {{delimiter: "\\r\\n"}}}}}}}}
""",
        data,
    )


def test_a_bound_splits_a_line_into_two_fields():
    tree = bounded(b"Content-Length: 68\r\n")
    assert tree.find("name").value == "Content-Length"
    assert tree.find("value").value == " 68"


def test_a_blank_line_takes_nothing_and_needs_no_special_case():
    """The case the whole construct was chosen for."""
    tree = bounded(b"\r\n")
    assert tree.find("name").value == ""
    assert tree.find("value").value == ""
    assert tree.off_end == 2


def test_a_delimiter_past_the_bound_reads_as_absent():
    """It belongs to the *next* line, and an optional terminator takes nothing."""
    tree = bounded(b"no-colon-here\r\nnext: value\r\n")
    assert tree.find("name").value == ""
    assert tree.find("value").value == "no-colon-here"


def test_an_optional_bounded_terminator_reads_nothing_when_absent():
    """Not the rest of the run, and not up to the bound: nothing.

    The bound limits the search; it is never a second terminator. Reading to it
    would be reading under a delimiter the spec did not find.
    """
    tree = bounded(b"no-colon-here\r\ntail")
    name = tree.find("name")
    assert name.value == ""
    assert name.off_start == name.off_end


def test_an_unbounded_optional_terminator_still_reads_the_rest():
    """The other half of the contrast above, unchanged by this stage."""
    tree = decode(
        '      - {name: a, type: {string: {size: {terminated: '
        '{delimiter: ":", required: false}}}}}\n',
        b"no-colon-here",
    )
    assert tree.find("a").value == "no-colon-here"


def test_a_required_bounded_terminator_is_truncated_when_absent():
    """`required` still decides; the bound only changes what "absent" means."""
    tree = bounded(b"no-colon-here\r\n", required="true")
    assert tree.status is NodeStatus.TRUNCATED
    assert "before b'\\r\\n'" in tree.find("name").detail


def test_a_bounded_terminator_with_neither_present_is_truncated_when_required():
    tree = bounded(b"nothing at all", required="true")
    assert tree.status is NodeStatus.TRUNCATED


def test_a_bound_that_is_absent_lets_the_search_run_on():
    """Nothing bounds it, so it finds the delimiter as an unbounded read would."""
    tree = decode(
        '      - {name: a, type: {string: {size: {terminated: '
        '{delimiter: ":", within: "\\r\\n"}}}}}\n',
        b"name: value with no line ending",
    )
    assert tree.find("a").value == "name"
