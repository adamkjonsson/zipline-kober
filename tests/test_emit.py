"""Tests for turning a decode tree into records."""

from __future__ import annotations

import struct

import pytest

from kober.decoder import Decoder
from kober.emit import (
    TEXT_CONTENT_TYPE,
    Emission,
    field_path,
    normalize_int,
    plan,
    prim_token,
)
from kober.spec import Emit, Spec

DNS_QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

DNS_SPEC = """
name: dns
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: id, type: {int: {bits: 16}}}
      - {name: flags, type: {unit: flags}}
      - {name: qdcount, type: {int: {bits: 16}}}
      - {name: ancount, type: {int: {bits: 16}}}
      - {name: nscount, type: {int: {bits: 16}}}
      - {name: arcount, type: {int: {bits: 16}}}
      - {name: qname, type: {bytes: {size: {terminated: {delimiter: "\\0"}}}}}
      - {name: qtype, type: {int: {bits: 16}}}
      - {name: qclass, type: {int: {bits: 16}}}
  flags:
    fields:
      - {name: qr, type: {int: {bits: 1}}}
      - {name: opcode, type: {int: {bits: 4}}}
      - {name: null, type: {int: {bits: 3}}}
      - {name: null, type: {int: {bits: 8}}}
"""


def dns_plan(emit: Emit = Emit.FIELD):
    spec = Spec.from_yaml(DNS_SPEC)
    tree = Decoder(spec).decode_bytes(DNS_QUERY)
    return plan(spec, tree, DNS_QUERY, emit=emit)


# --- the prim: vocabulary is closed ---------------------------------------


@pytest.mark.parametrize(
    ("bits", "signed", "expected"),
    [
        (8, False, "u8"),
        (16, False, "u16"),
        (32, False, "u32"),
        (64, False, "u64"),
        (8, True, "i8"),
        (16, True, "i16"),
    ],
)
def test_exact_widths_get_their_own_token(bits: int, signed: bool, expected: str):
    assert prim_token(bits, signed) == expected


@pytest.mark.parametrize(
    ("bits", "expected"),
    [(1, "u8"), (4, "u8"), (7, "u8"), (12, "u16"), (24, "u32"), (48, "u64")],
)
def test_widths_without_a_token_widen_to_the_smallest_that_holds_them(
    bits: int, expected: str
):
    """Q5: prim: stops at 8/16/32/64, and a u4 or u24 has to go somewhere."""
    assert prim_token(bits, False) == expected


def test_a_width_wider_than_the_vocabulary_is_refused():
    with pytest.raises(ValueError, match="no prim: token"):
        prim_token(65, False)


def test_normalization_is_little_endian():
    """prim: is little-endian by definition; the wire was big-endian."""
    assert normalize_int(0x1234, 16, False) == b"\x34\x12"


def test_normalization_widens_with_the_token():
    assert normalize_int(5, 4, False) == b"\x05"
    assert normalize_int(5, 24, False) == b"\x05\x00\x00\x00"


def test_normalization_of_negatives():
    assert normalize_int(-1, 16, True) == b"\xff\xff"
    assert normalize_int(-1, 4, True) == b"\xff"


# --- the field path, formatted in one place -------------------------------


def test_field_path():
    assert field_path(["dns", "flags", "qr"]) == "dns.flags.qr"


def test_anonymous_fields_keep_their_place_in_a_path():
    assert field_path(["dns", None, "x"]) == "dns._.x"


# --- message granularity ---------------------------------------------------


def test_message_granularity_is_one_record():
    emissions, unclaimed = dns_plan(Emit.MESSAGE)
    assert len(emissions) == 1
    assert unclaimed == []
    record = emissions[0]
    assert record.content_type == "dec:dns-message"
    assert record.payload == DNS_QUERY
    assert (record.off_start, record.off_end) == (0, len(DNS_QUERY))


def test_message_granularity_carries_no_comment():
    emissions, _ = dns_plan(Emit.MESSAGE)
    assert emissions[0].comment is None


# --- field granularity -----------------------------------------------------


def test_field_granularity_names_every_record():
    emissions, _ = dns_plan(Emit.FIELD)
    assert all(record.comment for record in emissions)


def test_the_two_identical_flag_values_are_distinguishable():
    """The exact failure DESIGN.md §4.1 called 'correct and useless'."""
    emissions, _ = dns_plan(Emit.FIELD)
    zeros = [r for r in emissions if r.payload == b"\x00" and r.content_type == "prim:u8"]
    comments = {r.comment for r in zeros}
    assert "dns.flags.qr" in comments
    assert "dns.flags.opcode" in comments


def test_sub_byte_fields_overlap_the_same_byte():
    emissions, _ = dns_plan(Emit.FIELD)
    flags = [r for r in emissions if r.comment.startswith("dns.flags.")]
    assert len(flags) == 4
    assert all(r.off_start == 2 for r in flags[:3])


def test_integers_are_normalized_and_labelled():
    emissions, _ = dns_plan(Emit.FIELD)
    ident = next(r for r in emissions if r.comment == "dns.id")
    assert ident.content_type == "prim:u16"
    assert ident.payload == b"\x34\x12"
    assert (ident.off_start, ident.off_end) == (0, 2)


def test_bytes_fields_use_prim_bytes():
    emissions, _ = dns_plan(Emit.FIELD)
    name = next(r for r in emissions if r.comment == "dns.qname")
    assert name.content_type == "prim:bytes"
    assert name.payload == b"\x07example\x03com"


def test_strings_are_labelled_as_text():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: s, type: {string: {size: 2}}}
""")
    tree = Decoder(spec).decode_bytes(b"hi")
    emissions, _ = plan(spec, tree, b"hi", emit=Emit.FIELD)
    assert emissions[0].content_type == TEXT_CONTENT_TYPE
    assert emissions[0].payload == b"hi"


# --- emit: none ------------------------------------------------------------


def test_emit_none_claims_nothing_and_says_skipped():
    """§2 wants `skipped` said out loud, not left to auto-fill."""
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: a, type: {int: {bits: 8}}}
      - {name: pad, type: {bytes: {size: 2}}, emit: none}
      - {name: b, type: {int: {bits: 8}}}
""")
    tree = Decoder(spec).decode_bytes(b"\x01xy\x02")
    emissions, unclaimed = plan(spec, tree, b"\x01xy\x02", emit=Emit.FIELD)
    assert [r.comment for r in emissions] == ["t.a", "t.b"]
    assert [(u.off_start, u.off_end, u.reason) for u in unclaimed] == [(1, 3, "skipped")]


def test_granularity_resolves_field_over_unit_over_decoder():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: h, type: {unit: header}}
  header:
    emit: none
    fields:
      - {name: x, type: {int: {bits: 8}}}
      - {name: y, type: {int: {bits: 8}}, emit: field}
""")
    tree = Decoder(spec).decode_bytes(b"\x01\x02")
    emissions, unclaimed = plan(spec, tree, b"\x01\x02", emit=Emit.FIELD)
    # The unit says none; the field's own setting wins for y.
    assert [r.comment for r in emissions] == ["t.h.y"]
    assert [(u.off_start, u.off_end) for u in unclaimed] == [(0, 1)]


# --- computed cites its inputs ---------------------------------------------


def test_computed_cites_the_fields_it_read():
    """§3.2: it decodes nothing, so an empty span would say nothing."""
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: words, type: {int: {bits: 8}}}
      - {name: octets, type: {computed: "words * 4"}}
""")
    data = b"\x02"
    tree = Decoder(spec).decode_bytes(data)
    emissions, _ = plan(spec, tree, data, emit=Emit.FIELD)
    computed = next(r for r in emissions if r.comment == "t.octets")
    assert (computed.off_start, computed.off_end) == (0, 1)
    assert computed.payload == b"\x08"


# --- failures are named ----------------------------------------------------


def test_the_tail_after_a_truncation_is_left_to_the_driver():
    """Only the driver knows whether another message follows in the run."""
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: a, type: {int: {bits: 16}}}
      - {name: b, type: {int: {bits: 32}}}
""")
    data = b"\x00\x01\x00"
    tree = Decoder(spec).decode_bytes(data)
    emissions, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
    # What was decoded is claimed; the rest is beyond the tree.
    assert [r.comment for r in emissions] == ["t.a"]
    assert unclaimed == []
    assert tree.off_end == 2
    assert tree.status.value == "truncated", "the reason the driver will use"


def test_a_failure_does_not_reclaim_what_was_already_cited():
    """A unit that failed halfway still decoded — and cited — what came first."""
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: kind, type: {int: {bits: 8}}}
      - name: body
        type:
          switch: {on: "kind", cases: {1: {int: {bits: 8}}}}
""")
    data = b"\x09\x09"
    tree = Decoder(spec).decode_bytes(data)
    emissions, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
    assert [(r.off_start, r.off_end) for r in emissions] == [(0, 1)]
    assert unclaimed == [], "byte 0 is cited, so it must not also be undecoded"
    assert tree.status.value == "undecodable"


def test_a_hole_inside_a_failed_unit_takes_the_failure_reason():
    """An uncovered run gets the innermost failing node's reason, not `skipped`."""
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: a, type: {int: {bits: 8}}, emit: none}
      - {name: b, type: {int: {bits: 8}}}
""")
    data = b"\x01\x02"
    tree = Decoder(spec).decode_bytes(data)
    _, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
    assert [(u.off_start, u.off_end, u.reason) for u in unclaimed] == [(0, 1, "skipped")]


def test_adjacent_regions_with_one_reason_merge():
    spec = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: a, type: {bytes: {size: 1}}, emit: none}
      - {name: b, type: {bytes: {size: 1}}, emit: none}
""")
    data = b"xy"
    tree = Decoder(spec).decode_bytes(data)
    _, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
    assert [(u.off_start, u.off_end) for u in unclaimed] == [(0, 2)]


# --- the property the coverage guarantee needs ----------------------------


def test_records_and_unclaimed_together_cover_the_tree():
    """Every byte cited or named, which is what §2 requires."""
    emissions, unclaimed = dns_plan(Emit.FIELD)
    covered: set[int] = set()
    for record in emissions:
        covered.update(range(record.off_start, record.off_end))
    for region in unclaimed:
        covered.update(range(region.off_start, region.off_end))
    assert covered == set(range(len(DNS_QUERY)))


def test_no_emission_is_both_cited_and_unclaimed():
    """The rule the coverage checker actually enforces."""
    emissions, unclaimed = dns_plan(Emit.FIELD)
    cited: set[int] = set()
    for record in emissions:
        cited.update(range(record.off_start, record.off_end))
    named: set[int] = set()
    for region in unclaimed:
        named.update(range(region.off_start, region.off_end))
    assert not (cited & named)


def test_emission_is_frozen():
    record = Emission(b"", "prim:u8", 0, 1)
    with pytest.raises(AttributeError):
        record.payload = b"x"  # type: ignore[misc]
