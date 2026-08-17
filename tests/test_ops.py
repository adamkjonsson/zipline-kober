"""The neutral plan must describe the format and nothing about Python.

:mod:`kober.ops` is the seam a second backend attaches to, so these tests are
as much about what a plan does *not* carry as what it does: no identifiers
mapped for a target, no annotations, no source text. What it owes is the shape
of the format — which units exist, what each field can hold, whether it repeats,
and when it is there at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kober.errors import SpecError
from kober.ops import Kind, Plan, ValueType
from kober.spec import Spec

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def load(name: str) -> Spec:
    return Spec.from_file(EXAMPLES / name)


def dns() -> Plan:
    return Plan.from_spec(load("dns.yaml"))


# --- what a plan is made of ------------------------------------------------


def test_a_plan_carries_the_specs_own_identity():
    plan = dns()
    assert (plan.name, plan.version, plan.entry) == ("dns", "1.0", "message")
    assert plan.doc == "DNS messages, header and question section."


def test_units_keep_the_order_the_spec_declares_them_in():
    """A generated module should read like the spec it came from."""
    assert [obj.unit for obj in dns().objects] == [
        "message",
        "flags",
        "question",
        "name",
        "label",
    ]


def test_a_field_carries_what_the_wire_says_about_it():
    (field,) = [item for item in dns().object("label").fields if item.name == "length"]
    assert field.types == (ValueType(kind=Kind.INT, bits=8, signed=False, endian="big"),)


def test_a_unit_reference_names_the_unit_rather_than_a_class():
    """The spec's own name, unmapped: a Python class name would be the wrong layer."""
    (field,) = [item for item in dns().object("message").fields if item.name == "flags"]
    assert field.types == (ValueType(kind=Kind.OBJECT, unit="flags"),)


def test_an_enums_name_travels_with_the_value_it_labels():
    (field,) = [item for item in dns().object("flags").fields if item.name == "opcode"]
    assert field.types[0].labels == "opcode"
    assert dns().enums["opcode"].members[0] == "query"


def test_byte_order_is_a_string_rather_than_a_spec_enum():
    """Generated code must never need the spec model in order to read an integer."""
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: little, type: {int: {bits: 16, endian: little}}}
    """)
    (field,) = Plan.from_spec(spec).object("m").fields
    assert field.types[0].endian == "little"


def test_a_repeated_field_says_so():
    (field,) = [item for item in dns().object("message").fields if item.name == "questions"]
    assert field.repeated
    assert not field.optional


def test_a_conditional_field_carries_the_condition_not_a_flag():
    """A target may want to say *when* a field is present, not only that it may be absent."""
    (field,) = [
        item for item in dns().object("message").fields if item.name == "resource_records"
    ]
    assert field.optional
    assert field.condition is not None


def test_an_anonymous_field_is_kept():
    """Only a target decides that a nameless field cannot be named; it is still read."""
    names = [item.name for item in dns().object("flags").fields]
    assert names == ["qr", "opcode", "aa", "tc", "rd", "ra", None, "rcode"]


def test_the_specs_documentation_travels_verbatim():
    (field,) = [item for item in dns().object("message").fields if item.name == "id"]
    assert field.doc == "Copied into the reply; matches responses to requests."
    assert dns().object("flags").doc == "The 16-bit flags word, MSB first."


# --- the harder shapes -----------------------------------------------------


SWITCHED = """
name: t
version: "1"
entry: m
units:
  m:
    fields:
      - {name: kind, type: {int: {bits: 8}}}
      - name: body
        type:
          switch:
            on: kind
            cases:
              1: {int: {bits: 16}}
              2: {bytes: {size: {fixed: 4}}}
              3: {int: {bits: 16}}
            default: {unit: other}
  other:
    fields:
      - {name: rest, type: {bytes: {size: {remaining: true}}}}
"""


def test_a_switch_carries_every_type_it_can_decode_as():
    (_, body) = Plan.from_spec(Spec.from_yaml(SWITCHED)).object("m").fields
    assert [value.kind for value in body.types] == [Kind.INT, Kind.BYTES, Kind.OBJECT]


def test_a_switch_says_nothing_twice():
    """Two cases with one type are one alternative, in case order."""
    (_, body) = Plan.from_spec(Spec.from_yaml(SWITCHED)).object("m").fields
    assert body.types[0] == ValueType(kind=Kind.INT, bits=16)


def test_a_unit_reachable_only_through_a_switch_is_still_planned():
    assert "other" in [obj.unit for obj in Plan.from_spec(Spec.from_yaml(SWITCHED)).objects]


def test_a_computed_fields_kind_is_inferred_from_its_expression():
    """The one type a spec does not state, and the checker's scope is what answers it."""
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: words, type: {int: {bits: 8}}}
              - {name: octets, type: {computed: "words * 4"}}
              - {name: empty, type: {computed: "words == 0"}}
    """)
    fields = {item.name: item for item in Plan.from_spec(spec).object("m").fields}
    assert fields["octets"].types == (ValueType(kind=Kind.INT),)
    assert fields["empty"].types == (ValueType(kind=Kind.BOOL),)


def test_a_computed_integer_has_no_width():
    """Nothing declares one, and a backend that invented one would be guessing."""
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: doubled, type: {computed: "n * 2"}}
    """)
    fields = {item.name: item for item in Plan.from_spec(spec).object("m").fields}
    assert fields["doubled"].types[0].bits is None


def test_a_unit_nothing_references_is_left_out():
    """Dead code in any target, and the checker already warns that it is there."""
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: a, type: {int: {bits: 8}}}
          orphan:
            fields:
              - {name: b, type: {int: {bits: 8}}}
    """)
    assert [obj.unit for obj in Plan.from_spec(spec).objects] == ["m"]


def test_a_recursive_unit_does_not_loop():
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: more, type: {unit: m}, condition: "n > 0"}
    """)
    assert [obj.unit for obj in Plan.from_spec(spec).objects] == ["m"]


# --- refusing what it cannot describe --------------------------------------


def test_a_spec_with_errors_is_refused():
    """Errors move to build time; that is half of what compiling buys."""
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: missing
        units:
          m:
            fields:
              - {name: a, type: {int: {bits: 8}}}
    """)
    with pytest.raises(SpecError, match="entry names unit"):
        Plan.from_spec(spec)


def test_checking_can_be_skipped_by_a_caller_that_already_did_it():
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: a, type: {int: {bits: 8}}}
    """)
    assert Plan.from_spec(spec, check=False).objects


def test_asking_for_a_unit_that_is_not_there_says_what_is():
    with pytest.raises(KeyError, match="label"):
        dns().object("nonesuch")
