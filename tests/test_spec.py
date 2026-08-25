"""Tests for the spec model's own well-formedness rules."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kober.errors import SpecError
from kober.expr import ExprType, parse
from kober.spec import (
    MAX_INT_BITS,
    BytesType,
    Emit,
    Endian,
    EnumDef,
    Field,
    Fixed,
    InputShape,
    IntType,
    Param,
    Pointer,
    Remaining,
    Spec,
    StringType,
    Switch,
    Terminated,
    Unit,
    UnitRef,
)


def simple_spec(**overrides: object) -> Spec:
    unit = Unit(name="message", fields=[Field(name="id", type=IntType(bits=16))])
    kwargs: dict[str, object] = {
        "name": "dns",
        "version": "1.0",
        "entry": "message",
        "units": {"message": unit},
    }
    kwargs.update(overrides)
    return Spec(**kwargs)  # type: ignore[arg-type]


# --- defaults match the design --------------------------------------------


def test_int_defaults_to_unsigned_network_order():
    kind = IntType(bits=16)
    assert kind.signed is False
    assert kind.endian is Endian.BIG
    assert kind.enum is None


def test_spec_defaults_to_either_shape():
    assert simple_spec().input is InputShape.EITHER


def test_string_defaults_to_utf8():
    assert StringType(size=Remaining()).encoding == "utf-8"


def test_terminated_defaults_to_consuming_and_required():
    term = Terminated(delimiter=b"\r\n")
    assert term.consume is True
    assert term.required is True


# --- local invariants ------------------------------------------------------


@pytest.mark.parametrize("bits", [0, -1, MAX_INT_BITS + 1])
def test_int_width_out_of_range(bits: int):
    with pytest.raises(SpecError, match="integer width"):
        IntType(bits=bits)


@pytest.mark.parametrize("bits", [1, 4, 16, MAX_INT_BITS])
def test_int_width_in_range(bits: int):
    assert IntType(bits=bits).bits == bits


def test_sub_byte_widths_are_allowed():
    """Bitfields are the reason field granularity is worth having."""
    assert IntType(bits=1).bits == 1


def test_fixed_size_rejects_negative():
    with pytest.raises(SpecError, match="must not be negative"):
        Fixed(count=-1)


def test_fixed_size_allows_zero():
    assert Fixed(count=0).count == 0


def test_terminated_rejects_empty_delimiter():
    with pytest.raises(SpecError, match="must not be empty"):
        Terminated(delimiter=b"")


def test_switch_rejects_no_cases():
    with pytest.raises(SpecError, match="at least one case"):
        Switch(on=parse("kind"), cases={})


def test_enum_rejects_no_members():
    with pytest.raises(SpecError, match="has no members"):
        EnumDef(name="opcode", members={})


def test_blank_names_are_refused():
    with pytest.raises(SpecError, match="field name must not be blank"):
        Field(name="  ", type=IntType(bits=8))
    with pytest.raises(SpecError, match="unit name must not be blank"):
        Unit(name="", fields=[])
    with pytest.raises(SpecError, match="parameter name must not be blank"):
        Param(name="", type=ExprType.INT)


def test_anonymous_field_is_allowed():
    """None is a padding or reserved region, not a missing name."""
    assert Field(name=None, type=IntType(bits=2)).name is None


def test_blank_encoding_is_refused():
    with pytest.raises(SpecError, match="must not be blank"):
        StringType(size=Remaining(), encoding=" ")


def test_duplicate_field_names_are_refused():
    with pytest.raises(SpecError, match="duplicate field names: id"):
        Unit(
            name="message",
            fields=[
                Field(name="id", type=IntType(bits=16)),
                Field(name="id", type=IntType(bits=8)),
            ],
        )


def test_duplicate_anonymous_fields_are_fine():
    unit = Unit(
        name="message",
        fields=[Field(name=None, type=IntType(bits=2)), Field(name=None, type=IntType(bits=2))],
    )
    assert len(unit.fields) == 2


def test_spec_rejects_blank_name_and_version():
    with pytest.raises(SpecError, match="spec name must not be blank"):
        simple_spec(name=" ")
    with pytest.raises(SpecError, match="spec version must not be blank"):
        simple_spec(version="")


def test_spec_rejects_no_units():
    with pytest.raises(SpecError, match="declares no units"):
        simple_spec(units={})


def test_spec_rejects_key_name_mismatch():
    unit = Unit(name="message", fields=[])
    with pytest.raises(SpecError, match="does not match its name: header"):
        simple_spec(units={"header": unit})


# --- normalization and immutability ---------------------------------------


def test_sequences_become_tuples():
    unit = Unit(name="u", fields=[Field(name="a", type=IntType(bits=8))], params=[])
    assert isinstance(unit.fields, tuple)
    assert isinstance(unit.params, tuple)
    assert isinstance(UnitRef(unit="u", args=[parse("1")]).args, tuple)


def test_mappings_are_read_only_copies():
    units = {"message": Unit(name="message", fields=[])}
    spec = simple_spec(units=units)
    units["sneak"] = Unit(name="sneak", fields=[])
    assert "sneak" not in spec.units
    with pytest.raises(TypeError):
        spec.units["other"] = Unit(name="other", fields=[])  # type: ignore[index]


def test_frozen_attributes_cannot_be_rebound():
    with pytest.raises(AttributeError):
        IntType(bits=8).bits = 16  # type: ignore[misc]


# --- lookups ---------------------------------------------------------------


def test_unit_lookup_returns_the_unit():
    spec = simple_spec()
    assert spec.unit("message").name == "message"


def test_unit_lookup_names_what_it_knows():
    with pytest.raises(SpecError, match="known units: message"):
        simple_spec().unit("nope")


def test_field_lookup():
    unit = Unit(name="u", fields=[Field(name="a", type=IntType(bits=8))])
    assert unit.field("a") is not None
    assert unit.field("missing") is None


# --- the model carries the design's vocabulary ----------------------------


def test_emit_has_three_granularities():
    assert {member.value for member in Emit} == {"message", "field", "none"}


def test_input_shape_has_three_members():
    assert {member.value for member in InputShape} == {"stream", "datagram", "either"}


def test_a_realistic_spec_assembles():
    spec = Spec(
        name="dns",
        version="1.0",
        entry="message",
        input=InputShape.EITHER,
        enums={"opcode": EnumDef(name="opcode", members={0: "query", 1: "iquery"})},
        units={
            "message": Unit(
                name="message",
                fields=[
                    Field(name="id", type=IntType(bits=16), doc="Matches replies."),
                    Field(name="flags", type=UnitRef(unit="flags")),
                    Field(name="qdcount", type=IntType(bits=16)),
                    Field(
                        name="body",
                        type=BytesType(size=Fixed(count=4)),
                        condition=parse("qdcount > 0"),
                    ),
                ],
            ),
            "flags": Unit(
                name="flags",
                emit=Emit.FIELD,
                fields=[
                    Field(name="qr", type=IntType(bits=1)),
                    Field(name="opcode", type=IntType(bits=4, enum="opcode")),
                    Field(name=None, type=IntType(bits=2)),
                ],
            ),
        },
    )
    assert spec.unit("flags").emit is Emit.FIELD
    assert spec.unit("message").field("body").condition is not None


def test_pointer_is_a_field_type():
    kind = Pointer(at=parse("n"), type=IntType(bits=8))
    assert kind.type == IntType(bits=8)
    with pytest.raises(FrozenInstanceError):
        kind.at = parse("0")  # type: ignore[misc]


def test_pointer_nests_a_whole_type():
    """The target is any field type, a unit included — §3.2."""
    kind = Pointer(at=parse("0"), type=UnitRef(unit="name"))
    assert kind.type == UnitRef(unit="name")
