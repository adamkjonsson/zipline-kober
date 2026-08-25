"""Tests for building a spec from a mapping, JSON, or YAML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kober.check import check
from kober.errors import SpecError
from kober.expr import ExprType, IntLiteral, unparse
from kober.loader import from_dict, from_file, from_json, from_yaml
from kober.spec import (
    BytesType,
    Computed,
    Count,
    Emit,
    Endian,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Pointer,
    Remaining,
    Spec,
    StringType,
    Switch,
    Terminated,
    ToEnd,
    UnitRef,
    Until,
)

MINIMAL: dict[str, Any] = {
    "name": "dns",
    "version": "1.0",
    "entry": "message",
    "units": {"message": {"fields": [{"name": "id", "type": {"int": {"bits": 16}}}]}},
}


def with_field(field: dict[str, Any], **extra: Any) -> Spec:
    document = dict(MINIMAL)
    document["units"] = {"message": {"fields": [field], **extra}}
    return from_dict(document)


def sole_field(field: dict[str, Any], **extra: Any):
    return with_field(field, **extra).unit("message").fields[0]


# --- entry points ----------------------------------------------------------


def test_from_dict_minimal():
    spec = from_dict(MINIMAL)
    assert spec.name == "dns"
    assert spec.entry == "message"
    assert spec.input is InputShape.EITHER


def test_from_json():
    assert from_json(json.dumps(MINIMAL)).name == "dns"


def test_from_json_rejects_bad_json():
    with pytest.raises(SpecError, match="cannot parse JSON"):
        from_json("{not json")


def test_from_yaml():
    spec = from_yaml("name: dns\nversion: '1.0'\nentry: m\nunits:\n  m:\n    fields: []\n")
    assert spec.name == "dns"


def test_from_yaml_rejects_bad_yaml():
    with pytest.raises(SpecError, match="cannot parse YAML"):
        from_yaml("name: [unclosed\n")


@pytest.mark.parametrize("suffix", [".json", ".yaml", ".yml"])
def test_from_file_dispatches_on_suffix(tmp_path: Path, suffix: str):
    path = tmp_path / f"dns{suffix}"
    path.write_text(json.dumps(MINIMAL), encoding="utf-8")
    assert from_file(path).name == "dns"


def test_from_file_rejects_unknown_suffix(tmp_path: Path):
    path = tmp_path / "dns.txt"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(SpecError, match="cannot tell the format"):
        from_file(path)


def test_from_file_reports_a_missing_file(tmp_path: Path):
    with pytest.raises(SpecError, match="cannot read"):
        from_file(tmp_path / "absent.json")


def test_spec_classmethods_are_the_same_door():
    assert Spec.from_dict(MINIMAL).name == "dns"
    assert Spec.from_json(json.dumps(MINIMAL)).name == "dns"


# --- strictness ------------------------------------------------------------


def test_unknown_key_is_refused():
    """A misspelled key that loads and does nothing is a silent wrong decode."""
    document = dict(MINIMAL, unexpected=1)
    with pytest.raises(SpecError, match="unknown key\\(s\\) 'unexpected'"):
        from_dict(document)


def test_unknown_field_key_is_refused():
    with pytest.raises(SpecError, match="unknown key\\(s\\) 'conditon'"):
        with_field({"name": "a", "type": {"int": {"bits": 8}}, "conditon": "x > 1"})


@pytest.mark.parametrize("missing", ["name", "version", "entry", "units"])
def test_missing_required_key(missing: str):
    document = {key: value for key, value in MINIMAL.items() if key != missing}
    with pytest.raises(SpecError, match=f"missing required key '{missing}'"):
        from_dict(document)


def test_field_without_a_name_key_says_how_to_be_anonymous():
    with pytest.raises(SpecError, match="use 'name: null'"):
        with_field({"type": {"int": {"bits": 8}}})


def test_error_messages_carry_a_path():
    with pytest.raises(SpecError, match=r"spec\.units\.message\.fields\[0\]\.type"):
        with_field({"name": "a", "type": {"int": {"bits": "wide"}}})


# --- YAML implicit typing --------------------------------------------------


def test_unquoted_version_is_refused_with_a_hint():
    """YAML reads 1.10 as a float, which is not the string '1.10'."""
    with pytest.raises(SpecError, match="quote it"):
        from_yaml("name: dns\nversion: 1.10\nentry: m\nunits:\n  m:\n    fields: []\n")


def test_unquoted_enum_label_is_refused_with_a_hint():
    """`no` is a YAML boolean, not the word."""
    document = dict(MINIMAL, enums={"answer": {0: "yes", 1: False}})
    with pytest.raises(SpecError, match="on/off/yes/no"):
        from_dict(document)


def test_boolean_where_an_integer_belongs():
    with pytest.raises(SpecError, match="expected an integer"):
        with_field({"name": "a", "type": {"int": {"bits": True}}})


# --- tagged unions ---------------------------------------------------------

def test_type_needs_exactly_one_key():
    with pytest.raises(SpecError, match="exactly one key naming the kind"):
        with_field({"name": "a", "type": {"int": {"bits": 8}, "enum": "opcode"}})


def test_unknown_type_kind_lists_the_alternatives():
    with pytest.raises(SpecError, match="unknown kind 'flooat'"):
        with_field({"name": "a", "type": {"flooat": {}}})


# --- types -----------------------------------------------------------------


def test_int_defaults():
    kind = sole_field({"name": "a", "type": {"int": {"bits": 16}}}).type
    assert kind == IntType(bits=16, signed=False, endian=Endian.BIG, enum=None)


def test_int_full():
    kind = sole_field(
        {
            "name": "a",
            "type": {"int": {"bits": 32, "signed": True, "endian": "little", "enum": "op"}},
        }
    ).type
    assert kind == IntType(bits=32, signed=True, endian=Endian.LITTLE, enum="op")


def test_bytes_and_string():
    assert sole_field({"name": "a", "type": {"bytes": {"size": 4}}}).type == BytesType(Fixed(4))
    kind = sole_field(
        {"name": "a", "type": {"string": {"size": {"remaining": True}, "encoding": "ascii"}}}
    ).type
    assert kind == StringType(size=Remaining(), encoding="ascii")


def test_string_defaults_to_utf8():
    kind = sole_field({"name": "a", "type": {"string": {"size": 4}}}).type
    assert isinstance(kind, StringType)
    assert kind.encoding == "utf-8"


def test_unit_reference_shorthand():
    assert sole_field({"name": "a", "type": {"unit": "header"}}).type == UnitRef("header")


def test_unit_reference_with_arguments():
    kind = sole_field({"name": "a", "type": {"unit": {"name": "body", "args": [4]}}}).type
    assert isinstance(kind, UnitRef)
    assert kind.unit == "body"
    assert kind.args == (IntLiteral(4),)


def test_computed():
    kind = sole_field({"name": "a", "type": {"computed": "1 + 2"}}).type
    assert isinstance(kind, Computed)
    assert unparse(kind.expr) == "1 + 2"


def test_switch():
    kind = sole_field(
        {
            "name": "a",
            "type": {
                "switch": {
                    "on": "kind",
                    "cases": {1: {"int": {"bits": 8}}, "text": {"bytes": {"size": 2}}},
                    "default": {"bytes": {"size": 1}},
                }
            },
        }
    ).type
    assert isinstance(kind, Switch)
    assert set(kind.cases) == {1, "text"}
    assert kind.default == BytesType(Fixed(1))


def test_unquoted_on_survives_yamls_boolean_reading():
    """`on` is a YAML 1.1 boolean, and it is this schema's dispatch key."""
    spec = from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: kind, type: {int: {bits: 8}}}
      - name: body
        type:
          switch:
            on: "kind"
            cases: {1: {int: {bits: 8}}}
            default: {bytes: {size: 1}}
""")
    switch = spec.unit("message").fields[1].type
    assert isinstance(switch, Switch)
    assert unparse(switch.on) == "kind"


def test_quoted_on_works_too():
    spec = from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: kind, type: {int: {bits: 8}}}
      - name: body
        type:
          switch:
            "on": "kind"
            cases: {1: {int: {bits: 8}}}
            default: {bytes: {size: 1}}
""")
    assert isinstance(spec.unit("message").fields[1].type, Switch)


def test_both_spellings_of_on_at_once_is_refused():
    with pytest.raises(SpecError, match="both 'on' and an unquoted"):
        from_yaml("""
name: t
version: "1.0"
entry: message
units:
  message:
    fields:
      - name: body
        type:
          switch:
            on: "a"
            "on": "b"
            cases: {1: {int: {bits: 8}}}
""")


def test_json_switch_needs_no_repair():
    """JSON has no boolean coercion, so its `on` arrives intact."""
    body = {
        "name": "a",
        "type": {"switch": {"on": "kind", "cases": {"1": {"int": {"bits": 8}}}}},
    }
    assert isinstance(sole_field(body).type, Switch)


def test_json_and_yaml_switch_keys_agree():
    """JSON can only spell a key as a string; both must mean the integer."""
    body = {
        "name": "a",
        "type": {"switch": {"on": "kind", "cases": {"1": {"int": {"bits": 8}}}}},
    }
    kind = sole_field(body).type
    assert isinstance(kind, Switch)
    assert set(kind.cases) == {1}


# --- sizes -----------------------------------------------------------------


def test_size_shorthand_is_fixed():
    kind = sole_field({"name": "a", "type": {"bytes": {"size": 8}}}).type
    assert isinstance(kind, BytesType)
    assert kind.size == Fixed(8)


def test_size_from_expression():
    kind = sole_field({"name": "a", "type": {"bytes": {"size": {"expr": "n * 2"}}}}).type
    assert isinstance(kind, BytesType)
    assert isinstance(kind.size, FromExpr)


def test_size_terminated_defaults():
    kind = sole_field(
        {"name": "a", "type": {"bytes": {"size": {"terminated": {"delimiter": "\r\n"}}}}}
    ).type
    assert isinstance(kind, BytesType)
    assert kind.size == Terminated(delimiter=b"\r\n", consume=True, required=True)


def test_delimiter_as_byte_values():
    kind = sole_field(
        {"name": "a", "type": {"bytes": {"size": {"terminated": {"delimiter": [13, 10]}}}}}
    ).type
    assert isinstance(kind, BytesType)
    assert isinstance(kind.size, Terminated)
    assert kind.size.delimiter == b"\r\n"


def test_delimiter_byte_value_out_of_range():
    with pytest.raises(SpecError, match="must be 0..255"):
        with_field(
            {"name": "a", "type": {"bytes": {"size": {"terminated": {"delimiter": [999]}}}}}
        )


def test_missing_size_is_refused():
    with pytest.raises(SpecError, match="missing required key 'size'"):
        with_field({"name": "a", "type": {"bytes": {}}})


# --- repeats ---------------------------------------------------------------


def test_repeat_count():
    field = sole_field({"name": "a", "type": {"int": {"bits": 8}}, "repeat": {"count": 3}})
    assert isinstance(field.repeat, Count)


def test_repeat_until():
    field = sole_field({"name": "a", "type": {"int": {"bits": 8}}, "repeat": {"until": "a == 0"}})
    assert isinstance(field.repeat, Until)


def test_repeat_to_end():
    field = sole_field({"name": "a", "type": {"int": {"bits": 8}}, "repeat": {"to_end": True}})
    assert isinstance(field.repeat, ToEnd)


# --- units, params, enums, emit -------------------------------------------


def test_anonymous_field():
    assert sole_field({"name": None, "type": {"int": {"bits": 2}}}).name is None


def test_params():
    spec = with_field(
        {"name": "a", "type": {"int": {"bits": 8}}},
        params=[{"name": "size", "type": "int"}],
    )
    param = spec.unit("message").params[0]
    assert param.name == "size"
    assert param.type is ExprType.INT


def test_emit_on_unit_and_field():
    spec = with_field({"name": "a", "type": {"int": {"bits": 8}}, "emit": "field"}, emit="none")
    assert spec.unit("message").emit is Emit.NONE
    assert spec.unit("message").fields[0].emit is Emit.FIELD


def test_unknown_emit_lists_the_alternatives():
    with pytest.raises(SpecError, match="expected one of: field, message, none"):
        with_field({"name": "a", "type": {"int": {"bits": 8}}, "emit": "loud"})


def test_enum_shorthand_and_long_form():
    short = from_dict(dict(MINIMAL, enums={"op": {0: "query"}}))
    assert short.enums["op"].members == {0: "query"}
    long = from_dict(dict(MINIMAL, enums={"op": {"members": {0: "query"}, "doc": "why"}}))
    assert long.enums["op"].doc == "why"


def test_enum_member_key_must_be_an_integer():
    with pytest.raises(SpecError, match="is not an integer"):
        from_dict(dict(MINIMAL, enums={"op": {"query": "query"}}))


def test_confirm_and_reject_and_docs():
    spec = with_field(
        {"name": "a", "type": {"int": {"bits": 8}}, "doc": "the field"},
        confirm="a == 1",
        reject="a == 2",
        doc="the unit",
    )
    unit = spec.unit("message")
    assert unit.confirm is not None
    assert unit.reject is not None
    assert unit.doc == "the unit"
    assert unit.fields[0].doc == "the field"


def test_input_shape():
    assert from_dict(dict(MINIMAL, input="stream")).input is InputShape.STREAM


# --- the design's own example ----------------------------------------------


def test_design_example_loads_and_checks_clean():
    """DESIGN.md §7, which is only worth printing if it is real."""
    document = """
    name: dns
    version: "1.0"
    entry: message
    input: either

    enums:
      opcode: {0: query, 1: iquery, 2: status}

    units:
      message:
        fields:
          - name: id
            type: {int: {bits: 16}}
            doc: Copied into the reply; matches responses to requests.
          - name: flags
            type: {unit: flags}
          - name: qdcount
            type: {int: {bits: 16}}
          - name: questions
            type: {unit: question}
            repeat: {count: "this.qdcount"}

      flags:
        fields:
          - name: qr
            type: {int: {bits: 1}}
          - name: opcode
            type: {int: {bits: 4, enum: opcode}}
          - {name: null, type: {int: {bits: 2}}}

      question:
        fields:
          - name: qname
            type: {string: {size: {terminated: {delimiter: "\\0"}}}}
          - name: qtype
            type: {int: {bits: 16}}
    """
    spec = from_yaml(document)
    assert check(spec) == ()


# --- pointer ---------------------------------------------------------------


def test_pointer_loads():
    field = sole_field(
        {"name": "target", "type": {"pointer": {"at": "n * 2", "type": {"int": {"bits": 8}}}}}
    )
    assert isinstance(field.type, Pointer)
    assert unparse(field.type.at) == "n * 2"
    assert field.type.type == IntType(bits=8)


def test_pointer_nests_any_type():
    """The target is a field type like any other, including a unit."""
    field = sole_field(
        {"name": "target", "type": {"pointer": {"at": "0", "type": {"unit": "name"}}}}
    )
    assert field.type.type == UnitRef(unit="name")


@pytest.mark.parametrize("missing", ["at", "type"])
def test_pointer_requires_both_keys(missing: str):
    body = {"at": "0", "type": {"int": {"bits": 8}}}
    del body[missing]
    with pytest.raises(SpecError, match=f"missing required key '{missing}'"):
        sole_field({"name": "t", "type": {"pointer": body}})


def test_pointer_rejects_an_unknown_key():
    """A misspelled key must not load and quietly do nothing."""
    with pytest.raises(SpecError, match="offset"):
        sole_field(
            {
                "name": "t",
                "type": {
                    "pointer": {"at": "0", "type": {"int": {"bits": 8}}, "offset": 4}
                },
            }
        )


def test_pointer_errors_carry_a_path():
    with pytest.raises(SpecError, match=r"units\.message\.fields\[0\]\.type\.pointer\.at"):
        sole_field({"name": "t", "type": {"pointer": {"at": "??", "type": {"int": {"bits": 8}}}}})
