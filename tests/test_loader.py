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
    Fill,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Pointer,
    Remaining,
    Select,
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
                    "dispatch": "kind",
                    "cases": {1: {"int": {"bits": 8}}, "text": {"bytes": {"size": 2}}},
                    "default": {"bytes": {"size": 1}},
                }
            },
        }
    ).type
    assert isinstance(kind, Switch)
    assert set(kind.cases) == {1, "text"}
    assert kind.default == BytesType(Fixed(1))


def test_the_dispatch_key_needs_no_quoting():
    """The whole point of the rename: `dispatch` is not a YAML 1.1 boolean."""
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
            dispatch: "kind"
            cases: {1: {int: {bits: 8}}}
            default: {bytes: {size: 1}}
""")
    switch = spec.unit("message").fields[1].type
    assert isinstance(switch, Switch)
    assert unparse(switch.dispatch) == "kind"


def test_an_unquoted_on_names_the_rename():
    """YAML turns it into `True`, so the error must not report the coercion.

    Falling through to "keys must be strings, got True" would name the symptom
    and leave the author to work out that a boolean key came from the word they
    wrote. This is the one place the old key is still known about.
    """
    with pytest.raises(SpecError, match="dispatch key is 'dispatch'"):
        from_yaml("""
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
""")


def test_a_quoted_on_names_the_rename_too():
    """JSON has no boolean coercion, so this is how the old key reaches JSON."""
    body = {
        "name": "a",
        "type": {"switch": {"on": "kind", "cases": {"1": {"int": {"bits": 8}}}}},
    }
    with pytest.raises(SpecError, match="dispatch key is 'dispatch'"):
        sole_field(body)


def test_json_and_yaml_switch_keys_agree():
    """JSON can only spell a key as a string; both must mean the integer."""
    body = {
        "name": "a",
        "type": {"switch": {"dispatch": "kind", "cases": {"1": {"int": {"bits": 8}}}}},
    }
    kind = sole_field(body).type
    assert isinstance(kind, Switch)
    assert set(kind.cases) == {1}


# --- sizes -----------------------------------------------------------------


def test_size_shorthand_is_fixed():
    kind = sole_field({"name": "a", "type": {"bytes": {"size": 8}}}).type
    assert isinstance(kind, BytesType)
    assert kind.size == Fixed(8)


def test_size_fill():
    kind = sole_field({"name": "a", "type": {"bytes": {"size": {"fill": True}}}}).type
    assert isinstance(kind, BytesType)
    assert kind.size == Fill()


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


# --- select ----------------------------------------------------------------


SELECT_BODY = {
    "from": "headers",
    "where": "lower(headers.name) == 'content-length'",
    "value": "to_int(headers.value)",
    "default": "-1",
}


def test_select_loads():
    field = sole_field({"name": "length", "type": {"select": dict(SELECT_BODY)}})
    assert isinstance(field.type, Select)
    assert field.type.source == "headers"
    assert unparse(field.type.where) == "lower(headers.name) == 'content-length'"
    assert unparse(field.type.value) == "to_int(headers.value)"
    assert unparse(field.type.default) == "-1"


@pytest.mark.parametrize("missing", ["from", "where", "value", "default"])
def test_select_requires_all_four_keys(missing: str):
    """`default` included: totality is what makes the construct total."""
    body = dict(SELECT_BODY)
    del body[missing]
    with pytest.raises(SpecError, match=f"missing required key\\(s\\) '{missing}'"):
        sole_field({"name": "length", "type": {"select": body}})


def test_select_names_every_missing_key_at_once():
    """An author writing a new construct wants the whole shape, not one key a run."""
    with pytest.raises(SpecError, match="'default', 'value'"):
        sole_field({"name": "length", "type": {"select": {"from": "h", "where": "true"}}})


def test_select_rejects_an_unknown_key():
    """A misspelled key must not load and quietly do nothing."""
    with pytest.raises(SpecError, match="otherwise"):
        sole_field(
            {"name": "length", "type": {"select": {**SELECT_BODY, "otherwise": "0"}}}
        )


def test_select_errors_carry_a_path():
    body = {**SELECT_BODY, "where": "??"}
    with pytest.raises(SpecError, match=r"fields\[0\]\.type\.select\.where"):
        sole_field({"name": "length", "type": {"select": body}})


def test_select_from_must_be_text():
    body = {**SELECT_BODY, "from": 3}
    with pytest.raises(SpecError, match=r"select\.from"):
        sole_field({"name": "length", "type": {"select": body}})


def test_terminated_loads_a_bound():
    field = sole_field(
        {
            "name": "n",
            "type": {
                "string": {
                    "size": {"terminated": {"delimiter": ":", "within": "\r\n"}}
                }
            },
        }
    )
    assert field.type.size.delimiter == b":"
    assert field.type.size.within == b"\r\n"


def test_terminated_has_no_bound_by_default():
    field = sole_field(
        {"name": "n", "type": {"string": {"size": {"terminated": {"delimiter": ":"}}}}}
    )
    assert field.type.size.within is None


def test_a_bound_accepts_byte_values_like_a_delimiter():
    field = sole_field(
        {
            "name": "n",
            "type": {
                "string": {
                    "size": {"terminated": {"delimiter": [58], "within": [13, 10]}}
                }
            },
        }
    )
    assert field.type.size.within == b"\r\n"


def test_an_empty_bound_is_refused():
    """Omitting it means "the whole run"; writing nothing means a mistake."""
    with pytest.raises(SpecError, match="bound must not be empty"):
        sole_field(
            {
                "name": "n",
                "type": {
                    "string": {"size": {"terminated": {"delimiter": ":", "within": ""}}}
                },
            }
        )


# --- shorthands ------------------------------------------------------------
#
# One rule each, and the test that matters for all of them is the same: both
# spellings must build the *identical* Spec. That equality is what makes these
# shorthands rather than features — nothing downstream can tell which was used.


LONG_FORM = """
name: t
version: "1.0"
entry: m
units:
  m:
    fields:
      - {name: count, type: {int: {bits: 8}}}
      - {name: qr, type: {int: {bits: 1}}}
      - {name: opcode, type: {int: {bits: 4, enum: kind}}}
      - {name: blob, type: {bytes: {size: {fixed: 4}}}}
      - {name: text, type: {string: {size: {fixed: 2}}}}
      - {name: line, type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}}
      - name: hname
        type:
          string:
            size: {terminated: {delimiter: ":", within: "\\r\\n", required: false}}
      - {name: sub, type: {unit: other}}
  other:
    fields:
      - {name: x, type: {int: {bits: 8}}}
enums:
  kind: {0: query}
"""

SHORT_FORM = """
name: t
version: "1.0"
entry: m
units:
  m:
    fields:
      - {name: count, bits: 8}
      - {name: qr, bits: 1}
      - {name: opcode, int: {bits: 4, enum: kind}}
      - {name: blob, bytes: 4}
      - {name: text, string: 2}
      - {name: line, string: {delimiter: "\\r\\n"}}
      - {name: hname, string: {delimiter: ":", within: "\\r\\n", required: false}}
      - {name: sub, unit: other}
  other:
    fields:
      - {name: x, int: 8}
enums:
  kind: {0: query}
"""


def test_the_short_and_long_forms_build_the_same_spec():
    """The cheapest test there is, and the one that says a shorthand is one."""
    assert from_yaml(SHORT_FORM) == from_yaml(LONG_FORM)


def test_a_lifted_kind_key_needs_no_type_key():
    kind = sole_field({"name": "a", "int": {"bits": 8}}).type
    assert kind == IntType(bits=8)


def test_bits_is_the_integer_shorthand():
    kind = sole_field({"name": "a", "bits": 4}).type
    assert kind == IntType(bits=4)


def test_bits_works_under_type_too():
    """A shorthand that only worked in one position would be a second grammar."""
    assert sole_field({"name": "a", "type": {"bits": 4}}).type == IntType(bits=4)


def test_a_bare_int_is_a_width():
    assert sole_field({"name": "a", "int": 8}).type == IntType(bits=8)


def test_a_bare_bytes_size_is_fixed():
    assert sole_field({"name": "a", "bytes": 4}).type == BytesType(size=Fixed(4))


def test_a_bare_string_size_is_fixed():
    assert sole_field({"name": "a", "string": 4}).type == StringType(size=Fixed(4))


def test_a_field_with_two_kind_keys_is_refused():
    with pytest.raises(SpecError, match="states its type once"):
        sole_field({"name": "a", "bits": 8, "bytes": 2})


def test_a_field_with_no_kind_key_is_refused():
    with pytest.raises(SpecError, match="missing required key 'type'"):
        sole_field({"name": "a", "doc": "nothing here"})


def test_a_field_with_both_type_and_a_lifted_kind_is_refused():
    with pytest.raises(SpecError, match="states its type once"):
        sole_field({"name": "a", "type": {"int": {"bits": 8}}, "bits": 8})


def test_an_int_option_beside_a_lifted_kind_is_refused():
    """The failure mode is loud, which is the bar for a convenience being safe.

    ``{name: opcode, bits: 4, enum: kind}`` is the natural next thing to try
    once a field needs an enum, and it must not quietly dissolve the type into
    the field mapping — ``size`` and ``encoding`` would have to follow, and
    ``{name: data, size: 4}`` cannot say whether it is bytes or a string.
    """
    with pytest.raises(SpecError, match="unknown key"):
        sole_field({"name": "a", "bits": 4, "enum": "kind"})


# --- a delimiter written beside the size ------------------------------------


def test_a_delimiter_beside_the_size_is_terminated():
    kind = sole_field({"name": "a", "string": {"delimiter": "\r\n"}}).type
    assert kind == StringType(size=Terminated(delimiter=b"\r\n"))


def test_the_terminator_companions_sit_beside_it():
    kind = sole_field(
        {
            "name": "a",
            "string": {"delimiter": ":", "within": "\r\n", "required": False},
        }
    ).type
    assert isinstance(kind, StringType)
    assert kind.size == Terminated(
        delimiter=b":", consume=True, required=False, within=b"\r\n"
    )


def test_bytes_may_be_delimited_too():
    kind = sole_field({"name": "a", "bytes": {"delimiter": [0]}}).type
    assert kind == BytesType(size=Terminated(delimiter=b"\x00"))


def test_a_delimiter_beside_an_encoding():
    kind = sole_field(
        {"name": "a", "string": {"delimiter": "\n", "encoding": "ascii"}}
    ).type
    assert kind == StringType(size=Terminated(delimiter=b"\n"), encoding="ascii")


def test_both_size_and_delimiter_is_refused():
    with pytest.raises(SpecError, match="states its extent once"):
        sole_field({"name": "a", "string": {"size": 4, "delimiter": ":"}})


def test_a_terminator_companion_without_a_delimiter_is_refused():
    with pytest.raises(SpecError, match="beside a 'delimiter'"):
        sole_field({"name": "a", "string": {"within": ":"}})


def test_the_long_terminated_form_still_works():
    """The shorthand may not become the only way to say a delimited size."""
    kind = sole_field(
        {"name": "a", "string": {"size": {"terminated": {"delimiter": ":"}}}}
    ).type
    assert kind == StringType(size=Terminated(delimiter=b":"))


# --- naming the element a construct binds ----------------------------------


def test_a_select_may_name_its_element():
    kind = sole_field(
        {
            "name": "a",
            "select": {
                "from": "items",
                "as": "item",
                "where": "item.x == 1",
                "value": "item.x",
                "default": "0",
            },
        }
    ).type
    assert isinstance(kind, Select)
    assert kind.source == "items"
    assert kind.alias == "item"


def test_a_select_without_as_binds_the_source_name():
    kind = sole_field(
        {
            "name": "a",
            "select": {
                "from": "items",
                "where": "items.x == 1",
                "value": "items.x",
                "default": "0",
            },
        }
    ).type
    assert isinstance(kind, Select)
    assert kind.alias is None


def test_as_is_not_among_a_selects_required_keys():
    """Every spec written before the key existed must still load."""
    with pytest.raises(SpecError, match="missing required key"):
        sole_field({"name": "a", "select": {"from": "items", "as": "item"}})


def test_until_takes_a_bare_expression():
    """The shorthand, and what every spec wrote before `as:` existed."""
    field = sole_field({"name": "a", "bits": 8, "repeat": {"until": "a == 0"}})
    assert isinstance(field.repeat, Until)
    assert field.repeat.alias is None


def test_until_may_name_its_element():
    field = sole_field(
        {"name": "a", "bits": 8, "repeat": {"until": {"expr": "e == 0", "as": "e"}}}
    )
    assert isinstance(field.repeat, Until)
    assert unparse(field.repeat.expr) == "e == 0"
    assert field.repeat.alias == "e"


def test_the_two_until_spellings_agree():
    plain = sole_field({"name": "a", "bits": 8, "repeat": {"until": "a == 0"}})
    spelled = sole_field(
        {"name": "a", "bits": 8, "repeat": {"until": {"expr": "a == 0"}}}
    )
    assert plain == spelled


def test_an_until_mapping_needs_its_expression():
    with pytest.raises(SpecError, match="missing required key 'expr'"):
        sole_field({"name": "a", "bits": 8, "repeat": {"until": {"as": "e"}}})


def test_an_unknown_key_in_an_until_is_refused():
    with pytest.raises(SpecError, match="unknown key"):
        sole_field(
            {"name": "a", "bits": 8, "repeat": {"until": {"expr": "a == 0", "az": "e"}}}
        )
