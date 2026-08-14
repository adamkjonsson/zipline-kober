"""Build a :class:`~kober.spec.Spec` from a mapping, JSON, or YAML.

The core parses the *model*, so :func:`from_dict` and :func:`from_json` work
with the standard library alone and only :func:`from_file` reaches for YAML —
which stays an optional extra (``pip install kober[yaml]``), imported lazily.
See ``DESIGN.md`` §8.

**The schema is strict, and deliberately so.** An unknown key is an error, not
something quietly ignored: a misspelled ``conditon:`` that loads and does
nothing is a decoder that silently does the wrong thing, which is exactly what
the coverage guarantee is meant to rule out.

**YAML's implicit typing is guarded against by name.** ``on``, ``off``,
``yes``, and ``no`` become booleans, and ``1.10`` becomes a float that is not
``"1.10"``. Rather than let those through as wrong-typed values, every scalar
accessor names the problem and says to quote it. That is why ``version: 1.10``
is refused rather than coerced.

A type is written as a **single-key mapping** naming the kind::

    type: {int: {bits: 16, enum: opcode}}
    type: {bytes: {size: {expr: "header.length"}}}
    type: {unit: question}
    type: {switch: {on: "kind", cases: {1: {int: {bits: 8}}}}}

Sizes and repeats follow the same shape, with two shorthands that are common
enough to earn one: a bare integer size means ``fixed``, and a bare string
where a type expects a unit means a unit reference with no arguments.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from kober.errors import SpecError
from kober.expr import ExprType, parse
from kober.spec import (
    BytesType,
    Computed,
    Count,
    Emit,
    Endian,
    EnumDef,
    Field,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Param,
    Remaining,
    Spec,
    StringType,
    Switch,
    Terminated,
    ToEnd,
    Unit,
    UnitRef,
    Until,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from kober.expr import Expr
    from kober.spec import FieldType, Repeat, SizeSpec

_E = TypeVar("_E", bound=Enum)

#: Suffixes :func:`from_file` recognizes, and the format each names.
SUFFIXES: Mapping[str, str] = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
}

_SPEC_KEYS = frozenset({"name", "version", "entry", "units", "enums", "input", "doc"})
_UNIT_KEYS = frozenset({"fields", "params", "confirm", "reject", "emit", "doc"})
_FIELD_KEYS = frozenset({"name", "type", "condition", "repeat", "emit", "doc"})
_INT_KEYS = frozenset({"bits", "signed", "endian", "enum"})
_BYTES_KEYS = frozenset({"size"})
_STRING_KEYS = frozenset({"size", "encoding"})
_SWITCH_KEYS = frozenset({"on", "cases", "default"})
_TERMINATED_KEYS = frozenset({"delimiter", "consume", "required"})
_PARAM_KEYS = frozenset({"name", "type"})
_ENUM_KEYS = frozenset({"members", "doc"})


# --- entry points ----------------------------------------------------------


def from_dict(document: Mapping[str, Any]) -> Spec:
    """Build a spec from an already-parsed mapping.

    Args:
        document: The spec document.

    Returns:
        The spec. It is well formed; run :func:`kober.check.check` to learn
        whether it is valid.

    Raises:
        SpecError: If the document is malformed.

    """
    return _spec(document, "spec")


def from_json(text: str) -> Spec:
    """Build a spec from JSON text.

    Args:
        text: The JSON document.

    Returns:
        The spec.

    Raises:
        SpecError: If the text is not JSON, or the document is malformed.

    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"cannot parse JSON: {exc}"
        raise SpecError(msg) from exc
    return from_dict(_require_mapping(document, "spec"))


def from_yaml(text: str) -> Spec:
    """Build a spec from YAML text.

    Args:
        text: The YAML document.

    Returns:
        The spec.

    Raises:
        SpecError: If PyYAML is not installed, the text is not YAML, or the
            document is malformed.

    """
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on the environment
        msg = (
            "YAML support needs PyYAML, which is an optional extra. "
            "Install it with: pip install 'kober[yaml]'"
        )
        raise SpecError(msg) from exc
    try:
        # safe_load only: a spec is data, and full_load would let a document
        # name Python types to construct.
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"cannot parse YAML: {exc}"
        raise SpecError(msg) from exc
    return from_dict(_require_mapping(document, "spec"))


def from_file(path: str | Path) -> Spec:
    """Build a spec from a file, dispatching on its suffix.

    Args:
        path: Path to a ``.json``, ``.yaml``, or ``.yml`` file.

    Returns:
        The spec.

    Raises:
        SpecError: If the suffix is unrecognized, the file cannot be read, or
            the document is malformed.

    """
    resolved = Path(path)
    fmt = SUFFIXES.get(resolved.suffix.lower())
    if fmt is None:
        known = ", ".join(sorted(SUFFIXES))
        msg = (
            f"cannot tell the format of {resolved.name!r} from its suffix; "
            f"expected one of: {known}"
        )
        raise SpecError(msg)
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read {resolved}: {exc}"
        raise SpecError(msg) from exc
    return from_json(text) if fmt == "json" else from_yaml(text)


# --- scalar accessors ------------------------------------------------------


def _yaml_hint(value: object) -> str:
    """Explain a value YAML's implicit typing probably mangled."""
    if isinstance(value, bool):
        return (
            " (YAML reads on/off/yes/no/true/false as booleans; "
            "quote it if you meant the word)"
        )
    if isinstance(value, float):
        return " (YAML reads 1.10 as a number, not a string; quote it)"
    return ""


def _require_mapping(value: object, where: str) -> Mapping[str, Any]:
    """Return ``value`` as a mapping with string keys, or raise."""
    mapping = _require_any_mapping(value, where)
    for key in mapping:
        if not isinstance(key, str):
            msg = f"{where}: keys must be strings, got {key!r}"
            raise SpecError(msg)
    return mapping


def _require_any_mapping(value: object, where: str) -> Mapping[Any, Any]:
    """Return ``value`` as a mapping, whatever its keys are.

    Enum members and switch cases are keyed by the *value* they name, which
    YAML gives as an integer and JSON can only give as a string. Both have to
    mean the same thing, so neither can be held to the string-key rule the
    rest of the schema follows.
    """
    if not isinstance(value, dict):
        msg = f"{where}: expected a mapping, got {type(value).__name__}"
        raise SpecError(msg)
    return value


def _require_list(value: object, where: str) -> list[Any]:
    """Return ``value`` as a list, or raise."""
    if not isinstance(value, list):
        msg = f"{where}: expected a list, got {type(value).__name__}"
        raise SpecError(msg)
    return value


def _require_str(value: object, where: str) -> str:
    """Return ``value`` as a string, or raise with a YAML hint."""
    if not isinstance(value, str):
        msg = f"{where}: expected a string, got {type(value).__name__}{_yaml_hint(value)}"
        raise SpecError(msg)
    return value


def _require_int(value: object, where: str) -> int:
    """Return ``value`` as an integer, or raise. Booleans are not integers."""
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{where}: expected an integer, got {type(value).__name__}{_yaml_hint(value)}"
        raise SpecError(msg)
    return value


def _require_bool(value: object, where: str) -> bool:
    """Return ``value`` as a boolean, or raise."""
    if not isinstance(value, bool):
        msg = f"{where}: expected true or false, got {type(value).__name__}"
        raise SpecError(msg)
    return value


def _reject_unknown(mapping: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    """Refuse keys outside the schema, naming the nearest allowed one."""
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        known = ", ".join(sorted(allowed))
        listed = ", ".join(repr(key) for key in unknown)
        msg = f"{where}: unknown key(s) {listed}; allowed here: {known}"
        raise SpecError(msg)


def _tagged(mapping: Mapping[str, Any], where: str, kinds: frozenset[str]) -> tuple[str, Any]:
    """Unpack a single-key tagged mapping, e.g. ``{int: {...}}``."""
    if len(mapping) != 1:
        known = ", ".join(sorted(kinds))
        listed = ", ".join(repr(key) for key in sorted(mapping)) or "nothing"
        msg = (
            f"{where}: expected exactly one key naming the kind, got {listed}. "
            f"Choose one of: {known}"
        )
        raise SpecError(msg)
    tag, value = next(iter(mapping.items()))
    if tag not in kinds:
        known = ", ".join(sorted(kinds))
        msg = f"{where}: unknown kind {tag!r}; expected one of: {known}"
        raise SpecError(msg)
    return tag, value


def _member(enum_class: type[_E], value: object, where: str) -> _E:
    """Look a string up in an enumeration, listing the alternatives."""
    text = _require_str(value, where)
    for member in enum_class:
        if member.value == text:
            return member
    known = ", ".join(sorted(str(member.value) for member in enum_class))
    msg = f"{where}: unknown value {text!r}; expected one of: {known}"
    raise SpecError(msg)


def _expr(value: object, where: str) -> Expr:
    """Parse an expression, accepting a bare integer as a literal."""
    if isinstance(value, bool):
        msg = f"{where}: expected an expression{_yaml_hint(value)}"
        raise SpecError(msg)
    if isinstance(value, int):
        return parse(str(value), where)
    return parse(_require_str(value, where), where)


# --- the document ----------------------------------------------------------


def _spec(document: Mapping[str, Any], where: str) -> Spec:
    """Build the top-level spec."""
    mapping = _require_mapping(document, where)
    _reject_unknown(mapping, _SPEC_KEYS, where)
    for required in ("name", "version", "entry", "units"):
        if required not in mapping:
            msg = f"{where}: missing required key {required!r}"
            raise SpecError(msg)

    units_doc = _require_mapping(mapping["units"], f"{where}.units")
    units = {
        name: _unit(name, value, f"{where}.units.{name}") for name, value in units_doc.items()
    }
    enums_doc = _require_mapping(mapping.get("enums", {}), f"{where}.enums")
    enums = {
        name: _enum(name, value, f"{where}.enums.{name}") for name, value in enums_doc.items()
    }
    shape = (
        InputShape.EITHER
        if "input" not in mapping
        else _member(InputShape, mapping["input"], f"{where}.input")
    )
    return Spec(
        name=_require_str(mapping["name"], f"{where}.name"),
        version=_require_str(mapping["version"], f"{where}.version"),
        entry=_require_str(mapping["entry"], f"{where}.entry"),
        units=units,
        enums=enums,
        input=shape,
        doc=_optional_str(mapping, "doc", where),
    )


def _optional_str(mapping: Mapping[str, Any], key: str, where: str) -> str | None:
    """Read an optional string key."""
    if key not in mapping or mapping[key] is None:
        return None
    return _require_str(mapping[key], f"{where}.{key}")


def _enum(name: str, document: object, where: str) -> EnumDef:
    """Build an enum, accepting the plain ``{0: label}`` shorthand."""
    mapping = _require_any_mapping(document, where)
    # A bare {0: query} mapping has no schema keys, so treat anything without
    # 'members' as the shorthand for it.
    if "members" not in mapping:
        return EnumDef(name=name, members=_enum_members(mapping, where))
    _reject_unknown(_require_mapping(mapping, where), _ENUM_KEYS, where)
    members = _require_any_mapping(mapping["members"], f"{where}.members")
    return EnumDef(
        name=name,
        members=_enum_members(members, f"{where}.members"),
        doc=_optional_str(mapping, "doc", where),
    )


def _enum_members(mapping: Mapping[Any, Any], where: str) -> dict[int, str]:
    """Read enum members, whose keys are integers however they were written."""
    members: dict[int, str] = {}
    for key, label in mapping.items():
        # JSON object keys are always strings; YAML gives real ints. A bool is
        # not a member value, however Python spells its subclassing.
        if isinstance(key, bool):
            msg = f"{where}: enum member key {key!r} is not an integer{_yaml_hint(key)}"
            raise SpecError(msg)
        try:
            value = int(key)
        except (TypeError, ValueError):
            msg = f"{where}: enum member key {key!r} is not an integer"
            raise SpecError(msg) from None
        members[value] = _require_str(label, f"{where}.{key}")
    return members


def _unit(name: str, document: object, where: str) -> Unit:
    """Build one unit."""
    mapping = _require_mapping(document, where)
    _reject_unknown(mapping, _UNIT_KEYS, where)
    if "fields" not in mapping:
        msg = f"{where}: missing required key 'fields'"
        raise SpecError(msg)
    fields = [
        _field(item, f"{where}.fields[{index}]")
        for index, item in enumerate(_require_list(mapping["fields"], f"{where}.fields"))
    ]
    params = [
        _param(item, f"{where}.params[{index}]")
        for index, item in enumerate(_require_list(mapping.get("params", []), f"{where}.params"))
    ]
    return Unit(
        name=name,
        fields=fields,
        params=params,
        confirm=_optional_expr(mapping, "confirm", where),
        reject=_optional_expr(mapping, "reject", where),
        emit=_optional_emit(mapping, where),
        doc=_optional_str(mapping, "doc", where),
    )


def _optional_expr(mapping: Mapping[str, Any], key: str, where: str) -> Expr | None:
    """Read an optional expression key."""
    if key not in mapping or mapping[key] is None:
        return None
    return _expr(mapping[key], f"{where}.{key}")


def _optional_emit(mapping: Mapping[str, Any], where: str) -> Emit | None:
    """Read an optional emit key."""
    if "emit" not in mapping or mapping["emit"] is None:
        return None
    return _member(Emit, mapping["emit"], f"{where}.emit")


def _param(document: object, where: str) -> Param:
    """Build one unit parameter."""
    mapping = _require_mapping(document, where)
    _reject_unknown(mapping, _PARAM_KEYS, where)
    for required in ("name", "type"):
        if required not in mapping:
            msg = f"{where}: missing required key {required!r}"
            raise SpecError(msg)
    return Param(
        name=_require_str(mapping["name"], f"{where}.name"),
        type=_member(ExprType, mapping["type"], f"{where}.type"),
    )


def _field(document: object, where: str) -> Field:
    """Build one field."""
    mapping = _require_mapping(document, where)
    _reject_unknown(mapping, _FIELD_KEYS, where)
    if "type" not in mapping:
        msg = f"{where}: missing required key 'type'"
        raise SpecError(msg)
    if "name" not in mapping:
        msg = f"{where}: missing required key 'name'; use 'name: null' for an anonymous field"
        raise SpecError(msg)
    raw_name = mapping["name"]
    name = None if raw_name is None else _require_str(raw_name, f"{where}.name")
    return Field(
        name=name,
        type=_field_type(mapping["type"], f"{where}.type"),
        condition=_optional_expr(mapping, "condition", where),
        repeat=_repeat(mapping["repeat"], f"{where}.repeat") if mapping.get("repeat") else None,
        emit=_optional_emit(mapping, where),
        doc=_optional_str(mapping, "doc", where),
    )


# --- types, sizes, repeats -------------------------------------------------

_TYPE_KINDS = frozenset({"int", "bytes", "string", "unit", "switch", "computed"})
_SIZE_KINDS = frozenset({"fixed", "expr", "terminated", "remaining"})
_REPEAT_KINDS = frozenset({"count", "until", "to_end"})


def _field_type(document: object, where: str) -> FieldType:
    """Build a field type from its single-key tagged mapping."""
    mapping = _require_mapping(document, where)
    tag, value = _tagged(mapping, where, _TYPE_KINDS)
    site = f"{where}.{tag}"
    if tag == "int":
        return _int_type(value, site)
    if tag == "bytes":
        body = _require_mapping(value, site)
        _reject_unknown(body, _BYTES_KEYS, site)
        return BytesType(size=_size(body.get("size"), f"{site}.size"))
    if tag == "string":
        body = _require_mapping(value, site)
        _reject_unknown(body, _STRING_KEYS, site)
        encoding = body.get("encoding")
        return StringType(
            size=_size(body.get("size"), f"{site}.size"),
            encoding="utf-8" if encoding is None else _require_str(encoding, f"{site}.encoding"),
        )
    if tag == "unit":
        return _unit_ref(value, site)
    if tag == "switch":
        return _switch(value, site)
    return Computed(expr=_expr(value, site))


def _int_type(document: object, where: str) -> IntType:
    """Build an integer type."""
    mapping = _require_mapping(document, where)
    _reject_unknown(mapping, _INT_KEYS, where)
    if "bits" not in mapping:
        msg = f"{where}: missing required key 'bits'"
        raise SpecError(msg)
    endian = mapping.get("endian")
    enum = mapping.get("enum")
    return IntType(
        bits=_require_int(mapping["bits"], f"{where}.bits"),
        signed=_require_bool(mapping.get("signed", False), f"{where}.signed"),
        endian=Endian.BIG if endian is None else _member(Endian, endian, f"{where}.endian"),
        enum=None if enum is None else _require_str(enum, f"{where}.enum"),
    )


def _unit_ref(document: object, where: str) -> UnitRef:
    """Build a unit reference, accepting the bare-name shorthand."""
    if isinstance(document, str):
        return UnitRef(unit=document)
    mapping = _require_mapping(document, where)
    _reject_unknown(mapping, frozenset({"name", "args"}), where)
    if "name" not in mapping:
        msg = f"{where}: missing required key 'name'"
        raise SpecError(msg)
    args = _require_list(mapping.get("args", []), f"{where}.args")
    return UnitRef(
        unit=_require_str(mapping["name"], f"{where}.name"),
        args=[_expr(item, f"{where}.args[{index}]") for index, item in enumerate(args)],
    )


def _switch(document: object, where: str) -> Switch:
    """Build a switch."""
    mapping = _require_mapping(document, where)
    _reject_unknown(mapping, _SWITCH_KEYS, where)
    for required in ("on", "cases"):
        if required not in mapping:
            msg = f"{where}: missing required key {required!r}"
            raise SpecError(msg)
    cases_doc = _require_any_mapping(mapping["cases"], f"{where}.cases")
    cases: dict[int | str, FieldType] = {}
    for key, value in cases_doc.items():
        cases[_case_key(key)] = _field_type(value, f"{where}.cases.{key}")
    default = mapping.get("default")
    return Switch(
        on=_expr(mapping["on"], f"{where}.on"),
        cases=cases,
        default=None if default is None else _field_type(default, f"{where}.default"),
    )


def _case_key(key: object) -> int | str:
    """Read a case key as an integer where it looks like one.

    JSON object keys are always strings, so ``{"1": ...}`` and YAML's ``{1:
    ...}`` have to mean the same thing. Whether the key is *correct* is the
    checker's call, against the type dispatched on — including a ``true:`` key
    YAML invented, which survives to be reported there rather than here.
    """
    if isinstance(key, (bool, int)):
        return key
    if isinstance(key, str):
        try:
            return int(key)
        except ValueError:
            return key
    msg = f"switch case key {key!r} must be an integer or a string"
    raise SpecError(msg)


def _size(document: object, where: str) -> SizeSpec:
    """Build a size spec, accepting a bare integer as ``fixed``."""
    if document is None:
        msg = f"{where}: missing required key 'size'"
        raise SpecError(msg)
    if isinstance(document, bool):
        msg = f"{where}: expected a size{_yaml_hint(document)}"
        raise SpecError(msg)
    if isinstance(document, int):
        return Fixed(count=document)
    mapping = _require_mapping(document, where)
    tag, value = _tagged(mapping, where, _SIZE_KINDS)
    site = f"{where}.{tag}"
    if tag == "fixed":
        return Fixed(count=_require_int(value, site))
    if tag == "expr":
        return FromExpr(expr=_expr(value, site))
    if tag == "remaining":
        return Remaining()
    body = _require_mapping(value, site)
    _reject_unknown(body, _TERMINATED_KEYS, site)
    if "delimiter" not in body:
        msg = f"{site}: missing required key 'delimiter'"
        raise SpecError(msg)
    return Terminated(
        delimiter=_delimiter(body["delimiter"], f"{site}.delimiter"),
        consume=_require_bool(body.get("consume", True), f"{site}.consume"),
        required=_require_bool(body.get("required", True), f"{site}.required"),
    )


def _delimiter(document: object, where: str) -> bytes:
    """Read a delimiter, as text or as a list of byte values."""
    if isinstance(document, str):
        return document.encode("utf-8")
    values = _require_list(document, where)
    out = bytearray()
    for index, item in enumerate(values):
        value = _require_int(item, f"{where}[{index}]")
        if not 0 <= value <= 0xFF:
            msg = f"{where}[{index}]: byte value must be 0..255, got {value}"
            raise SpecError(msg)
        out.append(value)
    return bytes(out)


def _repeat(document: object, where: str) -> Repeat:
    """Build a repeat clause."""
    mapping = _require_mapping(document, where)
    tag, value = _tagged(mapping, where, _REPEAT_KINDS)
    site = f"{where}.{tag}"
    if tag == "count":
        return Count(expr=_expr(value, site))
    if tag == "until":
        return Until(expr=_expr(value, site))
    return ToEnd()
