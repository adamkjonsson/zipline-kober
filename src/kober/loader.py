r"""Build a :class:`~kober.spec.Spec` from a mapping, JSON, or YAML.

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

A type is written as a **single-key mapping** naming the kind, and sizes and
repeats follow the same shape::

    type: {int: {bits: 16, enum: opcode}}
    type: {bytes: {size: {expr: "header.length"}}}
    type: {unit: question}
    type: {switch: {dispatch: "kind", cases: {1: {int: {bits: 8}}}}}

**Three shorthands shorten what that costs**, and they are one rule each rather
than a list of exceptions.

*A scalar where a mapping is expected fills in the one key that matters.* A
bare size is ``fixed``; ``{bytes: 4}`` and ``{string: 4}`` are a fixed size;
``{int: 8}`` is a width; ``{unit: question}`` is a reference with no arguments.
Anything carrying a second key writes the long form.

*A tagged construct's kind may lift into its parent where the key sets do not
overlap.* This is the general rule, stated once because it now governs two
constructs and will govern the next one:

    - {name: count, type: {int: {bits: 8}}}      # both mean the same thing
    - {name: count, int: {bits: 8}}
    - {name: count, bits: 8}

    - {name: qs, unit: q, repeat: {count: "n"}}  # and so do these
    - {name: qs, unit: q, count: n}

A field's keys are therefore drawn from three sets — its own, the type kinds,
and the repeat kinds — and no member of any of them appears in another, which
is what makes a lifted key unambiguous. Strictness is untouched: naming a kind
*and* its wrapper is an error, naming two kinds of the same construct is an
error, and a key in none of the three sets is an error as it always was.

*``bits`` names the integer kind*, because the word says what the number counts
where ``int: 8`` cannot.

Separately, a ``delimiter`` may be written beside ``size`` rather than under it,
which is what makes reading to a delimiter shallow —
``{string: {delimiter: "\r\n"}}`` rather than
``{string: {size: {terminated: {delimiter: "\r\n"}}}}``.

Every shorthand builds the **identical model**. Nothing downstream — the
checker, the engine, the compiler — can tell which spelling was used, which is
what makes them shorthands rather than features.

**Every fault knows where it is.** A position — an ``_At``, private to this
module — is threaded through every constructor rather than a dotted string, so a
:class:`~kober.errors.SpecError` names the file and the line as well as the
path. YAML mappings carry the line they started on; JSON and a mapping built in
memory carry none, and then a message reads exactly as it did before. The
constructs :func:`kober.check.check` reports on are additionally recorded in
the *checker's* vocabulary, since it runs later with the document gone. See
:mod:`kober.source`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from kober.errors import SpecError
from kober.expr import ExprType, parse
from kober.source import Location, SourceMap
from kober.spec import (
    BytesType,
    Computed,
    Concat,
    Count,
    Emit,
    Endian,
    EnumDef,
    Field,
    Fill,
    Fixed,
    Foreign,
    FromExpr,
    InputShape,
    IntType,
    Param,
    Pointer,
    Remaining,
    Select,
    Spec,
    StringType,
    Switch,
    Terminated,
    ToEnd,
    Transform,
    TransformDecl,
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

_SPEC_KEYS = frozenset(
    {
        "name", "version", "entry", "units", "enums", "input", "endian", "doc",
        "transforms", "params",
    }
)
_UNIT_KEYS = frozenset({"fields", "params", "confirm", "reject", "emit", "endian", "doc"})
_FIELD_KEYS = frozenset({"name", "type", "condition", "repeat", "emit", "const", "doc"})
_INT_KEYS = frozenset({"bits", "signed", "endian", "enum"})
_TERMINATED_KEYS = frozenset({"delimiter", "consume", "required", "within"})
#: A ``bytes`` body says its extent with ``size``, or with ``delimiter`` and its
#: companions written beside it.
_BYTES_KEYS = frozenset({"size"}) | _TERMINATED_KEYS
_STRING_KEYS = _BYTES_KEYS | {"encoding"}
_SWITCH_KEYS = frozenset({"dispatch", "cases", "default"})
_POINTER_KEYS = frozenset({"at", "type"})
#: Every key of a ``transform``. ``from``, ``with`` and ``limit`` are required;
#: ``from`` and ``with`` are Python keywords, so the model spells them
#: ``source`` and ``name``.
_TRANSFORM_KEYS = frozenset({"from", "with", "limit", "args", "type", "content_type"})
_TRANSFORM_REQUIRED = ("from", "with", "limit")
#: Every key of a transform's declaration under ``transforms:``.
_TRANSFORM_DECL_KEYS = frozenset({"params", "doc"})
#: Every key of a document parameter written out.
_DOC_PARAM_KEYS = frozenset({"type", "secret", "doc"})
_PARAM_KEYS = frozenset({"name", "type"})
_ENUM_KEYS = frozenset({"members", "doc"})

#: Keys belonging to [packeteer](https://github.com/adamkjonsson/packeteer)'s
#: dialect of this format, and why each has no meaning here. Mapped to the
#: reason so the warning explains itself rather than only naming the key.
#:
#: **Recognised, not implemented, and said out loud.** packeteer reads the
#: kober constructs it cannot implement and reports them through its checker as
#: "not supported yet", naming the construct; this is the mirror of that, and
#: without it a spec written for the sibling project is refused the way a
#: misspelled ``conditon:`` is. Ignoring any of these changes no decode, which
#: is why they are warnings and why the superset claim survives them.
#:
#: Strictness is untouched. An unknown key is still an error — the rule exists
#: so a misspelling cannot load and quietly do nothing. What changes is that
#: these four stop being *unknown*.
_FOREIGN_SPEC_KEYS: Mapping[str, str] = {
    "over": "kober is handed a spec rather than choosing one by transport",
    "ports": "kober is handed a spec rather than choosing one by port",
}
_FOREIGN_FIELD_KEYS: Mapping[str, str] = {
    "derive": "kober decodes and does not encode, so there is nothing to compute",
    "sensitive": "kober writes decoded records and has no redaction step",
}
#: Every one of them, for a message that has to name the whole set.
FOREIGN_KEYS: Mapping[str, str] = {**_FOREIGN_SPEC_KEYS, **_FOREIGN_FIELD_KEYS}


# --- where we are ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _At:
    """Where the loader is in the document, and what it has learned getting there.

    One value threaded through every constructor, rather than a parameter per
    thing that needs carrying: the location a fault would be reported at, the
    map of lines the checker will look faults up in later, and what this
    position inherits from the document above it.

    :attr:`endian` is the last of those, and it is why this is a record rather
    than a bare :class:`~kober.source.Location`. Byte order resolves **field →
    unit → document → big**, lexically, because a unit's integers are read the
    same way wherever the unit is referenced from — unlike emission
    granularity, whose chain has a dynamic hop through the enclosing unit and
    so cannot be folded in at load time.

    Attributes:
        loc: Path, line and file of the construct being read.
        lines: The map being filled in, shared by every position in one load.
        found: Foreign keys seen so far, shared the same way.
        endian: Byte order an integer here takes unless it says otherwise.

    """

    loc: Location
    lines: dict[str, int]
    found: list[Foreign]
    endian: Endian = Endian.BIG

    def child(self, step: object) -> _At:
        """Return the position of a step below this one."""
        return _At(self.loc.child(step), self.lines, self.found, self.endian)

    def within(self, document: object) -> _At:
        """Return this position carrying ``document``'s own line, if it has one.

        A mapping parsed from YAML knows the line it started on; one from JSON
        or from memory does not, and then this changes nothing.
        """
        line = getattr(document, "line", None)
        if not isinstance(line, int):
            return self
        return _At(self.loc.at_line(line), self.lines, self.found, self.endian)

    def defaulting(self, mapping: Mapping[str, Any]) -> _At:
        """Return this position with any lexical default ``mapping`` declares.

        Read where a scope opens — the document, and each unit — so everything
        built below it inherits. A scope that declares nothing inherits what it
        was given.

        Args:
            mapping: The document or unit body opening the scope.

        Returns:
            This position, or one carrying the declared default.

        Raises:
            SpecError: If the declared byte order is not one of the two.

        """
        declared = mapping.get("endian")
        if declared is None:
            return self
        endian = _member(Endian, declared, self.child("endian"))
        return _At(self.loc, self.lines, self.found, endian)

    def record(self, path: str) -> None:
        """Note this position's line under a path in the checker's vocabulary.

        The loader's paths (``spec.units.message.fields[0]``) and the checker's
        (``dns.message.id``) name the same constructs in different words, so
        the things :func:`kober.check.check` reports on are recorded under the
        words it will ask in. See :mod:`kober.source`.
        """
        if self.loc.line is not None:
            self.lines[path] = self.loc.line

    def note_foreign(self, mapping: Mapping[str, Any], keys: Mapping[str, str], path: str) -> None:
        """Note every key of ``keys`` that ``mapping`` carries, under ``path``.

        Collected here rather than reported here: the loader raises at the
        first fault, and these are not faults. :func:`kober.check.check` sees
        the whole spec and reports every one of them at once.
        """
        self.found.extend(Foreign(key=key, where=path) for key in sorted(keys) if key in mapping)


def _root(document: object, source: str | None) -> _At:
    """Return the position of the whole document."""
    return _At(Location("spec", source=source), {}, []).within(document)


class _LinedDict(dict[Any, Any]):
    """A mapping that remembers the line it started on.

    The line travels **on the object** rather than in a side table keyed by
    ``id()``. A side table has two ways to be wrong and no third: hold every
    mapping alive so its id stays valid, and it leaks; do not, and it reports
    some other object's line once an id has been reused.

    It is a ``dict`` in every other respect, and compares equal to one, so
    nothing downstream needs to know it exists.
    """

    __slots__ = ("line",)

    line: int


@cache
def _lined_loader(yaml: Any) -> Any:
    """Return a ``SafeLoader`` subclass that records where each mapping starts.

    Built on first use rather than at import: PyYAML is an optional extra, so
    there is nothing of its to subclass until a YAML spec is actually loaded.

    Still **safe**: this adds a constructor for the plain mapping tag and
    changes nothing else, so a document naming a Python type to build is
    refused here exactly as it is by ``safe_load``.

    Args:
        yaml: The imported PyYAML module.

    Returns:
        The loader class, the same one every time.

    """

    class LinedLoader(yaml.SafeLoader):  # type: ignore[misc, name-defined]
        """``SafeLoader``, plus the line each mapping starts on."""

        def construct_yaml_map(self, node: Any) -> Any:
            """Build a mapping that carries its own line."""
            data = _LinedDict()
            data.line = node.start_mark.line + 1
            # Two-step, as PyYAML's own does: the empty mapping is yielded
            # first so a document that refers to itself has something to
            # point at before its contents exist.
            yield data
            data.update(self.construct_mapping(node))

    LinedLoader.add_constructor("tag:yaml.org,2002:map", LinedLoader.construct_yaml_map)
    return LinedLoader


# --- entry points ----------------------------------------------------------


def from_dict(document: Mapping[str, Any], *, source: str | None = None) -> Spec:
    """Build a spec from an already-parsed mapping.

    Every path leads here, including the two that know where the document came
    from, so line tracking is one implementation rather than three: a mapping
    parsed by :func:`from_yaml` carries its own lines and this reads them off,
    and a mapping from anywhere else does not and this reports paths alone.

    Args:
        document: The spec document.
        source: The file it was read from, for error messages. ``None`` when it
            came from memory, which is the ordinary case for a generated spec.

    Returns:
        The spec. It is well formed; run :func:`kober.check.check` to learn
        whether it is valid.

    Raises:
        SpecError: If the document is malformed.

    """
    return _spec(document, _root(document, source))


def from_json(text: str, *, source: str | None = None) -> Spec:
    """Build a spec from JSON text.

    ``json`` reports no positions, so a fault carries its path and no line.

    Args:
        text: The JSON document.
        source: The file it was read from, for error messages.

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
    at = _root(document, source)
    return from_dict(_require_mapping(document, at), source=source)


def from_yaml(text: str, *, source: str | None = None) -> Spec:
    """Build a spec from YAML text.

    Args:
        text: The YAML document.
        source: The file it was read from, for error messages.

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
        document = yaml.load(text, _lined_loader(yaml))
    except yaml.YAMLError as exc:
        msg = f"cannot parse YAML: {exc}"
        raise SpecError(msg) from exc
    at = _root(document, source)
    return from_dict(_require_mapping(document, at), source=source)


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
    source = str(resolved)
    return from_json(text, source=source) if fmt == "json" else from_yaml(text, source=source)


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


def _require_mapping(value: object, at: _At) -> Mapping[str, Any]:
    """Return ``value`` as a mapping with string keys, or raise."""
    mapping = _require_any_mapping(value, at)
    for key in mapping:
        if not isinstance(key, str):
            msg = f"keys must be strings, got {key!r}"
            raise SpecError(msg, at.loc)
    return mapping


def _require_any_mapping(value: object, at: _At) -> Mapping[Any, Any]:
    """Return ``value`` as a mapping, whatever its keys are.

    Enum members and switch cases are keyed by the *value* they name, which
    YAML gives as an integer and JSON can only give as a string. Both have to
    mean the same thing, so neither can be held to the string-key rule the
    rest of the schema follows.
    """
    if not isinstance(value, dict):
        msg = f"expected a mapping, got {type(value).__name__}"
        raise SpecError(msg, at.loc)
    return value


def _require_list(value: object, at: _At) -> list[Any]:
    """Return ``value`` as a list, or raise."""
    if not isinstance(value, list):
        msg = f"expected a list, got {type(value).__name__}"
        raise SpecError(msg, at.loc)
    return value


def _require_str(value: object, at: _At) -> str:
    """Return ``value`` as a string, or raise with a YAML hint."""
    if not isinstance(value, str):
        msg = f"expected a string, got {type(value).__name__}{_yaml_hint(value)}"
        raise SpecError(msg, at.loc)
    return value


def _require_int(value: object, at: _At) -> int:
    """Return ``value`` as an integer, or raise. Booleans are not integers."""
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"expected an integer, got {type(value).__name__}{_yaml_hint(value)}"
        raise SpecError(msg, at.loc)
    return value


def _require_bool(value: object, at: _At) -> bool:
    """Return ``value`` as a boolean, or raise."""
    if not isinstance(value, bool):
        msg = f"expected true or false, got {type(value).__name__}"
        raise SpecError(msg, at.loc)
    return value


def _reject_unknown(
    mapping: Mapping[str, Any],
    allowed: frozenset[str],
    at: _At,
    *groups: tuple[str, frozenset[str]],
) -> None:
    """Refuse keys outside the schema, saying which set each allowed key is from.

    A field's keys come from three sets rather than one, since both the type
    kind and the repeat kind lift into it. Listing all eighteen as a single
    alphabetical run would say nothing about why each is there, so ``groups``
    names the extra sets and the message keeps them apart.

    Args:
        mapping: The mapping to check.
        allowed: The keys this construct takes in its own right.
        at: Where in the document this is.
        *groups: Further ``(label, keys)`` sets, each named in the message.

    Raises:
        SpecError: If any key is in none of the sets.

    """
    every = allowed.union(*(keys for _, keys in groups))
    unknown = sorted(set(mapping) - every)
    if unknown:
        listed = ", ".join(repr(key) for key in unknown)
        named = [f"allowed here: {', '.join(sorted(allowed))}"]
        named += [f"{label}: {', '.join(sorted(keys))}" for label, keys in groups]
        msg = f"unknown key(s) {listed}; " + "; ".join(named)
        raise SpecError(msg, at.loc)


def _tagged(mapping: Mapping[str, Any], at: _At, kinds: frozenset[str]) -> tuple[str, Any]:
    """Unpack a single-key tagged mapping, e.g. ``{int: {...}}``."""
    if len(mapping) != 1:
        known = ", ".join(sorted(kinds))
        listed = ", ".join(repr(key) for key in sorted(mapping)) or "nothing"
        msg = (
            f"expected exactly one key naming the kind, got {listed}. "
            f"Choose one of: {known}"
        )
        raise SpecError(msg, at.loc)
    tag, value = next(iter(mapping.items()))
    if tag not in kinds:
        known = ", ".join(sorted(kinds))
        msg = f"unknown kind {tag!r}; expected one of: {known}"
        raise SpecError(msg, at.loc)
    return tag, value


def _member(enum_class: type[_E], value: object, at: _At) -> _E:
    """Look a string up in an enumeration, listing the alternatives."""
    text = _require_str(value, at)
    for member in enum_class:
        if member.value == text:
            return member
    known = ", ".join(sorted(str(member.value) for member in enum_class))
    msg = f"unknown value {text!r}; expected one of: {known}"
    raise SpecError(msg, at.loc)


def _expr(value: object, at: _At) -> Expr:
    """Parse an expression, accepting a bare integer as a literal."""
    if isinstance(value, bool):
        msg = f"expected an expression{_yaml_hint(value)}"
        raise SpecError(msg, at.loc)
    if isinstance(value, int):
        return parse(str(value), at.loc)
    return parse(_require_str(value, at), at.loc)


# --- the document ----------------------------------------------------------


def _spec(document: Mapping[str, Any], at: _At) -> Spec:
    """Build the top-level spec, recording where its named parts are."""
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, _SPEC_KEYS, at, ("a packeteer key", frozenset(_FOREIGN_SPEC_KEYS)))
    for required in ("name", "version", "entry", "units"):
        if required not in mapping:
            msg = f"missing required key {required!r}"
            raise SpecError(msg, at.loc)

    # The checker's paths lead with the spec's name, so the name is needed
    # before the units are built rather than when the spec is constructed. It
    # is read without validating: a name that is not a string is still an
    # error, raised where it always was, below.
    declared = mapping["name"]
    owner = declared if isinstance(declared, str) else "spec"
    at.record(owner)
    at.note_foreign(mapping, _FOREIGN_SPEC_KEYS, owner)
    at = at.defaulting(mapping)

    units_doc = _require_mapping(mapping["units"], at.child("units"))
    units = {
        name: _unit(name, value, at.child("units").child(name), owner)
        for name, value in units_doc.items()
    }
    enums_doc = _require_mapping(mapping.get("enums", {}), at.child("enums"))
    enums = {
        name: _enum(name, value, at.child("enums").child(name)) for name, value in enums_doc.items()
    }
    shape = (
        InputShape.EITHER
        if "input" not in mapping
        else _member(InputShape, mapping["input"], at.child("input"))
    )
    transforms = _transform_decls(mapping.get("transforms", {}), at.child("transforms"), owner)
    doc_params = _doc_params(mapping.get("params", {}), at.child("params"), owner)
    return Spec(
        name=_require_str(mapping["name"], at.child("name")),
        version=_require_str(mapping["version"], at.child("version")),
        entry=_require_str(mapping["entry"], at.child("entry")),
        units=units,
        enums=enums,
        input=shape,
        doc=_optional_str(mapping, "doc", at),
        sources=SourceMap(source=at.loc.source, lines=dict(at.lines)),
        transforms=transforms,
        params=doc_params,
        foreign=tuple(at.found),
    )


def _optional_str(mapping: Mapping[str, Any], key: str, at: _At) -> str | None:
    """Read an optional string key."""
    if key not in mapping or mapping[key] is None:
        return None
    return _require_str(mapping[key], at.child(key))


def _enum(name: str, document: object, at: _At) -> EnumDef:
    """Build an enum, accepting the plain ``{0: label}`` shorthand."""
    at = at.within(document)
    mapping = _require_any_mapping(document, at)
    # A bare {0: query} mapping has no schema keys, so treat anything without
    # 'members' as the shorthand for it.
    if "members" not in mapping:
        return EnumDef(name=name, members=_enum_members(mapping, at))
    _reject_unknown(_require_mapping(mapping, at), _ENUM_KEYS, at)
    members = _require_any_mapping(mapping["members"], at.child("members"))
    return EnumDef(
        name=name,
        members=_enum_members(members, at.child("members")),
        doc=_optional_str(mapping, "doc", at),
    )


def _enum_members(mapping: Mapping[Any, Any], at: _At) -> dict[int, str]:
    """Read enum members, whose keys are integers however they were written."""
    members: dict[int, str] = {}
    for key, label in mapping.items():
        # JSON object keys are always strings; YAML gives real ints. A bool is
        # not a member value, however Python spells its subclassing.
        if isinstance(key, bool):
            msg = f"enum member key {key!r} is not an integer{_yaml_hint(key)}"
            raise SpecError(msg, at.loc)
        try:
            value = int(key)
        except (TypeError, ValueError):
            msg = f"enum member key {key!r} is not an integer"
            raise SpecError(msg, at.loc) from None
        members[value] = _require_str(label, at.child(key))
    return members


def _unit(name: str, document: object, at: _At, owner: str) -> Unit:
    """Build one unit.

    Args:
        name: The unit's name, which is its key in the ``units`` mapping.
        document: The unit's body.
        at: Where in the document this is.
        owner: The spec's name, which leads the paths the checker reports at.

    Returns:
        The unit.

    Raises:
        SpecError: If the body is malformed.

    """
    at = at.within(document)
    path = f"{owner}.{name}"
    at.record(path)
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, _UNIT_KEYS, at)
    at = at.defaulting(mapping)
    if "fields" not in mapping:
        msg = "missing required key 'fields'"
        raise SpecError(msg, at.loc)
    fields = [
        _field(item, at.child("fields").child(f"[{index}]"), path, index)
        for index, item in enumerate(_require_list(mapping["fields"], at.child("fields")))
    ]
    params = [
        _param(item, at.child("params").child(f"[{index}]"))
        for index, item in enumerate(_require_list(mapping.get("params", []), at.child("params")))
    ]
    return Unit(
        name=name,
        fields=fields,
        params=params,
        confirm=_optional_expr(mapping, "confirm", at),
        reject=_optional_expr(mapping, "reject", at),
        emit=_optional_emit(mapping, at),
        doc=_optional_str(mapping, "doc", at),
    )


def _optional_expr(mapping: Mapping[str, Any], key: str, at: _At) -> Expr | None:
    """Read an optional expression key."""
    if key not in mapping or mapping[key] is None:
        return None
    return _expr(mapping[key], at.child(key))


def _optional_emit(mapping: Mapping[str, Any], at: _At) -> Emit | None:
    """Read an optional emit key."""
    if "emit" not in mapping or mapping["emit"] is None:
        return None
    return _member(Emit, mapping["emit"], at.child("emit"))


def _param(document: object, at: _At) -> Param:
    """Build one unit parameter, from either spelling.

    A parameter is a name and a type, and every other tagged construct in the
    schema is a single-key mapping from a name to a body — so a parameter may
    be written as one too::

        params: [{name: high, type: int}]   # long
        params: [{high: int}]               # the same thing

    **Which form is meant is decided by the keys, not by the count.** A mapping
    naming ``name`` or ``type`` is the long form, so ``{name: high}`` is a long
    form missing its type rather than a parameter called ``name`` of type
    ``high`` — which would be the reading a count-based rule gave it, and an
    unhelpful error. The cost is that the short form cannot declare a parameter
    called ``name`` or ``type``; the long form can, and that is what it is for.

    **The list stays a list.** Arguments bind positionally, so parameter order
    is load-bearing, and YAML does not promise mapping order — a bare
    ``params: {high: int}`` would make argument binding depend on something the
    encoding does not guarantee.

    Args:
        document: One entry of ``params``.
        at: Where in the document this is.

    Returns:
        The parameter.

    Raises:
        SpecError: If a key is missing, unknown, or the entry names more than
            one parameter.

    """
    at = at.within(document)
    mapping = _require_mapping(document, at)
    if not _PARAM_KEYS & set(mapping):
        return _short_param(mapping, at)
    _reject_unknown(mapping, _PARAM_KEYS, at)
    for required in ("name", "type"):
        if required not in mapping:
            msg = (
                f"missing required key {required!r}; a parameter is "
                "{name: type}, or {name: …, type: …} written out"
            )
            raise SpecError(msg, at.loc)
    return Param(
        name=_require_str(mapping["name"], at.child("name")),
        type=_member(ExprType, mapping["type"], at.child("type")),
    )


def _short_param(mapping: Mapping[str, Any], at: _At) -> Param:
    """Build a parameter from the single-key ``{name: type}`` spelling."""
    if len(mapping) != 1:
        listed = ", ".join(repr(key) for key in sorted(mapping)) or "nothing"
        msg = (
            f"a parameter entry names one parameter, and this names {listed}. "
            "Give each its own entry, since arguments bind in order."
        )
        raise SpecError(msg, at.loc)
    name, declared = next(iter(mapping.items()))
    return Param(name=name, type=_member(ExprType, declared, at.child(name)))


def _field(document: object, at: _At, owner: str, index: int) -> Field:
    """Build one field, from either spelling of its type and its repetition.

    Both tagged constructs a field carries may be **lifted into it**, under the
    rule this module's docstring states: a kind key stands where its wrapper
    would have gone, because the three key sets do not overlap.

        - {name: n, type: {int: {bits: 8}}, repeat: {count: "n"}}
        - {name: n, bits: 8, count: n}

    It costs no strictness either way: exactly one key may name a type kind and
    at most one a repeat kind, naming both a kind and its wrapper is an error,
    and a key in none of the three sets is still an error.

    Args:
        document: The field's mapping.
        at: Where in the document this is.
        owner: The unit's path, which the checker reports this field under.
        index: Its position in the unit, which names it when it is anonymous —
            the same label the checker uses.

    Returns:
        The field.

    Raises:
        SpecError: If the mapping is malformed.

    """
    at = at.within(document)
    mapping = _require_mapping(document, at)
    _reject_unknown(
        mapping,
        _FIELD_KEYS,
        at,
        ("a type kind", _TYPE_KEYS),
        ("a repeat kind", _REPEAT_KINDS),
        ("a packeteer key", frozenset(_FOREIGN_FIELD_KEYS)),
    )
    if "name" not in mapping:
        msg = "missing required key 'name'; use 'name: null' for an anonymous field"
        raise SpecError(msg, at.loc)
    raw_name = mapping["name"]
    name = None if raw_name is None else _require_str(raw_name, at.child("name"))
    label = name if name is not None else f"<anonymous {index}>"
    if name is not None:
        # An anonymous field is recorded under nothing: the checker has no name
        # to report it by either, so there is no path to key it on.
        at.record(f"{owner}.{name}")
    at.note_foreign(mapping, _FOREIGN_FIELD_KEYS, f"{owner}.{label}")
    kind = _declared_type(mapping, at)
    return Field(
        name=name,
        type=kind,
        condition=_optional_expr(mapping, "condition", at),
        repeat=_declared_repeat(mapping, at),
        emit=_optional_emit(mapping, at),
        doc=_optional_str(mapping, "doc", at),
        const=_const(mapping, kind, at),
    )


def _const(mapping: Mapping[str, Any], kind: FieldType, at: _At) -> int | bytes | str | None:
    """Read a field's constant, in the spelling its own type gives it.

    A number for an integer, text for a string, and for ``bytes`` either a list
    of byte values or text — which is encoded here, so a magic number reads as
    what it is (``const: "GET"``) rather than as four numbers.

    That one conversion is the whole of what this knows about types. Whether
    the constant *fits* the field — that the type holds a value at all, that
    the two types agree, that an integer is not wider than its field — is
    :func:`kober.check.check`'s, which reports every fault at once rather than
    stopping at this one.

    Args:
        mapping: The field's mapping.
        kind: The field's type, already built.
        at: Where in the document this is.

    Returns:
        The constant, or ``None`` when the field declares none.

    Raises:
        SpecError: If the value is not a number, text, or a list of byte
            values.

    """
    if "const" not in mapping or mapping["const"] is None:
        return None
    site = at.child("const")
    value = mapping["const"]
    if isinstance(value, bool):
        msg = f"a constant is a number, text, or a list of byte values{_yaml_hint(value)}"
        raise SpecError(msg, site.loc)
    if isinstance(value, list):
        return _delimiter(value, site)
    if isinstance(value, str) and isinstance(kind, BytesType):
        return value.encode("utf-8")
    if isinstance(value, (int, str)):
        return value
    msg = f"a constant is a number, text, or a list of byte values, not {type(value).__name__}"
    raise SpecError(msg, site.loc)


def _declared_type(mapping: Mapping[str, Any], at: _At) -> FieldType:
    """Read a field's type, from ``type:`` or from a lifted kind key."""
    lifted = sorted(set(mapping) & _TYPE_KEYS)
    if "type" in mapping:
        if lifted:
            listed = ", ".join(repr(key) for key in lifted)
            msg = (
                "a field states its type once; it has 'type' and also "
                f"{listed}. Drop one."
            )
            raise SpecError(msg, at.loc)
        return _field_type(mapping["type"], at.child("type"))
    if len(lifted) > 1:
        listed = ", ".join(repr(key) for key in lifted)
        msg = f"a field states its type once, and this names {listed}"
        raise SpecError(msg, at.loc)
    if not lifted:
        known = ", ".join(sorted(_TYPE_KEYS))
        msg = (
            "missing required key 'type'; a field must say what it "
            f"decodes, either as 'type:' or as one of: {known}"
        )
        raise SpecError(msg, at.loc)
    tag = lifted[0]
    return _field_type({tag: mapping[tag]}, at)


def _declared_repeat(mapping: Mapping[str, Any], at: _At) -> Repeat | None:
    """Read a field's repetition, from ``repeat:`` or from a lifted kind key.

    The same rule as :func:`_declared_type`, applied to the construct beside
    it: repetition is the second most common thing a field says, and it was
    the only common one still paying for its wrapper.

    Unlike a type, a repetition is **optional**, so no kind at all is the
    ordinary case rather than an error.
    """
    lifted = sorted(set(mapping) & _REPEAT_KINDS)
    if "repeat" in mapping:
        if lifted:
            listed = ", ".join(repr(key) for key in lifted)
            msg = (
                "a field repeats one way; it has 'repeat' and also "
                f"{listed}. Drop one."
            )
            raise SpecError(msg, at.loc)
        # A falsy body — `repeat:` with nothing under it — has always meant no
        # repetition rather than an empty one.
        return _repeat(mapping["repeat"], at.child("repeat")) if mapping["repeat"] else None
    if len(lifted) > 1:
        listed = ", ".join(repr(key) for key in lifted)
        msg = f"a field repeats one way, and this names {listed}"
        raise SpecError(msg, at.loc)
    if not lifted:
        return None
    tag = lifted[0]
    return _repeat({tag: mapping[tag]}, at)


# --- types, sizes, repeats -------------------------------------------------

_TYPE_KINDS = frozenset(
    {
        "int", "bytes", "string", "unit", "switch", "computed", "pointer", "select",
        "concat", "transform",
    }
)
#: Every key that may *name* a type, whether lifted into a field or used as the
#: tag under ``type:``. ``bits`` is an alias for the ``int`` kind rather than a
#: kind of its own — which is why it is not in :data:`_TYPE_KINDS`, the set of
#: things this language actually decodes.
#:
#: It earns the alias by saying what the number counts. ``int: 8`` is shorter
#: and cannot: Kaitai's ``u8`` means eight *bytes*, so a reader arriving from
#: there would read ``int: 8`` as a 64-bit field and be silently wrong. Sub-byte
#: fields are the normal case here rather than the exotic one — a DNS flags word
#: is eight of them — and ``bits: 1`` needs no prior knowledge of this schema to
#: read correctly.
_TYPE_KEYS = _TYPE_KINDS | {"bits"}
#: Every key of a ``select``, and all four are required. There is no default
#: for ``default``: the whole case for putting aggregation in the model is that
#: "nothing matched" has an answer the author wrote (:class:`~kober.spec.Select`).
_SELECT_KEYS = frozenset({"from", "where", "value", "default", "as"})
#: The four of them that are required. ``as`` is not: omitting it binds the
#: element under the source's own name, which is what every spec did before
#: the key existed.
_SELECT_REQUIRED = frozenset({"from", "where", "value", "default"})
#: Every key of an ``until``, whose principal key is ``expr`` — so a bare
#: expression is the shorthand, exactly as a bare size is ``fixed``.
_UNTIL_KEYS = frozenset({"expr", "as"})
_SIZE_KINDS = frozenset({"fixed", "expr", "terminated", "remaining", "fill"})
_REPEAT_KINDS = frozenset({"count", "until", "to_end"})


def _field_type(document: object, at: _At) -> FieldType:
    """Build a field type from its single-key tagged mapping."""
    at = at.within(document)
    mapping = _require_mapping(document, at)
    tag, value = _tagged(mapping, at, _TYPE_KEYS)
    site = at.child(tag)
    if tag == "bits":
        # The alias, and it takes the number directly: `bits` *is* the key it
        # would otherwise name, so a mapping under it would be `bits: {bits: 4}`.
        # It is the shorthand an inherited byte order exists to keep usable, so
        # it takes the default like any other integer.
        return IntType(bits=_require_int(value, site), endian=at.endian)
    if tag == "int":
        return _int_type(value, site)
    if tag == "bytes":
        return BytesType(size=_body_size(value, site, _BYTES_KEYS))
    if tag == "string":
        if isinstance(value, (int, str)) and not isinstance(value, bool):
            return StringType(size=_body_size(value, site, _STRING_KEYS))
        body = _require_mapping(value, site)
        encoding = body.get("encoding")
        return StringType(
            size=_body_size(body, site, _STRING_KEYS),
            encoding=(
                "utf-8" if encoding is None else _require_str(encoding, site.child("encoding"))
            ),
        )
    if tag == "unit":
        return _unit_ref(value, site)
    if tag == "switch":
        return _switch(value, site)
    if tag == "pointer":
        return _pointer(value, site)
    if tag == "select":
        return _select(value, site)
    if tag == "concat":
        return _concat(value, site)
    if tag == "transform":
        return _transform(value, site)
    return Computed(expr=_expr(value, site))


def _body_size(document: object, at: _At, allowed: frozenset[str]) -> SizeSpec:
    r"""Read how far a ``bytes`` or ``string`` value extends.

    Three spellings, and the last two are the reason this is one function.

    A **bare scalar** is the principal key filled in: ``{bytes: 4}`` is a fixed
    size, the same rule that lets ``size: 4`` mean ``{fixed: 4}``.

    A ``delimiter:`` **beside** ``size:`` says the value is terminated, with
    ``consume``, ``required`` and ``within`` sitting alongside it. Reading up to
    a delimiter is the commonest thing a text protocol does and was the deepest
    thing to write — ``{string: {size: {terminated: {delimiter: "\\r\\n"}}}}``
    is four levels to say *read to CRLF* — and the long form is most of that
    depth rather than the terminator's own keys.

    ``delimiter`` rather than a bare string size (``size: "\\r\\n"``) because it
    **says what it is**: a bare string there reads like a mistake until you know
    the rule, where this needs no rule. It is not the rejected ``until:`` either
    — that word already means a repeat kind, and this one appears nowhere else.
    Its companions sit beside it so the growth path is adding a key rather than
    rewriting the shape: half of ``examples/http.yaml``'s header unit needs
    ``within`` and ``required``, so the bounded case is not the rare one.

    The long ``size: {terminated: {…}}`` form still works and is what a nested
    or unusual size uses.

    Args:
        document: The type's body, or a bare scalar.
        at: Where in the document this is.
        allowed: The keys this type's body accepts.

    Returns:
        The size.

    Raises:
        SpecError: If the body says its size twice, not at all, or with a
            terminator key and no delimiter.

    """
    at = at.within(document)
    if isinstance(document, bool) or not isinstance(document, dict):
        return _size(document, at.child("size"))
    _reject_unknown(document, allowed, at)
    delimited = sorted(set(document) & _TERMINATED_KEYS)
    if "size" in document:
        if delimited:
            listed = ", ".join(repr(key) for key in delimited)
            msg = (
                "a value states its extent once; it has 'size' and also "
                f"{listed}. Put the terminator under size: {{terminated: ...}}, "
                "or drop size."
            )
            raise SpecError(msg, at.loc)
        return _size(document["size"], at.child("size"))
    if not delimited:
        msg = "missing required key 'size'"
        raise SpecError(msg, at.loc)
    if "delimiter" not in document:
        listed = ", ".join(repr(key) for key in delimited)
        verb = "means" if len(delimited) == 1 else "mean"
        msg = (
            f"{listed} only {verb} something beside a 'delimiter', and "
            "there is none here"
        )
        raise SpecError(msg, at.loc)
    return _terminated(document, at)


def _int_type(document: object, at: _At) -> IntType:
    """Build an integer type, accepting a bare width."""
    at = at.within(document)
    if isinstance(document, bool) or not isinstance(document, dict):
        return IntType(bits=_require_int(document, at.child("bits")), endian=at.endian)
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, _INT_KEYS, at)
    if "bits" not in mapping:
        msg = "missing required key 'bits'"
        raise SpecError(msg, at.loc)
    endian = mapping.get("endian")
    enum = mapping.get("enum")
    return IntType(
        bits=_require_int(mapping["bits"], at.child("bits")),
        signed=_require_bool(mapping.get("signed", False), at.child("signed")),
        endian=at.endian if endian is None else _member(Endian, endian, at.child("endian")),
        enum=None if enum is None else _require_str(enum, at.child("enum")),
    )


def _unit_ref(document: object, at: _At) -> UnitRef:
    """Build a unit reference, accepting the bare-name shorthand."""
    at = at.within(document)
    if isinstance(document, str):
        return UnitRef(unit=document)
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, frozenset({"name", "args"}), at)
    if "name" not in mapping:
        msg = "missing required key 'name'"
        raise SpecError(msg, at.loc)
    args = _require_list(mapping.get("args", []), at.child("args"))
    return UnitRef(
        unit=_require_str(mapping["name"], at.child("name")),
        args=[_expr(item, at.child("args").child(f"[{index}]")) for index, item in enumerate(args)],
    )


def _select(document: object, at: _At) -> Select:
    """Build a select: which repetition, which element, and what to take from it.

    All four keys are required, ``default`` included, and the error names every
    one that is missing rather than the first — an author writing a new
    construct wants the whole shape, not one key at a time.

    ``from`` is spelled that way in a document and stored as
    :attr:`~kober.spec.Select.source`, because ``from`` is a Python keyword and
    cannot be a field name.

    Args:
        document: The mapping under the ``select`` tag.
        at: Where in the document this is.

    Returns:
        The select.

    Raises:
        SpecError: If a key is missing, unknown, or the wrong shape.

    """
    at = at.within(document)
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, _SELECT_KEYS, at)
    missing = sorted(_SELECT_REQUIRED - set(mapping))
    if missing:
        listed = ", ".join(repr(key) for key in missing)
        msg = f"missing required key(s) {listed}"
        raise SpecError(msg, at.loc)
    return Select(
        source=_require_str(mapping["from"], at.child("from")),
        where=_expr(mapping["where"], at.child("where")),
        value=_expr(mapping["value"], at.child("value")),
        default=_expr(mapping["default"], at.child("default")),
        alias=_optional_str(mapping, "as", at),
    )


def _concat(document: object, at: _At) -> Concat:
    """Build a concat from ``repeated.member``.

    One dotted name, of exactly two parts: the repeated field, and the field of
    each element to join. A deeper path would be a list inside a list, which
    the construct does not mean.

    Args:
        document: The value under the ``concat`` tag.
        at: Where in the document this is.

    Returns:
        The concat.

    Raises:
        SpecError: If it is not a two-part dotted name.

    """
    text = _require_str(document, at)
    repeated, dot, member = text.partition(".")
    if not dot or not repeated or not member or "." in member:
        msg = (
            f"concat names a repeated field and the field of each element to join, "
            f"as 'chunks.data'; got {text!r}"
        )
        raise SpecError(msg, at.loc)
    return Concat(repeated=repeated, member=member)


def _transform(document: object, at: _At) -> Transform:
    """Build a transform: which bytes, which transform, and what comes out.

    ``from``, ``with`` and ``limit`` are required, and the error names every
    one that is missing. ``args`` maps a declared parameter to an expression.

    Args:
        document: The mapping under the ``transform`` tag.
        at: Where in the document this is.

    Returns:
        The transform.

    Raises:
        SpecError: If a key is missing, unknown, or the wrong shape.

    """
    at = at.within(document)
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, _TRANSFORM_KEYS, at)
    missing = [key for key in _TRANSFORM_REQUIRED if key not in mapping]
    if missing:
        listed = ", ".join(repr(key) for key in missing)
        msg = f"missing required key(s) {listed}"
        raise SpecError(msg, at.loc)
    args_doc = _require_mapping(mapping.get("args", {}), at.child("args"))
    try:
        return Transform(
            source=_require_str(mapping["from"], at.child("from")),
            name=_require_str(mapping["with"], at.child("with")),
            limit=_require_int(mapping["limit"], at.child("limit")),
            args={
                _require_str(name, at.child("args")): _expr(value, at.child("args").child(name))
                for name, value in args_doc.items()
            },
            type=_field_type(mapping["type"], at.child("type")) if "type" in mapping else None,
            content_type=_optional_str(mapping, "content_type", at),
        )
    except SpecError as exc:
        # The model's own checks (a limit that is not positive) know no
        # position; this is where the transform is.
        if exc.loc is not None:
            raise
        raise SpecError(exc.message, at.loc) from exc


def _transform_decls(document: object, at: _At, owner: str) -> dict[str, TransformDecl]:
    """Build the ``transforms:`` block: each name a spec uses and its parameters.

    A declaration with nothing to say is written ``{}`` or left empty, which is
    how a spec says it uses an extended-tier name.
    """
    mapping = _require_mapping(document, at)
    decls: dict[str, TransformDecl] = {}
    for name, value in mapping.items():
        site = at.child(name)
        body = _require_mapping({} if value is None else value, site)
        _reject_unknown(body, _TRANSFORM_DECL_KEYS, site)
        params_doc = _require_mapping(body.get("params", {}), site.child("params"))
        site.record(f"{owner}.transforms.{name}")
        decls[name] = TransformDecl(
            name=name,
            params={
                param: _member(ExprType, kind, site.child("params").child(param))
                for param, kind in params_doc.items()
            },
        )
    return decls


def _doc_params(document: object, at: _At, owner: str) -> list[Param]:
    """Build the ``params:`` block: values supplied when a decode is set up.

    Keyed by name, unlike a unit's list, because they are supplied by name
    rather than bound in order. ``key: bytes`` is the short form, and
    ``key: {type: bytes, secret: true}`` the long one.
    """
    mapping = _require_mapping(document, at)
    params: list[Param] = []
    for name, value in mapping.items():
        site = at.child(name)
        site.record(f"{owner}.params.{name}")
        if isinstance(value, str):
            params.append(Param(name=name, type=_member(ExprType, value, site)))
            continue
        body = _require_mapping(value, site)
        _reject_unknown(body, _DOC_PARAM_KEYS, site)
        if "type" not in body:
            msg = "missing required key 'type'"
            raise SpecError(msg, site.loc)
        secret = body.get("secret", False)
        if not isinstance(secret, bool):
            msg = f"'secret' is true or false, got {secret!r}"
            raise SpecError(msg, site.child("secret").loc)
        kind = _member(ExprType, body["type"], site.child("type"))
        params.append(Param(name=name, type=kind, secret=secret))
    return params


def _pointer(document: object, at: _At) -> Pointer:
    """Build a pointer: where to read, and what is there.

    Both keys are required. There is deliberately no shorthand and no default
    offset space — the ``at`` key is always message-relative, so there is
    nothing for a spec to mean by accident.

    Args:
        document: The mapping under the ``pointer`` tag.
        at: Where in the document this is.

    Returns:
        The pointer.

    Raises:
        SpecError: If a key is missing or unknown.

    """
    at = at.within(document)
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, _POINTER_KEYS, at)
    for required in ("at", "type"):
        if required not in mapping:
            msg = f"missing required key {required!r}"
            raise SpecError(msg, at.loc)
    return Pointer(
        at=_expr(mapping["at"], at.child("at")),
        type=_field_type(mapping["type"], at.child("type")),
    )


def _switch(document: object, at: _At) -> Switch:
    """Build a switch, naming the old dispatch key if it is still being used."""
    at = at.within(document)
    raw = _require_any_mapping(document, at)
    _reject_renamed_dispatch(raw, at)
    mapping = _require_mapping(raw, at)
    _reject_unknown(mapping, _SWITCH_KEYS, at)
    for required in ("dispatch", "cases"):
        if required not in mapping:
            msg = f"missing required key {required!r}"
            raise SpecError(msg, at.loc)
    cases_doc = _require_any_mapping(mapping["cases"], at.child("cases"))
    cases: dict[int | str, FieldType] = {}
    for key, value in cases_doc.items():
        site = at.child("cases").child(key)
        cases[_case_key(key, site)] = _field_type(value, site)
    default = mapping.get("default")
    return Switch(
        dispatch=_expr(mapping["dispatch"], at.child("dispatch")),
        cases=cases,
        default=None if default is None else _field_type(default, at.child("default")),
    )


def _reject_renamed_dispatch(mapping: Mapping[Any, Any], at: _At) -> None:
    """Name the rename for a spec still written with the old ``on`` key.

    ``on`` was the dispatch key until 0.1.0 and is now ``dispatch``. Both
    spellings of the old one are caught: the quoted ``"on"``, and the ``True``
    that YAML 1.1 turns an unquoted ``on:`` into — which is why the key was
    renamed, and why leaving the boolean to fall through to "keys must be
    strings" would report the coercion rather than the cause.

    This accepts nothing. It is an error message, not an alias: there is one
    spelling of the dispatch key, and the point of the rename was to stop the
    loader carrying a second one.
    """
    for key in (True, "on"):
        if key in mapping:
            msg = (
                "the switch dispatch key is 'dispatch'; it was 'on' "
                "until 0.1.0 and was renamed because YAML 1.1 reads an unquoted "
                "on: as the boolean true. Write dispatch: instead."
            )
            raise SpecError(msg, at.loc)


def _case_key(key: object, at: _At) -> int | str:
    """Read a case key as an integer where it looks like one.

    JSON object keys are always strings, so ``{"1": ...}`` and YAML's ``{1:
    ...}`` have to mean the same thing. Whether the key is *correct* is the
    checker's call, against the type dispatched on — including a ``true:`` key
    YAML invented, which survives to be reported there rather than here.

    Args:
        key: The case key as authored.
        at: Where in the document this is.

    Returns:
        The key, as an integer where it reads as one.

    Raises:
        SpecError: If the key is neither an integer nor a string.

    """
    if isinstance(key, (bool, int)):
        return key
    if isinstance(key, str):
        try:
            return int(key)
        except ValueError:
            return key
    msg = f"switch case key {key!r} must be an integer or a string"
    raise SpecError(msg, at.loc)


def _size(document: object, at: _At) -> SizeSpec:
    """Build a size spec, accepting a bare integer as ``fixed``."""
    at = at.within(document)
    if document is None:
        msg = "missing required key 'size'"
        raise SpecError(msg, at.loc)
    if isinstance(document, bool):
        msg = f"expected a size{_yaml_hint(document)}"
        raise SpecError(msg, at.loc)
    if isinstance(document, int):
        return Fixed(count=document)
    mapping = _require_mapping(document, at)
    tag, value = _tagged(mapping, at, _SIZE_KINDS)
    site = at.child(tag)
    if tag == "fixed":
        return Fixed(count=_require_int(value, site))
    if tag == "expr":
        return FromExpr(expr=_expr(value, site))
    if tag == "remaining":
        return Remaining()
    if tag == "fill":
        return Fill()
    body = _require_mapping(value, site)
    _reject_unknown(body, _TERMINATED_KEYS, site)
    if "delimiter" not in body:
        msg = "missing required key 'delimiter'"
        raise SpecError(msg, site.loc)
    return _terminated(body, site)


def _terminated(body: Mapping[str, Any], at: _At) -> Terminated:
    """Build a delimited size from the keys ``delimiter`` heads.

    One reader for both spellings — the long ``size: {terminated: {…}}`` and the
    ``delimiter:`` written beside ``size:`` — so a shorthand cannot come to mean
    anything the long form does not.
    """
    at = at.within(body)
    within = body.get("within")
    return Terminated(
        delimiter=_delimiter(body["delimiter"], at.child("delimiter")),
        consume=_require_bool(body.get("consume", True), at.child("consume")),
        required=_require_bool(body.get("required", True), at.child("required")),
        within=None if within is None else _delimiter(within, at.child("within")),
    )


def _delimiter(document: object, at: _At) -> bytes:
    """Read a delimiter, as text or as a list of byte values."""
    at = at.within(document)
    if isinstance(document, str):
        return document.encode("utf-8")
    values = _require_list(document, at)
    out = bytearray()
    for index, item in enumerate(values):
        value = _require_int(item, at.child(f"[{index}]"))
        if not 0 <= value <= 0xFF:
            msg = f"byte value must be 0..255, got {value}"
            raise SpecError(msg, at.child(f"[{index}]").loc)
        out.append(value)
    return bytes(out)


def _repeat(document: object, at: _At) -> Repeat:
    """Build a repeat clause."""
    at = at.within(document)
    mapping = _require_mapping(document, at)
    tag, value = _tagged(mapping, at, _REPEAT_KINDS)
    site = at.child(tag)
    if tag == "count":
        return Count(expr=_expr(value, site))
    if tag == "until":
        return _until(value, site)
    return ToEnd()


def _until(document: object, at: _At) -> Until:
    """Build an ``until``, accepting the bare-expression shorthand.

    ``expr`` is the principal key, so ``{until: "x == 0"}`` is
    ``{until: {expr: "x == 0"}}`` — the same rule that makes a bare size
    ``fixed``. The long form exists to carry ``as``, which names the element
    the condition tests rather than borrowing the repeated field's own name.
    """
    at = at.within(document)
    if not isinstance(document, dict):
        return Until(expr=_expr(document, at))
    mapping = _require_mapping(document, at)
    _reject_unknown(mapping, _UNTIL_KEYS, at)
    if "expr" not in mapping:
        msg = "missing required key 'expr'"
        raise SpecError(msg, at.loc)
    return Until(
        expr=_expr(mapping["expr"], at.child("expr")),
        alias=_optional_str(mapping, "as", at),
    )
