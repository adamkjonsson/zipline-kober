"""The language-neutral plan a backend renders into source text.

The compiler is split in two, and this is the middle::

    Spec ──→ Plan ──→ backend ──→ source text
             (here)   (kober.pygen)

**The rule that decides what belongs here.** This layer describes *what the
format means*; a backend decides *how a language says it*. A field has a byte
range and a value of some kind — that is meaning. Whether the range is exposed
as a dunder, a parallel array or an accessor, and whether the value's name is
``snake_case`` or has a trailing underscore to dodge a keyword, is a target's
business. Anything here that reads like a Python decision is in the wrong
layer.

So a plan carries **the spec's own names**, unmapped. Rust wants different
identifiers than Python and reserves different words, and a plan holding Python
identifiers would hand a second backend a mapping made for the wrong language.

**It is not an intermediate representation and should not become one.** It is
the ordered description a backend walks, with the spec's indirections resolved
and nothing invented. Stage 2 of the compiler phase puts the *object model*
here — what a decoded instance of each unit holds. The read and emit operations
join it in later stages.

Expressions stay as :mod:`kober.expr`'s ``Expr``, which is neutral already: the AST
is the spec's, not Python's, and every backend needs the same tree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING

from kober.check import require_valid, scope_at
from kober.errors import SpecError
from kober.expr import ExprType, infer_type, unparse
from kober.spec import BytesType, Computed, IntType, StringType, Switch, UnitRef

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from kober.expr import Expr
    from kober.spec import EnumDef, Field, FieldType, Spec


class Kind(Enum):
    """What kind of value a field holds, in no particular language.

    The four scalars are :class:`kober.expr.ExprType`'s members — a spec's
    values and its expressions are the same small set of types, and having two
    vocabularies for it would be surface with nothing behind it. ``OBJECT`` is
    the one addition: an instance of another unit, which an expression cannot
    name and therefore has no expression type.
    """

    INT = "int"
    BOOL = "bool"
    TEXT = "text"
    BYTES = "bytes"
    OBJECT = "object"


#: How an expression's type maps onto a value's kind. A ``computed:`` field's
#: kind is whatever its expression infers to.
KINDS: Mapping[ExprType, Kind] = MappingProxyType(
    {
        ExprType.INT: Kind.INT,
        ExprType.BOOL: Kind.BOOL,
        ExprType.STR: Kind.TEXT,
        ExprType.BYTES: Kind.BYTES,
    }
)


@dataclass(frozen=True)
class ValueType:
    """One kind of value a field can hold, and what is known about it.

    Attributes:
        kind: Which kind.
        bits: Declared width, for an ``INT`` read off the wire. ``None`` for a
            computed integer, which has no width until something writes it.
        signed: Whether an ``INT`` is two's complement.
        endian: Byte order of an ``INT``, as ``"big"`` or ``"little"``. A
            string rather than :class:`kober.spec.Endian` so that generated
            code never needs the spec model to read an integer.
        labels: Name of the enum labelling the value, as the spec spells it.
        encoding: Codec name for ``TEXT``, as the spec spells it.
        unit: Name of the unit an ``OBJECT`` is an instance of, as the spec
            spells it.

    """

    kind: Kind
    bits: int | None = None
    signed: bool = False
    endian: str = "big"
    labels: str | None = None
    encoding: str | None = None
    unit: str | None = None


@dataclass(frozen=True)
class FieldPlan:
    """What one field of a unit contributes to a decoded instance of it.

    Attributes:
        name: The field's name as the spec spells it, or ``None`` for an
            anonymous region. Anonymous fields are kept: they are read and
            cited, and only a *target* decides that they cannot be named.
        types: What it can hold. More than one only for a ``switch``, whose
            cases may differ — in case order, with any ``default`` last.
        repeated: Whether it holds many rather than one.
        condition: The expression deciding whether it is there at all, if any.
            Carried rather than reduced to a flag, because a target may want
            to say *when* a field is present.
        doc: The spec's own description, verbatim. Author-supplied text, and
            the reason a backend must escape rather than interpolate.

    """

    name: str | None
    types: tuple[ValueType, ...]
    repeated: bool = False
    condition: Expr | None = None
    doc: str | None = None

    @property
    def optional(self) -> bool:
        """Whether the field may be absent from a decoded instance."""
        return self.condition is not None


@dataclass(frozen=True)
class ParamPlan:
    """A value whoever references a unit must supply.

    Not a field: it decodes nothing and appears in no decoded instance. It is
    here because it is *in scope* for the unit's expressions, and because a
    target has to name it somewhere — a parameter of a function, most likely.

    Attributes:
        name: The parameter's name as the spec spells it.
        kind: What kind of value the caller must pass.

    """

    name: str
    kind: Kind


@dataclass(frozen=True)
class ObjectPlan:
    """One unit's shape: what a decoded instance of it holds.

    Attributes:
        unit: The unit's name as the spec spells it.
        fields: Its fields, in decode order, anonymous ones included.
        params: Values its callers supply, in declaration order.
        doc: The spec's own description, verbatim.

    """

    unit: str
    fields: tuple[FieldPlan, ...]
    params: tuple[ParamPlan, ...] = ()
    doc: str | None = None

    def field(self, name: str) -> FieldPlan | None:
        """Return one field by the name the spec gives it, or ``None``.

        Args:
            name: The field's name as the spec spells it.

        Returns:
            The field, or ``None`` if the unit has no such field. An anonymous
            field is never found: it has no name to look up.

        """
        for item in self.fields:
            if item.name == name:
                return item
        return None

    def param(self, name: str) -> ParamPlan | None:
        """Return one parameter by name, or ``None``.

        Args:
            name: The parameter's name as the spec spells it.

        Returns:
            The parameter, or ``None``.

        """
        for item in self.params:
            if item.name == name:
                return item
        return None


@dataclass(frozen=True)
class Plan:
    """A whole spec, reduced to what a backend needs and nothing more.

    Attributes:
        name: The spec's name.
        version: The spec's version.
        entry: Name of the unit a decode starts at.
        doc: The spec's own description, verbatim.
        enums: Every declared enum, by name.
        objects: One per unit reachable from ``entry``, in the order the spec
            declares them.

    """

    name: str
    version: str
    entry: str
    doc: str | None = None
    enums: Mapping[str, EnumDef] = field(default_factory=dict)
    objects: tuple[ObjectPlan, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "enums", MappingProxyType(dict(self.enums)))
        object.__setattr__(self, "objects", tuple(self.objects))

    @classmethod
    def from_spec(cls, spec: Spec, *, check: bool = True) -> Plan:
        """Reduce a spec to a plan.

        Args:
            spec: The spec to compile.
            check: Validate it first, refusing to build on an error. Every
                guarantee this reduction makes — that a unit reference
                resolves, that a ``computed:`` expression has a type at all —
                is one :func:`kober.check.check` proves, so skipping it means
                promising them by hand. The same trade
                :class:`kober.decoder.Decoder` makes.

        Returns:
            The plan.

        Raises:
            SpecError: If ``check`` is set and the spec has errors.

        Example:
            >>> plan = Plan.from_spec(spec)
            >>> [obj.unit for obj in plan.objects]
            ['message', 'flags']

        """
        if check:
            require_valid(spec)
        reachable = _reachable(spec)
        objects = tuple(
            _object(spec, name) for name in spec.units if name in reachable
        )
        return cls(
            name=spec.name,
            version=spec.version,
            entry=spec.entry,
            doc=spec.doc,
            enums=spec.enums,
            objects=objects,
        )

    def object(self, unit: str) -> ObjectPlan:
        """Return one unit's shape by name.

        Args:
            unit: The unit's name as the spec spells it.

        Returns:
            Its plan.

        Raises:
            KeyError: If the plan has no such unit.

        """
        for entry in self.objects:
            if entry.unit == unit:
                return entry
        known = ", ".join(entry.unit for entry in self.objects) or "none"
        msg = f"no unit named {unit!r} in this plan; it has: {known}"
        raise KeyError(msg)


def _reachable(spec: Spec) -> set[str]:
    """Return every unit reachable from the entry unit, the entry included.

    A unit nothing references is dead code in any target, and generated source
    a reader is expected to open should not contain a decoder nothing calls.
    :func:`kober.check.check` already warns that the spec declares it.
    """
    found: set[str] = set()
    pending = [spec.entry]
    while pending:
        name = pending.pop()
        if name in found or name not in spec.units:
            continue
        found.add(name)
        for item in spec.unit(name).fields:
            for kind in _types(item.type):
                if isinstance(kind, UnitRef):
                    pending.append(kind.unit)
    return found


def _types(kind: FieldType) -> tuple[FieldType, ...]:
    """Flatten a field type to the alternatives it can actually decode as.

    A ``switch`` decodes as one of its cases, so the cases are what a target
    has to be able to hold — and a case may itself be a ``switch``.
    """
    if not isinstance(kind, Switch):
        return (kind,)
    flat: list[FieldType] = []
    for case in kind.cases.values():
        flat.extend(_types(case))
    if kind.default is not None:
        flat.extend(_types(kind.default))
    return tuple(flat)


def _object(spec: Spec, unit: str) -> ObjectPlan:
    """Reduce one unit to its shape."""
    target = spec.unit(unit)
    fields = tuple(_field(spec, unit, index, item) for index, item in enumerate(target.fields))
    params = tuple(ParamPlan(name=param.name, kind=KINDS[param.type]) for param in target.params)
    return ObjectPlan(unit=unit, fields=fields, params=params, doc=target.doc)


def _field(spec: Spec, unit: str, index: int, item: Field) -> FieldPlan:
    """Reduce one field to what it contributes."""
    kinds: list[ValueType] = []
    for kind in _types(item.type):
        value = _value(spec, unit, index, kind)
        if value not in kinds:
            # A switch whose cases share a type says nothing twice.
            kinds.append(value)
    return FieldPlan(
        name=item.name,
        types=tuple(kinds),
        repeated=item.repeat is not None,
        condition=item.condition,
        doc=item.doc,
    )


def _value(spec: Spec, unit: str, index: int, kind: FieldType) -> ValueType:
    """Describe one alternative a field can decode as."""
    if isinstance(kind, IntType):
        return ValueType(
            kind=Kind.INT,
            bits=kind.bits,
            signed=kind.signed,
            endian=kind.endian.value,
            labels=kind.enum,
        )
    if isinstance(kind, StringType):
        return ValueType(kind=Kind.TEXT, encoding=kind.encoding)
    if isinstance(kind, BytesType):
        return ValueType(kind=Kind.BYTES)
    if isinstance(kind, UnitRef):
        return ValueType(kind=Kind.OBJECT, unit=kind.unit)
    if isinstance(kind, Computed):
        # The one type the spec does not state: it is whatever the expression
        # infers to, against the same scope the checker used to accept it.
        scope = scope_at(spec, unit, index)
        inferred = infer_type(kind.expr, scope, unparse(kind.expr))
        return ValueType(kind=KINDS[inferred])
    msg = f"unsupported field type {type(kind).__name__} in unit {unit!r}"
    raise TypeError(msg)


# --- resolving a reference -------------------------------------------------


@dataclass(frozen=True)
class Step:
    """One hop of a resolved reference path.

    Attributes:
        unit: The unit the name was looked up in, as the spec spells it.
        name: The field or parameter's name, as the spec spells it.
        param: Whether it names one of the unit's parameters rather than a
            field. A parameter is always the last hop: it holds a scalar, so
            there is nothing to descend into.

    """

    unit: str
    name: str
    param: bool = False


def walk_path(plan: Plan, unit: str, parts: Sequence[str]) -> tuple[Step, ...]:
    """Resolve a reference path to the fields it traverses.

    What a backend needs in order to *reach* a value: which unit each name
    belongs to, so the name can be mapped the way that language maps it. The
    scope word — ``this``, ``parent``, ``root`` — is the caller's to strip,
    because which unit a path starts in is the only part of scoping a target
    has an opinion about (a ``parent`` may be a caller's argument in one
    language and a back-pointer in another).

    Args:
        plan: The plan the units belong to.
        unit: The unit the first name is looked up in.
        parts: The path's components, scope word already removed.

    Returns:
        One :class:`Step` per component, outermost first.

    Raises:
        SpecError: If the path does not resolve. :func:`kober.check.check`
            refuses every such path already, so reaching this means a plan was
            built from a spec that was never checked.

    Example:
        >>> walk_path(plan, "question", ("qname", "labels"))
        (Step(unit='question', name='qname'), Step(unit='name', name='labels'))

    """
    if not parts:
        msg = f"a reference in unit {unit!r} must name a field"
        raise SpecError(msg)
    steps: list[Step] = []
    current = unit
    remaining = list(parts)
    while remaining:
        name = remaining.pop(0)
        obj = plan.object(current)
        param = obj.param(name)
        if param is not None:
            if remaining:
                msg = f"parameter {name!r} of unit {current!r} has no fields to reference"
                raise SpecError(msg)
            steps.append(Step(unit=current, name=name, param=True))
            return tuple(steps)
        item = obj.field(name)
        if item is None:
            known = ", ".join(
                field.name for field in obj.fields if field.name is not None
            ) or "none"
            msg = f"unit {current!r} has no field {name!r}; it has: {known}"
            raise SpecError(msg)
        steps.append(Step(unit=current, name=name))
        if not remaining:
            return tuple(steps)
        # The path continues, so this hop has to be something with fields. A
        # repeated field is allowed through: an `until` clause reads the
        # element it just decoded, which is one instance rather than the list.
        if len(item.types) != 1 or item.types[0].kind is not Kind.OBJECT:
            msg = (
                f"field {name!r} of unit {current!r} is not a unit, so "
                f"{remaining[0]!r} cannot be read"
            )
            raise SpecError(msg)
        current = item.types[0].unit or ""
    return tuple(steps)
