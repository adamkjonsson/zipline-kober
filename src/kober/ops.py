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

from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING

from kober.check import (
    Starved,
    message_tail_fields,
    require_valid,
    scope_at,
    starved_fields,
    trailing_width,
)
from kober.errors import CompileError, SpecError
from kober.expr import SCOPE_WORDS, ExprType, IntLiteral, Ref, infer_type, references, unparse
from kober.spec import (
    BytesType,
    Computed,
    Concat,
    Count,
    Emit,
    Fill,
    Fixed,
    FromExpr,
    IntType,
    Pointer,
    Select,
    StringType,
    Switch,
    Terminated,
    Transform,
    UnitRef,
    Until,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

    from kober.expr import Expr
    from kober.spec import EnumDef, Field, FieldType, Repeat, SizeSpec, Spec, Unit


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
class TransformPlan:
    """A transform: which bytes, which transform, and what it may produce.

    Attributes:
        name: The transform's name, as ``with`` spells it.
        source: The field or parameter whose bytes it reads, as the spec
            spells it.
        limit: The most bytes the output may have.
        args: Each argument's name and expression, in the spec's order.
        content_type: The record label for an output kept as bytes.
        typed: Whether the output is decoded as a unit (the :class:`ValueType`
            carrying this describes that unit), rather than kept as bytes.

    """

    name: str
    source: str
    limit: int
    args: tuple[tuple[str, Expr], ...] = ()
    content_type: str | None = None
    typed: bool = False


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
        size: How far a ``TEXT`` or ``BYTES`` value extends.
        trailing: What a ``fill`` size resolves to — the bytes the fields after
            this one claim. Resolved here rather than by each backend, so the
            boundary a fill lands on is decided once
            (:func:`kober.check.trailing_width`). ``None`` for every other size.
        args: Arguments bound to an ``OBJECT``'s parameters, positionally.
        expr: The expression a computed value comes from, or a select's
            projection. It reads nothing, so these are the kinds whose value is
            not on the wire at all.
        at: Where to read this, for a back-reference — an integer expression
            in the **message's** offset space, per ``DESIGN.md`` §3.2. ``None``
            means the ordinary case: read it where the position stands. A
            value with an ``at`` never advances the position, so ``consumes``
            is always false alongside it.
        source: Name of the repeated field a select asks about, as the spec
            spells it. It is what tells a select from a computed: both carry an
            ``expr``, and only a select has a repetition behind it.
        bound: The name one element of that repetition answers to inside
            ``where`` and ``expr`` — a select's ``as:``, or ``source`` where
            there is none. Carried separately because a backend renders the
            *walk* from ``source`` and the *expressions* against this.
        where: A select's predicate over one element. The **first** element it
            holds for is the one ``expr`` projects.
        default: A select's value when no element matched. Never ``None``
            alongside a ``source``, which is what makes the construct total —
            a backend has no "nothing matched" case to invent an answer for.
        consumes: Whether reading this provably advances the read position.
            What lets a backend drop the runtime check that a repetition is
            making progress — see :func:`consumes`.
        concat: For a ``concat``, the repeated field and the member of each
            element that is joined. It reads nothing where it stands.
        transform: For a ``transform``, what it reads and runs. The value
            type is the output's: an ``OBJECT`` for a unit, ``BYTES`` for an
            output kept as is. It reads nothing where it stands.

    """

    kind: Kind
    bits: int | None = None
    signed: bool = False
    endian: str = "big"
    labels: str | None = None
    encoding: str | None = None
    unit: str | None = None
    size: SizeSpec | None = None
    trailing: int | None = None
    args: tuple[Expr, ...] = ()
    expr: Expr | None = None
    at: Expr | None = None
    source: str | None = None
    bound: str | None = None
    where: Expr | None = None
    default: Expr | None = None
    consumes: bool = False
    concat: tuple[str, str] | None = None
    transform: TransformPlan | None = None


@dataclass(frozen=True)
class Branch:
    """One case of a ``switch``, and what it decodes as.

    Attributes:
        case: The value that selects it, or ``None`` for the default.
        type: What that case decodes.

    """

    case: int | str | None
    type: ValueType


@dataclass(frozen=True)
class FieldPlan:
    """What one field of a unit contributes to a decoded instance of it.

    Attributes:
        name: The field's name as the spec spells it, or ``None`` for an
            anonymous region. Anonymous fields are kept: they are read and
            cited, and only a *target* decides that they cannot be named.
        types: What it can hold. More than one only for a ``switch``, whose
            cases may differ — in case order, with any ``default`` last.
        selector: The expression a ``switch`` dispatches on. ``None`` for
            anything else, which is what tells the two apart.
        branches: One per case, in case order, with the default last. Empty
            unless there is a selector.
        repeat: How it repeats, if it does.
        condition: The expression deciding whether it is there at all, if any.
            Carried rather than reduced to a flag, because a target may want
            to say *when* a field is present.
        emit: How much of this field reaches an output file, if the spec says.
            ``None`` inherits, and what it inherits from is the enclosing unit
            and then whatever granularity the decoder was asked for.
        doc: The spec's own description, verbatim. Author-supplied text, and
            the reason a backend must escape rather than interpolate.
        const: A value the field must equal, or ``None``. A backend has to
            compare what it read against this and refuse the input when they
            disagree, which is why it is carried rather than left in the spec.
        starved: Whether the terminal rule leaves this field no bytes, and why
            (:func:`kober.check.starved_fields`). Always ``None`` in a spec that
            passes ``check``; carried so a backend running one that does not
            can call its short read ``undecodable``, as the interpreter does.
        tail: Whether nothing in the message reads a byte after this field
            (:func:`kober.check.message_tail_fields`). A backend reports where
            a fixed-size or counted read of it would have ended when the read
            runs out, so the driver can resume there after a gap (#49).

    """

    name: str | None
    types: tuple[ValueType, ...]
    selector: Expr | None = None
    branches: tuple[Branch, ...] = ()
    repeat: Repeat | None = None
    condition: Expr | None = None
    emit: Emit | None = None
    doc: str | None = None
    const: int | bytes | str | None = None
    starved: Starved | None = None
    tail: bool = False

    @property
    def exhaustive(self) -> bool:
        """Whether every value leaves the field decided.

        A ``switch`` with no default is the one shape that does not: §2 calls
        that "tried and failed", so the region is marked rather than guessed at.
        """
        return self.selector is None or any(branch.case is None for branch in self.branches)

    @property
    def optional(self) -> bool:
        """Whether the field may be absent from a decoded instance."""
        return self.condition is not None

    @property
    def repeated(self) -> bool:
        """Whether it holds many values rather than one."""
        return self.repeat is not None

    @property
    def element_consumes(self) -> bool:
        """Whether decoding **one value** of this field provably advances the position.

        The question a repetition asks: an element that always reads a byte
        cannot spin, so the loop needs no runtime progress check. Deliberately
        blind to :attr:`condition`, which decides whether the loop runs at all
        and says nothing about whether an iteration of it gets anywhere — the
        two were one property once, and a conditional repeat carried a guard it
        could never need.

        A ``switch`` with no default is not exhaustive, so an element could be
        undecodable rather than read, and the check stays.
        """
        return (
            bool(self.types)
            and all(value.consumes for value in self.types)
            and self.exhaustive
        )

    @property
    def consumes(self) -> bool:
        """Whether decoding this field provably advances the read position.

        False for a conditional field however it is typed: the condition may
        not hold, and then nothing is read. That is the *field's* answer, and
        it is what an enclosing unit needs; a repetition wants
        :attr:`element_consumes` instead.
        """
        return self.condition is None and self.element_consumes


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
        emit: How much of this unit reaches an output file, if the spec says.
        confirm: The dispatch guess held up, if this expression is true.
        reject: The input is not this unit, if this expression is true.
        recursive: Whether decoding it can reach itself. A target that decodes
            a unit by calling a function needs a depth bound only here.
        parents: Every unit that references this one, in plan order. What
            ``parent`` can mean, and the checker has already required them to
            agree about the types it resolves to.
        needs_parent: First components of every ``parent.x`` its expressions
            name. What a caller has to supply, and all it has to supply.
        needs_root: The same for ``root.x``, including what the units it
            decodes need, since those values are threaded through it.
        doc: The spec's own description, verbatim.

    """

    unit: str
    fields: tuple[FieldPlan, ...]
    params: tuple[ParamPlan, ...] = ()
    emit: Emit | None = None
    confirm: Expr | None = None
    reject: Expr | None = None
    recursive: bool = False
    parents: tuple[str, ...] = ()
    needs_parent: tuple[str, ...] = ()
    needs_root: tuple[str, ...] = ()
    doc: str | None = None

    @property
    def consumes(self) -> bool:
        """Whether decoding this unit provably advances the read position.

        One field that always reads something is enough, and its position among
        the others does not matter — a repetition whose element reads a byte
        cannot spin, whichever byte it is.
        """
        return any(item.consumes for item in self.fields)

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
        transforms: Every transform name the spec uses, sorted: what a backend
            binds when it is set up.
        params: The document's parameters, in the spec's order.
        spec_digest: :meth:`kober.spec.Spec.digest`, so a backend without the
            spec model computes the same ``params_digest``.

    """

    name: str
    version: str
    entry: str
    doc: str | None = None
    enums: Mapping[str, EnumDef] = field(default_factory=dict)
    objects: tuple[ObjectPlan, ...] = ()
    transforms: tuple[str, ...] = ()
    params: tuple[ParamPlan, ...] = ()
    spec_digest: str = ""

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
        units = [name for name in spec.units if name in reachable]
        recursive = _recursive(spec, units)
        roots = _roots(spec, units)
        callers = {
            name: tuple(caller for caller in units if name in _calls(spec, caller))
            for name in units
        }
        starved = starved_fields(spec)
        tails = message_tail_fields(spec)
        objects = tuple(
            _object(spec, name, name in recursive, roots, callers[name], starved, tails)
            for name in units
        )
        used = {
            kind.name
            for unit in units
            for item in spec.unit(unit).fields
            for kind in _nested_types(item.type)
            if isinstance(kind, Transform)
        }
        return cls(
            name=spec.name,
            version=spec.version,
            entry=spec.entry,
            doc=spec.doc,
            enums=spec.enums,
            objects=objects,
            transforms=tuple(sorted(used)),
            params=tuple(
                ParamPlan(name=param.name, kind=KINDS[param.type]) for param in spec.params
            ),
            spec_digest=spec.digest(),
        )

    @property
    def recursive(self) -> bool:
        """Whether any unit's decoding can reach itself.

        A target that needs a depth bound needs it consistently: mixing bounded
        and unbounded nesting would put the limit somewhere the interpreter does
        not, and the two are supposed to refuse the same inputs.
        """
        return any(obj.recursive for obj in self.objects)

    @property
    def pointers(self) -> bool:
        """Whether any field is read at an offset rather than where it stands.

        A **whole-plan** answer, like :attr:`recursive`, and for the same
        reason: a back-reference needs the message's origin and the ceiling of
        the chain so far threaded through every decode that could contain one,
        and threading it into only some of them would put the bound somewhere
        the interpreter does not. A plan with no pointer pays nothing.
        """
        return any(
            value.at is not None
            for obj in self.objects
            for item in obj.fields
            for value in item.types
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


def nonnegative(plan: Plan, unit: str, expr: Expr) -> bool:
    """Whether an expression is provably not negative.

    A count or a size read off the wire is refused when it comes back negative,
    and that check is dead code whenever the value cannot be one. Both cases
    that matter are easy to see: a literal, and an unsigned integer field. A
    conservative ``False`` only costs a comparison in generated code, so nothing
    here guesses.

    Args:
        plan: The plan the unit belongs to.
        unit: The unit the expression is written in.
        expr: The expression.

    Returns:
        Whether it is certainly zero or more.

    Example:
        >>> nonnegative(plan, "message", parse("qdcount"))
        True

    """
    if isinstance(expr, IntLiteral):
        return expr.value >= 0
    if not isinstance(expr, Ref):
        # Arithmetic could go either way — `a - b` on two unsigned fields is the
        # ordinary case, not a strange one.
        return False
    parts = expr.path[1:] if expr.path[0] == "this" else expr.path
    if not parts or (expr.path[0] in SCOPE_WORDS and expr.path[0] != "this"):
        # `parent` and `root` resolve elsewhere, and proving something about
        # another unit's field is not worth the reach.
        return False
    try:
        steps = walk_path(plan, unit, parts)
    except SpecError:  # pragma: no cover - the checker resolved it already
        return False
    last = steps[-1]
    if last.param:
        # A parameter is whatever its caller passed, and that is an expression.
        return False
    item = plan.object(last.unit).field(last.name)
    if item is None or item.repeat is not None or len(item.types) != 1:
        return False
    value = item.types[0]
    return value.kind is Kind.INT and not value.signed and value.bits is not None


def _referenced(kind: FieldType) -> Iterator[str]:
    """Yield every unit one field type can decode, at any depth inside it.

    Through a ``switch``'s cases and **through a pointer's target**, which is
    the one that is easy to miss: a unit reached only by a back-reference is
    still decoded, and dropping it leaves the plan without a decoder its own
    generated code calls.
    """
    if isinstance(kind, UnitRef):
        yield kind.unit
    elif isinstance(kind, Switch):
        for case in kind.cases.values():
            yield from _referenced(case)
        if kind.default is not None:
            yield from _referenced(kind.default)
    elif isinstance(kind, Pointer) or (isinstance(kind, Transform) and kind.type is not None):
        yield from _referenced(kind.type)


def _nested_types(kind: FieldType) -> Iterator[FieldType]:
    """Yield a type and every type inside it: switch cases, targets, outputs."""
    yield kind
    if isinstance(kind, Switch):
        for case in (*kind.cases.values(), kind.default):
            if case is not None:
                yield from _nested_types(case)
    elif isinstance(kind, Pointer) or (isinstance(kind, Transform) and kind.type is not None):
        yield from _nested_types(kind.type)


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
            pending.extend(_referenced(item.type))
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


def _object(
    spec: Spec,
    unit: str,
    recursive: bool,
    roots: Mapping[str, tuple[str, ...]],
    parents: tuple[str, ...],
    starved: Mapping[tuple[str, int], Starved],
    tails: frozenset[tuple[str, int]] = frozenset(),
) -> ObjectPlan:
    """Reduce one unit to its shape."""
    target = spec.unit(unit)
    fields = tuple(
        _field(spec, unit, index, item, starved.get((unit, index)), tail=(unit, index) in tails)
        for index, item in enumerate(target.fields)
    )
    params = tuple(ParamPlan(name=param.name, kind=KINDS[param.type]) for param in target.params)
    return ObjectPlan(
        unit=unit,
        fields=fields,
        params=params,
        emit=target.emit,
        confirm=target.confirm,
        reject=target.reject,
        recursive=recursive,
        parents=parents,
        needs_parent=_outer(spec, target, "parent"),
        needs_root=roots[unit],
        doc=target.doc,
    )


def _outer(spec: Spec, unit: Unit, word: str) -> tuple[str, ...]:
    """Return the first components of every ``word.x`` the unit's expressions name.

    The first component and no more: ``parent.header.length`` needs the
    parent's ``header``, and the rest of the path is reached from it. What a
    caller has to supply, and all it has to supply.
    """
    found: list[str] = []
    for expr in _unit_exprs(spec, unit):
        for ref in references(expr):
            if len(ref.path) > 1 and ref.path[0] == word and ref.path[1] not in found:
                found.append(ref.path[1])
    return tuple(found)


def _unit_exprs(spec: Spec, unit: Unit) -> Iterator[Expr]:
    """Yield every expression a unit evaluates while decoding.

    All of them, because any one can name an outer value: a condition, a size,
    a repeat clause, a switch selector, an argument to a nested unit, a computed
    value, and the two guards.
    """
    for guard in (unit.confirm, unit.reject):
        if guard is not None:
            yield guard
    for item in unit.fields:
        if item.condition is not None:
            yield item.condition
        if isinstance(item.repeat, (Count, Until)):
            yield item.repeat.expr
        for kind in _types(item.type):
            yield from _kind_exprs(kind)
        if isinstance(item.type, Switch):
            yield item.type.dispatch


def _kind_exprs(kind: FieldType) -> Iterator[Expr]:
    """Yield the expressions one field type evaluates.

    **All of a select's three**, which is easy to get wrong and expensive to:
    :func:`_outer` reads this walk to decide which ``parent`` and ``root``
    values a unit needs threaded in, so a select naming one in a predicate it
    does not yield would compile to a function missing the argument.
    """
    if isinstance(kind, Computed):
        yield kind.expr
    elif isinstance(kind, Select):
        yield kind.where
        yield kind.value
        yield kind.default
    elif isinstance(kind, Pointer):
        yield kind.at
        yield from _kind_exprs(kind.type)
    elif isinstance(kind, UnitRef):
        yield from kind.args
    elif isinstance(kind, Transform):
        yield from kind.args.values()
        if kind.type is not None:
            yield from _kind_exprs(kind.type)
    else:
        size = kind.size if isinstance(kind, (BytesType, StringType)) else None
        if isinstance(size, FromExpr):
            yield size.expr


def _calls(spec: Spec, unit: str) -> tuple[str, ...]:
    """Return every unit one unit decodes directly, in order, without repeats."""
    found: list[str] = []
    if unit not in spec.units:
        return ()
    for item in spec.unit(unit).fields:
        for name in _referenced(item.type):
            if name not in found:
                found.append(name)
    return tuple(found)


def _roots(spec: Spec, units: Sequence[str]) -> dict[str, tuple[str, ...]]:
    """Return the ``root.x`` values each unit needs, its callees' needs included.

    ``root`` reaches the entry unit from any depth, so a value named deep in the
    tree has to be threaded through everything above it. Solved as a fixed point
    rather than by walking down, because a recursive spec has no bottom to start
    from.
    """
    needs = {unit: list(_outer(spec, spec.unit(unit), "root")) for unit in units}
    changed = True
    while changed:
        changed = False
        for unit in units:
            for callee in _calls(spec, unit):
                for name in needs.get(callee, ()):
                    if name not in needs[unit]:
                        needs[unit].append(name)
                        changed = True
    return {unit: tuple(names) for unit, names in needs.items()}


def _recursive(spec: Spec, units: Sequence[str]) -> set[str]:
    """Return every unit whose decoding can reach itself.

    A target that decodes a unit by calling a function needs a depth bound in
    exactly these, and nowhere else. ``check`` refuses *left* recursion, which
    cannot terminate; this is the rest of it, which can.
    """
    reachable = {unit: set(_calls(spec, unit)) for unit in units}
    changed = True
    while changed:
        changed = False
        for unit in units:
            for callee in tuple(reachable[unit]):
                for onward in reachable.get(callee, ()):
                    if onward not in reachable[unit]:
                        reachable[unit].add(onward)
                        changed = True
    return {unit for unit in units if unit in reachable[unit]}


def _field(
    spec: Spec,
    unit: str,
    index: int,
    item: Field,
    starved: Starved | None = None,
    *,
    tail: bool = False,
) -> FieldPlan:
    """Reduce one field to what it contributes."""
    switch = item.type if isinstance(item.type, Switch) else None
    branches = tuple(_branches(spec, unit, index, item.type)) if switch is not None else ()
    types = (
        tuple(dict.fromkeys(branch.type for branch in branches))
        if switch is not None
        else (_value(spec, unit, index, item.type),)
    )
    # Two cases decoding the same thing say nothing twice in `types`, which is
    # what a target declares a field as — but each case still has to be matched,
    # so `branches` keeps every one of them.
    return FieldPlan(
        name=item.name,
        types=types,
        selector=switch.dispatch if switch is not None else None,
        branches=branches,
        repeat=item.repeat,
        condition=item.condition,
        emit=item.emit,
        doc=item.doc,
        const=item.const,
        starved=starved,
        tail=tail,
    )


def _branches(spec: Spec, unit: str, index: int, kind: FieldType) -> Iterator[Branch]:
    """Yield one branch per case of a switch, flattening a nested one.

    A nested switch's cases are hoisted into the outer one's list under their own
    values, which loses nothing: the inner selector is re-read where it matters,
    and what a target needs from here is the set of things this field can be.
    """
    if not isinstance(kind, Switch):
        yield Branch(case=None, type=_value(spec, unit, index, kind))
        return
    for case, chosen in kind.cases.items():
        for branch in _branches(spec, unit, index, chosen):
            yield Branch(case=case, type=branch.type)
    if kind.default is not None:
        for branch in _branches(spec, unit, index, kind.default):
            yield Branch(case=None, type=branch.type)


def _value(spec: Spec, unit: str, index: int, kind: FieldType) -> ValueType:
    """Describe one alternative a field can decode as."""
    if isinstance(kind, IntType):
        return ValueType(
            kind=Kind.INT,
            bits=kind.bits,
            signed=kind.signed,
            endian=kind.endian.value,
            labels=kind.enum,
            consumes=kind.bits > 0,
        )
    if isinstance(kind, (StringType, BytesType)):
        return ValueType(
            kind=Kind.TEXT if isinstance(kind, StringType) else Kind.BYTES,
            encoding=kind.encoding if isinstance(kind, StringType) else None,
            size=kind.size,
            trailing=(
                trailing_width(spec, unit, index) if isinstance(kind.size, Fill) else None
            ),
            consumes=_size_consumes(kind.size),
        )
    if isinstance(kind, UnitRef):
        return ValueType(
            kind=Kind.OBJECT,
            unit=kind.unit,
            args=tuple(kind.args),
            consumes=_unit_consumes(spec, kind.unit, ()),
        )
    if isinstance(kind, Computed):
        # The one type the spec does not state: it is whatever the expression
        # infers to, against the same scope the checker used to accept it. It
        # reads nothing, so it never advances the position.
        scope = scope_at(spec, unit, index)
        inferred = infer_type(kind.expr, scope, unparse(kind.expr))
        return ValueType(kind=KINDS[inferred], expr=kind.expr)
    if isinstance(kind, Pointer):
        return _pointer(spec, unit, index, kind)
    if isinstance(kind, Select):
        return _select(spec, unit, index, kind)
    if isinstance(kind, Concat):
        return ValueType(kind=Kind.BYTES, concat=(kind.repeated, kind.member))
    if isinstance(kind, Transform):
        return _transform(spec, unit, index, kind)
    msg = f"unsupported field type {type(kind).__name__} in unit {unit!r}"
    raise TypeError(msg)


def _pointer(spec: Spec, unit: str, index: int, kind: Pointer) -> ValueType:
    """Describe a back-reference: what is there, and where to read it.

    The value is whatever the target is — a pointer adds no kind of its own —
    so this describes the target and stamps ``at`` on it. ``consumes`` is
    forced false whatever the target would say: a pointer reads elsewhere and
    leaves the position alone, which is what makes a repetition of them
    terminate on its own progress check rather than looping.

    Args:
        spec: The spec being planned.
        unit: The unit the pointer is written in.
        index: The field's position, for scoping a computed target.
        kind: The pointer.

    Returns:
        The target's value type, with ``at`` set.

    Raises:
        CompileError: If the target is a ``switch``. A plan describes one
            alternative per :class:`ValueType` and carries the selector on the
            *field*, so a switch **under** a pointer has nowhere to put its
            selector. It decodes under the interpreter; only this compilation
            is impossible.

    """
    if isinstance(kind.type, Switch):
        msg = (
            f"unit {unit!r}: the compiler cannot express a switch under a pointer; "
            f"put the pointer inside the switch's cases, or use the interpreter"
        )
        raise CompileError(msg)
    return replace(_value(spec, unit, index, kind.type), at=kind.at, consumes=False)


def _transform(spec: Spec, unit: str, index: int, kind: Transform) -> ValueType:
    """Describe a transform: the output's value type, with the transform stamped on.

    A transform adds no kind of its own, as a pointer adds none: its value is
    its output, bytes as they are or a unit decoded from them. ``consumes`` is
    false, since it reads nothing where it stands.

    Raises:
        CompileError: If the output's ``type`` is anything but a unit. The
            interpreter decodes one; this compiler decodes an output by calling
            a unit's function over it, and a scalar type has no function. Wrap
            it in a unit.

    """
    plan = TransformPlan(
        name=kind.name,
        source=kind.source,
        limit=kind.limit,
        args=tuple(kind.args.items()),
        content_type=kind.content_type,
        typed=kind.type is not None,
    )
    if kind.type is None:
        return ValueType(kind=Kind.BYTES, transform=plan)
    if not isinstance(kind.type, UnitRef):
        msg = (
            f"unit {unit!r}: the compiler decodes a transform's output only as a unit; "
            f"wrap its type in one, or use the interpreter"
        )
        raise CompileError(msg)
    output = _value(spec, unit, index, kind.type)
    return replace(output, transform=plan, consumes=False)


def _select(spec: Spec, unit: str, index: int, kind: Select) -> ValueType:
    """Describe a select: which repetition, which element, and what to take.

    Said in the spec's own words — a field name, a predicate, a projection, a
    default — and in no language in particular. Rendering the walk is the
    backend's business, and there is nothing here for it to guess at: the
    default is required, so "nothing matched" has an answer already.

    The kind is the projection's, typed the way :class:`~kober.spec.Computed`'s
    is and against the same scope the checker used to accept it — with the
    element bound, since that is what the projection reads. ``consumes`` is
    false: the repetition is decoded before this runs, so there is nothing left
    to read and no position to move.

    Args:
        spec: The spec being planned.
        unit: The unit the select is written in.
        index: The field's position, for scoping.
        kind: The select.

    Returns:
        The value type, with ``source``, ``where``, ``expr`` and ``default``.

    """
    scope = scope_at(spec, unit, index, element_of=kind.source, element_as=kind.alias)
    inferred = infer_type(kind.value, scope, unparse(kind.value))
    return ValueType(
        kind=KINDS[inferred],
        source=kind.source,
        bound=kind.alias or kind.source,
        where=kind.where,
        expr=kind.value,
        default=kind.default,
    )


def _size_consumes(size: SizeSpec) -> bool:
    """Whether a size provably reads at least one byte.

    Only two of the four do. A ``fixed`` size says so, and a required
    terminator means at least the delimiter is read once it is found. An
    expression could be zero and ``remaining`` could be nothing left, and a
    repetition of either could spin — which is what the runtime check exists
    for, and why this answer has to be conservative rather than hopeful.
    """
    if isinstance(size, Fixed):
        return size.count > 0
    if isinstance(size, Terminated):
        return size.required and size.consume
    return False


def _unit_consumes(spec: Spec, unit: str, seen: tuple[str, ...]) -> bool:
    """Whether decoding a unit provably reads something, following references.

    ``seen`` guards a recursive spec: a unit reached again on the way to
    deciding about itself proves nothing, so it answers ``False`` and the
    runtime check stays.
    """
    if unit in seen or unit not in spec.units:
        return False
    target = spec.unit(unit)
    return any(_field_consumes(spec, target, index, item, (*seen, unit))
               for index, item in enumerate(target.fields))


def _field_consumes(
    spec: Spec, unit: Unit, index: int, item: Field, seen: tuple[str, ...]
) -> bool:
    """Whether one field provably reads something."""
    if item.condition is not None:
        return False
    kinds = _types(item.type)
    if isinstance(item.type, Switch) and item.type.default is None:
        return False
    return bool(kinds) and all(
        _kind_consumes(spec, unit, index, kind, seen) for kind in kinds
    )


def _kind_consumes(
    spec: Spec, unit: Unit, index: int, kind: FieldType, seen: tuple[str, ...]
) -> bool:
    """Whether one alternative provably reads something."""
    if isinstance(kind, IntType):
        return kind.bits > 0
    if isinstance(kind, (BytesType, StringType)):
        return _size_consumes(kind.size)
    if isinstance(kind, UnitRef):
        return _unit_consumes(spec, kind.unit, seen)
    # A pointer reads elsewhere, so it never advances the position — which is
    # exactly why a unit whose only field is one cannot terminate a repeat.
    return False


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
