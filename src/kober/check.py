"""Whole-spec validation: references, scoping, ordering, and expression types.

:mod:`kober.spec` checks what one object can see by itself. This module checks
everything else, and it is what lets a spec be trusted before any data exists.

To be precise about the claim, since ``DESIGN.md`` §2 used to overstate it:
this does not prove coverage — ``fill_undecoded=True`` makes coverage true by
construction whatever the spec says. What a clean check buys is that the spec
will account for its input *honestly*, marking ``undecodable`` where it tried
and failed rather than letting bytes fall through to an auto-filled
``skipped``. See §2.1.

:func:`check` **collects rather than raises.** A validator that stops at the
first fault makes an author fix a spec one line per run. It returns every
:class:`Finding` it can see, ordered by location, and an empty result means the
spec is valid.

**Scoping follows Kaitai** (``DESIGN.md`` §3.3): ``this`` is the containing
unit, ``parent`` the unit that referenced it, ``root`` the entry unit, and a
bare name is shorthand for ``this``. Two rules make references honest:

- *Ordering.* A field may reference only fields declared **before** it, since
  a later field has not been decoded when the expression runs. ``until``
  expressions additionally see the field they repeat, which is the element
  just decoded, and so do a :class:`~kober.spec.Select`'s ``where`` and
  ``value``.
- *Reachability.* ``parent`` resolves against every site that references the
  unit, and must resolve at all of them — a unit reachable from two parents
  cannot rely on a field only one of them has.

The ordering rule is about **where the reference stands**, and it is applied
where the reference is written. Descending a dotted path into another field's
own expression does not re-apply it: that field's ordering was checked at its
own declaration site, and re-checking it against the referrer's names asks the
wrong question — cross-unit, against the wrong unit's names entirely.

A repeated field may **not** be referenced, because the expression language has
no list type and never gains one. The two exemptions above are the whole of the
exception, and both are narrow by construction: each binds the repeated name to
one *element* for the length of one expression, so nothing anywhere can hold a
list.

``root`` is the exception: it resolves against the entry unit's fields
without an ordering rule, because how much of the entry unit has been decoded
at an arbitrary depth is not knowable statically. It is a power tool, and
mis-using it is a decode-time surprise the checker cannot take back.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from kober.errors import ExprError, SpecError
from kober.expr import ExprType, IntLiteral, infer_type, unparse
from kober.loader import FOREIGN_KEYS
from kober.spec import (
    BytesType,
    Computed,
    Count,
    Field,
    Fill,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Pointer,
    Select,
    StringType,
    Switch,
    Terminated,
    Unit,
    UnitRef,
    Until,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from kober.expr import Expr, Scope
    from kober.source import Location
    from kober.spec import FieldType, Repeat, SizeSpec, Spec


class Severity(Enum):
    """How much a finding matters.

    An ``ERROR`` means the spec cannot be run. A ``WARNING`` means it can, but
    something in it is probably not what the author meant.
    """

    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    """One problem found in a spec.

    ``where`` is a :class:`~kober.source.Location` rather than the dotted
    string it was before ``0.2.0``. :func:`check` reports every fault it can
    see rather than stopping at the first, and a list of a dozen faults with no
    line numbers is a list of a dozen things to go hunting for. The path is
    still on it, as :attr:`~kober.source.Location.path`.

    Attributes:
        severity: Whether this stops the spec from running.
        where: Where the problem is: the path always, and the file and line
            when the spec was read from a source that reports them.
        message: What is wrong, in the author's vocabulary.

    """

    severity: Severity
    where: Location
    message: str

    def __str__(self) -> str:
        return f"{self.severity.value}: {self.where}: {self.message}"


def check(spec: Spec) -> tuple[Finding, ...]:
    """Validate a spec against everything that needs the whole spec in view.

    Args:
        spec: The spec to validate.

    Returns:
        Every problem found, ordered by location. Empty means valid.

    Example:
        >>> findings = check(spec)
        >>> if not findings:
        ...     print("ok")

    """
    return _Checker(spec).run()


def require_valid(spec: Spec) -> None:
    """Refuse a spec that has errors, listing every one of them.

    The counterpart of :func:`check` for callers that cannot proceed on a
    broken spec — the decode engine and the compiler both rely on what a clean
    check proves, so both refuse rather than promise it by hand.

    Args:
        spec: The spec to validate.

    Raises:
        SpecError: If the spec has any ``ERROR`` finding. Warnings do not stop
            it: they say something is probably not what the author meant, not
            that it cannot be run.

    """
    errors = [finding for finding in check(spec) if finding.severity is Severity.ERROR]
    if errors:
        listed = "\n  ".join(str(finding) for finding in errors)
        msg = f"spec {spec.name!r} has {len(errors)} error(s):\n  {listed}"
        raise SpecError(msg)


def scope_at(
    spec: Spec,
    unit: str,
    index: int,
    *,
    element_of: str | None = None,
    element_as: str | None = None,
) -> Scope:
    """Return the scope an expression at one field's position resolves against.

    The compiler needs exactly what the checker computes — which names are
    visible where, and what type each has — and **one** implementation of that
    is the point: a second would be a second set of scoping rules, drifting
    from the rules the checker enforces.

    Args:
        spec: The spec the unit belongs to.
        unit: Name of the unit the expression is written in.
        index: Position of the field the expression belongs to. A field sees
            its unit's parameters and every *named* field declared before it,
            so ``index`` is what makes the answer precise.
        element_of: Name of the field an enclosing ``until`` or ``select``
            repeats. One element of it is in scope rather than the list,
            because both constructs run once per element with that element in
            hand.
        element_as: The name that element is in scope *under* — a construct's
            ``as:``. ``None`` binds it under ``element_of``, which is the
            shorthand. When it is given, the repeated field's own name goes
            back to being refused as a list, so exactly one name means one
            element and it is the one the author chose.

    Returns:
        A :class:`kober.expr.Scope` to hand to :func:`kober.expr.infer_type`.

    Raises:
        SpecError: If ``unit`` is not a unit of ``spec``.

    Example:
        >>> scope = scope_at(spec, "message", 3)
        >>> infer_type(expr, scope, unparse(expr))
        <ExprType.INT: 'int'>

    """
    target = spec.unit(unit)
    return _Scope(
        _Checker(spec), target, _visible_names(target, index), element_of, element_as
    )


def trailing_width(spec: Spec, unit: str, index: int) -> int:
    """Return how many bytes the fields after ``index`` in ``unit`` still claim.

    What a ``fill`` size resolves to: at decode time the field reads
    ``remaining - trailing``, so this number has to be knowable from the spec
    alone. **One implementation**, for the same reason :func:`scope_at` is one:
    the checker, the interpreter and the compiler must agree about a boundary,
    and a second answer would be a second place for a spec to mean two things.

    Total by refusal rather than by approximation. A field whose width cannot
    be measured raises instead of contributing a guess, because a guessed
    boundary is exactly what §2 exists to prevent — the decoder would read the
    wrong bytes confidently and mark nothing.

    What has a width: an integer is its ``bits``; a ``bytes`` or ``string``
    sized ``fixed`` is known; a nested unit is the sum of its own fields; a
    ``switch`` counts only when every case *and* a present default agree. A
    ``computed``, ``select`` or ``pointer`` reads nothing where it stands and so
    claims none of the trailer.

    Args:
        spec: The spec the unit belongs to.
        unit: Name of the unit the ``fill`` is in.
        index: Position of the ``fill`` field itself; the fields measured are
            the ones after it.

    Returns:
        The trailing width in bytes.

    Raises:
        SpecError: If any trailing field's width is not statically known,
            naming the field and why.

    Example:
        >>> trailing_width(spec, "message", 1)
        4

    """
    bits = _trailing_bits(spec, spec.unit(unit), index, ())
    if bits % 8:
        msg = (
            f"unit {unit!r}: the fields after a fill total {bits} bits, which is "
            "not a whole number of bytes, so where the fill ends is undefined"
        )
        raise SpecError(msg)
    return bits // 8


def fill_widths(spec: Spec) -> dict[tuple[str, int], int | None]:
    """Resolve every ``fill`` in a spec, by ``(unit name, field index)``.

    What both backends need and neither should work out for itself. The
    interpreter precomputes this when a :class:`~kober.decoder.Decoder` is
    built and the compiler bakes it into the generated source, so the boundary
    a fill lands on is decided once, here.

    Args:
        spec: The spec to resolve.

    Returns:
        The trailing width in bytes for each field carrying a ``fill``, and
        ``None`` for one whose width the spec does not fix. A ``None`` is
        reported as an error by :func:`check`, so it reaches a backend only
        when the check was skipped.

    Example:
        >>> fill_widths(spec)
        {('message', 1): 4}

    """
    widths: dict[tuple[str, int], int | None] = {}
    for unit in spec.units.values():
        for index, item in enumerate(unit.fields):
            if not any(isinstance(_size_of(kind), Fill) for kind in _walk_types(item.type)):
                continue
            try:
                widths[unit.name, index] = trailing_width(spec, unit.name, index)
            except SpecError:
                widths[unit.name, index] = None
    return widths


def _trailing_bits(spec: Spec, unit: Unit, index: int, seen: tuple[str, ...]) -> int:
    """Sum the widths of ``unit``'s fields after ``index``, in bits."""
    total = 0
    for position, item in enumerate(unit.fields):
        if position <= index:
            continue
        total += _field_bits(spec, unit, item, seen)
    return total


def _field_bits(spec: Spec, unit: Unit, item: Field, seen: tuple[str, ...]) -> int:
    """Return one trailing field's width in bits, or refuse to guess."""
    where = f"unit {unit.name!r}, field {item.name or '<anonymous>'!r}"
    if item.condition is not None:
        msg = (
            f"{where}: it follows a fill and is conditional, so whether it is "
            "there at all depends on the data; a fill cannot be sized against it"
        )
        raise SpecError(msg)
    times = 1
    if item.repeat is not None:
        count = _literal_count(item.repeat)
        if count is None:
            msg = (
                f"{where}: it follows a fill and repeats a number of times the "
                "spec does not fix; a fill cannot be sized against it"
            )
            raise SpecError(msg)
        times = count
    return times * _type_bits(spec, unit, item, item.type, seen)


def _literal_count(repeat: Repeat) -> int | None:
    """Return a repeat's element count when the spec states it outright."""
    if isinstance(repeat, Count) and isinstance(repeat.expr, IntLiteral):
        return repeat.expr.value
    return None


def _type_bits(  # noqa: PLR0911
    spec: Spec, unit: Unit, item: Field, kind: FieldType, seen: tuple[str, ...]
) -> int:
    """Return a field type's width in bits, or refuse to guess."""
    where = f"unit {unit.name!r}, field {item.name or '<anonymous>'!r}"
    if isinstance(kind, IntType):
        return kind.bits
    if isinstance(kind, (Computed, Select, Pointer)):
        # None of the three reads anything where it stands — a pointer's bytes
        # are read by the ordinary fields whose citations already cover them —
        # so none of them claims any of the trailer.
        return 0
    if isinstance(kind, (BytesType, StringType)):
        if isinstance(kind.size, Fixed):
            return kind.size.count * 8
        msg = (
            f"{where}: it follows a fill and its size is not fixed, so how much "
            "of the input it claims is not knowable before decoding it"
        )
        raise SpecError(msg)
    if isinstance(kind, UnitRef):
        if kind.unit in seen:
            msg = (
                f"{where}: it follows a fill and unit {kind.unit!r} is recursive, "
                "so it has no width the spec fixes"
            )
            raise SpecError(msg)
        target = spec.units.get(kind.unit)
        if target is None:
            msg = f"{where}: it follows a fill and names unknown unit {kind.unit!r}"
            raise SpecError(msg)
        return _trailing_bits(spec, target, -1, (*seen, kind.unit))
    if isinstance(kind, Switch):
        widths = {
            _type_bits(spec, unit, item, case, seen) for case in kind.cases.values()
        }
        if kind.default is None:
            msg = (
                f"{where}: it follows a fill and is a switch with no default, so "
                "an unmatched value has no width"
            )
            raise SpecError(msg)
        widths.add(_type_bits(spec, unit, item, kind.default, seen))
        if len(widths) != 1:
            listed = ", ".join(str(width) for width in sorted(widths))
            msg = (
                f"{where}: it follows a fill and its switch cases have differing "
                f"widths ({listed} bits), so the trailer has no single size"
            )
            raise SpecError(msg)
        return widths.pop()
    msg = f"{where}: it follows a fill and has no width the spec fixes"
    raise SpecError(msg)


def _walk_types(kind: FieldType) -> Iterator[FieldType]:
    """Yield a field type and every type nested inside it.

    A pointer's target counts as nested, which is what makes a unit reached
    *only* through a pointer both reachable and parented: the two callers that
    matter here are :meth:`_Checker._index_parents` and
    :meth:`_Checker._check_reachability`, and neither should treat a
    back-reference as a dead end.
    """
    yield kind
    if isinstance(kind, Switch):
        for case in kind.cases.values():
            yield from _walk_types(case)
        if kind.default is not None:
            yield from _walk_types(kind.default)
    elif isinstance(kind, Pointer):
        yield from _walk_types(kind.type)


def _size_of(kind: FieldType) -> SizeSpec | None:
    """Return the size spec of a sized type, if it has one."""
    if isinstance(kind, (BytesType, StringType)):
        return kind.size
    return None


def _int_range(kind: IntType) -> tuple[int, int]:
    """Return the lowest and highest value an integer field can hold."""
    if kind.signed:
        half = 1 << (kind.bits - 1)
        return -half, half - 1
    return 0, (1 << kind.bits) - 1


def _visible_names(unit: Unit, upto: int) -> set[str]:
    """Names a field at index ``upto`` may reference.

    A field sees its unit's parameters and every *named* field declared
    before it. Anonymous fields are unreferenceable by construction, which is
    what makes them safe for padding and reserved bits.

    Args:
        unit: The unit being decoded.
        upto: Index of the referencing field.

    Returns:
        The names in scope at that position.

    """
    names = {param.name for param in unit.params}
    for item in unit.fields[:upto]:
        if item.name is not None:
            names.add(item.name)
    return names


class _Checker:
    """Accumulates findings over one spec."""

    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        self.findings: list[Finding] = []
        # Every site referencing a unit, as (containing unit, field index).
        # Field index is what makes `parent` visibility precise: a parent's
        # later fields are not decoded when the child runs.
        self.parents: dict[str, list[tuple[Unit, int]]] = {}
        self._index_parents()

    def report(self, severity: Severity, where: str, message: str) -> None:
        """Record one finding, looking up where in the document it is.

        Every check builds its path from model names, which is the vocabulary
        the loader recorded lines under — so this is the one place a path
        becomes a location, and the checks themselves need not carry one.
        """
        self.findings.append(Finding(severity, self.spec.sources.locate(where), message))

    def error(self, where: str, message: str) -> None:
        """Record an error."""
        self.report(Severity.ERROR, where, message)

    def warn(self, where: str, message: str) -> None:
        """Record a warning."""
        self.report(Severity.WARNING, where, message)

    def run(self) -> tuple[Finding, ...]:
        """Run every check and return the findings."""
        self._check_entry()
        for unit in self.spec.units.values():
            self._check_unit(unit)
        self._check_reachability()
        self._check_left_recursion()
        self._check_foreign()
        return tuple(self.findings)

    def _check_foreign(self) -> None:
        """Report every packeteer key the spec used, and why it means nothing here.

        A **warning**, because ignoring any of them changes no decode: the spec
        describes the same messages either way, which is the whole basis of the
        claim that one dialect covers both projects. ``--strict`` turns them
        into failures for a project that wants them refused outright.
        """
        for item in self.spec.foreign:
            reason = FOREIGN_KEYS.get(item.key)
            if reason is None:  # pragma: no cover - the loader collects no others
                continue
            self.warn(
                item.where,
                f"{item.key!r} is a packeteer key and has no meaning here; {reason}",
            )

    # --- structure ---------------------------------------------------------

    def _index_parents(self) -> None:
        """Record where each unit is referenced from."""
        for unit in self.spec.units.values():
            for index, item in enumerate(unit.fields):
                for kind in _walk_types(item.type):
                    if isinstance(kind, UnitRef):
                        self.parents.setdefault(kind.unit, []).append((unit, index))

    def _check_entry(self) -> None:
        """Require the entry unit to exist and to take no parameters."""
        entry = self.spec.units.get(self.spec.entry)
        if entry is None:
            known = ", ".join(sorted(self.spec.units))
            self.error(
                self.spec.name,
                f"entry names unit {self.spec.entry!r}, which does not exist; "
                f"known units: {known}",
            )
        elif entry.params:
            names = ", ".join(param.name for param in entry.params)
            self.error(
                f"{self.spec.name}.{entry.name}",
                f"the entry unit cannot take parameters; nothing can supply {names}",
            )

    def _check_reachability(self) -> None:
        """Warn about units nothing can reach."""
        reached: set[str] = set()
        pending = [self.spec.entry]
        while pending:
            name = pending.pop()
            if name in reached or name not in self.spec.units:
                continue
            reached.add(name)
            for item in self.spec.unit(name).fields:
                for kind in _walk_types(item.type):
                    if isinstance(kind, UnitRef):
                        pending.append(kind.unit)
        for name in sorted(set(self.spec.units) - reached):
            self.warn(
                f"{self.spec.name}.{name}",
                "unit is never referenced from the entry unit",
            )

    def _check_left_recursion(self) -> None:
        """Refuse recursion that cannot consume input and so cannot terminate.

        Only the guaranteed case is reported: a chain of units whose *first*
        field is an unconditional, unrepeated reference back into the chain.
        Recursion elsewhere is legitimate — nested structures need it — and
        whether it terminates depends on data the checker does not have.
        """
        reported: set[frozenset[str]] = set()
        for name in sorted(self.spec.units):
            chain = self._leading_chain(name)
            if chain is None:
                continue
            cycle = frozenset(chain)
            if cycle in reported:
                continue
            reported.add(cycle)
            self.error(
                f"{self.spec.name}.{name}",
                "unit recurses without consuming input and cannot terminate: "
                + " -> ".join([*chain, name]),
            )

    def _leading_chain(self, name: str) -> list[str] | None:
        """Follow first-field unit references from ``name`` back to itself.

        Returns:
            The chain of unit names if following each unit's leading field
            returns to ``name``, or ``None`` if the walk stops first — at a
            unit with no fields, a leading field that is not a plain unit
            reference, or a conditional or repeated one, any of which give
            the recursion a way out.

        """
        chain: list[str] = []
        current = name
        while True:
            unit = self.spec.units.get(current)
            if unit is None or not unit.fields:
                return None
            head = unit.fields[0]
            if (
                head.condition is not None
                or head.repeat is not None
                or not isinstance(head.type, UnitRef)
            ):
                return None
            chain.append(current)
            following = head.type.unit
            if following == name:
                return chain
            if following in chain:
                # A cycle that does not include `name`; whoever owns it reports.
                return None
            current = following

    # --- units and fields --------------------------------------------------

    def _check_unit(self, unit: Unit) -> None:
        """Check one unit's fields, expressions, and guards."""
        where = f"{self.spec.name}.{unit.name}"
        if not unit.fields:
            self.warn(where, "unit has no fields")
        seen_params = {param.name for param in unit.params}
        if len(seen_params) != len(unit.params):
            self.error(where, "unit declares duplicate parameter names")

        # confirm/reject see the whole unit: both are decided once it is done.
        whole = _visible_names(unit, len(unit.fields))
        for label, guard in (("confirm", unit.confirm), ("reject", unit.reject)):
            if guard is not None:
                self._expect(guard, ExprType.BOOL, unit, whole, f"{where}.{label}", label)

        for index, item in enumerate(unit.fields):
            self._check_field(unit, index, item)
        self._check_fills(unit)

    def _check_fills(self, unit: Unit) -> None:
        """Resolve every ``fill`` in this unit, or say why it cannot be.

        Its own pass because it is the one rule that needs a field's *index*:
        every other check asks about a field, and this one asks about the
        fields after it. At most one fill may be in a unit — two would each be
        sized against the other's unknown extent.
        """
        where = f"{self.spec.name}.{unit.name}"
        filled = [
            (index, item)
            for index, item in enumerate(unit.fields)
            if any(isinstance(_size_of(kind), Fill) for kind in _walk_types(item.type))
        ]
        if len(filled) > 1:
            listed = ", ".join(repr(item.name or "<anonymous>") for _, item in filled)
            self.error(
                where,
                f"unit declares more than one fill ({listed}); each would be sized "
                "against the other's unknown extent",
            )
            return
        for index, item in filled:
            label = item.name or f"<anonymous {index}>"
            if item.repeat is not None:
                self.error(
                    f"{where}.{label}",
                    "a fill cannot repeat: the first element would take everything "
                    "the trailing fields do not claim, leaving the rest nothing",
                )
                continue
            try:
                trailing_width(self.spec, unit.name, index)
            except SpecError as exc:
                self.error(f"{where}.{label}", str(exc))
                continue
            if self.spec.input is InputShape.STREAM:
                self.warn(
                    f"{where}.{label}",
                    "a fill under 'input: stream' takes the rest of the run, not the "
                    "rest of the message; every message after this one in the same "
                    "segment would be swallowed by this field",
                )

    def _check_field(self, unit: Unit, index: int, item: Field) -> None:
        """Check one field's type, guards, size, and repetition."""
        label = item.name or f"<anonymous {index}>"
        where = f"{self.spec.name}.{unit.name}.{label}"
        visible = _visible_names(unit, index)

        if item.condition is not None:
            self._expect(item.condition, ExprType.BOOL, unit, visible, where, "condition")

        if item.repeat is not None:
            self._check_repeat(unit, index, item, where)

        if item.const is not None:
            self._check_const(item, where)

        for kind in _walk_types(item.type):
            self._check_type(unit, kind, visible, where)

        if isinstance(item.type, Switch):
            self._check_switch(unit, item.type, visible, where)

    def _check_const(self, item: Field, where: str) -> None:
        """Check that a field's constant is something the field could read.

        Three ways it cannot be, and each is otherwise found by a decode that
        never matches anything — which looks like traffic that is not ours
        rather than like a spec that cannot match.
        """
        const = item.const
        kind = item.type
        if not isinstance(kind, (IntType, BytesType, StringType)):
            self.error(
                where,
                f"a constant needs a field that holds a value, and this is a "
                f"{type(kind).__name__.removesuffix('Type').lower()}; a condition "
                "over more than one field is a unit's 'confirm'",
            )
            return
        wanted = {IntType: int, BytesType: bytes, StringType: str}[type(kind)]
        if not isinstance(const, wanted):
            self.error(
                where,
                f"the constant is {type(const).__name__}, and the field decodes "
                f"{wanted.__name__}",
            )
            return
        if isinstance(kind, IntType) and isinstance(const, int):
            low, high = _int_range(kind)
            if not low <= const <= high:
                self.error(
                    where,
                    f"the constant {const} does not fit {kind.bits} "
                    f"{'signed ' if kind.signed else ''}bits, which holds {low} to {high}",
                )

    def _check_repeat(self, unit: Unit, index: int, item: Field, where: str) -> None:
        """Check a repeat clause. ``until`` additionally sees its own field."""
        repeat = item.repeat
        if isinstance(repeat, Count):
            visible = _visible_names(unit, index)
            self._expect(repeat.expr, ExprType.INT, unit, visible, where, "repeat count")
        elif isinstance(repeat, Until):
            # `until` runs after each element, so the field it repeats is in
            # scope and means *that element* rather than the list so far.
            visible = _visible_names(unit, index + 1)
            self._expect(
                repeat.expr,
                ExprType.BOOL,
                unit,
                visible,
                where,
                "repeat until",
                element_of=item.name,
                element_as=repeat.alias,
            )

    def _check_type(self, unit: Unit, kind: FieldType, visible: set[str], where: str) -> None:
        """Check one field type: references, enums, sizes, and arguments."""
        if isinstance(kind, IntType) and kind.enum is not None and kind.enum not in self.spec.enums:
            known = ", ".join(sorted(self.spec.enums)) or "none"
            self.error(where, f"unknown enum {kind.enum!r}; declared enums: {known}")
        if isinstance(kind, UnitRef):
            self._check_unit_ref(unit, kind, visible, where)
        if isinstance(kind, Computed):
            # Any type is fine; it just has to resolve and type-check.
            self._infer(kind.expr, unit, visible, where, "computed")
        if isinstance(kind, Pointer):
            # The offset obeys the same forward-reference rule as a size: it
            # may only read fields already decoded where the pointer stands.
            self._expect(kind.at, ExprType.INT, unit, visible, where, "pointer at")
        if isinstance(kind, Select):
            self._check_select(unit, kind, visible, where)
        size = _size_of(kind)
        if isinstance(size, FromExpr):
            self._expect(size.expr, ExprType.INT, unit, visible, where, "size")
        if (
            isinstance(size, Terminated)
            and not size.required
            and size.within is None
            and isinstance(kind, StringType)
        ):
            # `within` is exempt because it *is* the guarantee this warns about
            # the absence of. An unbounded optional terminator swallows the rest
            # of the run, so a truncated message reads as a whole one; a bounded
            # one cannot reach past its bound, so there is nothing to hide.
            self.warn(where, "a non-required terminator on a string makes truncation invisible")

    def _check_select(self, unit: Unit, kind: Select, visible: set[str], where: str) -> None:
        """Check a select: a real, earlier, repeated source, and agreeing types.

        The ordering rule is the ordinary one — a select may only ask about a
        repetition already decoded — so it is checked against ``visible``
        exactly as any other reference is. What is *not* ordinary is that the
        source may be repeated at all, which nothing else may be; that
        exemption lives in :class:`_Scope` and reaches only ``where`` and
        ``value``.
        """
        source = unit.field(kind.source)
        if kind.source not in visible:
            if source is not None:
                self.error(
                    where,
                    f"select from {kind.source!r}: it is declared later in unit "
                    f"{unit.name!r}; a select may only ask about a repetition "
                    "already decoded",
                )
            else:
                known = ", ".join(sorted(visible)) or "none"
                self.error(
                    where,
                    f"select from {kind.source!r}: unknown name in unit "
                    f"{unit.name!r}; in scope: {known}",
                )
            return
        if source is None:
            # In scope but not a field: a unit parameter holds a scalar, so
            # there is no repetition behind it to ask about.
            self.error(
                where,
                f"select from {kind.source!r}: that is a parameter, not a repeated field",
            )
            return
        if source.repeat is None:
            self.error(
                where,
                f"select from {kind.source!r}: it is not repeated, so there is "
                "nothing to select from",
            )
            return
        # `where` and `value` see the element, under the repetition's own name,
        # exactly as an `until` does. `default` does not: nothing matched, so
        # there is no element for it to mean.
        self._expect(
            kind.where, ExprType.BOOL, unit, visible, where, "select where",
            element_of=kind.source, element_as=kind.alias,
        )
        projected = self._infer(
            kind.value, unit, visible, where, "select value",
            element_of=kind.source, element_as=kind.alias,
        )
        fallback = self._infer(kind.default, unit, visible, where, "select default")
        if projected is not None and fallback is not None and projected is not fallback:
            self.error(
                where,
                f"select value is {projected.value} but its default is "
                f"{fallback.value}; they must agree, because either one can end up "
                "being the field's value",
            )

    def _check_unit_ref(self, unit: Unit, kind: UnitRef, visible: set[str], where: str) -> None:
        """Check that a unit reference resolves and its arguments match."""
        target = self.spec.units.get(kind.unit)
        if target is None:
            known = ", ".join(sorted(self.spec.units))
            self.error(where, f"unknown unit {kind.unit!r}; known units: {known}")
            return
        if len(kind.args) != len(target.params):
            self.error(
                where,
                f"unit {kind.unit!r} takes {len(target.params)} argument(s), "
                f"got {len(kind.args)}",
            )
            return
        for argument, param in zip(kind.args, target.params, strict=True):
            self._expect(argument, param.type, unit, visible, where, f"argument {param.name!r}")

    def _check_switch(self, unit: Unit, kind: Switch, visible: set[str], where: str) -> None:
        """Check that switch keys agree with the type dispatched on."""
        on_type = self._infer(kind.dispatch, unit, visible, where, "switch dispatch")
        if on_type is None:
            return
        if on_type not in (ExprType.INT, ExprType.STR):
            self.error(where, f"switch dispatches on {on_type.value}; use int or str")
            return
        wanted = int if on_type is ExprType.INT else str
        for key in kind.cases:
            # bool is an int subclass; a `true:` key is a YAML accident.
            if isinstance(key, bool) or not isinstance(key, wanted):
                self.error(
                    where,
                    f"switch case key {key!r} does not match the {on_type.value} "
                    "expression it dispatches on",
                )
        if kind.default is None:
            self.warn(
                where,
                "switch has no default; an unmatched value becomes an undecodable region",
            )

    # --- expressions -------------------------------------------------------

    def _expect(
        self,
        expr: Expr,
        wanted: ExprType,
        unit: Unit,
        visible: set[str],
        where: str,
        label: str,
        element_of: str | None = None,
        element_as: str | None = None,
    ) -> None:
        """Infer an expression's type and report if it is not ``wanted``."""
        actual = self._infer(expr, unit, visible, where, label, element_of, element_as)
        if actual is not None and actual is not wanted:
            self.error(
                where,
                f"{label} must be {wanted.value}, got {actual.value}: {unparse(expr)}",
            )

    def _infer(
        self,
        expr: Expr,
        unit: Unit,
        visible: set[str],
        where: str,
        label: str,
        element_of: str | None = None,
        element_as: str | None = None,
    ) -> ExprType | None:
        """Infer an expression's type, turning any failure into a finding."""
        scope = _Scope(self, unit, visible, element_of, element_as)
        try:
            return infer_type(expr, scope, unparse(expr), where)
        except ExprError as exc:
            self.error(where, f"{label}: {exc.message}")
            return None


class _Scope:
    """Resolves a reference path to a type, for one field's position.

    ``element_of`` names the field an enclosing ``until`` or ``select``
    repeats. One element of it resolves to the element type rather than being
    refused as a list, because both constructs are evaluated once per element
    with that element in hand.

    ``element_as`` is the name that element answers to. Without one it is the
    repeated field's own name, which is the shorthand; with one, the repeated
    field's name is a list again and only the alias means an element. Exactly
    one name means an element either way, which is what keeps a list from ever
    being held: the language has no type for one.
    """

    def __init__(
        self,
        checker: _Checker,
        unit: Unit,
        visible: set[str],
        element_of: str | None = None,
        element_as: str | None = None,
    ) -> None:
        self.checker = checker
        self.unit = unit
        self.visible = visible
        self.element_of = element_of
        self.element_as = element_as

    @property
    def element_name(self) -> str | None:
        """The name one element of the repetition is in scope under, if any."""
        return self.element_as or self.element_of

    def resolve(self, path: tuple[str, ...]) -> ExprType:
        """Return the type named by ``path``, or raise :class:`ExprError`."""
        head, *rest = path
        if head == "this":
            return self._in_unit(self.unit, tuple(rest), self.visible, path)
        if head == "root":
            return self._resolve_root(tuple(rest), path)
        if head == "parent":
            return self._resolve_parent(tuple(rest), path)
        return self._in_unit(self.unit, path, self.visible, path)

    def _fail(self, path: tuple[str, ...], message: str) -> ExprError:
        """Build the error for an unresolvable path."""
        return ExprError(message, ".".join(path))

    def _resolve_root(self, rest: tuple[str, ...], path: tuple[str, ...]) -> ExprType:
        """Resolve against the entry unit, with no ordering rule (see module doc)."""
        entry = self.checker.spec.units.get(self.checker.spec.entry)
        if entry is None:
            raise self._fail(path, "root is unresolvable: the entry unit does not exist")
        return self._in_unit(entry, rest, None, path)

    def _resolve_parent(self, rest: tuple[str, ...], path: tuple[str, ...]) -> ExprType:
        """Resolve against every referencing site, requiring them to agree."""
        sites = self.checker.parents.get(self.unit.name, [])
        if not sites:
            raise self._fail(
                path, f"parent is unresolvable: nothing references unit {self.unit.name!r}"
            )
        types = set()
        for parent_unit, index in sites:
            visible = _visible_names(parent_unit, index)
            types.add(self._in_unit(parent_unit, rest, visible, path))
        if len(types) > 1:
            listed = ", ".join(sorted(kind.value for kind in types))
            message = f"parent reference has conflicting types across callers: {listed}"
            raise self._fail(path, message)
        return types.pop()

    def _in_unit(
        self,
        unit: Unit,
        parts: tuple[str, ...],
        visible: set[str] | None,
        path: tuple[str, ...],
    ) -> ExprType:
        """Walk a dotted path through ``unit``, descending into nested units."""
        if not parts:
            raise self._fail(path, "a reference must name a field")
        head, *rest = parts
        if (
            self.element_as is not None
            and head == self.element_as
            and unit is self.unit
        ):
            # The alias is not a field of the unit, so it never appears in
            # `visible` and the ordinary lookup below cannot find it. It stands
            # for one element of `element_of`, whose own ordering was checked
            # where the construct was written.
            item = unit.field(self.element_of or "")
            if item is None:
                known = ", ".join(sorted(visible or ())) or "none"
                message = (
                    f"unknown name {self.element_of!r} in unit {unit.name!r}; "
                    f"in scope: {known}"
                )
                raise self._fail(path, message)
            return self._type_of(item, unit, tuple(rest), path, as_element=True)
        if visible is not None and head not in visible:
            declared = unit.field(head) is not None
            if declared:
                message = (
                    f"{head!r} is declared later in unit {unit.name!r}; a field may only "
                    "reference fields decoded before it"
                )
            else:
                known = ", ".join(sorted(visible)) or "none"
                message = f"unknown name {head!r} in unit {unit.name!r}; in scope: {known}"
            raise self._fail(path, message)

        for param in unit.params:
            if param.name == head:
                if rest:
                    raise self._fail(path, f"parameter {head!r} has no fields to reference")
                return param.type

        item = unit.field(head)
        if item is None:
            known = ", ".join(sorted(visible or ())) or "none"
            message = f"unknown name {head!r} in unit {unit.name!r}; in scope: {known}"
            raise self._fail(path, message)
        return self._type_of(item, unit, tuple(rest), path)

    def _type_of(
        self,
        item: Field,
        unit: Unit,
        rest: tuple[str, ...],
        path: tuple[str, ...],
        *,
        as_element: bool = False,
    ) -> ExprType:
        """Type one field, descending into it when the path continues."""
        if item.repeat is not None and not (
            as_element or (self.element_as is None and item.name == self.element_of)
        ):
            raise self._fail(
                path,
                f"{item.name!r} is repeated; the expression language has no list type",
            )
        kind = item.type
        if isinstance(kind, UnitRef):
            target = self.checker.spec.units.get(kind.unit)
            if target is None:
                raise self._fail(path, f"unknown unit {kind.unit!r}")
            # Ordering inside a nested unit is that unit's business: by the
            # time it can be referenced, all of it has been decoded.
            return self._in_unit(target, rest, None, path)
        if rest:
            raise self._fail(path, f"{item.name!r} is not a unit, so {rest[0]!r} cannot be read")
        if isinstance(kind, IntType):
            return ExprType.INT
        if isinstance(kind, StringType):
            return ExprType.STR
        if isinstance(kind, BytesType):
            return ExprType.BYTES
        if isinstance(kind, Computed):
            # `None`, not the referrer's visible set. The ordering rule is
            # about where the *reference* stands, and it was applied when the
            # head of this path was looked up; re-applying it to the computed's
            # own expression asks the wrong question, and asks it against the
            # wrong unit whenever the path crossed into a nested one. Its own
            # ordering was checked at its own declaration site by
            # `_Checker._check_field`. Same argument as the `UnitRef` branch
            # above, which states it for descending rather than for typing.
            return infer_type(kind.expr, _Scope(self.checker, unit, None), unparse(kind.expr))
        if isinstance(kind, Select):
            # A select's type is its projection's, which is the whole reason
            # aggregation went into the model: no new `ExprType` member, and a
            # scalar any later field can reference. `value` is evaluated with
            # the element bound, so typing it needs that binding too.
            scope = _Scope(self.checker, unit, None, kind.source, kind.alias)
            return infer_type(kind.value, scope, unparse(kind.value))
        raise self._fail(
            path,
            f"{item.name!r} is a switch; its type depends on the value dispatched on, "
            "so it cannot be referenced directly",
        )
