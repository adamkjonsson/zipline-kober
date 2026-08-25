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
  just decoded.
- *Reachability.* ``parent`` resolves against every site that references the
  unit, and must resolve at all of them — a unit reachable from two parents
  cannot rely on a field only one of them has.

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
from kober.expr import ExprType, infer_type, unparse
from kober.spec import (
    BytesType,
    Computed,
    Count,
    Field,
    FromExpr,
    IntType,
    Pointer,
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
    from kober.spec import FieldType, SizeSpec, Spec


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

    Attributes:
        severity: Whether this stops the spec from running.
        where: Dotted location, e.g. ``"dns.message.qdcount"``.
        message: What is wrong, in the author's vocabulary.

    """

    severity: Severity
    where: str
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


def scope_at(spec: Spec, unit: str, index: int, *, element_of: str | None = None) -> Scope:
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
        element_of: Name of the field an enclosing ``until`` repeats. That
            field alone resolves to its element type rather than being refused
            as a list, because ``until`` runs once per element with that
            element in hand.

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
    return _Scope(_Checker(spec), target, _visible_names(target, index), element_of)


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
        """Record one finding."""
        self.findings.append(Finding(severity, where, message))

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
        return tuple(self.findings)

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

    def _check_field(self, unit: Unit, index: int, item: Field) -> None:
        """Check one field's type, guards, size, and repetition."""
        label = item.name or f"<anonymous {index}>"
        where = f"{self.spec.name}.{unit.name}.{label}"
        visible = _visible_names(unit, index)

        if item.condition is not None:
            self._expect(item.condition, ExprType.BOOL, unit, visible, where, "condition")

        if item.repeat is not None:
            self._check_repeat(unit, index, item, where)

        for kind in _walk_types(item.type):
            self._check_type(unit, kind, visible, where)

        if isinstance(item.type, Switch):
            self._check_switch(unit, item.type, visible, where)

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
        size = _size_of(kind)
        if isinstance(size, FromExpr):
            self._expect(size.expr, ExprType.INT, unit, visible, where, "size")
        if isinstance(size, Terminated) and not size.required and isinstance(kind, StringType):
            self.warn(where, "a non-required terminator on a string makes truncation invisible")

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
        on_type = self._infer(kind.on, unit, visible, where, "switch on")
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
    ) -> None:
        """Infer an expression's type and report if it is not ``wanted``."""
        actual = self._infer(expr, unit, visible, where, label, element_of)
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
    ) -> ExprType | None:
        """Infer an expression's type, turning any failure into a finding."""
        scope = _Scope(self, unit, visible, element_of)
        try:
            return infer_type(expr, scope, unparse(expr), where)
        except ExprError as exc:
            self.error(where, f"{label}: {exc.message}")
            return None


class _Scope:
    """Resolves a reference path to a type, for one field's position.

    ``element_of`` names the field an enclosing ``until`` repeats. That field
    alone resolves to its element type rather than being refused as a list,
    because ``until`` is evaluated once per element with that element in hand.
    """

    def __init__(
        self,
        checker: _Checker,
        unit: Unit,
        visible: set[str],
        element_of: str | None = None,
    ) -> None:
        self.checker = checker
        self.unit = unit
        self.visible = visible
        self.element_of = element_of

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
        self, item: Field, unit: Unit, rest: tuple[str, ...], path: tuple[str, ...]
    ) -> ExprType:
        """Type one field, descending into it when the path continues."""
        if item.repeat is not None and item.name != self.element_of:
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
            scope = _Scope(self.checker, unit, self.visible)
            return infer_type(kind.expr, scope, unparse(kind.expr))
        raise self._fail(
            path,
            f"{item.name!r} is a switch; its type depends on the value dispatched on, "
            "so it cannot be referenced directly",
        )
