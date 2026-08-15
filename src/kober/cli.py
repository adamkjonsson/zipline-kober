"""The ``kober`` command line, one verb per API entry point.

Two verbs exist so far, both of which need only a spec::

    kober check SPEC    # validate and type-check, reporting every fault
    kober show  SPEC    # print the field tree a spec describes

``run`` and ``try`` from ``DESIGN.md`` §6 need the decoder, which is not built
yet. They are deliberately *not* registered: a verb that exists and refuses is
a worse answer than one that is honestly absent.

Exit codes are the usual three: ``0`` success, ``1`` the spec is unusable
(unreadable, malformed, or invalid), ``2`` the command line itself was wrong,
which argparse reports.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from kober import __version__
from kober.check import Severity, check
from kober.errors import KoberError
from kober.expr import unparse
from kober.spec import (
    BytesType,
    Computed,
    Count,
    Fixed,
    FromExpr,
    IntType,
    Remaining,
    Spec,
    StringType,
    Switch,
    Terminated,
    ToEnd,
    UnitRef,
    Until,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from kober.spec import Field, FieldType, Repeat, SizeSpec, Unit

OK = 0
FAILED = 1

_EPILOG = (
    "The 'run' and 'try' verbs are not implemented yet; they need the decoder, "
    "which lands in a later phase."
)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    Returns:
        The parser, exposed so tests and documentation can inspect it.

    """
    parser = argparse.ArgumentParser(
        prog="kober",
        description="Decode network protocols from a declarative specification.",
        epilog=_EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"kober {__version__}")
    verbs = parser.add_subparsers(dest="verb", required=True, metavar="VERB")

    checker = verbs.add_parser("check", help="validate a spec and type its expressions")
    checker.add_argument("spec", metavar="SPEC", help="path to a .yaml, .yml, or .json spec")
    checker.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as failures too",
    )

    shower = verbs.add_parser("show", help="print the field tree a spec describes")
    shower.add_argument("spec", metavar="SPEC", help="path to a .yaml, .yml, or .json spec")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line.

    Args:
        argv: Arguments, defaulting to :data:`sys.argv`.

    Returns:
        The process exit code.

    """
    args = build_parser().parse_args(argv)
    try:
        spec = Spec.from_file(args.spec)
    except KoberError as exc:
        print(f"kober: {exc}", file=sys.stderr)
        return FAILED
    if args.verb == "check":
        return _check(spec, strict=args.strict)
    return _show(spec)


def _check(spec: Spec, *, strict: bool) -> int:
    """Report every finding, and fail if any of them counts."""
    findings = check(spec)
    for finding in findings:
        stream = sys.stderr if finding.severity is Severity.ERROR else sys.stdout
        print(finding, file=stream)
    errors = sum(1 for finding in findings if finding.severity is Severity.ERROR)
    warnings = len(findings) - errors
    if not findings:
        print(f"{spec.name} {spec.version}: ok")
        return OK
    print(f"{spec.name} {spec.version}: {errors} error(s), {warnings} warning(s)")
    return FAILED if errors or (strict and warnings) else OK


def _show(spec: Spec) -> int:
    """Print the field tree the spec describes."""
    print(f"{spec.name} {spec.version} — input: {spec.input.value}, entry: {spec.entry}")
    if spec.doc:
        print(f"  {spec.doc}")
    if spec.enums:
        print()
        for name in sorted(spec.enums):
            members = spec.enums[name].members
            listed = ", ".join(f"{value}={label}" for value, label in sorted(members.items()))
            print(f"enum {name}: {listed}")
    print()
    entry = spec.units.get(spec.entry)
    if entry is None:
        print(f"entry unit {spec.entry!r} does not exist", file=sys.stderr)
        return FAILED
    print(entry.name)
    for line in _unit_lines(spec, entry, prefix="", seen=(entry.name,)):
        print(line)
    unreached = sorted(set(spec.units) - _reachable(spec))
    if unreached:
        print()
        print(f"not reachable from {spec.entry}: {', '.join(unreached)}")
    return OK


def _reachable(spec: Spec) -> set[str]:
    """Return every unit reachable from the entry unit."""
    seen: set[str] = set()
    pending = [spec.entry]
    while pending:
        name = pending.pop()
        if name in seen or name not in spec.units:
            continue
        seen.add(name)
        for item in spec.unit(name).fields:
            for kind in _nested(item.type):
                if isinstance(kind, UnitRef):
                    pending.append(kind.unit)
    return seen


def _nested(kind: FieldType) -> list[FieldType]:
    """Return a type and every type nested in it."""
    found = [kind]
    if isinstance(kind, Switch):
        for case in kind.cases.values():
            found.extend(_nested(case))
        if kind.default is not None:
            found.extend(_nested(kind.default))
    return found


def _unit_lines(spec: Spec, unit: Unit, prefix: str, seen: tuple[str, ...]) -> list[str]:
    """Render one unit's fields as tree lines."""
    lines: list[str] = []
    for index, item in enumerate(unit.fields):
        last = index == len(unit.fields) - 1
        stem = "└── " if last else "├── "
        cont = "    " if last else "│   "
        lines.append(f"{prefix}{stem}{_field_label(item)}")
        if item.doc:
            lines.append(f"{prefix}{cont}  {item.doc}")
        lines.extend(_descend(spec, item.type, prefix + cont, seen))
    return lines


def _descend(spec: Spec, kind: FieldType, prefix: str, seen: tuple[str, ...]) -> list[str]:
    """Expand a unit reference, guarding against recursion."""
    if not isinstance(kind, UnitRef):
        return []
    target = spec.units.get(kind.unit)
    if target is None:
        return [f"{prefix}    (unknown unit {kind.unit!r})"]
    if kind.unit in seen:
        return [f"{prefix}    (recurses into {kind.unit})"]
    return _unit_lines(spec, target, prefix, (*seen, kind.unit))


def _field_label(item: Field) -> str:
    """Render one field as a single line."""
    name = item.name if item.name is not None else "(anonymous)"
    parts = [f"{name}: {_render_type(item.type)}"]
    if item.repeat is not None:
        parts.append(_render_repeat(item.repeat))
    if item.condition is not None:
        parts.append(f"if {unparse(item.condition)}")
    if item.emit is not None:
        parts.append(f"emit={item.emit.value}")
    return "  ".join(parts)


def _render_type(kind: FieldType) -> str:
    """Render a field type compactly."""
    if isinstance(kind, IntType):
        sign = "i" if kind.signed else "u"
        label = f"{sign}{kind.bits}"
        if kind.endian.value != "big":
            label += f" {kind.endian.value}-endian"
        if kind.enum is not None:
            label += f" enum {kind.enum}"
        return label
    if isinstance(kind, BytesType):
        return f"bytes[{_render_size(kind.size)}]"
    if isinstance(kind, StringType):
        return f"string[{_render_size(kind.size)}] {kind.encoding}"
    if isinstance(kind, UnitRef):
        args = ", ".join(unparse(arg) for arg in kind.args)
        return f"→ {kind.unit}({args})" if args else f"→ {kind.unit}"
    if isinstance(kind, Computed):
        return f"computed {unparse(kind.expr)}"
    cases = ", ".join(f"{key!r}" for key in kind.cases)
    tail = "" if kind.default is not None else ", no default"
    return f"switch on {unparse(kind.on)} [{cases}{tail}]"


def _render_size(size: SizeSpec) -> str:
    """Render a size spec compactly."""
    if isinstance(size, Fixed):
        return str(size.count)
    if isinstance(size, FromExpr):
        return unparse(size.expr)
    if isinstance(size, Remaining):
        return "remaining"
    if isinstance(size, Terminated):
        flags = "" if size.required else ", optional"
        return f"until {size.delimiter!r}{flags}"
    return "?"


def _render_repeat(repeat: Repeat) -> str:
    """Render a repeat clause compactly."""
    if isinstance(repeat, Count):
        return f"×{unparse(repeat.expr)}"
    if isinstance(repeat, Until):
        return f"×until {unparse(repeat.expr)}"
    if isinstance(repeat, ToEnd):
        return "×to end"
    return "×?"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
