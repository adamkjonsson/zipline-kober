"""The ``kober`` command line, one verb per API entry point.

The four verbs of ``DESIGN.md`` §6, and the one the compiler adds::

    kober check   SPEC                    # validate and type-check
    kober show    SPEC                    # print the field tree a spec describes
    kober run     SPEC IN.zpf -o OUT.zpf  # decode a file into a decode stage
    kober try     SPEC --hex 0a0b         # decode one buffer, print the tree
    kober compile SPEC -o dns.py          # write a decoder for it, as Python

``compile`` is the one verb whose output is not a decode. It turns a spec into
a module with a typed API, which then decodes without this project's loader,
checker or spec model — only :mod:`kober.runtime`. The interpreter stays: it is
what ``try`` should always use, and it is the reference the generated code is
checked against.

Exit codes are the usual three: ``0`` success, ``1`` the work could not be
done, ``2`` the command line itself was wrong, which argparse reports.

One distinction worth stating, because it decides two of those exit codes.
A spec that will not load or check is a **failure** — nothing can be done with
it. Input that will not fully decode is **not**: an undecodable or truncated
region is a legitimate, conformant result, and ``run`` reports it and exits
``0``. ``try`` is the exception, and deliberately so — it exists to answer
"does this spec read these bytes", so it fails when the answer is no.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from kober import __version__
from kober.check import Severity, check
from kober.decoder import Decoder
from kober.errors import KoberError
from kober.expr import unparse
from kober.node import NodeStatus
from kober.ops import Plan
from kober.pygen import render_spec
from kober.spec import (
    BytesType,
    Computed,
    Count,
    Emit,
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
    "An undecodable or truncated region is a conformant result, not an error: "
    "'run' reports it and still succeeds. 'try' is the exception, since asking "
    "whether a spec reads some bytes is the whole point of it."
)

_SPEC_HELP = "path to a .yaml, .yml, or .json spec"


def _add_spec(parser: argparse.ArgumentParser) -> None:
    """Add the SPEC argument every verb takes."""
    parser.add_argument("spec", metavar="SPEC", help=_SPEC_HELP)


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
    _add_spec(checker)
    checker.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as failures too",
    )

    shower = verbs.add_parser("show", help="print the field tree a spec describes")
    _add_spec(shower)

    runner = verbs.add_parser("run", help="decode a .zpf file into a decode stage")
    _add_spec(runner)
    runner.add_argument("input", metavar="IN.zpf", help="the .zpf file to decode")
    runner.add_argument(
        "-o",
        "--output",
        metavar="OUT.zpf",
        required=True,
        help="where to write the decode stage",
    )
    runner.add_argument(
        "--emit",
        choices=[Emit.MESSAGE.value, Emit.FIELD.value],
        default=Emit.MESSAGE.value,
        help="one record per message (default) or per field",
    )
    runner.add_argument(
        "--produced-by",
        default=f"kober {__version__}",
        help="what to record as the producer",
    )

    compiler = verbs.add_parser("compile", help="write a decoder for a spec, as Python")
    _add_spec(compiler)
    compiler.add_argument(
        "-o",
        "--output",
        metavar="OUT.py",
        help="where to write the module; standard output if omitted",
    )
    compiler.add_argument(
        "--emit",
        choices=[Emit.MESSAGE.value, Emit.FIELD.value, Emit.NONE.value],
        default=Emit.MESSAGE.value,
        help=(
            "granularity to compile for: one record per message (default), one per "
            "field, or none at all. A compile-time choice, not a flag the module "
            "carries — at message granularity it builds no field paths at all"
        ),
    )

    prober = verbs.add_parser("try", help="decode one buffer and print the tree")
    _add_spec(prober)
    prober.add_argument(
        "--hex",
        required=True,
        metavar="BYTES",
        help="the buffer as hex, e.g. 0a0b or '0a 0b'",
    )
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
        if args.verb == "check":
            return _check(spec, strict=args.strict)
        if args.verb == "show":
            return _show(spec)
        if args.verb == "run":
            return _run(spec, args)
        if args.verb == "compile":
            return _compile(spec, args)
        return _try(spec, args)
    except KoberError as exc:
        print(f"kober: {exc}", file=sys.stderr)
        return FAILED


def _run(spec: Spec, args: argparse.Namespace) -> int:
    """Decode a file into a decode stage, then report what landed in it."""
    decoder = Decoder(spec, emit=Emit(args.emit))
    decoder.run(
        args.input,
        args.output,
        produced_by=args.produced_by,
        produced_at=datetime.now(tz=UTC),
    )
    records, regions = _summarize(args.output)
    print(f"{args.output}: {records} record(s), {len(regions)} undecoded region(s)")
    for reason, count in sorted(regions.items()):
        print(f"  {reason}: {count}")
    return OK


def _compile(spec: Spec, args: argparse.Namespace) -> int:
    """Write a decoder for a spec, and say where it went.

    Errors move to build time, which is half of what compiling buys: a spec that
    does not check refuses here rather than at decode time, with the same
    findings ``kober check`` prints.
    """
    findings = check(spec)
    errors = [finding for finding in findings if finding.severity is Severity.ERROR]
    for finding in findings:
        print(finding, file=sys.stderr)
    if errors:
        print(f"kober: {spec.name!r} has {len(errors)} error(s); nothing written", file=sys.stderr)
        return FAILED

    source = render_spec(spec, emit=Emit(args.emit), check=False)
    if args.output is None:
        print(source, end="")
        return OK
    Path(args.output).write_text(source, encoding="utf-8")
    units = len(Plan.from_spec(spec, check=False).objects)
    print(f"{args.output}: {units} unit(s), {Emit(args.emit).value} granularity")
    return OK


def _summarize(path: str) -> tuple[int, dict[str, int]]:
    """Count what was written, by reading the output back.

    Reading the file is the honest way to report on it: it counts what a
    consumer will actually find, not what the writer believed it sent.
    """
    import zpf

    records = 0
    regions: dict[str, int] = {}
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, zpf.Record):
                records += 1
            elif isinstance(block, zpf.Undecoded):
                reason = block.reason or "unstated"
                regions[reason] = regions.get(reason, 0) + 1
    return records, regions


def _try(spec: Spec, args: argparse.Namespace) -> int:
    """Decode one buffer and print the tree.

    Fails when the decode did not complete, which is the question this verb
    exists to answer — unlike ``run``, where an undecodable region is a
    conformant result rather than a problem.
    """
    try:
        data = bytes.fromhex(args.hex.replace(":", " ").replace("-", " "))
    except ValueError as exc:
        print(f"kober: --hex is not valid hex: {exc}", file=sys.stderr)
        return FAILED
    tree = Decoder(spec).decode_bytes(data)
    print(tree.render())
    print()
    print(f"{tree.off_end} of {len(data)} byte(s) decoded: {tree.status.value}")
    if tree.detail:
        print(f"  {tree.detail}")
    return OK if tree.status is NodeStatus.OK and tree.off_end == len(data) else FAILED


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
