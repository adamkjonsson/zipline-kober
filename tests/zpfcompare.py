"""What it means for a decoded file to be right, and for two of them to agree.

One definition, shared by the suite and by ``tools/pipeline.py``. The release
checklist requires the deeper pipeline to compare the interpreter's file with
the compiled module's "block for block", and that phrase is only worth
something if it means the same thing in the pipeline as in the differential
tests. Keeping :func:`blocks` here, rather than one copy in each, is what stops
the two from drifting apart.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import zpf
from zpf.blocks import Participant, Record, Undecoded

if TYPE_CHECKING:
    from pathlib import Path


def blocks(path: Path) -> list[tuple[object, ...]]:
    """Return what a decoded file says, in file order.

    Records and undecoded regions both, since a difference in either is a
    difference in the file — and each participant's declared adjacency, since
    that is a statement about every record in it, derived separately by each
    implementation. A region's comment is included because it is the only
    place a region can say *why*, and two implementations that disagree about
    that have written different files. Read from the raw block stream rather
    than the session views, because the order the two implementations write in
    is part of what is being compared.

    Args:
        path: A decoded ``.zpf`` file.

    Returns:
        One tuple per participant, record and undecoded region, tagged with
        its kind.

    """
    out: list[tuple[object, ...]] = []
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, Participant):
                out.append(("participant", block.participant_id, zpf.Adjacency(block.adjacency)))
            elif isinstance(block, Record):
                spans = tuple((s.off_start, s.off_end) for s in block.spans)
                out.append(("record", block.content_type, block.role, block.payload, spans))
            elif isinstance(block, Undecoded):
                out.append(
                    ("undecoded", block.reason, block.off_start, block.off_end, block.comment)
                )
    return out


def conformance_problems(path: Path, source: Path) -> list[str]:
    """Return everything wrong with a decoded file, as readable lines.

    Conformance first, then the coverage guarantee against the input it was
    decoded from. The checker raises on the first violation it meets, so that
    one is reported and the rest of the conformance pass is not; the coverage
    findings are complete either way.

    Args:
        path: The decoded file.
        source: The file it was decoded from.

    Returns:
        One line per problem; empty when the file is conformant and accounts
        for every byte of its input.

    """
    problems: list[str] = []
    checker = zpf.ConformanceChecker()
    try:
        with zpf.open(path) as handle:
            checker.check(handle.blocks())
        checker.finish()
    except zpf.ZpfError as exc:
        problems.append(f"conformance: {exc}")
    problems.extend(f"coverage: {finding}" for finding in checker.coverage_findings())
    problems.extend(f"coverage: {finding}" for finding in zpf.check_coverage(path, source))
    return problems


def assert_conformant(path: Path, source: Path) -> None:
    """Fail unless the file passes conformance and accounts for its input.

    Args:
        path: The decoded file.
        source: The file it was decoded from.

    """
    assert conformance_problems(path, source) == []
