"""Turn a decode tree into the records a `zpf` stage should write.

Split in two on purpose. :func:`plan` is pure — a tree in, a list of
:class:`Emission` and :class:`Unclaimed` out — so every decision about *what*
to write is testable without opening a file. The stage driver does the writing.

**The field path is formatted in exactly one place** (:func:`field_path`), which
is ``DESIGN.md`` §4.1's requirement rather than a tidiness preference: the path
currently rides in ``comment=``, which `zpf` documents as free text no consumer
may depend on, and upstream
`#58 <https://github.com/adamkjonsson/python-zipline/issues/58>`_ is expected to
replace it with a real per-record label. Keeping the formatting to one function
is what makes that a one-line change. For the same reason **nothing here reads
a comment back** — the read side is the tree, not the file.

The ``prim:`` vocabulary is closed (``u8``…``u64``, ``i8``…``i64``, ``bytes``),
so a field whose width is not 8, 16, 32, or 64 bits has no token of its own. See
:func:`kober.runtime.prim_token`, which lives in the runtime rather than here
because a *generated* decoder normalizes its payloads the same way and may not
import this module — and two answers to "what is a ``u4`` written as" would be
one too many.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kober.expr import references
from kober.node import NodeStatus
from kober.runtime import TEXT_CONTENT_TYPE, normalize_int, prim_int, prim_token
from kober.spec import Computed, Emit, IntType, Select

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from kober.node import Node
    from kober.spec import Spec

@dataclass(frozen=True)
class Emission:
    """One record to write.

    Attributes:
        payload: The bytes to write, already normalized for ``content_type``.
        content_type: The label.
        off_start: First input byte this is evidence about.
        off_end: One past the last.
        comment: The field path, for field granularity. Free text — see the
            module docstring.

    """

    payload: bytes
    content_type: str
    off_start: int
    off_end: int
    comment: str | None = None


@dataclass(frozen=True)
class Unclaimed:
    """One input region no record will cite, and why.

    Attributes:
        off_start: First byte.
        off_end: One past the last.
        reason: A `zpf` ``reason=`` string, straight off a
            :class:`~kober.node.NodeStatus` value.

    """

    off_start: int
    off_end: int
    reason: str


def field_path(names: Sequence[str | None]) -> str:
    """Format a field path from the names on the way down to a node.

    **The single site.** Anonymous fields keep their position rather than
    disappearing, so two of them in one unit stay distinguishable.

    Args:
        names: Names from the root down to and including the node.

    Returns:
        A dotted path, e.g. ``"dns.flags.qr"``.

    Example:
        >>> field_path(["dns", "flags", "qr"])
        'dns.flags.qr'

    """
    return ".".join(name if name is not None else "_" for name in names)


#: Field types whose value has **no declared width**, so its magnitude decides
#: the ``prim:`` token. Both compute rather than read: a ``computed:`` names an
#: expression and a ``select:`` names a projection, and neither has bits behind
#: it the way an ``int:`` does. They differ in what they *cite* — a computed
#: cites the fields its expression read, a select cites the element it chose —
#: but not in how they are sized.
UNDECLARED_WIDTH = (Computed, Select)


def _int_bits(node: Node) -> tuple[int, bool]:
    """Return the declared width and signedness behind an integer node."""
    kind = node.resolved_type
    if isinstance(kind, IntType):
        return kind.bits, kind.signed
    # No declared width; `kober.runtime.prim_int` sizes it by its magnitude,
    # and this is only reached for the declared ones.
    value = node.value
    magnitude = abs(value) if isinstance(value, int) else 0
    bits = max(8, magnitude.bit_length() + 1)
    return bits, isinstance(value, int) and value < 0


def resolve_emit(node: Node, spec: Spec, default: Emit) -> Emit:
    """Return the granularity in force for a node: field, then unit, then decoder.

    Args:
        node: The node being considered.
        spec: The spec, for the unit's own setting.
        default: The decoder's setting.

    Returns:
        The granularity to apply.

    """
    if node.spec_field is not None and node.spec_field.emit is not None:
        return node.spec_field.emit
    if node.unit is not None:
        unit = spec.units.get(node.unit)
        if unit is not None and unit.emit is not None:
            return unit.emit
    return default


def plan(
    spec: Spec,
    tree: Node,
    data: bytes,
    *,
    emit: Emit = Emit.MESSAGE,
    base: int = 0,
) -> tuple[list[Emission], list[Unclaimed]]:
    """Decide what a stage should write for one decoded tree.

    Args:
        spec: The spec that produced the tree, for names and unit settings.
        tree: The decode tree.
        data: The run the tree was decoded from, for message payloads.
        emit: The decoder's default granularity.
        base: Stream offset of ``data[0]``.

    Returns:
        The records to write, and the regions to mark undecoded. The tail
        beyond ``tree.off_end`` is **not** included: only the driver knows how
        much input there was, so it accounts for that.

    """
    emissions: list[Emission] = []
    unclaimed: list[Unclaimed] = []
    granularity = resolve_emit(tree, spec, emit)

    if granularity is Emit.MESSAGE:
        # Only a *whole* message is a message. Emitting a record for a tree
        # that truncated or went undecodable would claim we decoded something
        # we did not, and the bytes are better named with the reason instead.
        if tree.width and tree.status is NodeStatus.OK:
            start = tree.off_start - base
            emissions.append(
                Emission(
                    payload=data[start : start + tree.width],
                    content_type=f"dec:{spec.name}-message",
                    off_start=tree.off_start,
                    off_end=tree.off_end,
                )
            )
    elif granularity is Emit.FIELD:
        # Paths are rooted at the *spec* name, not the entry unit's, matching
        # `dns.flags.qr` in §4.1 and the pressure test.
        _walk(spec, tree, [spec.name], emit, emissions, unclaimed)
    elif tree.width:
        unclaimed.append(Unclaimed(tree.off_start, tree.off_end, NodeStatus.SKIPPED.value))

    unclaimed.extend(_holes(tree, emissions, unclaimed))
    return emissions, _merge(unclaimed)


def _holes(
    tree: Node, emissions: Sequence[Emission], named: Sequence[Unclaimed]
) -> list[Unclaimed]:
    """Account for bytes inside the tree that nothing has claimed.

    Attributing a *failure* is not the same as marking its whole unit: a unit
    that truncated halfway still decoded — and cited — everything before the
    trouble, and a region may not be both cited and undecoded. So the reason
    is worked out per uncovered run, from the innermost failing node that
    covers it.
    """
    spoken = _union(
        [(e.off_start, e.off_end) for e in emissions]
        + [(u.off_start, u.off_end) for u in named]
    )
    holes = _subtract([(tree.off_start, tree.off_end)], spoken)
    return [Unclaimed(start, end, _reason_for(tree, start, end)) for start, end in holes]


def _reason_for(tree: Node, start: int, end: int) -> str:
    """Return the reason for an uncovered run, from the innermost failure over it."""
    reason = NodeStatus.SKIPPED.value
    best = None
    for node in tree.walk():
        if node.status is NodeStatus.OK:
            continue
        if node.off_start <= start and end <= max(node.off_end, node.off_start):
            width = node.off_end - node.off_start
            if best is None or width <= best:
                best, reason = width, node.status.value
    if best is None and tree.status is not NodeStatus.OK:
        # The failure stopped the decode before its own extent was known —
        # truncation is the usual case — so the root's verdict stands.
        return tree.status.value
    return reason


def _union(intervals: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping half-open intervals."""
    ordered = sorted((s, e) for s, e in intervals if e > s)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _subtract(
    base: Sequence[tuple[int, int]], remove: Sequence[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Return ``base`` minus ``remove``, both half-open and already merged."""
    out: list[tuple[int, int]] = []
    for start, end in base:
        cursor = start
        for cut_start, cut_end in remove:
            if cut_end <= cursor or cut_start >= end:
                continue
            if cut_start > cursor:
                out.append((cursor, min(cut_start, end)))
            cursor = max(cursor, cut_end)
            if cursor >= end:
                break
        if cursor < end:
            out.append((cursor, end))
    return out


def _walk(
    spec: Spec,
    node: Node,
    names: list[str | None],
    default: Emit,
    emissions: list[Emission],
    unclaimed: list[Unclaimed],
) -> None:
    """Walk a tree at field granularity, emitting one record per leaf."""
    for child in node.children:
        # A repetition contributes no path segment of its own: its elements are
        # already named `field[0]`, `field[1]`, so counting the container too
        # would spell every repeat twice — `questions.questions[0]`.
        path = names if child.is_repetition else [*names, child.name]
        granularity = resolve_emit(child, spec, default)
        if not child.is_leaf:
            # A container's setting becomes the default *inside* it rather
            # than a verdict on it, so a field that names its own granularity
            # still wins over the unit holding it — field, then unit, then
            # whatever encloses that, then the decoder.
            _walk(spec, child, path, granularity, emissions, unclaimed)
            continue
        if granularity is Emit.NONE:
            # Decoded for control flow only. The bytes were deliberately
            # passed over, which is exactly what `skipped` means — and §2
            # wants it said rather than left to auto-fill.
            if child.width:
                unclaimed.append(
                    Unclaimed(child.off_start, child.off_end, NodeStatus.SKIPPED.value)
                )
            continue
        emission = _leaf(child, path, node)
        if emission is not None:
            emissions.append(emission)


def _leaf(node: Node, path: list[str | None], parent: Node) -> Emission | None:
    """Build the record for one leaf, or ``None`` if it has nothing to say."""
    if node.status is not NodeStatus.OK or node.value is None:
        return None
    off_start, off_end = node.off_start, node.off_end
    if isinstance(node.resolved_type, Computed):
        # §3.2: it decodes nothing, so it cites the fields it read.
        off_start, off_end = _cited_inputs(node, parent)
    value = node.value
    if isinstance(value, bytes):
        return Emission(value, "prim:bytes", off_start, off_end, field_path(path))
    if isinstance(value, str):
        payload = value.encode("utf-8", errors="replace")
        return Emission(payload, TEXT_CONTENT_TYPE, off_start, off_end, field_path(path))
    if isinstance(value, bool):
        return Emission(bytes([int(value)]), "prim:u8", off_start, off_end, field_path(path))
    if isinstance(node.resolved_type, UNDECLARED_WIDTH):
        # Nothing declared its width, so the value decides it — and a value
        # wider than the vocabulary gets no record. See `kober.runtime.prim_int`.
        labelled = prim_int(value)
        if labelled is None:
            return None
        return Emission(*labelled, off_start, off_end, field_path(path))
    bits, signed = _int_bits(node)
    payload = normalize_int(value, bits, signed)
    token = prim_token(bits, signed)
    return Emission(payload, f"prim:{token}", off_start, off_end, field_path(path))


def _cited_inputs(node: Node, parent: Node) -> tuple[int, int]:
    """Return the range a computed field's inputs cover.

    A computed value consumed nothing, so citing its own position would claim
    an empty range and say nothing about where the value came from. It cites
    the fields its expression read instead — the design's answer in §3.2.
    """
    kind = node.resolved_type
    if not isinstance(kind, Computed):
        return node.off_start, node.off_end
    starts: list[int] = []
    ends: list[int] = []
    for ref in references(kind.expr):
        target = _lookup(ref.path, parent)
        if target is not None and target.width:
            starts.append(target.off_start)
            ends.append(target.off_end)
    if not starts:
        return node.off_start, node.off_end
    return min(starts), max(ends)


def _lookup(path: Sequence[str], parent: Node) -> Node | None:
    """Resolve a reference path against the tree, for citation purposes only."""
    parts = list(path)
    if parts and parts[0] in ("this", "root", "parent"):
        # `root` and `parent` reach outside what this walk holds; citing the
        # sibling range is the honest approximation, so those are skipped.
        if parts[0] != "this":
            return None
        parts = parts[1:]
    node: Node | None = parent
    for part in parts:
        if node is None:
            return None
        node = node.find(part)
    return node


def _merge(regions: Iterable[Unclaimed]) -> list[Unclaimed]:
    """Coalesce adjacent regions sharing a reason, and drop the empty ones."""
    ordered = sorted((r for r in regions if r.off_end > r.off_start), key=lambda r: r.off_start)
    merged: list[Unclaimed] = []
    for region in ordered:
        if merged and merged[-1].reason == region.reason and merged[-1].off_end >= region.off_start:
            previous = merged.pop()
            merged.append(
                Unclaimed(
                    previous.off_start,
                    max(previous.off_end, region.off_end),
                    region.reason,
                )
            )
            continue
        merged.append(region)
    return merged
