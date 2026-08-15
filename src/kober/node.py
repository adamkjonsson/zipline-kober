"""The in-memory decode tree.

A :class:`Node` is what a decode produces: a field, a unit instance, or a
repetition, with the byte range it came from and what became of it.

**It is deliberately not written to any file** (``DESIGN.md`` §6). `zpf` already
has a representation for decoded output — records, spans, and `Undecoded`
blocks — and inventing a parallel one alongside it is what this design set out
to avoid. The tree is what :meth:`kober.decoder.Decoder.decode_bytes` returns,
what ``kober try`` prints, and what the emitter walks to produce records. It
then goes away.

Ranges are **byte** offsets, half-open, and absolute in the stream's offset
space. A sub-byte field cites the bytes *containing* it, because `zpf` spans
are byte offsets (§1) and overlapping citations are legal — which is what makes
a flags word and the bits inside it all expressible.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    from kober.expr import ExprValue
    from kober.spec import Field, FieldType


class NodeStatus(Enum):
    """What became of the region a node covers.

    The four non-``OK`` members are exactly ``DESIGN.md`` §2's vocabulary, and
    their values are the ``reason=`` strings `zpf` expects — so the emitter
    translates a status into an ``undecoded()`` call without a mapping table,
    and the design's list cannot drift from the code's.
    """

    OK = "ok"
    UNDECODABLE = "undecodable"
    TRUNCATED = "truncated"
    GAP = "gap"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Node:
    """One decoded field, unit instance, or repetition.

    Attributes:
        name: Field name, or ``None`` for an anonymous region. The root of a
            decode carries its unit's name.
        value: The decoded value for a leaf; ``None`` for a container.
        off_start: First byte of the range this covers.
        off_end: One past the last byte.
        status: What became of the region.
        children: Fields of a unit, or elements of a repetition.
        unit: The unit's name when this node is a unit instance.
        detail: Why, for a non-``OK`` status — and for the one case where a
            node is ``OK`` but imperfect, a string whose bytes did not decode
            cleanly in its declared encoding.
        is_repetition: Whether this node is a repetition's *container*, whose
            children are its elements. A container and its elements share a
            :attr:`spec_field`, so nothing else tells them apart — and the
            emitter has to, since the elements are already named ``field[0]``
            and counting the container as well would spell every repeat twice.
        spec_field: The spec field this came from, when there is one. Carried
            so the emitter can read ``emit`` and ``doc`` without re-walking
            the spec in parallel with the tree.
        resolved_type: The field type actually decoded. Differs from
            ``spec_field.type`` for a :class:`~kober.spec.Switch`, where it is
            the case that matched.

    """

    name: str | None
    value: ExprValue | None = None
    off_start: int = 0
    off_end: int = 0
    status: NodeStatus = NodeStatus.OK
    children: tuple[Node, ...] = ()
    unit: str | None = None
    detail: str | None = None
    is_repetition: bool = False
    spec_field: Field | None = None
    resolved_type: FieldType | None = None

    def __post_init__(self) -> None:
        if self.off_end < self.off_start:
            msg = f"node {self.name!r} ends at {self.off_end} before it starts at {self.off_start}"
            raise ValueError(msg)

    @property
    def is_leaf(self) -> bool:
        """Whether this node decoded a value rather than containing others."""
        return not self.children

    @property
    def width(self) -> int:
        """How many bytes this node covers."""
        return self.off_end - self.off_start

    def walk(self) -> Iterator[Node]:
        """Yield this node and every descendant, depth first, in decode order.

        Returns:
            Every node in the subtree, this one first.

        """
        yield self
        for child in self.children:
            yield from child.walk()

    def leaves(self) -> Iterator[Node]:
        """Yield only the leaves, in decode order.

        Returns:
            Every node with no children.

        """
        for node in self.walk():
            if node.is_leaf:
                yield node

    def find(self, name: str) -> Node | None:
        """Return the first direct child with this name.

        Args:
            name: The field name to look for.

        Returns:
            The child, or ``None``.

        """
        for child in self.children:
            if child.name == name:
                return child
        return None

    def render(self, indent: str = "") -> str:
        """Render the subtree as indented text, for ``kober try`` and tests.

        Args:
            indent: Prefix for this node's line.

        Returns:
            The rendered tree, newline separated.

        """
        name = self.name if self.name is not None else "(anonymous)"
        parts = [f"{indent}{name}"]
        if self.value is not None:
            parts.append(f" = {self.value!r}")
        parts.append(f"  [{self.off_start}, {self.off_end})")
        if self.status is not NodeStatus.OK:
            parts.append(f"  {self.status.value}")
        if self.detail:
            parts.append(f"  ({self.detail})")
        lines = ["".join(parts)]
        lines.extend(child.render(indent + "  ") for child in self.children)
        return "\n".join(lines)
