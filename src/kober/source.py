"""Where a fault is, in the file the author wrote.

A spec is hand-written YAML, so a message that names the construct and not the
line is a description of a problem rather than a way to find it.
``units.message.fields[0]`` means counting field entries by hand, over the
*loaded* document, so a commented-out field shifts the count away from anything
visible.

Two records, and the split is by who needs them:

- :class:`Location` is what a raised fault carries. The loader threads one down
  the document as it descends, so a :class:`~kober.errors.SpecError` knows the
  file, the line, and the path without anything having to reconstruct them.
- :class:`SourceMap` is what a *returned* fault looks one up in.
  :func:`kober.check.check` runs on a built :class:`~kober.spec.Spec` with the
  document long gone, and derives its paths from model names — ``dns.message``,
  not ``spec.units.message``. So the loader records the lines of the things the
  checker reports on, in the checker's own vocabulary, and the map travels on
  the spec.

**Nothing here participates in equality.** ``Spec.sources`` is declared
``compare=False``, because three of this release's shorthands rest on the test
that two spellings of the same spec build an *identical* model, and two
spellings differ in line layout. A location is something a spec was read from,
not something it is.

**A source that reports no positions degrades, and does not break.** ``json``
has no line information and a mapping built in memory has no source at all, so
:attr:`Location.line` is ``None`` and the message carries the path alone —
exactly what was printed before any of this existed. That path is the one the
standard library alone supports, so it stays first-class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class Location:
    """Where in a document something is.

    Attributes:
        path: Dotted path to the construct, e.g. ``"spec.units.message"``.
        line: 1-based line in the source, or ``None`` when the format reports
            no positions.
        source: The file the document was read from, or ``None`` for text and
            mappings that came from nowhere on disk.

    Example:
        >>> str(Location("dns.message.id", line=27, source="dns.yaml"))
        'dns.yaml:27: dns.message.id'

    """

    path: str
    line: int | None = None
    source: str | None = None

    def child(self, step: object) -> Location:
        """Return the location of a step below this one.

        A step naming an index is appended directly, so a field is
        ``fields[0]`` rather than ``fields.[0]``. The line is inherited: a
        fault on a key of a mapping is reported at the mapping, which is the
        line the author is looking at.

        Args:
            step: The path segment, or an index written as ``"[0]"``.

        Returns:
            The child location.

        """
        text = step if isinstance(step, str) else str(step)
        separator = "" if text.startswith("[") else "."
        return Location(f"{self.path}{separator}{text}", self.line, self.source)

    def at_line(self, line: int | None) -> Location:
        """Return this location with a line attached.

        Args:
            line: The 1-based line, or ``None`` to keep the inherited one.

        Returns:
            This location when there is nothing to attach, otherwise a new one.

        """
        return self if line is None else Location(self.path, line, self.source)

    def __str__(self) -> str:
        if self.source is not None and self.line is not None:
            return f"{self.source}:{self.line}: {self.path}"
        return self.path


@dataclass(frozen=True, slots=True)
class SourceMap:
    """The lines of everything :func:`kober.check.check` reports on.

    Keyed by the checker's vocabulary — ``dns``, ``dns.message``,
    ``dns.message.qdcount`` — because that is what a :class:`~kober.check.Finding`
    has in hand. Anonymous fields are absent, having no name to be reported
    under, and :meth:`locate` answers for them by falling back to their unit.

    Attributes:
        source: The file the spec was read from, when it was read from one.
        lines: Line of each named construct.

    """

    source: str | None = None
    lines: Mapping[str, int] = field(default_factory=dict)

    def locate(self, path: str) -> Location:
        """Return the location of ``path``, or of the nearest thing above it.

        The fallback is what makes this useful on the paths the checker builds
        that name no construct of their own: ``dns.message.confirm`` is a
        guard rather than a field, and the unit's line is the right answer for
        it.

        Args:
            path: Dotted path, in the checker's vocabulary.

        Returns:
            The location. Its line is ``None`` when nothing above the path is
            known, which is every path when the document reported no positions.

        """
        probe = path
        while probe:
            line = self.lines.get(probe)
            if line is not None:
                return Location(path, line, self.source)
            probe = probe.rpartition(".")[0]
        return Location(path, None, self.source)
