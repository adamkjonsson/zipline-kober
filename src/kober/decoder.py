"""The decode engine: a spec and some bytes in, a :class:`~kober.node.Node` out.

This is the loop ``DESIGN.md`` §1 calls the whole product, minus the file
plumbing. Nothing here touches `zpf`: it walks a :class:`~kober.spec.Spec` over
a :class:`~kober.cursor.Cursor` and builds the tree that the emitter later
turns into records.

**Failure never raises out of a decode.** The two internal signals —
:class:`~kober.errors.TruncatedRead` and :class:`~kober.errors.EvalError` — are
caught here and become a node status, because a decoder that raises leaves its
input unaccounted for and the coverage guarantee is a promise about output
(§2). What a caller gets back is always a tree.

**Where a decode stops, it says so.** On a failure the engine marks the node,
stops consuming, and propagates the status to the root. The root's
``off_end`` is therefore *how far the decode got*, not how much input there
was, and the difference is the caller's to account for — which is exactly what
the stage driver needs in order to emit one honest ``undecoded`` region for the
tail rather than guessing at a reason per byte.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from typing import TYPE_CHECKING

from kober.check import require_valid
from kober.cursor import Cursor
from kober.errors import EvalError, TruncatedRead
from kober.expr import ExprValue, evaluate
from kober.node import Node, NodeStatus
from kober.spec import (
    BytesType,
    Computed,
    Count,
    Emit,
    Fixed,
    FromExpr,
    IntType,
    Pointer,
    Remaining,
    Select,
    StringType,
    Switch,
    Terminated,
    ToEnd,
    UnitRef,
    Until,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from datetime import datetime
    from pathlib import Path

    from kober.expr import Expr
    from kober.spec import Field, FieldType, Repeat, SizeSpec, Spec, Unit

#: How deep unit references may nest before the decode is abandoned. A
#: recursive spec over crafted input would otherwise exhaust the interpreter
#: stack, and a `RecursionError` escaping a decode is the failure this module
#: promises never to have.
MAX_DEPTH = 64

#: How many pointer hops one chain may take before the decode is abandoned.
#: Separate from :data:`MAX_DEPTH` because a deep unit tree and a long pointer
#: chain are different pathologies with different natural limits, and one
#: shared constant would make tuning for one protocol move the other's
#: threshold.
#:
#: It is **not** what stops a cycle. A chain's offsets strictly decrease, so a
#: cycle cannot be constructed at all; this bounds *recursion*, since a large
#: message admits a legal chain long enough to exhaust the interpreter stack.
MAX_POINTER_HOPS = 16


@dataclass(frozen=True)
class _Read:
    """Where a decode is, and how far it is still allowed to reach.

    Threaded through the decode in place of a bare depth counter. What it
    carries is the whole of what a redirect needs in order to be safe, and it
    is the shape a byte transform would reuse: the bytes themselves come from
    the cursor, and this says what they are measured from and how far back a
    reference may reach.

    Attributes:
        origin: Stream offset of the message being decoded. A pointer offset
            is measured from here, which is the only space it can mean, since
            a run holds many messages.
        limit: Exclusive ceiling on what a pointer may target, or ``None``
            before the first hop. Each hop lowers it to its own target, so a
            chain's offsets strictly decrease.
        depth: Unit nesting so far.
        hops: Pointer hops taken so far.

    """

    origin: int
    limit: int | None = None
    depth: int = 0
    hops: int = 0


def _indexed(name: str | None, elements: list[Node]) -> list[Node]:
    """Name a repetition's elements ``field[0]``, ``field[1]``, and so on.

    Only the rendered name changes. A repeated field cannot be referenced from
    an expression anyway — the checker refuses it, since the language has no
    list type — and the one exception, an ``until`` clause seeing the element
    just decoded, binds it by the field's own name in the frame rather than by
    the node's.
    """
    if name is None:
        return elements
    return [replace(node, name=f"{name}[{index}]") for index, node in enumerate(elements)]


class _Stop(Exception):
    """Internal: abandon the enclosing unit, carrying a status and a reason.

    Not an error and never seen by a caller — it is how a failure deep in a
    field unwinds to the unit that has to record it. Named without the
    ``Error`` suffix on purpose: it is control flow.
    """

    def __init__(self, status: NodeStatus, detail: str) -> None:
        self.status = status
        self.detail = detail
        super().__init__(detail)


@dataclass
class _Frame:
    """One unit's scope during a decode: what its expressions can see."""

    unit: Unit
    params: dict[str, ExprValue] = dataclass_field(default_factory=dict)
    named: dict[str, Node] = dataclass_field(default_factory=dict)
    parent: _Frame | None = None

    def root(self) -> _Frame:
        """Return the outermost frame."""
        frame = self
        while frame.parent is not None:
            frame = frame.parent
        return frame


class _Environment:
    """Resolves a reference path to a value, for one frame.

    The value-side counterpart of :class:`kober.check._Scope`, and it resolves
    against **the tree being built** rather than a separate symbol table — a
    decoded field's node already holds its value and its children, so the tree
    is the environment.
    """

    def __init__(self, frame: _Frame) -> None:
        self.frame = frame

    def lookup(self, path: tuple[str, ...]) -> ExprValue:
        """Return the value named by ``path``."""
        head, *rest = path
        if head == "this":
            return self._in_frame(self.frame, tuple(rest), path)
        if head == "root":
            return self._in_frame(self.frame.root(), tuple(rest), path)
        if head == "parent":
            parent = self.frame.parent
            if parent is None:
                msg = f"{'.'.join(path)}: this unit has no parent at decode time"
                raise EvalError(msg)
            return self._in_frame(parent, tuple(rest), path)
        return self._in_frame(self.frame, path, path)

    def _in_frame(
        self, frame: _Frame, parts: tuple[str, ...], path: tuple[str, ...]
    ) -> ExprValue:
        """Resolve ``parts`` against one frame's params and decoded fields."""
        if not parts:
            msg = f"{'.'.join(path)}: a reference must name a field"
            raise EvalError(msg)
        head, *rest = parts
        if head in frame.params and not rest:
            return frame.params[head]
        node = frame.named.get(head)
        if node is None:
            msg = f"{'.'.join(path)}: {head!r} has not been decoded"
            raise EvalError(msg)
        for part in rest:
            child = node.find(part)
            if child is None:
                msg = f"{'.'.join(path)}: {part!r} is not a field of {node.name!r}"
                raise EvalError(msg)
            node = child
        if node.value is None:
            msg = f"{'.'.join(path)}: {node.name!r} has no scalar value"
            raise EvalError(msg)
        return node.value


class Decoder:
    """Decodes input according to a specification.

    Args:
        spec: The specification to decode by.
        emit: Default emission granularity, used by the emitter. A field's own
            ``emit`` wins, then its unit's, then this.
        check: Validate the spec on construction, refusing to build on an
            error. Every guarantee this engine relies on — that references
            resolve, that ordering holds, that expressions are typed — is one
            :func:`kober.check.check` proves, so skipping it means promising
            those by hand.

    Raises:
        SpecError: If ``check`` is set and the spec has errors.

    Example:
        >>> decoder = Decoder(spec)
        >>> tree = decoder.decode_bytes(payload)
        >>> print(tree.render())

    """

    def __init__(self, spec: Spec, *, emit: Emit = Emit.MESSAGE, check: bool = True) -> None:
        if check:
            require_valid(spec)
        self.spec = spec
        self.emit = emit

    def decode_bytes(self, data: bytes, *, base: int = 0) -> Node:
        """Decode one buffer as a single instance of the entry unit.

        The buffer is one contiguous run — a caller holding a stream with gaps
        splits it first, since a message may not span a hole.

        Args:
            data: The bytes to decode.
            base: Stream offset of ``data[0]``, so the tree's ranges are
                absolute.

        Returns:
            The tree. Its ``off_end`` is how far the decode got; a status
            other than ``OK`` says why it stopped there.

        """
        return self.decode_one(Cursor(data, base))

    def decode_one(self, cursor: Cursor) -> Node:
        """Decode a single entry-unit instance from ``cursor`` where it stands.

        Args:
            cursor: The cursor to read from. It is left after the last byte
                consumed.

        Returns:
            The tree for this instance.

        """
        entry = self.spec.unit(self.spec.entry)
        return self._unit(entry, (), None, cursor, _Read(origin=cursor.byte_offset()))

    # The stage driver imports this module, so these import it back lazily —
    # the same trade as `Spec.from_file`. It keeps every `zpf` import in one
    # file while leaving the API where `DESIGN.md` §6 puts it.

    def decode_stream(self, stage: object, stream: object) -> None:
        """Decode one input stream into an already-open decode stage.

        The lower-level entry point of §6, so a caller can mix spec-driven
        decoding with hand-written logic in the same stage.

        Args:
            stage: An open :class:`zpf.DecodeStage`.
            stream: One of that stage's ``streams()``.

        """
        from kober.stage import decode_stream

        decode_stream(self, stage, stream)

    def run(
        self,
        source: str | Path,
        sink: str | Path,
        *,
        produced_by: str,
        produced_at: int | datetime,
        comment: str | None = None,
    ) -> None:
        """Decode one file into another: the main entry point of §6.

        Args:
            source: The input ``.zpf`` file.
            sink: The output ``.zpf`` file.
            produced_by: What to record as the producer.
            produced_at: When, as ticks or a datetime.
            comment: Free-text note for the output's File Header.

        """
        from kober.stage import run

        run(
            self,
            source,
            sink,
            produced_by=produced_by,
            produced_at=produced_at,
            comment=comment,
        )

    def content_registry(self) -> object:
        """Build a registry that reads this spec's own message records back.

        Returns:
            A :class:`zpf.ContentRegistry` to pass to :func:`zpf.open`.

        """
        from kober.stage import content_registry

        return content_registry(self)

    # --- units -------------------------------------------------------------

    def _unit(
        self,
        unit: Unit,
        args: Sequence[ExprValue],
        parent: _Frame | None,
        cursor: Cursor,
        read: _Read,
    ) -> Node:
        """Decode one instance of ``unit``."""
        mark = cursor.tell()
        if read.depth > MAX_DEPTH:
            detail = f"unit nesting passed {MAX_DEPTH} levels at {unit.name!r}"
            start, end = cursor.span(mark)
            return Node(
                name=unit.name,
                unit=unit.name,
                off_start=start,
                off_end=end,
                status=NodeStatus.UNDECODABLE,
                detail=detail,
            )
        frame = _Frame(unit=unit, parent=parent)
        for param, value in zip(unit.params, args, strict=False):
            frame.params[param.name] = value

        children: list[Node] = []
        status, detail = NodeStatus.OK, None
        try:
            for item in unit.fields:
                child = self._field(item, frame, cursor, read)
                if child is None:
                    continue
                children.append(child)
                if item.name is not None:
                    frame.named[item.name] = child
                if child.status is not NodeStatus.OK:
                    # The field is kept — it says what was read before the
                    # trouble — but the unit stops here, because everything
                    # after it would be decoded from the wrong offset.
                    raise _Stop(
                        child.status,
                        child.detail or f"field {item.name!r} could not be decoded",
                    )
            status, detail = self._guards(unit, frame)
        except _Stop as stop:
            status, detail = stop.status, stop.detail

        start, end = cursor.span(mark)
        return Node(
            name=unit.name,
            unit=unit.name,
            off_start=start,
            off_end=end,
            status=status,
            children=tuple(children),
            detail=detail,
        )

    def _guards(self, unit: Unit, frame: _Frame) -> tuple[NodeStatus, str | None]:
        """Apply ``confirm`` and ``reject`` once the unit's fields are decoded.

        A guess that did not hold up becomes an honest ``undecodable`` region
        rather than a fabricated field tree — ``DESIGN.md`` §3.1.
        """
        env = _Environment(frame)
        if unit.confirm is not None:
            try:
                if not evaluate(unit.confirm, env):
                    return NodeStatus.UNDECODABLE, f"unit {unit.name!r} did not confirm"
            except EvalError as exc:
                return NodeStatus.UNDECODABLE, f"confirm could not be decided: {exc}"
        if unit.reject is not None:
            try:
                if evaluate(unit.reject, env):
                    return NodeStatus.UNDECODABLE, f"unit {unit.name!r} rejected the input"
            except EvalError as exc:
                return NodeStatus.UNDECODABLE, f"reject could not be decided: {exc}"
        return NodeStatus.OK, None

    # --- fields ------------------------------------------------------------

    def _field(self, item: Field, frame: _Frame, cursor: Cursor, read: _Read) -> Node | None:
        """Decode one field, or return ``None`` if its condition excluded it."""
        env = _Environment(frame)
        if item.condition is not None:
            try:
                present = evaluate(item.condition, env)
            except EvalError as exc:
                raise _Stop(NodeStatus.UNDECODABLE, f"condition failed: {exc}") from exc
            if not present:
                # Absent, not empty: a field that is not there consumes
                # nothing and gets no node, so it creates no empty span.
                return None
        if item.repeat is not None:
            return self._repeat(item, frame, cursor, read)
        return self._one(item, item.type, frame, cursor, read)

    def _repeat(self, item: Field, frame: _Frame, cursor: Cursor, read: _Read) -> Node:
        """Decode a repeated field into a container node."""
        mark = cursor.tell()
        repeat = item.repeat
        elements: list[Node] = []
        status, detail = NodeStatus.OK, None
        try:
            for element in self._elements(item, repeat, frame, cursor, read):
                elements.append(element)
        except _Stop as stop:
            status, detail = stop.status, stop.detail
        start, end = cursor.span(mark)
        return Node(
            name=item.name,
            off_start=start,
            off_end=end,
            status=status,
            children=tuple(_indexed(item.name, elements)),
            detail=detail,
            is_repetition=True,
            spec_field=item,
        )

    def _elements(
        self, item: Field, repeat: Repeat, frame: _Frame, cursor: Cursor, read: _Read
    ) -> Iterator[Node]:
        """Decode a repetition's elements, guarding against a loop that cannot end.

        A generator, so that an element reaches the caller *before* anything can
        go wrong after it. Accumulating them here and returning the list would
        lose every one of them when the fourth of four ran out, and those three
        were read: the same reason :meth:`_unit_ref` hands back a nested unit
        that failed part-way rather than throwing it away.
        """
        env = _Environment(frame)
        count = 0
        wanted: int | None = None
        if isinstance(repeat, Count):
            wanted = self._int(repeat.expr, env, "repeat count")
            if wanted < 0:
                raise _Stop(NodeStatus.UNDECODABLE, f"negative repeat count {wanted}")

        while True:
            if wanted is not None and count >= wanted:
                return
            if isinstance(repeat, ToEnd) and cursor.at_end():
                return
            before = cursor.tell()
            element = self._one(item, item.type, frame, cursor, read)
            yield element
            count += 1
            if element.status is not NodeStatus.OK:
                # Stop rather than spin: the next element would fail the same
                # way, and a Count read off the wire could ask for billions.
                raise _Stop(element.status, element.detail or "element could not be decoded")
            if cursor.tell() == before:
                raise _Stop(
                    NodeStatus.UNDECODABLE,
                    f"repeated field {item.name!r} consumed no input; the repetition "
                    "cannot terminate",
                )
            if isinstance(repeat, Until):
                if item.name is not None:
                    frame.named[item.name] = element
                if self._bool(repeat.expr, _Environment(frame), "repeat until"):
                    return

    # --- values ------------------------------------------------------------

    def _one(
        self, item: Field, kind: FieldType, frame: _Frame, cursor: Cursor, read: _Read
    ) -> Node:
        """Decode one value of ``kind``."""
        env = _Environment(frame)
        mark = cursor.tell()
        try:
            return self._value(item, kind, frame, cursor, read, mark, env)
        except TruncatedRead as exc:
            start, end = cursor.span(mark)
            return Node(
                name=item.name,
                off_start=start,
                off_end=end,
                status=NodeStatus.TRUNCATED,
                detail=str(exc),
                spec_field=item,
                resolved_type=kind,
            )
        except EvalError as exc:
            start, end = cursor.span(mark)
            return Node(
                name=item.name,
                off_start=start,
                off_end=end,
                status=NodeStatus.UNDECODABLE,
                detail=str(exc),
                spec_field=item,
                resolved_type=kind,
            )

    def _value(
        self,
        item: Field,
        kind: FieldType,
        frame: _Frame,
        cursor: Cursor,
        read: _Read,
        mark: int,
        env: _Environment,
    ) -> Node:
        """Decode one value, having already marked the start."""
        if isinstance(kind, Switch):
            return self._switch(item, kind, frame, cursor, read, env)
        if isinstance(kind, UnitRef):
            return self._unit_ref(item, kind, frame, cursor, read, env)
        if isinstance(kind, Computed):
            value = evaluate(kind.expr, env)
            start, end = cursor.span(mark)
            return self._leaf(item, kind, value, start, end)
        if isinstance(kind, Pointer):
            return self._pointer(item, kind, frame, cursor, read, env)
        if isinstance(kind, Select):
            return self._select(item, kind, frame, cursor, mark)
        if isinstance(kind, IntType):
            value = cursor.read_int(kind.bits, signed=kind.signed, endian=kind.endian)
            start, end = cursor.span(mark)
            return self._leaf(item, kind, value, start, end)
        if isinstance(kind, (BytesType, StringType)):
            return self._sized(item, kind, cursor, mark, env)
        # A field type the engine does not implement. Said out loud rather
        # than reached by falling off the end of the chain: this used to be an
        # unguarded `_sized` call, so a type the model gained before the engine
        # did raised an `AttributeError` out of a decode that promises never to
        # raise. An honest `undecodable` region is the right answer, and it is
        # the answer the checker cannot give — a spec using such a type is
        # well formed and valid.
        raise _Stop(
            NodeStatus.UNDECODABLE,
            f"{type(kind).__name__} is not implemented by this decoder",
        )

    def _pointer(
        self,
        item: Field,
        kind: Pointer,
        frame: _Frame,
        cursor: Cursor,
        read: _Read,
        env: _Environment,
    ) -> Node:
        """Read ``kind.type`` at ``kind.at``, leaving ``cursor`` where it is.

        §2.1 survives this. The spec *names* an offset and the runtime does the
        seeking, on a second cursor from :meth:`Cursor.view`, so the reading
        position never moves and coverage stays provable. That is the whole
        reason ``DESIGN.md`` §3.2 chose a construct over a hook.

        The node cites the region it read — one contiguous range, because a
        pointer consumes nothing where it stands and the bytes encoding the
        reference were read by ordinary fields.
        """
        offset = self._int(kind.at, env, "pointer offset")
        target = read.origin + offset
        # The ceiling is the message's high-water mark, lowered by every hop
        # already taken. Bounding at the *run* instead would make a message's
        # decode depend on the bytes that happen to follow it, which is not a
        # theory: the same message given three different neighbours decoded
        # three ways before this rule replaced it.
        ceiling = cursor.byte_offset()
        if read.limit is not None:
            ceiling = min(ceiling, read.limit)
        if offset < 0 or target < read.origin or target >= ceiling:
            return self._unreadable(
                item,
                kind,
                cursor,
                f"pointer target {offset} is outside the bytes already decoded",
            )
        if read.hops >= MAX_POINTER_HOPS:
            return self._unreadable(
                item, kind, cursor, f"pointer chain passed {MAX_POINTER_HOPS} hops"
            )

        # The window is the message *so far*, not the target onward: a further
        # hop has to reach back past this one, since each lands strictly
        # earlier. Bounding it at both ends is also what stops a pointer
        # reading into a neighbouring message that shares the run.
        second = cursor.view(read.origin, ceiling)
        second.seek_to(target)
        node = self._one(
            item,
            kind.type,
            frame,
            second,
            replace(read, limit=target, hops=read.hops + 1),
        )
        if node.status is NodeStatus.TRUNCATED:
            # A short read *inside a pointer target* is not a short input.
            # `truncated` is hole-class (§5), so leaving it would declare a
            # seam and say those bytes never existed — a lie about input that
            # arrived intact, when what happened is that the spec aimed badly.
            return replace(
                node,
                status=NodeStatus.UNDECODABLE,
                detail=f"pointer target does not decode: {node.detail}",
            )
        return node

    def _unreadable(self, item: Field, kind: FieldType, cursor: Cursor, detail: str) -> Node:
        """Build the node for a pointer that cannot be followed.

        Undecodable rather than a hole, and zero width because the reference
        bytes belong to the fields that read them; this node is about the
        region it could not reach.
        """
        start, end = cursor.span(cursor.tell())
        return Node(
            name=item.name,
            off_start=start,
            off_end=end,
            status=NodeStatus.UNDECODABLE,
            detail=detail,
            spec_field=item,
            resolved_type=kind,
        )

    def _leaf(
        self,
        item: Field,
        kind: FieldType,
        value: ExprValue,
        start: int,
        end: int,
        detail: str | None = None,
    ) -> Node:
        """Build a decoded leaf node."""
        return Node(
            name=item.name,
            value=value,
            off_start=start,
            off_end=end,
            detail=detail,
            spec_field=item,
            resolved_type=kind,
        )

    def _sized(
        self,
        item: Field,
        kind: BytesType | StringType,
        cursor: Cursor,
        mark: int,
        env: _Environment,
    ) -> Node:
        """Decode a bytes or string field, whose extent comes from its size."""
        raw = self._read_sized(kind.size, cursor, env)
        start, end = cursor.span(mark)
        if isinstance(kind, BytesType):
            return self._leaf(item, kind, raw, start, end)
        try:
            text = raw.decode(kind.encoding)
        except (UnicodeDecodeError, LookupError) as exc:
            # A malformed string is a fact about the input, not a failure of
            # the decoder (§3.2). The bytes are accounted for either way, so
            # the region stays OK and the damage is recorded on the node.
            text = raw.decode(kind.encoding, errors="replace")
            return self._leaf(item, kind, text, start, end, detail=f"decode error: {exc}")
        return self._leaf(item, kind, text, start, end)

    def _read_sized(self, size: SizeSpec, cursor: Cursor, env: _Environment) -> bytes:
        """Read the bytes a size spec describes."""
        if isinstance(size, Fixed):
            return cursor.read_bytes(size.count)
        if isinstance(size, FromExpr):
            count = self._int(size.expr, env, "size")
            if count < 0:
                raise _Stop(NodeStatus.UNDECODABLE, f"negative size {count}")
            return cursor.read_bytes(count)
        if isinstance(size, Remaining):
            return cursor.read_remaining()
        return self._read_terminated(size, cursor)

    def _read_terminated(self, size: Terminated, cursor: Cursor) -> bytes:
        """Read up to a delimiter, treating its absence per ``required``."""
        found = cursor.find(size.delimiter)
        if found is None:
            if size.required:
                # Not an error: in STREAM shape the value may simply continue
                # in a segment we do not hold (§3.2).
                msg = (
                    f"no terminator {size.delimiter!r} in the remaining "
                    f"{cursor.remaining_bytes()} byte(s)"
                )
                raise TruncatedRead(msg)
            return cursor.read_remaining()
        value = cursor.read_bytes(found)
        if size.consume:
            cursor.read_bytes(len(size.delimiter))
        return value

    def _select(
        self,
        item: Field,
        kind: Select,
        frame: _Frame,
        cursor: Cursor,
        mark: int,
    ) -> Node:
        """Walk a decoded repetition, project the first match, else the default.

        **It reads nothing and moves nothing.** The repetition is complete
        before this runs, so there is no position to advance and no input to
        claim — which is why the construct sits on the unconstrained side of
        §2.1's table, exactly as :class:`~kober.spec.Computed` does. The claim
        is asserted directly in the tests rather than inferred from coverage
        staying whole, because a select that *did* consume would leave coverage
        whole anyway: the byte it took would simply be covered by whatever
        followed.

        The element binds under the repetition's own name for the length of one
        expression, which is what :meth:`_elements` already does for an
        ``until``. The name is put back afterwards however this returns, so a
        failure part-way cannot leave an element standing where the container
        belongs.

        Citations are the selected element's own range. That is the honest
        evidence — this value came from *that* header, not from all of them —
        and it is why a select does not inherit ``Computed``'s "cite what the
        expression read", which here would cite every element. A default
        matched nothing, so it cites nothing: zero width at the cursor.
        """
        container = frame.named.get(kind.source)
        chosen: Node | None = None
        try:
            if container is not None and container.is_repetition:
                for element in container.children:
                    frame.named[kind.source] = element
                    # Deliberately unguarded. An expression that cannot be
                    # evaluated makes the field `undecodable` by way of
                    # `_one`, exactly as an unevaluable size does. Treating it
                    # as "no match" would report the author's default as though
                    # it had been read off the wire, which is the one failure
                    # this project exists to avoid.
                    if self._bool(kind.where, _Environment(frame), "select where"):
                        chosen = element
                        break
            if chosen is None:
                frame.named.pop(kind.source, None)
                if container is not None:
                    frame.named[kind.source] = container
                value = evaluate(kind.default, _Environment(frame))
                start, end = cursor.span(mark)
            else:
                value = evaluate(kind.value, _Environment(frame))
                start, end = chosen.off_start, chosen.off_end
        finally:
            if container is None:
                frame.named.pop(kind.source, None)
            else:
                frame.named[kind.source] = container
        return self._leaf(item, kind, value, start, end)

    def _switch(
        self,
        item: Field,
        kind: Switch,
        frame: _Frame,
        cursor: Cursor,
        read: _Read,
        env: _Environment,
    ) -> Node:
        """Dispatch on a value, or mark the region undecodable."""
        selector = evaluate(kind.on, env)
        chosen = kind.cases.get(selector, kind.default)  # type: ignore[arg-type]
        if chosen is None:
            # §2: no case and no default is "tried and failed", and the
            # extent is unknowable, so the unit stops here and the driver
            # accounts for the tail.
            raise _Stop(
                NodeStatus.UNDECODABLE,
                f"no case for {selector!r} and no default",
            )
        return self._one(item, chosen, frame, cursor, read)

    def _unit_ref(
        self,
        item: Field,
        kind: UnitRef,
        frame: _Frame,
        cursor: Cursor,
        read: _Read,
        env: _Environment,
    ) -> Node:
        """Decode a nested unit instance.

        A nested unit that failed part-way is **returned rather than thrown
        away**. The enclosing unit stops on it either way — its loop appends the
        field and then raises, which is what it already does for a scalar that
        failed — and the difference is that everything the nested unit decoded
        before the trouble stays in the tree. Those bytes were read and
        understood; discarding them made the emitter name them ``truncated``,
        which was true of the byte that ran out and false of the ones before it.
        """
        target = self.spec.unit(kind.unit)
        args = [evaluate(argument, env) for argument in kind.args]
        node = self._unit(target, args, frame, cursor, replace(read, depth=read.depth + 1))
        # Keep the field's name, not the unit's: `header: {unit: header_v4}`
        # is referenced as `header`.
        return Node(
            name=item.name,
            value=None,
            off_start=node.off_start,
            off_end=node.off_end,
            status=node.status,
            children=node.children,
            unit=target.name,
            detail=node.detail,
            spec_field=item,
            resolved_type=kind,
        )

    # --- expression helpers ------------------------------------------------

    def _int(self, expr: Expr, env: _Environment, label: str) -> int:
        """Evaluate an expression expected to be an integer."""
        value = evaluate(expr, env)
        if isinstance(value, bool) or not isinstance(value, int):
            msg = f"{label} is not an integer: {value!r}"
            raise EvalError(msg)
        return value

    def _bool(self, expr: Expr, env: _Environment, label: str) -> bool:
        """Evaluate an expression expected to be a boolean."""
        value = evaluate(expr, env)
        if not isinstance(value, bool):
            msg = f"{label} is not a boolean: {value!r}"
            raise EvalError(msg)
        return value
