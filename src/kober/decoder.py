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

from kober import transforms as transforms_module
from kober.check import (
    Starved,
    fill_widths,
    message_tail_fields,
    require_valid,
    starved_fields,
)
from kober.cursor import Cursor
from kober.errors import EvalError, ParameterError, TransformError, TruncatedRead
from kober.expr import ExprType, ExprValue, evaluate, references
from kober.node import Node, NodeStatus
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
    Remaining,
    Select,
    StringType,
    Switch,
    Terminated,
    ToEnd,
    Transform,
    UnitRef,
    Until,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence
    from datetime import datetime
    from pathlib import Path

    from kober.expr import Expr
    from kober.spec import Field, FieldType, Repeat, SizeSpec, Spec, Unit
    from kober.transforms import Registry

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


def _starved(node: Node, starved: Starved) -> Node:
    """Name a starved field's short read for what it is.

    Called only for a field the terminal rule leaves no bytes for, and only when
    it started with nothing left to read — which is what a field after a
    ``remaining`` always meets, and what honestly short input almost never does.
    A ``truncated`` there says the input was cut short, and it was not: every
    byte arrived and the spec read them into the field before. ``truncated`` is
    hole-class, so leaving it would put a false break in a stream that had none
    — the reason a short read inside a ``pointer`` target is converted too
    (``DESIGN.md`` §11.5). Any other status is left alone.
    """
    if node.status is not NodeStatus.TRUNCATED:
        return node
    return replace(node, status=NodeStatus.UNDECODABLE, detail=starved.detail)


def _in_space(node: Node, space: str) -> Node:
    """Mark a subtree as measured in a transform's output rather than the input."""
    return replace(
        node,
        space=space,
        children=tuple(_in_space(child, space) for child in node.children),
    )


#: The Python types a document parameter of each declared type may hold. A
#: ``bool`` is an ``int`` to Python, and is refused where an integer is wanted.
_PARAM_TYPES: Mapping[ExprType, type] = {
    ExprType.INT: int,
    ExprType.BOOL: bool,
    ExprType.STR: str,
    ExprType.BYTES: bytes,
}


def _document_params(spec: Spec, supplied: Mapping[str, ExprValue]) -> dict[str, ExprValue]:
    """Check the values supplied for a spec's ``params:``, and return them.

    Every declared parameter must be supplied, nothing undeclared may be, and
    each must be of its declared type. A run missing one could not be
    reproduced, so it never starts. A secret value's text is never put in a
    message.
    """
    declared = {param.name: param for param in spec.params}
    unknown = sorted(set(supplied) - set(declared))
    if unknown:
        listed = ", ".join(repr(name) for name in unknown)
        msg = f"parameter(s) {listed} are not declared by spec {spec.name!r}"
        raise ParameterError(msg)
    missing = sorted(set(declared) - set(supplied))
    if missing:
        listed = ", ".join(repr(name) for name in missing)
        msg = f"spec {spec.name!r} needs parameter(s) {listed}, and none was supplied"
        raise ParameterError(msg)
    for name, value in supplied.items():
        wanted = declared[name].type
        python = _PARAM_TYPES[wanted]
        if not isinstance(value, python) or (python is int and isinstance(value, bool)):
            msg = f"parameter {name!r} must be {wanted.value}, got {type(value).__name__}"
            raise ParameterError(msg)
    return dict(supplied)


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
    #: What the field being decoded resolves a ``fill`` to, in bytes. Set per
    #: field rather than passed down, because a size is read four calls below
    #: the loop that knows which field it belongs to — and the frame is already
    #: the thing that travels that distance.
    fill: int | None = None
    #: Whether the field being decoded is one the terminal rule leaves no bytes
    #: for (:func:`kober.check.starved_fields`), and why. Set per field for the
    #: reason :attr:`fill` is: a repetition's elements are decoded below the
    #: loop that knows which field they belong to.
    starved: Starved | None = None
    #: Whether the field being decoded is one after which nothing in the
    #: message reads a byte (:func:`kober.check.message_tail_fields`), so a
    #: fixed-size or counted read of it that runs out knows where the message
    #: ends. Set per field for the reason :attr:`fill` is.
    tail: bool = False
    #: The document's parameters (:attr:`kober.spec.Spec.params`), as supplied
    #: to the decoder: in scope in every unit, after its own names.
    document: Mapping[str, ExprValue] = dataclass_field(default_factory=dict)

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
        if node is None and head in frame.document and not rest:
            return frame.document[head]
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

        params: Values for the document's ``params:``, by name: every one it
            declares, of the type it declares. A key, above all.
        transforms: Where the spec's transforms are bound. The default is
            :data:`kober.transforms.DEFAULT`, which holds what the standard
            library can run and whatever the program registered.

    Raises:
        SpecError: If ``check`` is set and the spec has errors.
        UnboundTransformError: If a transform the spec uses is bound to
            nothing in ``transforms``.
        ParameterError: If a parameter is missing, not one the spec
            declares, or not of its declared type.

    Example:
        >>> decoder = Decoder(spec)
        >>> tree = decoder.decode_bytes(payload)
        >>> print(tree.render())

    """

    def __init__(
        self,
        spec: Spec,
        *,
        emit: Emit = Emit.MESSAGE,
        check: bool = True,
        params: Mapping[str, ExprValue] | None = None,
        transforms: Registry | None = None,
    ) -> None:
        if check:
            require_valid(spec)
        self.spec = spec
        self.emit = emit
        #: The document's parameters, as supplied: every one the spec declares,
        #: of the type it declares, checked here so that a run nothing could
        #: reproduce never starts.
        self._params = _document_params(spec, params or {})
        #: What each transform the spec uses is bound to, bound here so that a
        #: transform this process cannot run fails once, before any input,
        #: rather than making every message ``undecodable``.
        self._transforms = (transforms or transforms_module.DEFAULT).bind(spec)
        #: What each ``fill`` field resolves to, by ``(unit, field index)``.
        #: Precomputed rather than asked per decode, and kept here rather than
        #: taken off a check result: a decoder may run with ``check=False``, so
        #: it cannot rely on a check having happened. ``None`` is a width the
        #: spec does not fix, which only reaches here under ``check=False`` and
        #: becomes an ``undecodable`` field rather than a guess.
        self._fills = fill_widths(spec)
        #: The fields a spec that ``check`` would refuse leaves no bytes for,
        #: by ``(unit, field index)`` — precomputed for the reason
        #: :attr:`_fills` is. Empty for every spec that passes ``check``.
        self._starved = starved_fields(spec)
        #: The fields whose cut-off read tells where the message ends, for the
        #: driver to resume at after a gap (#49). Precomputed like the others.
        self._tails = message_tail_fields(spec)

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

        The output says what its records assert about one another, and the
        value is derived rather than chosen: at field granularity every
        participant is declared a **unit sequence** (``adjacency=units``),
        because consecutive leaves of a tree walk do not join; at message
        granularity nothing is declared, so a chained stage carries its
        input's adjacency forward. See :mod:`kober.stage`.

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
        frame = _Frame(unit=unit, parent=parent, document=self._params)
        for param, value in zip(unit.params, args, strict=False):
            frame.params[param.name] = value

        children: list[Node] = []
        status, detail = NodeStatus.OK, None
        refused = False
        try:
            for index, item in enumerate(unit.fields):
                frame.fill = self._fills.get((unit.name, index))
                frame.starved = self._starved.get((unit.name, index))
                frame.tail = (unit.name, index) in self._tails
                empty = cursor.at_end()
                child = self._field(item, frame, cursor, read)
                if child is None:
                    continue
                if empty and frame.starved is not None and not frame.starved.elements:
                    child = _starved(child, frame.starved)
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
            refused = status is not NodeStatus.OK
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
            refused=refused,
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
                return NodeStatus.UNDECODABLE, str(exc)
        if unit.reject is not None:
            try:
                if evaluate(unit.reject, env):
                    return NodeStatus.UNDECODABLE, f"unit {unit.name!r} rejected the input"
            except EvalError as exc:
                return NodeStatus.UNDECODABLE, str(exc)
        return NodeStatus.OK, None

    # --- fields ------------------------------------------------------------

    def _field(self, item: Field, frame: _Frame, cursor: Cursor, read: _Read) -> Node | None:
        """Decode one field, or return ``None`` if its condition excluded it."""
        env = _Environment(frame)
        if item.condition is not None:
            try:
                present = evaluate(item.condition, env)
            except EvalError as exc:
                raise _Stop(NodeStatus.UNDECODABLE, str(exc)) from exc
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
        except EvalError as exc:
            # The count, or the `until` test, could not be computed from what
            # was read — a division by zero off the wire. Every other place an
            # expression is evaluated turns this into a verdict, and failure
            # must never escape a decode (`DESIGN.md` §2).
            status, detail = NodeStatus.UNDECODABLE, str(exc)
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

        start = cursor.tell()
        starved = frame.starved if frame.starved is not None and frame.starved.elements else None
        while True:
            if wanted is not None and count >= wanted:
                return
            if isinstance(repeat, ToEnd) and cursor.at_end():
                return
            before = cursor.tell()
            empty = cursor.at_end()
            element = self._one(item, item.type, frame, cursor, read)
            if starved is not None and empty and before > start:
                element = _starved(element, starved)
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
                bound = repeat.alias or item.name
                if bound is not None:
                    frame.named[bound] = element
                if self._bool(repeat.expr, _Environment(frame), "repeat until"):
                    return

    # --- values ------------------------------------------------------------

    def _one(
        self, item: Field, kind: FieldType, frame: _Frame, cursor: Cursor, read: _Read
    ) -> Node:
        """Decode one value of ``kind``, and check any constant it must equal."""
        env = _Environment(frame)
        mark = cursor.tell()
        try:
            return self._constrained(item, kind, frame, cursor, read, mark, env)
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
                reach=exc.reach,
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

    def _constrained(
        self,
        item: Field,
        kind: FieldType,
        frame: _Frame,
        cursor: Cursor,
        read: _Read,
        mark: int,
        env: _Environment,
    ) -> Node:
        """Decode one value, and refuse it if it disagrees with the field's ``const``.

        **The region is undecodable, and nothing is raised.** That is this
        project's existing vocabulary for *tried and could not*, and the same
        verdict a failing ``confirm`` already produces. packeteer, where the
        key comes from, raises instead — its decoder is allowed to, because
        the bytes fall back to an opaque payload; here the coverage guarantee
        means a failed decode is recorded rather than thrown (``DESIGN.md``
        §2).

        The bytes stay cited either way. A constant is not a spec-side value
        that vanishes from the output: it was read, it is real, and it is
        accounted for.

        This sits in :meth:`_one` rather than in :meth:`_field`, so a constant
        on a repeated field constrains **every element** — which is what it
        should mean, and what stops the repetition at the first that disagrees.
        """
        node = self._value(item, kind, frame, cursor, read, mark, env)
        if item.const is None or node.status is not NodeStatus.OK:
            return node
        if node.value == item.const and type(node.value) is type(item.const):
            return node
        return replace(
            node,
            status=NodeStatus.UNDECODABLE,
            detail=f"expected {item.const!r}, read {node.value!r}",
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
        if isinstance(kind, Concat):
            return self._concat(item, kind, frame, cursor, mark)
        if isinstance(kind, Transform):
            return self._transform(item, kind, frame, cursor, read, mark)
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

    def _concat(
        self, item: Field, kind: Concat, frame: _Frame, cursor: Cursor, mark: int
    ) -> Node:
        """Join one field of every element of a repetition; cite their hull.

        Reads nothing where it stands. The hull runs from the first non-empty
        member's first byte to the last one's last: an empty member cites
        nothing, which keeps the terminating chunk's size line out of it (the
        transform plan's Stage 1). With no member at all it cites nothing, at
        the cursor, as a ``select`` default does.
        """
        container = frame.named.get(kind.repeated)
        if container is None or not container.is_repetition:
            msg = f"concat: {kind.repeated!r} is not a decoded repetition"
            raise EvalError(msg)
        pieces: list[bytes] = []
        spans: list[tuple[int, int]] = []
        for element in container.children:
            member = element.find(kind.member)
            if member is None:
                continue
            if not isinstance(member.value, bytes):
                msg = f"concat: {kind.repeated}.{kind.member} is not bytes"
                raise EvalError(msg)
            pieces.append(member.value)
            if member.width:
                spans.append((member.off_start, member.off_end))
        if spans:
            start, end = spans[0][0], spans[-1][1]
        else:
            start, end = cursor.span(mark)
        return self._leaf(item, kind, b"".join(pieces), start, end)

    def _transform(
        self,
        item: Field,
        kind: Transform,
        frame: _Frame,
        cursor: Cursor,
        read: _Read,
        mark: int,
    ) -> Node:
        """Transform bytes already decoded, and decode the output in its own space.

        Reads nothing where it stands, so the position is the same after as
        before, and the decoder's unit and field loops never see anything but
        a field. The node cites its **source and every field its ``args``
        read**, first to last: for a cipher whose nonce and associated data are
        the header, that is the whole datagram (the plan's *Decided* 3).

        **A transform that fails does not fail its message** (*Decided* 1).
        Whatever went wrong, the codec, the ``limit``, an argument that could
        not be evaluated, an output its ``type`` does not decode or does not
        read to its end, the node is ``OK`` with no value and no children,
        :attr:`~kober.node.Node.failed` set, and the failure as its detail. The
        message decodes whole, so the driver goes on after it; the emitter
        names the source's bytes ``undecodable``.

        With a ``type``, the output is decoded on a second cursor from its first
        byte, and every node decoded there carries the transform's name as its
        :attr:`~kober.node.Node.space`: its offsets are the output's.
        """
        env = _Environment(frame)
        start, end = self._transform_citation(kind, frame, cursor, mark)
        try:
            data = env.lookup((kind.source,))
            if not isinstance(data, bytes):
                msg = f"transform: {kind.source!r} is not bytes"
                raise EvalError(msg)
            args = {name: evaluate(expr, env) for name, expr in kind.args.items()}
            output = transforms_module.apply(
                kind.name, self._transforms[kind.name], data, limit=kind.limit, args=args
            )
        except (EvalError, TransformError) as exc:
            return self._transform_failed(item, kind, start, end, str(exc))
        if kind.type is None:
            return self._leaf(item, kind, output, start, end)

        second = Cursor(output, 0)
        inner = self._one(item, kind.type, frame, second, _Read(origin=0, depth=read.depth + 1))
        if inner.status is not NodeStatus.OK:
            return self._transform_failed(
                item, kind, start, end, f"{kind.name} output does not decode: {inner.detail}"
            )
        if not second.at_end():
            unread = second.remaining_bytes()
            detail = f"{kind.name} output has {unread} byte(s) its type does not read"
            return self._transform_failed(item, kind, start, end, detail)
        inner = _in_space(inner, item.name or kind.name)
        if inner.children or inner.unit is not None:
            # A unit: its fields are the transform's, measured in the output.
            return Node(
                name=item.name,
                off_start=start,
                off_end=end,
                children=inner.children,
                unit=inner.unit,
                spec_field=item,
                resolved_type=kind,
            )
        # A single value: the output has no structure below it, so the node is
        # the value itself, citing the input like any leaf.
        return Node(
            name=item.name,
            value=inner.value,
            off_start=start,
            off_end=end,
            detail=inner.detail,
            spec_field=item,
            resolved_type=kind,
        )

    def _transform_citation(
        self, kind: Transform, frame: _Frame, cursor: Cursor, mark: int
    ) -> tuple[int, int]:
        """Return what a transform cites: its source and its arguments' fields, first to last.

        Only fields of this unit count, as for a ``computed``: a document or
        unit parameter holds no input bytes, and ``root`` or ``parent`` reach
        outside what this node can see. With nothing to cite, it cites nothing,
        at the cursor.
        """
        spans: list[tuple[int, int]] = []
        read = [ref.path[0] for expr in kind.args.values() for ref in references(expr)]
        names = [kind.source, *read]
        for name in names:
            node = frame.named.get(name)
            if node is not None and node.width:
                spans.append((node.off_start, node.off_end))
        if not spans:
            return cursor.span(mark)
        return min(start for start, _ in spans), max(end for _, end in spans)

    def _transform_failed(
        self, item: Field, kind: Transform, start: int, end: int, detail: str
    ) -> Node:
        """Build the node for a transform that produced nothing usable (*Decided* 1)."""
        return Node(
            name=item.name,
            off_start=start,
            off_end=end,
            detail=detail,
            spec_field=item,
            resolved_type=kind,
            failed=True,
        )

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
            return self._read_counted(size.count, cursor, env)
        if isinstance(size, FromExpr):
            count = self._int(size.expr, env, "size")
            if count < 0:
                raise _Stop(NodeStatus.UNDECODABLE, f"negative size {count}")
            return self._read_counted(count, cursor, env)
        if isinstance(size, Remaining):
            return cursor.read_remaining()
        if isinstance(size, Fill):
            return self._read_fill(cursor, env)
        return self._read_terminated(size, cursor)

    def _read_counted(self, count: int, cursor: Cursor, env: _Environment) -> bytes:
        """Read ``count`` bytes, saying where the message ends if they run out.

        Only for a field after which nothing in the message reads
        (:attr:`_Frame.tail`): then the read that ran out was the message's
        last, and its length was decided before a byte of it was read, so the
        message ends exactly where this read would have. The stage driver
        resumes there after a gap rather than reading the rest of a body as a
        new message (#49).
        """
        start = cursor.byte_offset()
        try:
            return cursor.read_bytes(count)
        except TruncatedRead as exc:
            if env.frame.tail:
                raise TruncatedRead(str(exc), reach=start + count) from exc
            raise

    def _read_fill(self, cursor: Cursor, env: _Environment) -> bytes:
        """Read everything left except what the fields after this one claim.

        The trailing width was resolved from the spec when the decoder was
        built, so this is arithmetic rather than a decision. Too little input
        to hold the trailer is a **truncation** — the message was cut short,
        which is exactly what a short counted read means — and not a bad spec.
        """
        trailing = env.frame.fill
        if trailing is None:
            raise _Stop(
                NodeStatus.UNDECODABLE,
                "a fill whose trailing width the spec does not fix; run the checker",
            )
        available = cursor.remaining_bytes()
        if available < trailing:
            msg = (
                f"a fill leaves {trailing} byte(s) to the fields after it, and only "
                f"{available} remain"
            )
            raise TruncatedRead(msg)
        return cursor.read_bytes(available - trailing)

    def _read_terminated(self, size: Terminated, cursor: Cursor) -> bytes:
        """Read up to a delimiter, treating its absence per ``required``.

        A ``within`` bound makes "absent" mean *absent before the bound*, and
        changes nothing else: ``required`` still decides between a truncation
        and an ordinary empty value.

        The one place the two differ is what an *optional* absent terminator
        reads. Unbounded, the value runs to the end of the run, because nothing
        said where else it could stop. Bounded, it reads **nothing** — the
        bound is a limit on the search, not a second terminator, and letting
        the value run to it would be reading under a delimiter the spec never
        found.
        """
        found = cursor.find(size.delimiter, size.within)
        if found is None:
            if size.required:
                # Not an error: in STREAM shape the value may simply continue
                # in a segment we do not hold (§3.2).
                where = f" before {size.within!r}" if size.within is not None else ""
                msg = (
                    f"no terminator {size.delimiter!r}{where} in the remaining "
                    f"{cursor.remaining_bytes()} byte(s)"
                )
                raise TruncatedRead(msg)
            return b"" if size.within is not None else cursor.read_remaining()
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

        The element binds under the select's ``as:`` name, or under the
        repetition's own name where there is none — which is what
        :meth:`_elements` also does for an ``until``. Under the shorthand the
        binding is temporary and the container is put back afterwards however
        this returns, so a failure part-way cannot leave an element standing
        where the repetition belongs. Under an alias nothing is shadowed at
        all, which is the point of writing one.

        Citations are the selected element's own range. That is the honest
        evidence — this value came from *that* header, not from all of them —
        and it is why a select does not inherit ``Computed``'s "cite what the
        expression read", which here would cite every element. A default
        matched nothing, so it cites nothing: zero width at the cursor.
        """
        container = frame.named.get(kind.source)
        bound = kind.alias or kind.source
        chosen: Node | None = None
        try:
            if container is not None and container.is_repetition:
                for element in container.children:
                    frame.named[bound] = element
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
                # `default` sees no element under either name: nothing matched,
                # so there is none for it to mean.
                frame.named.pop(bound, None)
                if container is not None:
                    frame.named[kind.source] = container
                value = evaluate(kind.default, _Environment(frame))
                start, end = cursor.span(mark)
            else:
                value = evaluate(kind.value, _Environment(frame))
                start, end = chosen.off_start, chosen.off_end
        finally:
            frame.named.pop(bound, None)
            if container is not None:
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
        selector = evaluate(kind.dispatch, env)
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
            refused=node.refused,
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
