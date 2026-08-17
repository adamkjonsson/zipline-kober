"""Driving a `zpf` decode stage from a spec: the file-facing half of the decoder.

Everything in kober that touches `zpf` lives here, so what this project needs
from the format is auditable in one file. The engine (:mod:`kober.decoder`) and
the emitter (:mod:`kober.emit`) stay pure.

**The input is read as :meth:`~zpf.StreamView.chunks`.** Not
``reassembled()``, which refuses outright on any gap, and not ``segments()``,
which skips holes *silently* — leaving two runs with nothing to say whether
they abut or straddle one. Only ``chunks()`` yields the ``Gap``, and the gap is
what a ``reason="gap"`` region and a ``"stream-gap"`` seam are both made of.

**A gap is a hard message boundary.** Bytes either side of one were never
observed to be adjacent, so no message may span it and decoding restarts after
it.

**Shape comes from the stream, never the spec.** A decoded input is always
packet-oriented, whatever transport it started on, so a spec's declared
:class:`~kober.spec.InputShape` cannot decide the iterator — see
``DESIGN.md`` §9.2.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import zpf
from zpf.blocks import UNDECODED_REASONS
from zpf.reassembly import Gap

from kober.cursor import Cursor
from kober.emit import plan
from kober.errors import EvalError, SpecError, TruncatedRead, Undecodable
from kober.node import NodeStatus
from kober.spec import InputShape

if TYPE_CHECKING:
    import os
    from collections.abc import Callable
    from datetime import datetime

    from kober.decoder import Decoder
    from kober.runtime import Sink

    #: One message, decoded from a cursor into a sink. Returns the ``reason=``
    #: for what it could not decode, or ``None`` for a whole message. The seam
    #: between this project's two implementations: the loop around it does not
    #: care which one it is calling.
    _Step = Callable[[Cursor, Sink, bytes, int], str | None]

#: Reason recorded for a hole the capture never contained.
GAP_REASON = NodeStatus.GAP.value

#: Why two output records either side of a lost region do not join
#: (``DESIGN.md`` §5).
SEAM_REASON = "stream-gap"


def _seam_for(reason: str) -> zpf.Seam | None:
    """Return the seam owed after an undecoded region, if any.

    A seam is owed after a **hole**-class region, not only after a ``Gap``.
    `zpf` sorts reasons into two recoverability classes and puts both ``gap``
    and ``truncated`` in ``hole`` — bytes that never existed — while
    ``undecodable`` and ``skipped`` are ``bytes``, which did exist and simply
    were not decoded. Content either side of *those* still runs on, so they
    owe nothing; content either side of a hole does not.

    Read from :data:`zpf.blocks.UNDECODED_REASONS` rather than restated here,
    so the classification cannot drift from the one the conformance checker
    enforces.

    Args:
        reason: The ``reason=`` written for the region.

    Returns:
        The seam to attach to the next record, or ``None``.

    """
    if UNDECODED_REASONS.get(reason) != "hole":
        return None
    # Width stays absent: zpf defines it in the output's offset space, and how
    # many decoded units a hole cost is not recoverable from its byte count.
    return zpf.Seam(reason=SEAM_REASON if reason == GAP_REASON else reason)


def decode_stream(decoder: Decoder, stage: zpf.DecodeStage, stream: object) -> None:
    """Decode one input stream into ``stage``.

    Args:
        decoder: The decoder to drive.
        stage: The open decode stage to write into.
        stream: One of ``stage.streams()``.

    Raises:
        SpecError: If the spec declares a shape this stream cannot satisfy.

    """
    _check_shape(decoder.spec.input, decoder.spec.name, stream)
    _drive(_interpreted(decoder), _Writer(stage, stream), stream)


def decode_stream_compiled(module: object, stage: zpf.DecodeStage, stream: object) -> None:
    """Decode one input stream into ``stage`` with a generated module.

    The same driver as :func:`decode_stream`, because everything it does —
    treating a gap as a message boundary, owing a seam after a hole, accounting
    for the tail of a run — is true of a decode however the decode was written.
    Only the step in the middle differs.

    Args:
        module: A module produced by :func:`kober.pygen.render`.
        stage: The open decode stage to write into.
        stream: One of ``stage.streams()``.

    """
    _drive(_compiled(module), _Writer(stage, stream), stream)


def _check_shape(shape: InputShape, name: str, stream: object) -> None:
    """Refuse only the mismatch that would fabricate a field tree.

    A ``DATAGRAM`` spec assumes each message arrives whole and self-contained.
    Run over a byte stream it has no framing to find message boundaries with,
    and would produce a confident tree over the wrong bytes — the outcome §3
    says declaring a shape exists to prevent.

    The mirror case is allowed on purpose: a ``STREAM`` spec over datagram
    input decodes one message per datagram, which is coherent, and is what
    every chained stage needs since a decoded input is always packet-oriented.
    """
    if shape is InputShape.DATAGRAM and stream.is_stream_oriented:
        msg = (
            f"spec {name!r} declares input: datagram, but this stream is "
            "byte-oriented and carries no message framing the spec accounts for. "
            "Declare 'either' if the spec can frame its own messages."
        )
        raise SpecError(msg)


class _Writer:
    """The sink a decode stage is written through.

    Everything the driver knows about `zpf` that is not the stream loop itself:
    which call a record is, which a region is, and when the two sides of a hole
    stop running on. It is a :class:`kober.runtime.Sink`, which is the point —
    the interpreter's emitter and a generated decoder both write through this
    one implementation, so a difference between them cannot be a difference in
    how they were written out.

    A seam is owed after a **hole**-class region and carried by the next record.
    Adjacent regions sharing a reason are coalesced, which
    :func:`kober.emit.plan` also does within one message; doing it here as well
    joins the tail of one message to the head of the next when they agree.
    """

    def __init__(self, stage: zpf.DecodeStage, stream: object) -> None:
        self.stage = stage
        self.stream = stream
        #: The timestamp records are written with. The run's, since a decode
        #: stage has no per-field time to offer — see ``DESIGN.md`` §5.
        self.ts = 0
        self._pending: tuple[int, int, str] | None = None
        self._seam: zpf.Seam | None = None

    def record(
        self,
        payload: bytes,
        content_type: str,
        off_start: int,
        off_end: int,
        comment: str | None,
    ) -> None:
        """Write one record citing ``[off_start, off_end)``."""
        self.flush()
        self.stage.record(
            self.stream,
            payload,
            ts=self.ts,
            content_type=content_type,
            cites=(off_start, off_end),
            comment=comment,
            seam=self._seam,
        )
        self._seam = None

    def undecoded(self, off_start: int, off_end: int, reason: str) -> None:
        """Mark ``[off_start, off_end)`` as not decoded, and say why."""
        if off_end <= off_start:
            return
        pending = self._pending
        if pending is not None and pending[2] == reason and pending[1] >= off_start:
            self._pending = (pending[0], max(pending[1], off_end), reason)
            return
        self.flush()
        self._pending = (off_start, off_end, reason)

    def flush(self) -> None:
        """Write out the region still being coalesced, if there is one."""
        if self._pending is None:
            return
        off_start, off_end, reason = self._pending
        self._pending = None
        self.stage.undecoded(self.stream, off_start, off_end, reason=reason)
        self._seam = _seam_for(reason) or self._seam


def _interpreted(decoder: Decoder) -> _Step:
    """Return the step that decodes one message with the interpreter.

    :func:`kober.emit.plan` is what decides the records; this hands them to the
    sink. That is the shape the compiler phase's Q1 argued for from the other
    end — ``plan`` gains a second producer rather than being replaced — and here
    the two producers meet the same writer.
    """

    def step(cursor: Cursor, sink: Sink, data: bytes, base: int) -> str | None:
        tree = decoder.decode_one(cursor)
        emissions, unclaimed = plan(decoder.spec, tree, data, emit=decoder.emit, base=base)
        for record in emissions:
            sink.record(
                record.payload,
                record.content_type,
                record.off_start,
                record.off_end,
                record.comment,
            )
        for region in unclaimed:
            sink.undecoded(region.off_start, region.off_end, region.reason)
        return None if tree.status is NodeStatus.OK else tree.status.value

    return step


def _compiled(module: object) -> _Step:
    """Return the step that decodes one message with a generated module.

    The module writes its own records as it reads them, so there is nothing to
    hand on here — only the failure to name, which it reports by raising.
    """

    def step(cursor: Cursor, sink: Sink, data: bytes, base: int) -> str | None:
        try:
            module.decode_from(cursor, sink)
        except TruncatedRead:
            return NodeStatus.TRUNCATED.value
        except (EvalError, Undecodable, ZeroDivisionError):
            return NodeStatus.UNDECODABLE.value
        return None

    return step


def _drive(step: _Step, writer: _Writer, stream: object) -> None:
    """Decode one stream, whichever way its messages are framed."""
    if stream.is_stream_oriented:
        _drive_stream(step, writer, stream)
    else:
        _drive_datagrams(step, writer, stream)
    writer.flush()


def _drive_stream(step: _Step, writer: _Writer, stream: object) -> None:
    """Decode a byte-oriented stream, run by run, marking the holes between."""
    for chunk in stream.chunks():
        if isinstance(chunk, Gap):
            writer.undecoded(chunk.off_start, chunk.off_end, GAP_REASON)
            continue
        writer.ts = chunk.ts
        _decode_run(step, writer, chunk.data, chunk.off_start)


def _decode_run(step: _Step, writer: _Writer, data: bytes, base: int) -> None:
    """Decode as many messages as fit in one contiguous run."""
    cursor = Cursor(data, base)
    end = base + len(data)
    while not cursor.at_end():
        before = cursor.tell()
        reason = step(cursor, writer, data, base)
        if reason is not None:
            # The decode stopped here and said why; the rest of the run is the
            # tail a message deliberately leaves to whoever owns the run.
            writer.undecoded(_stopped_at(cursor, base), end, reason)
            return
        if cursor.tell() == before:
            # A message that consumes nothing would loop forever. It cannot be
            # decoded and neither can what follows it.
            writer.undecoded(_stopped_at(cursor, base), end, NodeStatus.UNDECODABLE.value)
            return


def _drive_datagrams(step: _Step, writer: _Writer, stream: object) -> None:
    """Decode a packet-oriented stream: one message per datagram.

    Each datagram is self-contained, so there is no framing to find and no gap
    to straddle — the reason chained stages are the simple case.
    """
    for datagram in stream.datagrams():
        writer.ts = datagram.ts
        cursor = Cursor(datagram.data, datagram.off_start)
        reason = step(cursor, writer, datagram.data, datagram.off_start)
        # Whatever the message did not claim is this datagram's alone; a
        # following message cannot use it, so it is accounted for here. A
        # truncated datagram is a hole, so the *next* datagram's records do not
        # join these — across datagrams just as within a stream.
        writer.undecoded(
            _stopped_at(cursor, datagram.off_start),
            datagram.off_end,
            reason or NodeStatus.SKIPPED.value,
        )


def _stopped_at(cursor: Cursor, base: int) -> int:
    """Return the first byte no record has claimed, in stream offsets.

    Rounded **up**: the cursor can only sit inside a byte because a field read
    part of it, and that field cited the whole byte. Starting an undecoded
    region there would name a byte a record already claims.
    """
    return base + (cursor.tell() + 7) // 8


def run(
    decoder: Decoder,
    source: str | os.PathLike[str],
    sink: str | os.PathLike[str],
    *,
    produced_by: str,
    produced_at: int | datetime,
    comment: str | None = None,
) -> None:
    """Decode one file into another.

    Args:
        decoder: The decoder to drive.
        source: The input ``.zpf`` file.
        sink: The output ``.zpf`` file.
        produced_by: What to record as the producer.
        produced_at: When, as ticks or a datetime.
        comment: Free-text note for the output's File Header.

    """
    with zpf.decode_stage(
        source,
        sink,
        decoder=(decoder.spec.name, decoder.spec.version),
        produced_by=produced_by,
        produced_at=produced_at,
        comment=comment,
    ) as stage:
        for stream in stage.streams():
            decode_stream(decoder, stage, stream)


def run_compiled(
    module: object,
    source: str | os.PathLike[str],
    sink: str | os.PathLike[str],
    *,
    produced_by: str,
    produced_at: int | datetime,
    comment: str | None = None,
) -> None:
    """Decode one file into another with a generated module.

    What :func:`run` is for the interpreter. The module names itself: a
    generated decoder carries the spec's name and version, so the output says
    which specification produced it exactly as the interpreter's output does.

    Args:
        module: A module produced by :func:`kober.pygen.render` — anything with
            ``NAME``, ``VERSION`` and ``decode_from``.
        source: The input ``.zpf`` file.
        sink: The output ``.zpf`` file.
        produced_by: What to record as the producer.
        produced_at: When, as ticks or a datetime.
        comment: Free-text note for the output's File Header.

    Example:
        >>> import dns
        >>> run_compiled(dns, "in.zpf", "out.zpf", produced_by="me", produced_at=0)

    """
    with zpf.decode_stage(
        source,
        sink,
        decoder=(module.NAME, module.VERSION),
        produced_by=produced_by,
        produced_at=produced_at,
        comment=comment,
    ) as stage:
        for stream in stage.streams():
            decode_stream_compiled(module, stage, stream)


def content_registry(decoder: Decoder) -> zpf.ContentRegistry:
    """Build a registry that reads this spec's own records back.

    A ``dec:`` type means "whatever that decoder documents", and what this one
    documents is the spec — so a message record's payload is handed back to
    the same spec and returned as a :class:`~kober.node.Node` tree.

    Only message granularity needs this. Field records are ``prim:``, which is
    normative and read by `zpf` itself without any registry — which was the
    argument for normalizing into it in the first place (``DESIGN.md`` §4.1).

    Args:
        decoder: The decoder whose spec should read the records.

    Returns:
        A registry to pass to :func:`zpf.open`.

    """
    registry = zpf.ContentRegistry()
    registry.register_dec(
        decoder.spec.name,
        f"{decoder.spec.name}-message",
        decoder.decode_bytes,
    )
    return registry
