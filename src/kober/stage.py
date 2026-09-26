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

**Field-granularity output is a unit sequence, and the file says so.** Its
records are adjacent because they are consecutive leaves of a tree walk, not
because content ran from one into the next: sub-byte fields all cite the byte
that holds them, a ``computed`` field cites the fields its expression read, a
``pointer`` target cites bytes behind the cursor, and every payload is created
rather than copied. So the participant is declared
:attr:`~zpf.Adjacency.UNITS` — no two adjacent records may be assumed to join,
and no seam is owed at any seam — which is the shape spec 0.21 added the field
for. Message granularity declares nothing: its records do join, the
:class:`~zpf.Seam` after a hole is the honest per-seam form, and leaving the
value unset lets a stage chained over a unit sequence carry that forward
instead of contradicting its input. See ``_adjacency``.

**A stream is confirmed before anything it holds is believed.** Zeek's rule for
dynamic protocol detection, applied per stream: until one whole message has
decoded, the stream may not be in this protocol at all, and a failure then is
evidence of the wrong protocol rather than of a corrupt message in the right
one. So until the first whole message, everything written for the stream is
held back. The first whole message **confirms** it and releases what was held,
unchanged. An ``undecodable`` before that **declines** the stream, and so does
reaching its end without a whole message — a spec reading a foreign stream does
not always fail ``undecodable``; one looking for a line ending in plain text
runs out, and ``truncated`` would claim a hole the capture never had. A
declined stream keeps no record: every run or datagram that was tried is
``undecodable`` across its whole extent, every one after the decline is
``skipped`` without being tried, and both carry a comment saying why
(``not dns: …``). Gaps stay gaps. After confirmation nothing changes: a failure
is a desync in the right protocol, worth resynchronising after, and the
driver does exactly what it always did. See ``_Writer``.

The trade-off is deliberate: a stream in the right protocol whose only message
was cut short, or whose first message the spec cannot read, is declined too.
The bytes alone cannot tell that from a stream in another protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import zpf
from zpf.blocks import UNDECODED_REASONS
from zpf.reassembly import Gap

from kober.cursor import Cursor
from kober.emit import plan, root_emit
from kober.errors import EvalError, SpecError, TruncatedRead, Undecodable
from kober.node import NodeStatus
from kober.runtime import Held
from kober.spec import Emit, InputShape

if TYPE_CHECKING:
    import os
    from collections.abc import Callable
    from datetime import datetime

    from kober.decoder import Decoder
    from kober.runtime import Sink

    #: One message, decoded from a cursor into a sink. Returns what went wrong,
    #: or ``None`` for a whole message. The seam between this project's two
    #: implementations: the loop around it does not care which one it is
    #: calling.
    _Step = Callable[[Cursor, Sink, bytes, int], "_Verdict | None"]

#: Reason recorded for a hole the capture never contained.
GAP_REASON = NodeStatus.GAP.value

#: Why two output records either side of a lost region do not join
#: (``DESIGN.md`` §5).
SEAM_REASON = "stream-gap"

#: The comment on the bytes after a gap that finish a message the gap cut,
#: when that message's end was known (#49). They are ``skipped``: what they are
#: is known, and they are passed over on purpose.
CUT_COMMENT = "rest of a message cut by a gap"

#: The comment on a run after a gap whose first message did not decode whole,
#: when where the gap left off was not known (#49). ``undecodable``: an attempt
#: was made there, and it could not be told from the middle of a message.
LOST_COMMENT = "no message boundary found after a gap"


@dataclass(frozen=True)
class _Verdict:
    """Why one message did not decode.

    Attributes:
        reason: The ``reason=`` for the region it leaves undecoded.
        detail: What went wrong, as the decoder said it. Quoted in the comment
            of a stream it declines, so both implementations must say it the
            same way — the differential holds them to that.
        reach: For a truncation, where the message would have ended, when
            that is known (:class:`~kober.errors.TruncatedRead`); else ``None``.

    """

    reason: str
    detail: str
    reach: int | None = None


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


def _adjacency(emit: Emit) -> zpf.Adjacency | None:
    """Return what the output's participants declare about their neighbours.

    Decided by the granularity in force at the root and nothing else, because
    that is what decides whether the file can hold a field record at all
    (:func:`kober.emit.root_emit`). One function for both drivers: the
    interpreter resolves the root from the spec and the decoder, a generated
    module records the value it was compiled at, and both hand it here — so
    the two cannot write participant lines that disagree.

    ``UNITS`` for field granularity, for the reasons in the module docstring.
    It asserts less than ``contiguous`` and is never wrong, even for a flat
    spec whose leaves happen to abut — a walk order is not a continuity claim,
    and deciding per spec whether the tree "has containment" would be a
    fragile predicate for a distinction no consumer can use.

    ``None`` — not ``CONTIGUOUS`` — for the other two. The difference is what
    a chained stage does: ``None`` carries the *input's* effective adjacency
    forward, while an explicit ``CONTIGUOUS`` overrides it. A message-
    granularity stage reading a unit sequence therefore keeps saying ``units``,
    which the specification requires of a stage reading one, and the datagram
    driver never joins two input units anyway. ``NONE`` writes no record, so
    the value is moot and the same rule costs nothing.

    Args:
        emit: The granularity in force at the entry unit.

    Returns:
        The ``adjacency=`` to pass to :func:`zpf.decode_stage`.

    """
    return zpf.Adjacency.UNITS if emit is Emit.FIELD else None


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
    _drive(_interpreted(decoder), _Writer(stage, stream, decoder.spec.name), stream)


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
    _drive(_compiled(module), _Writer(stage, stream, module.NAME), stream)


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
    The seam is written whatever the participant's adjacency: under a unit
    sequence it is redundant — nothing joins anyway — but the format keeps the
    block permitted there, both drivers share this writer, and a branch to
    suppress it would be a second path through the one place seams are decided.

    **A timestamp is passed only where none can be derived.** Omitting ``ts``
    lets `zpf` take it from ``cites``, which is the specification's rule: a
    decoded record carries the completion time of the last input record **in its
    own span set**. This used to write the run's ``ts`` on every record, on the
    grounds that a decode stage had no per-field time to offer — which was
    upstream `#62 <https://github.com/adamkjonsson/python-zipline/issues/62>`_,
    and was wrong wherever a message straddled two packets: three messages
    arriving in three packets carry three times even though reassembly offers
    them as one run. Deriving it is also the only way to get the lossy case
    right, since contributors are recorded *after* overlap trimming, so a
    retransmit that contributed no accepted byte does not move the answer.

    The exception is a record citing an **empty** range, which this project
    really does emit and which nothing can be derived for. Two constructs make
    one: a ``select`` whose default matched cites nothing, because nothing
    matched and there is no element to point at; and a bounded optional
    terminator that found nothing reads an empty value, which is how the blank
    line ending an HTTP header block is recognised. Both are real values worth
    writing, and `zpf` documents passing ``ts`` explicitly for exactly this
    case. The run's completion time is the only honest answer available — the
    value was computed from a message that completed then — and it is used
    *only* here, never in place of a derivable one.

    **Until the stream is confirmed, nothing is written.** Everything is held,
    run by run and gap by gap, in order, with each record's timestamp fixed
    when it was held. :meth:`confirm` releases it unchanged, so a stream that
    confirms writes exactly what it would have written without any of this.
    :meth:`decline` discards the held records and marks each held run
    ``undecodable`` whole, with the comment — the discarded records cited
    those bytes, and something has to name them now. The cost is memory in
    proportion to the unconfirmed prefix, which for a stream that never
    confirms is the whole stream, because the decline that ends it cannot come
    before its end. A cap would mean writing records for a stream that may be
    in another protocol, which is what holding exists to prevent.
    """

    def __init__(self, stage: zpf.DecodeStage, stream: object, name: str) -> None:
        self.stage = stage
        self.stream = stream
        #: The spec's name, for the comment on a declined stream.
        self.name = name
        #: Completion time of the run being decoded, for the empty-range case
        #: above. Never passed for a record that cites bytes.
        self.ts = 0
        #: Whether a whole message has decoded. Until it has, everything is held.
        self.confirmed = False
        #: The comment every region of a declined stream carries, once it is.
        self.declined: str | None = None
        #: Whether a run after a gap had its first message dropped for failing
        #: other than by running out (#49). Such an attempt neither confirms nor
        #: declines, so a stream that ends unconfirmed may have had one, and
        #: then its comment must not say every attempt ran out.
        self.lost = False
        #: While unconfirmed: each run as ``(start, end, writes)``, and each gap
        #: as ``(start, end, None)``, in stream order.
        self._held: list[tuple[int, int, list[tuple[object, ...]] | None]] = []
        self._pending: tuple[int, int, str, str | None] | None = None
        self._seam: zpf.Seam | None = None

    # --- what the driver says ------------------------------------------------

    def begin(self, off_start: int, off_end: int) -> None:
        """Note that a run or datagram is about to be tried."""
        if not self.confirmed:
            self._held.append((off_start, off_end, []))

    def gap(self, off_start: int, off_end: int) -> None:
        """Mark a hole the capture never contained."""
        if self.confirmed or self.declined is not None:
            self._undecoded(off_start, off_end, GAP_REASON)
        else:
            self._held.append((off_start, off_end, None))

    def skip(self, off_start: int, off_end: int) -> None:
        """Mark a run or datagram of a declined stream, never tried."""
        self._undecoded(off_start, off_end, NodeStatus.SKIPPED.value, self.declined)

    def confirm(self) -> None:
        """Write everything held, as it was: a whole message has decoded."""
        if self.confirmed:
            return
        self.confirmed = True
        for off_start, off_end, writes in self._held:
            if writes is None:
                self._undecoded(off_start, off_end, GAP_REASON)
                continue
            for write in writes:
                if write[0] == "record":
                    self._record(*write[1:])
                else:
                    self._undecoded(*write[1:])
        self._held.clear()

    def failed(self, verdict: _Verdict, stopped: int) -> None:
        """Decline the stream if a message failed before any had decoded whole."""
        if self.confirmed or verdict.reason != NodeStatus.UNDECODABLE.value:
            return
        self.decline(f"not {self.name}: {verdict.detail}, stopped at offset {stopped}")

    def decline(self, comment: str) -> None:
        """Decide the stream is not in this protocol: name what was tried, keep nothing."""
        self.declined = comment
        for off_start, off_end, writes in self._held:
            reason = GAP_REASON if writes is None else NodeStatus.UNDECODABLE.value
            self._undecoded(off_start, off_end, reason, None if writes is None else comment)
        self._held.clear()

    def finish(self) -> None:
        """End the stream: decline it if nothing ever decoded, then write what is left."""
        if not self.confirmed and self.declined is None:
            if any(writes is not None for _, _, writes in self._held):
                how = (
                    "ran out of input or found no message boundary after a gap"
                    if self.lost
                    else "ran out of input"
                )
                self.decline(f"not {self.name}: no message decoded; every attempt {how}")
            else:
                # Nothing was tried — the stream is gaps, or nothing at all.
                self.confirm()
        self.flush()

    # --- the sink a decode writes through -----------------------------------

    def record(
        self,
        payload: bytes,
        content_type: str,
        off_start: int,
        off_end: int,
        role: str | None,
    ) -> None:
        """Write one record citing ``[off_start, off_end)``."""
        ts = self.ts if off_end <= off_start else None
        if self.confirmed:
            self._record(payload, content_type, off_start, off_end, role, ts)
        else:
            write = ("record", payload, content_type, off_start, off_end, role, ts)
            self._held[-1][2].append(write)

    def undecoded(self, off_start: int, off_end: int, reason: str) -> None:
        """Mark ``[off_start, off_end)`` as not decoded, and say why."""
        self.note(off_start, off_end, reason, None)

    def note(self, off_start: int, off_end: int, reason: str, comment: str | None) -> None:
        """Mark ``[off_start, off_end)`` as not decoded, with a comment saying why."""
        if self.confirmed:
            self._undecoded(off_start, off_end, reason, comment)
        else:
            self._held[-1][2].append(("undecoded", off_start, off_end, reason, comment))

    # --- the file -------------------------------------------------------------

    def _record(
        self,
        payload: bytes,
        content_type: str,
        off_start: int,
        off_end: int,
        role: str | None,
        ts: int | None,
    ) -> None:
        self.flush()
        self.stage.record(
            self.stream,
            payload,
            ts=ts,
            content_type=content_type,
            role=role,
            cites=(off_start, off_end),
            seam=self._seam,
        )
        self._seam = None

    def _undecoded(
        self, off_start: int, off_end: int, reason: str, comment: str | None = None
    ) -> None:
        if off_end <= off_start:
            return
        pending = self._pending
        if (
            pending is not None
            and pending[2:] == (reason, comment)
            and pending[1] >= off_start
        ):
            self._pending = (pending[0], max(pending[1], off_end), reason, comment)
            return
        self.flush()
        self._pending = (off_start, off_end, reason, comment)

    def flush(self) -> None:
        """Write out the region still being coalesced, if there is one."""
        if self._pending is None:
            return
        off_start, off_end, reason, comment = self._pending
        self._pending = None
        self.stage.undecoded(self.stream, off_start, off_end, reason=reason, comment=comment)
        self._seam = _seam_for(reason) or self._seam


def _interpreted(decoder: Decoder) -> _Step:
    """Return the step that decodes one message with the interpreter.

    :func:`kober.emit.plan` is what decides the records; this hands them to the
    sink. That is the shape the compiler phase's Q1 argued for from the other
    end — ``plan`` gains a second producer rather than being replaced — and here
    the two producers meet the same writer.
    """

    def step(cursor: Cursor, sink: Sink, data: bytes, base: int) -> _Verdict | None:
        tree = decoder.decode_one(cursor)
        emissions, unclaimed = plan(decoder.spec, tree, data, emit=decoder.emit, base=base)
        for record in emissions:
            sink.record(
                record.payload,
                record.content_type,
                record.off_start,
                record.off_end,
                record.role,
            )
        for region in unclaimed:
            sink.undecoded(region.off_start, region.off_end, region.reason)
        if tree.status is NodeStatus.OK:
            return None
        reach = next((node.reach for node in tree.walk() if node.reach is not None), None)
        return _Verdict(tree.status.value, tree.detail or tree.status.value, reach)

    return step


def _compiled(module: object) -> _Step:
    """Return the step that decodes one message with a generated module.

    The module writes its own records as it reads them, so there is nothing to
    hand on here — only the failure to name, which it reports by raising.
    """

    def step(cursor: Cursor, sink: Sink, data: bytes, base: int) -> _Verdict | None:
        try:
            module.decode_from(cursor, sink)
        except TruncatedRead as exc:
            return _Verdict(NodeStatus.TRUNCATED.value, str(exc), exc.reach)
        except (EvalError, Undecodable, ZeroDivisionError) as exc:
            return _Verdict(NodeStatus.UNDECODABLE.value, str(exc))
        return None

    return step


def _drive(step: _Step, writer: _Writer, stream: object) -> None:
    """Decode one stream, whichever way its messages are framed."""
    if stream.is_stream_oriented:
        _drive_stream(step, writer, stream)
    else:
        _drive_datagrams(step, writer, stream)
    writer.finish()


def _drive_stream(step: _Step, writer: _Writer, stream: object) -> None:
    """Decode a byte-oriented stream, run by run, marking the holes between.

    A run after a gap starts wherever the gap left off, which is usually inside
    a message (#49). Where the message the gap cut said where it would end, the
    run resumes there, and the bytes before it are ``skipped`` as the rest of
    that message. Where nothing said, the run's first message is a guess, and
    :func:`_decode_run` holds it until it has decoded whole.
    """
    resume: int | None = None
    after_gap = False
    for chunk in stream.chunks():
        if isinstance(chunk, Gap):
            writer.gap(chunk.off_start, chunk.off_end)
            after_gap = True
            continue
        start, end = chunk.off_start, chunk.off_start + len(chunk.data)
        if writer.declined is not None:
            writer.skip(start, end)
            continue
        writer.ts = chunk.ts
        writer.begin(start, end)
        at, known = start, not after_gap
        if after_gap and resume is not None and resume >= start:
            at, known = min(resume, end), True
            writer.note(start, at, NodeStatus.SKIPPED.value, CUT_COMMENT)
        after_gap = False
        if resume is not None and resume > end:
            # The message the gap cut runs past this run too: all of it is the
            # rest of that message, and the next run may still finish it.
            continue
        resume = _decode_run(step, writer, chunk.data, chunk.off_start, at=at, known=known)


def _decode_run(
    step: _Step, writer: _Writer, data: bytes, base: int, *, at: int, known: bool
) -> int | None:
    """Decode as many messages as fit in one contiguous run, from ``at``.

    ``known`` says whether ``at`` is where a message starts. When it is not (a
    run after a gap that nothing said the end of), the first message is written
    through a :class:`~kober.runtime.Held` sink and released only if it decodes
    whole. If it does not, what it wrote is dropped and the rest of the run is
    ``undecodable``: a partial tree read from the middle of a body would be a
    fabrication. Such a failure never declines the stream, since it says
    nothing about the protocol.

    Returns:
        Where the message the run ended inside would have ended, when the run
        ended by cutting it off and its end was known; else ``None``.

    """
    cursor = Cursor(data, base)
    cursor.seek_to(at)
    end = base + len(data)
    while not cursor.at_end():
        before = cursor.tell()
        held = None if known else Held(writer)
        verdict = step(cursor, held or writer, data, base)
        if verdict is None and cursor.tell() == before:
            # A message that consumes nothing would loop forever. It cannot be
            # decoded and neither can what follows it.
            verdict = _Verdict(NodeStatus.UNDECODABLE.value, "a message consumed no input")
        if held is not None:
            if verdict is not None:
                writer.note(at, end, NodeStatus.UNDECODABLE.value, LOST_COMMENT)
                writer.lost = writer.lost or verdict.reason != NodeStatus.TRUNCATED.value
                return None
            held.release()
            known = True
        if verdict is not None:
            # The decode stopped here and said why; the rest of the run is the
            # tail a message deliberately leaves to whoever owns the run.
            stopped = _stopped_at(cursor, base)
            writer.undecoded(stopped, end, verdict.reason)
            writer.failed(verdict, stopped)
            return verdict.reach if verdict.reason == NodeStatus.TRUNCATED.value else None
        writer.confirm()
    return None


def _drive_datagrams(step: _Step, writer: _Writer, stream: object) -> None:
    """Decode a packet-oriented stream: one message per datagram.

    Each datagram is self-contained, so there is no framing to find and no gap
    to straddle — the reason chained stages are the simple case.
    """
    for datagram in stream.datagrams():
        if writer.declined is not None:
            writer.skip(datagram.off_start, datagram.off_end)
            continue
        writer.ts = datagram.ts
        writer.begin(datagram.off_start, datagram.off_end)
        cursor = Cursor(datagram.data, datagram.off_start)
        verdict = step(cursor, writer, datagram.data, datagram.off_start)
        stopped = _stopped_at(cursor, datagram.off_start)
        # Whatever the message did not claim is this datagram's alone; a
        # following message cannot use it, so it is accounted for here. A
        # truncated datagram is a hole, so the *next* datagram's records do not
        # join these — across datagrams just as within a stream.
        writer.undecoded(
            stopped,
            datagram.off_end,
            NodeStatus.SKIPPED.value if verdict is None else verdict.reason,
        )
        if verdict is None:
            writer.confirm()
        else:
            writer.failed(verdict, stopped)


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

    What the output declares about its records is derived from the decoder,
    not passed: field granularity writes a unit sequence, message granularity
    carries the input's adjacency forward (``_adjacency``). A caller-
    supplied value would be a way to state something false about the file.

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
        decoder=decoder.spec.as_decoder(),
        produced_by=produced_by,
        produced_at=produced_at,
        comment=comment,
        adjacency=_adjacency(root_emit(decoder.spec, decoder.emit)),
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

    What :func:`run` is for the interpreter. The module says what it is: a
    generated decoder carries the spec's name and version, so the output says
    which specification produced it exactly as the interpreter's output does,
    and the granularity it was compiled at, so the output declares what its
    records assert about one another exactly as the interpreter's would
    (``_adjacency``). A module from before ``EMIT`` existed is refused rather
    than defaulted: a stale field module writing ``contiguous`` over sub-byte
    fields is precisely the silent wrong statement the field exists to
    prevent, and a module compiled against an older `zpf` was never tested
    against this one anyway.

    Args:
        module: A module produced by :func:`kober.pygen.render` — anything with
            ``NAME``, ``VERSION``, ``EMIT`` and ``decode_from``.
        source: The input ``.zpf`` file.
        sink: The output ``.zpf`` file.
        produced_by: What to record as the producer.
        produced_at: When, as ticks or a datetime.
        comment: Free-text note for the output's File Header.

    Raises:
        TypeError: If the module has no ``EMIT`` — it was generated by a kober
            before 0.3.0 and must be compiled again.

    Example:
        >>> import dns
        >>> run_compiled(dns, "in.zpf", "out.zpf", produced_by="me", produced_at=0)

    """
    emit = getattr(module, "EMIT", None)
    if emit is None:
        msg = (
            f"module {getattr(module, 'NAME', module)!r} has no EMIT: it was "
            "generated by a kober before 0.3.0, which did not record the "
            "granularity a module was compiled at, so the output's adjacency "
            "cannot be declared. Compile the spec again with `kober compile`."
        )
        raise TypeError(msg)
    with zpf.decode_stage(
        source,
        sink,
        decoder=(module.NAME, module.VERSION),
        produced_by=produced_by,
        produced_at=produced_at,
        comment=comment,
        adjacency=_adjacency(Emit(emit)),
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
