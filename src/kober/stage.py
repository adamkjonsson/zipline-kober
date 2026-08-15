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
from zpf.reassembly import Gap

from kober.cursor import Cursor
from kober.emit import plan
from kober.errors import SpecError
from kober.node import NodeStatus
from kober.spec import InputShape

if TYPE_CHECKING:
    import os
    from datetime import datetime

    from kober.decoder import Decoder
    from kober.node import Node

#: Reason recorded for a hole the capture never contained.
GAP_REASON = NodeStatus.GAP.value

#: Why two output records either side of a hole do not join (``DESIGN.md`` §5).
SEAM_REASON = "stream-gap"


def decode_stream(decoder: Decoder, stage: zpf.DecodeStage, stream: object) -> None:
    """Decode one input stream into ``stage``.

    Args:
        decoder: The decoder to drive.
        stage: The open decode stage to write into.
        stream: One of ``stage.streams()``.

    Raises:
        SpecError: If the spec declares a shape this stream cannot satisfy.

    """
    _check_shape(decoder, stream)
    if stream.is_stream_oriented:
        _drive_stream(decoder, stage, stream)
    else:
        _drive_datagrams(decoder, stage, stream)


def _check_shape(decoder: Decoder, stream: object) -> None:
    """Refuse only the mismatch that would fabricate a field tree.

    A ``DATAGRAM`` spec assumes each message arrives whole and self-contained.
    Run over a byte stream it has no framing to find message boundaries with,
    and would produce a confident tree over the wrong bytes — the outcome §3
    says declaring a shape exists to prevent.

    The mirror case is allowed on purpose: a ``STREAM`` spec over datagram
    input decodes one message per datagram, which is coherent, and is what
    every chained stage needs since a decoded input is always packet-oriented.
    """
    if decoder.spec.input is InputShape.DATAGRAM and stream.is_stream_oriented:
        msg = (
            f"spec {decoder.spec.name!r} declares input: datagram, but this stream is "
            "byte-oriented and carries no message framing the spec accounts for. "
            "Declare 'either' if the spec can frame its own messages."
        )
        raise SpecError(msg)


def _drive_stream(decoder: Decoder, stage: zpf.DecodeStage, stream: object) -> None:
    """Decode a byte-oriented stream, run by run, marking the holes between."""
    seam: zpf.Seam | None = None
    for chunk in stream.chunks():
        if isinstance(chunk, Gap):
            stage.undecoded(stream, chunk.off_start, chunk.off_end, reason=GAP_REASON)
            # The next record this stage writes does not join the previous
            # one. Width is left absent deliberately: zpf defines it in the
            # *output's* offset space, and how many decoded units the hole
            # cost is not recoverable from how many bytes it swallowed.
            seam = zpf.Seam(reason=SEAM_REASON)
            continue
        seam = _decode_run(decoder, stage, stream, chunk.data, chunk.off_start, chunk.ts, seam)


def _decode_run(
    decoder: Decoder,
    stage: zpf.DecodeStage,
    stream: object,
    data: bytes,
    base: int,
    ts: int,
    seam: zpf.Seam | None,
) -> zpf.Seam | None:
    """Decode as many messages as fit in one contiguous run.

    Returns:
        The seam still owed, if nothing was written to carry it.

    """
    cursor = Cursor(data, base)
    end = base + len(data)
    while not cursor.at_end():
        before = cursor.tell()
        tree = decoder.decode_one(cursor)
        seam = _write(decoder, stage, stream, tree, data, base, ts, seam)
        if tree.status is not NodeStatus.OK:
            # The decode stopped here and said why; the rest of the run is
            # the tail the emitter deliberately left to us.
            _mark_tail(stage, stream, tree.off_end, end, tree.status.value)
            return seam
        if cursor.tell() == before:
            # A message that consumes nothing would loop forever. It cannot
            # be decoded and neither can what follows it.
            _mark_tail(stage, stream, tree.off_end, end, NodeStatus.UNDECODABLE.value)
            return seam
    return seam


def _drive_datagrams(decoder: Decoder, stage: zpf.DecodeStage, stream: object) -> None:
    """Decode a packet-oriented stream: one message per datagram.

    Each datagram is self-contained, so there is no framing to find and no
    gap to straddle — the reason chained stages are the simple case.
    """
    for datagram in stream.datagrams():
        tree = decoder.decode_bytes(datagram.data, base=datagram.off_start)
        _write(decoder, stage, stream, tree, datagram.data, datagram.off_start, datagram.ts, None)
        # Whatever the message did not claim is this datagram's alone; a
        # following message cannot use it, so it is accounted for here.
        reason = (
            NodeStatus.SKIPPED.value if tree.status is NodeStatus.OK else tree.status.value
        )
        _mark_tail(stage, stream, tree.off_end, datagram.off_end, reason)


def _write(
    decoder: Decoder,
    stage: zpf.DecodeStage,
    stream: object,
    tree: Node,
    data: bytes,
    base: int,
    ts: int,
    seam: zpf.Seam | None,
) -> zpf.Seam | None:
    """Write one tree's records and undecoded regions.

    Returns:
        The seam still owed — ``None`` once a record has carried it.

    """
    emissions, unclaimed = plan(decoder.spec, tree, data, emit=decoder.emit, base=base)
    for record in emissions:
        stage.record(
            stream,
            record.payload,
            ts=ts,
            content_type=record.content_type,
            cites=(record.off_start, record.off_end),
            comment=record.comment,
            seam=seam,
        )
        seam = None
    for region in unclaimed:
        stage.undecoded(stream, region.off_start, region.off_end, reason=region.reason)
    return seam


def _mark_tail(
    stage: zpf.DecodeStage, stream: object, start: int, end: int, reason: str
) -> None:
    """Account for a region no record claimed."""
    if end > start:
        stage.undecoded(stream, start, end, reason=reason)


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
