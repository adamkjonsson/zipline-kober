"""Pressure-test ``zpf`` against what a spec-driven decoder needs.

Run with a Python that has ``zpf`` importable, e.g. from the sibling checkout::

    ../python-zipline/.venv/bin/python pressure_test.py

Questions, and the answers this script produced against ``zpf`` 0.16:

===  ==========================================================  ======
Q    Question                                                    Answer
===  ==========================================================  ======
Q1   Can a decode stage read a *decoded* file as input?          yes
Q2   Are overlapping spans accepted (bitfields sharing bytes)?   yes
Q3   May a created payload differ from its cited bytes?          yes
Q4   Does a message spanning segments get the last segment's ts? yes
===  ==========================================================  ======

The finding that blocks field-granularity decoding is not a question here but
an omission: :meth:`zpf.DecodeStage.record` accepts no ``comment=`` (nor any
other label), so the ``prim:`` records below come back anonymous. See
``DESIGN.md`` §4.1.
"""

from __future__ import annotations

import struct
import traceback
from pathlib import Path

import zpf

OUT = Path(__file__).parent / "_pressure_out"

# A DNS query: header (12 bytes) + question for example.com (17) = 29.
DNS = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

PROBE_ERRORS = (zpf.ZpfError, AttributeError, TypeError, ValueError)


def banner(text: str) -> None:
    """Print a section header."""
    print(f"\n=== {text} ===")


def report(path: Path, *, source: Path | None = None) -> None:
    """Run the conformance checker, and the coverage check when given an input."""
    checker = zpf.ConformanceChecker()
    try:
        with zpf.open(path) as handle:
            checker.check(handle.blocks())
        checker.finish()
        print(f"  conformance({path.name}): OK  advisory={checker.coverage_findings()}")
    except zpf.ZpfError as exc:
        print(f"  conformance({path.name}): VIOLATION -- {exc}")
    if source is not None:
        print(f"  coverage({path.name}): {zpf.check_coverage(path, source)}")


def build_transport(path: Path) -> None:
    """Write a transport-layer file whose single query arrives as two records."""
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="dns.pcap")
        with writer.begin_session(proto="tcp", key="10.0.0.1:51000 <-> 8.8.8.8:53") as session:
            client = session.participant("10.0.0.1:51000", isn=1000)
            # Split mid-message, so the decoder must coalesce -- and so Q4 has
            # two candidate timestamps to choose between.
            session.record(client, ts=1000, payload=DNS[:12], seq_start=1001)
            session.record(client, ts=2000, payload=DNS[12:], seq_start=1013)
            session.end(reason="fin")


def show_input(path: Path) -> None:
    """Print how the reassembly layer presents the input (Q4)."""
    with zpf.open(path) as handle:
        for session in handle.sessions():
            for view in session.reassemble():
                runs = [(sg.off_start, sg.off_end, sg.ts) for sg in view.segments()]
                print(f"  segments (off_start, off_end, ts): {runs}")
                print(f"  stream_oriented={view.is_stream_oriented}")


def stage_messages(source: Path, sink: Path) -> None:
    """Stage 1: one record per protocol message."""
    with zpf.decode_stage(
        source,
        sink,
        decoder=("dns", "1.0"),
        produced_by="zipline-decoder 0.1",
        produced_at=1_700_000_000,
    ) as stage:
        for stream in stage.streams():
            for seg in stream.segments():
                stage.record(
                    stream,
                    seg.data,
                    ts=seg.ts,
                    content_type="dec:dns-message",
                    cites=(seg.off_start, seg.off_end),
                )


def stage_chained(source: Path, sink: Path) -> None:
    """Q1: a second stage reading the *decoded* file produced by stage 1."""
    with zpf.decode_stage(
        source,
        sink,
        decoder=("dns-fields", "1.0"),
        produced_by="zipline-decoder 0.1",
        produced_at=1_700_000_000,
    ) as stage:
        streams = stage.streams()
        print(f"  streams from a decoded input: {len(streams)}")
        for stream in streams:
            print(f"    stream_oriented={stream.is_stream_oriented} off_start={stream.off_start}")
            # A decoded input is packet-oriented: each decoded record is a
            # datagram, so segments()/chunks() raise here.
            for dgram in stream.datagrams():
                print(f"    datagram [{dgram.off_start},{dgram.off_end}) ts={dgram.ts}")
                stage.record(
                    stream,
                    dgram.data[:2],
                    ts=dgram.ts,
                    content_type="prim:u16",
                    cites=(dgram.off_start, dgram.off_start + 2),
                )
                stage.undecoded(stream, dgram.off_start + 2, dgram.off_end, reason="skipped")


def stage_fields(source: Path, sink: Path) -> None:
    """Q2/Q3: one record per field, with overlapping spans and normalized payloads."""
    with zpf.decode_stage(
        source,
        sink,
        decoder=("dns", "1.0"),
        produced_by="zipline-decoder 0.1",
        produced_at=1_700_000_000,
    ) as stage:
        for stream in stage.streams():
            data = stream.reassembled()
            ts = max(seg.ts for seg in stream.segments())
            flags = struct.unpack_from(">H", data, 2)[0]
            # (name, offset, width, value). The name has nowhere to go -- that
            # is the finding.
            fields: list[tuple[str, int, int, int]] = [
                ("dns.id", 0, 2, struct.unpack_from(">H", data, 0)[0]),
                ("dns.flags", 2, 2, flags),
                # Q2: sub-byte fields, both citing [2, 4) and so overlapping
                # each other and the flags word above.
                ("dns.flags.qr", 2, 2, (flags >> 15) & 1),
                ("dns.flags.opcode", 2, 2, (flags >> 11) & 0xF),
                ("dns.qdcount", 4, 2, struct.unpack_from(">H", data, 4)[0]),
            ]
            for name, off, width, value in fields:
                # Q3: the payload is the value in prim:'s little-endian, which
                # is *not* the big-endian wire bytes the span cites.
                print(f"    emitting {name} = {value}")
                stage.record(
                    stream,
                    value.to_bytes(width, "little"),
                    ts=ts,
                    content_type=f"prim:u{width * 8}",
                    cites=(off, off + width),
                )
            # Claim the rest honestly rather than letting auto-fill call it
            # "skipped" on our behalf.
            stage.undecoded(stream, 6, len(data), reason="undecodable")


def read_back(path: Path) -> None:
    """Show what a consumer sees -- correct values, no way to tell them apart."""
    with zpf.open(path) as handle:
        for session in handle.sessions():
            for record in session.records():
                token = (record.content_type or ":").split(":", 1)[1]
                value = zpf.decode_prim(record.payload, token)
                spans = [(sp.off_start, sp.off_end) for sp in record.spans]
                print(
                    f"  ct={record.content_type:10} value={value!r:8} "
                    f"cites={spans} comment={record.comment!r}"
                )


def main() -> None:
    """Run every probe, reporting conformance and coverage at each step."""
    OUT.mkdir(exist_ok=True)
    transport, stage1 = OUT / "transport.zpf", OUT / "stage1.zpf"
    stage2, fields = OUT / "stage2.zpf", OUT / "fields.zpf"

    banner("build the transport input")
    build_transport(transport)
    show_input(transport)

    banner("stage 1: message granularity")
    stage_messages(transport, stage1)
    report(stage1, source=transport)

    banner("Q1: chain a second stage over the decoded file")
    try:
        stage_chained(stage1, stage2)
    except PROBE_ERRORS:
        print("  Q1: FAILED")
        traceback.print_exc()
    else:
        print("  Q1: YES -- a decoded file works as decode_stage input")
        report(stage2, source=stage1)

    banner("Q2/Q3: field granularity, overlapping spans, normalized payloads")
    try:
        stage_fields(transport, fields)
    except PROBE_ERRORS:
        print("  Q2/Q3: FAILED")
        traceback.print_exc()
    else:
        print("  Q2/Q3: accepted at write time")
        report(fields, source=transport)
        read_back(fields)


if __name__ == "__main__":
    main()
