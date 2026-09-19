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
Q5   Can a per-field record say which field it is?               yes
Q6   Can a per-field file say its records do not join, and does  yes
     a stage chained over it keep saying so?
===  ==========================================================  ======

Q6 was asked of ``zpf`` 0.5.0 (spec 0.21), the others of 0.16. It is the
question kober's own files raised upstream as `zipline#106
<https://github.com/adamkjonsson/zipline/issues/106>`_: whether a record naming
bytes an earlier record already cited is a well-formed decoded stream. Under
``contiguous`` such a file was untested rather than conformant — the seam
predicate declines a pair whose citations overlap — and 0.21 answered with a
Participant Descriptor field, ``adjacency``, whose ``units`` value declares
what field granularity is: every record citable, no two assumed to join, no
seam owed anywhere. ``decode_stage(adjacency=UNITS)`` writes it, and a stage
chained over such a file with the keyword left ``None`` carries it forward
rather than claiming its output joins. See ``DESIGN.md`` §5.

Q5 was the finding that blocked field granularity: the records below carried
correct values and correct spans with no way to tell one from another. It was
answered first by ``comment=`` on :meth:`zpf.DecodeStage.record` and now by
``role=``, the per-record label ``zpf`` 0.3.0 added for `#58
<https://github.com/adamkjonsson/python-zipline/issues/58>`_ — which is why the
asterisk is gone. ``comment`` is free text no consumer may depend on; ``role``
is opaque to the format but *declared* to the decoder's vocabulary, and it sits
beside ``content_type`` rather than instead of it, so a record carries
``prim:u16`` **and** ``dns.flags.qr``. See ``DESIGN.md`` §4.1.

Q4 is also answered differently than it was. A record's ``ts`` is derived from
its ``cites`` when omitted, per `#62
<https://github.com/adamkjonsson/python-zipline/issues/62>`_, so a message
spanning two segments takes the completion time of the last one that
contributed to *it* rather than the run's.
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
            session.record(client, ts=1000, payload=DNS[:12], hints=zpf.Hints(seq_start=1001))
            session.record(client, ts=2000, payload=DNS[12:], hints=zpf.Hints(seq_start=1013))
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
        produced_by="kober 0.1",
        produced_at=1_700_000_000,
    ) as stage:
        for stream in stage.streams():
            for seg in stream.segments():
                stage.record(
                    stream,
                    seg.data,
                    content_type="dec:dns-message",
                    cites=(seg.off_start, seg.off_end),
                )


def stage_chained(source: Path, sink: Path) -> None:
    """Q1: a second stage reading the *decoded* file produced by stage 1."""
    with zpf.decode_stage(
        source,
        sink,
        decoder=("dns-fields", "1.0"),
        produced_by="kober 0.1",
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
    """Q2/Q3/Q5/Q6: one record per field, overlapping spans, payloads, names, units."""
    with zpf.decode_stage(
        source,
        sink,
        decoder=("dns", "1.0"),
        produced_by="kober 0.1",
        produced_at=1_700_000_000,
        # Q6: the records below do not join -- two of them are *inside* a
        # third -- and since 0.21 the file can say so.
        adjacency=zpf.Adjacency.UNITS,
    ) as stage:
        for stream in stage.streams():
            data = stream.reassembled()
            flags = struct.unpack_from(">H", data, 2)[0]
            # (name, offset, width, value). Q5: the name rides in role=, the
            # per-record label the format grew for exactly this.
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
                    content_type=f"prim:u{width * 8}",
                    cites=(off, off + width),
                    role=name,
                )
            # Claim the rest honestly rather than letting auto-fill call it
            # "skipped" on our behalf.
            stage.undecoded(stream, 6, len(data), reason="undecodable")


def adjacency_of(path: Path) -> list[zpf.Adjacency]:
    """Return what each participant declares about its stored neighbours."""
    with zpf.open(path) as handle:
        return [
            zpf.Adjacency(p.adjacency)
            for session in handle.sessions()
            for p in session.participants
        ]


def stage_over_units(source: Path, sink: Path) -> None:
    """Q6: a stage over a unit sequence, with ``adjacency`` left unsaid.

    Each input unit is copied through whole. What matters is the participant
    line of the output: ``None`` must carry the input's ``units`` forward, since
    a stage reading a unit sequence may not claim its output joins.
    """
    with zpf.decode_stage(
        source,
        sink,
        decoder=("dns-copy", "1.0"),
        produced_by="kober 0.1",
        produced_at=1_700_000_000,
    ) as stage:
        for stream in stage.streams():
            for dgram in stream.datagrams():
                stage.record(
                    stream,
                    dgram.data,
                    content_type=dgram.record.content_type,
                    role=dgram.record.role,
                    cites=(dgram.off_start, dgram.off_end),
                )


def read_back(path: Path) -> list[str | None]:
    """Show what a consumer sees, and return each record's name for Q5."""
    names: list[str | None] = []
    with zpf.open(path) as handle:
        for session in handle.sessions():
            for record in session.records():
                names.append(record.role)
                token = (record.content_type or ":").split(":", 1)[1]
                value = zpf.decode_prim(record.payload, token)
                spans = [(sp.off_start, sp.off_end) for sp in record.spans]
                print(
                    f"  ct={record.content_type:10} value={value!r:8} "
                    f"cites={spans} role={record.role!r}"
                )
    return names


def main() -> None:
    """Run every probe, reporting conformance and coverage at each step."""
    OUT.mkdir(exist_ok=True)
    transport, stage1 = OUT / "transport.zpf", OUT / "stage1.zpf"
    stage2, fields = OUT / "stage2.zpf", OUT / "fields.zpf"
    over_units = OUT / "over-units.zpf"

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

    banner("Q2/Q3/Q5: field granularity, overlapping spans, normalized payloads, names")
    try:
        stage_fields(transport, fields)
    except PROBE_ERRORS:
        print("  Q2/Q3: FAILED")
        traceback.print_exc()
    else:
        print("  Q2/Q3: accepted at write time")
        report(fields, source=transport)
        names = read_back(fields)
        # Q5 is only answered if every record is *distinguishable*: the two
        # zero-valued flag records are the pair that used to be identical.
        if all(names) and len(set(names)) == len(names):
            print(f"  Q5: YES -- {len(names)} records, each named and distinct")
        else:
            print(f"  Q5: NO -- names={names}")

    banner("Q6: a unit sequence, and a stage chained over it")
    try:
        declared = adjacency_of(fields)
        print(f"  fields.zpf declares: {[a.name for a in declared]}")
        stage_over_units(fields, over_units)
        carried = adjacency_of(over_units)
        print(f"  over-units.zpf declares: {[a.name for a in carried]}")
    except PROBE_ERRORS:
        print("  Q6: FAILED")
        traceback.print_exc()
    else:
        report(over_units, source=fields)
        if declared == [zpf.Adjacency.UNITS] and carried == [zpf.Adjacency.UNITS]:
            print("  Q6: YES -- the file says units, and a stage over it keeps saying so")
        else:
            print("  Q6: NO")


if __name__ == "__main__":
    main()
