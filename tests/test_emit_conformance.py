"""Emissions written to a real `zpf` file must be conformant and cover the input.

The unit tests in ``test_emit.py`` check what the emitter *decides*. This
checks that `zpf` accepts it: the plan is written through a real decode stage
and put past ``ConformanceChecker`` and ``check_coverage``, which is the only
thing that actually settles whether the design's claims hold.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
import zpf

from kober.decoder import Decoder
from kober.emit import plan
from kober.spec import Emit, Spec

if TYPE_CHECKING:
    from pathlib import Path

DNS_QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

DNS_SPEC = """
name: dns
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: id, type: {int: {bits: 16}}}
      - {name: flags, type: {unit: flags}}
      - {name: qdcount, type: {int: {bits: 16}}}
      - {name: ancount, type: {int: {bits: 16}}}
      - {name: nscount, type: {int: {bits: 16}}}
      - {name: arcount, type: {int: {bits: 16}}}
      - {name: qname, type: {bytes: {size: {terminated: {delimiter: "\\0"}}}}}
      - {name: qtype, type: {int: {bits: 16}}}
      - {name: qclass, type: {int: {bits: 16}}}
  flags:
    fields:
      - {name: qr, type: {int: {bits: 1}}}
      - {name: opcode, type: {int: {bits: 4}}}
      - {name: null, type: {int: {bits: 3}}}
      - {name: null, type: {int: {bits: 8}}}
"""


def write_transport(path: Path, payload: bytes) -> None:
    """Write a one-record transport file holding ``payload``."""
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="dns.pcap")
        with writer.begin_session(proto="tcp", key="a <-> b") as session:
            client = session.participant("10.0.0.1:51000", isn=1000)
            session.record(client, ts=1000, payload=payload, hints=zpf.Hints(seq_start=1001))
            session.end(reason="fin")


def run_stage(source: Path, sink: Path, spec: Spec, emit: Emit) -> None:
    """Decode ``source`` into ``sink`` at the given granularity."""
    decoder = Decoder(spec, emit=emit)
    with zpf.decode_stage(
        source,
        sink,
        decoder=(spec.name, spec.version),
        produced_by="kober test",
        produced_at=1_700_000_000,
    ) as stage:
        for stream in stage.streams():
            data = stream.reassembled()
            tree = decoder.decode_bytes(data, base=stream.off_start)
            emissions, unclaimed = plan(
                spec, tree, data, emit=emit, base=stream.off_start
            )
            for record in emissions:
                stage.record(
                    stream,
                    record.payload,
                    content_type=record.content_type,
                    role=record.role,
                    cites=(record.off_start, record.off_end),
                )
            for region in unclaimed:
                stage.undecoded(
                    stream, region.off_start, region.off_end, reason=region.reason
                )
            # The tail the plan deliberately leaves to the driver.
            end = stream.off_start + len(data)
            if tree.off_end < end:
                stage.undecoded(
                    stream, tree.off_end, end, reason=tree.status.value
                )


def assert_conformant(path: Path, source: Path) -> None:
    """Fail unless the file passes conformance and coverage."""
    checker = zpf.ConformanceChecker()
    with zpf.open(path) as handle:
        checker.check(handle.blocks())
    checker.finish()
    assert checker.coverage_findings() == []
    assert zpf.check_coverage(path, source) == []


@pytest.fixture
def dns_files(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "transport.zpf"
    write_transport(source, DNS_QUERY)
    return source, tmp_path


def test_message_granularity_is_conformant(dns_files: tuple[Path, Path]):
    source, tmp_path = dns_files
    sink = tmp_path / "messages.zpf"
    run_stage(source, sink, Spec.from_yaml(DNS_SPEC), Emit.MESSAGE)
    assert_conformant(sink, source)


def test_field_granularity_is_conformant(dns_files: tuple[Path, Path]):
    """The claim §4.1 rests on, checked rather than asserted."""
    source, tmp_path = dns_files
    sink = tmp_path / "fields.zpf"
    run_stage(source, sink, Spec.from_yaml(DNS_SPEC), Emit.FIELD)
    assert_conformant(sink, source)


def test_field_records_read_back_named_and_typed(dns_files: tuple[Path, Path]):
    source, tmp_path = dns_files
    sink = tmp_path / "fields.zpf"
    run_stage(source, sink, Spec.from_yaml(DNS_SPEC), Emit.FIELD)

    seen: dict[str, object] = {}
    with zpf.open(sink) as handle:
        for session in handle.sessions():
            for record in session.records():
                token = (record.content_type or ":").split(":", 1)[1]
                seen[record.role] = zpf.decode_prim(record.payload, token)

    assert seen["dns.id"] == 0x1234
    assert seen["dns.qdcount"] == 1
    # The pair that was "correct and useless" before #55 landed.
    assert seen["dns.flags.qr"] == 0
    assert seen["dns.flags.opcode"] == 0
    assert seen["dns.qname"] == b"\x07example\x03com"


def test_a_widened_sub_byte_field_reads_back_as_its_value(
    dns_files: tuple[Path, Path],
):
    """Q5: a u4 is written as prim:u8, and any reader gets the right number."""
    source, tmp_path = dns_files
    sink = tmp_path / "fields.zpf"
    run_stage(source, sink, Spec.from_yaml(DNS_SPEC), Emit.FIELD)
    with zpf.open(sink) as handle:
        records = [
            record
            for session in handle.sessions()
            for record in session.records()
            if record.role == "dns.flags.opcode"
        ]
    assert len(records) == 1
    assert records[0].content_type == "prim:u8"
    assert zpf.decode_prim(records[0].payload, "u8") == 0


def test_truncated_input_still_covers_every_byte(tmp_path: Path):
    """A half message must leave nothing unaccounted for."""
    source = tmp_path / "partial.zpf"
    write_transport(source, DNS_QUERY[:5])
    sink = tmp_path / "partial-decoded.zpf"
    run_stage(source, sink, Spec.from_yaml(DNS_SPEC), Emit.FIELD)
    assert_conformant(sink, source)


def test_a_decoded_file_can_be_chained(dns_files: tuple[Path, Path]):
    """Q1 from the pressure test, now from a real spec rather than by hand."""
    source, tmp_path = dns_files
    first = tmp_path / "stage1.zpf"
    run_stage(source, first, Spec.from_yaml(DNS_SPEC), Emit.MESSAGE)
    with zpf.open(first) as handle:
        shapes = [
            view.is_stream_oriented
            for session in handle.sessions()
            for view in session.reassemble()
        ]
    assert shapes
    assert not any(shapes), "a decoded file is packet-oriented"


def test_sub_byte_fields_are_a_conformant_unit_sequence(tmp_path: Path):
    """The shape spec 0.21's `adjacency=units` exists for, through the real driver.

    `dns.flags.qr`, `.opcode` and the rest all cite the byte that holds them,
    so no two of them join — they are *inside* one another's bytes. A file
    that declares `units` says exactly that, and the checker and the coverage
    rule (at-least-once, containment allowed) accept it with no findings.
    """
    source, sink = tmp_path / "transport.zpf", tmp_path / "fields.zpf"
    write_transport(source, DNS_QUERY)
    Decoder(Spec.from_yaml(DNS_SPEC), emit=Emit.FIELD).run(
        source, sink, produced_by="kober test", produced_at=1_700_000_000
    )
    assert_conformant(sink, source)
    with zpf.open(sink) as handle:
        sessions = list(handle.sessions())
        adjacency = [zpf.Adjacency(p.adjacency) for s in sessions for p in s.participants]
        spans = [
            (r.spans[0].off_start, r.spans[0].off_end)
            for s in sessions
            for r in s.records()
            if r.role is not None and r.role.startswith("dns.flags.")
        ]
    assert adjacency == [zpf.Adjacency.UNITS]
    assert spans == [(2, 3), (2, 3), (2, 3), (3, 4)], "three fields share one byte"
