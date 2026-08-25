"""Tests for driving a real `zpf` decode stage from a spec."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
import zpf

from kober.decoder import Decoder
from kober.errors import SpecError
from kober.spec import Emit, Spec

if TYPE_CHECKING:
    from pathlib import Path

# Four-byte messages: a u16 length-ish tag and a u16 body, so several fit in
# one run and a boundary can be put anywhere.
MESSAGE = struct.pack(">HH", 0x1234, 0x5678)

SPEC = Spec.from_yaml("""
name: t
version: "1.0"
entry: message
input: either
units:
  message:
    fields:
      - {name: tag, type: {int: {bits: 16}}}
      - {name: body, type: {int: {bits: 16}}}
""")


def write_transport(path: Path, records: list[tuple[int, bytes, int]]) -> None:
    """Write a transport file from (ts, payload, seq_start) triples."""
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="x.pcap")
        with writer.begin_session(proto="tcp", key="a <-> b") as session:
            client = session.participant("10.0.0.1:51000", isn=1000)
            for ts, payload, seq in records:
                session.record(client, ts=ts, payload=payload, seq_start=seq)
            session.end(reason="fin")


def assert_conformant(path: Path, source: Path) -> None:
    checker = zpf.ConformanceChecker()
    with zpf.open(path) as handle:
        checker.check(handle.blocks())
    checker.finish()
    assert checker.coverage_findings() == []
    assert zpf.check_coverage(path, source) == []


def read_records(path: Path) -> list[zpf.Record]:
    with zpf.open(path) as handle:
        return [r for session in handle.sessions() for r in session.records()]


def read_blocks(path: Path) -> list[object]:
    with zpf.open(path) as handle:
        return list(handle.blocks())


# --- run(): one file in, one file out --------------------------------------


def test_run_decodes_a_whole_file(tmp_path: Path):
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE, 1001)])
    Decoder(SPEC).run(source, sink, produced_by="kober test", produced_at=1_700_000_000)
    assert_conformant(sink, source)
    records = read_records(sink)
    assert len(records) == 1
    assert records[0].content_type == "dec:t-message"
    assert records[0].payload == MESSAGE


def test_several_messages_in_one_run(tmp_path: Path):
    """STREAM framing: decode the entry unit repeatedly until the run ends."""
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE * 3, 1001)])
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    assert len(read_records(sink)) == 3


def test_field_granularity_over_a_file(tmp_path: Path):
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE, 1001)])
    Decoder(SPEC, emit=Emit.FIELD).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    comments = {r.comment for r in read_records(sink)}
    assert comments == {"t.tag", "t.body"}


def test_a_trailing_partial_message_is_truncated_not_an_error(tmp_path: Path):
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE + b"\x01\x02", 1001)])
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    assert len(read_records(sink)) == 1
    reasons = {b.reason for b in read_blocks(sink) if isinstance(b, zpf.Undecoded)}
    assert "truncated" in reasons


# --- gaps ------------------------------------------------------------------


def gapped(tmp_path: Path) -> tuple[Path, Path]:
    """Build a stream with a hole: bytes 0-3 present, 4-7 lost, 8-11 present."""
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(
        source,
        [(1000, MESSAGE, 1001), (3000, MESSAGE, 1009)],  # seq 1005-1008 missing
    )
    return source, sink


def test_a_gap_is_marked_with_its_own_reason(tmp_path: Path):
    source, sink = gapped(tmp_path)
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    gaps = [
        b
        for b in read_blocks(sink)
        if isinstance(b, zpf.Undecoded) and b.reason == "gap"
    ]
    assert len(gaps) == 1
    assert (gaps[0].off_start, gaps[0].off_end) == (4, 8)


def test_messages_either_side_of_a_gap_declare_a_seam(tmp_path: Path):
    """§5: only the producer knows, and the checker cannot catch a missing one."""
    source, sink = gapped(tmp_path)
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    breaks = [b for b in read_blocks(sink) if isinstance(b, zpf.Discontinuity)]
    assert len(breaks) == 1
    assert breaks[0].reason == "stream-gap"


def test_a_seam_leaves_its_width_absent(tmp_path: Path):
    """How many decoded units a hole cost is not recoverable from its bytes."""
    source, sink = gapped(tmp_path)
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    breaks = [b for b in read_blocks(sink) if isinstance(b, zpf.Discontinuity)]
    assert breaks[0].width is None


def test_a_message_does_not_span_a_gap(tmp_path: Path):
    """Bytes either side were never observed adjacent, so decoding restarts."""
    source, sink = gapped(tmp_path)
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    spans = [(s.off_start, s.off_end) for r in read_records(sink) for s in r.spans]
    assert spans == [(0, 4), (8, 12)]


def datagrams(path: Path, payloads: list[bytes]) -> None:
    """Write a packet-oriented transport file: no seq_start, so no byte stream."""
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="x.pcap")
        with writer.begin_session(proto="udp", key="a <-> b") as session:
            client = session.participant("10.0.0.1:5353")
            for index, payload in enumerate(payloads):
                session.record(client, ts=1000 + index, payload=payload)
            session.end(reason="close")


def test_a_truncated_message_owes_a_seam_to_the_next_record(tmp_path: Path):
    """`truncated` is hole-class, so what follows it does not join.

    Found by fuzzing real DNS: the driver seamed gaps only, and zpf sorts both
    `gap` and `truncated` into the same recoverability class.
    """
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    # A record, then a hole, then a record — the shape the rule is about. The
    # middle datagram is three bytes: `tag` reads and `body` runs out one byte
    # short, so [x, x+1) is a real truncated region rather than an empty one.
    # A seam needs a record *before* it; a stream's first record has nothing
    # to not-join, and zpf drops a seam offered there.
    datagrams(source, [MESSAGE, MESSAGE[:3], MESSAGE])
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    breaks = [b for b in read_blocks(sink) if isinstance(b, zpf.Discontinuity)]
    assert [b.reason for b in breaks] == ["truncated"]


def test_bytes_class_regions_owe_no_seam(tmp_path: Path):
    """`skipped` and `undecodable` bytes existed, so content either side joins."""
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    # Each datagram carries a whole message plus a spare byte the spec never
    # claims, which is `skipped` — bytes-class, so no break is owed.
    datagrams(source, [MESSAGE + b"\x99", MESSAGE + b"\x99"])
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    assert [b for b in read_blocks(sink) if isinstance(b, zpf.Discontinuity)] == []


# --- shape dispatch --------------------------------------------------------


def test_a_datagram_spec_over_a_byte_stream_is_refused(tmp_path: Path):
    """The mismatch that would fabricate a field tree over the wrong bytes."""
    spec = Spec.from_yaml(SPEC_TEXT_DATAGRAM)
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE, 1001)])
    with pytest.raises(SpecError, match="declares input: datagram"):
        Decoder(spec).run(source, sink, produced_by="t", produced_at=1)


SPEC_TEXT_DATAGRAM = """
name: d
version: "1.0"
entry: message
input: datagram
units:
  message:
    fields:
      - {name: tag, type: {int: {bits: 16}}}
      - {name: body, type: {int: {bits: 16}}}
"""

SPEC_TEXT_STREAM = """
name: s
version: "1.0"
entry: message
input: stream
units:
  message:
    fields:
      - {name: tag, type: {int: {bits: 16}}}
      - {name: body, type: {int: {bits: 16}}}
"""


def test_a_stream_spec_over_datagrams_is_allowed(tmp_path: Path):
    """Every chained stage needs this: a decoded input is packet-oriented."""
    source = tmp_path / "in.zpf"
    first, second = tmp_path / "one.zpf", tmp_path / "two.zpf"
    write_transport(source, [(1000, MESSAGE, 1001)])
    Decoder(Spec.from_yaml(SPEC_TEXT_STREAM)).run(
        source, first, produced_by="t", produced_at=1
    )
    # Stage 2 reads the decoded file, which presents datagrams.
    Decoder(Spec.from_yaml(SPEC_TEXT_STREAM)).run(
        first, second, produced_by="t", produced_at=1
    )
    assert_conformant(second, first)
    assert len(read_records(second)) == 1


def test_chaining_two_stages(tmp_path: Path):
    """Q1 of the pressure test, now driven end to end from a spec."""
    source = tmp_path / "in.zpf"
    first, second = tmp_path / "one.zpf", tmp_path / "two.zpf"
    write_transport(source, [(1000, MESSAGE, 1001)])
    Decoder(SPEC).run(source, first, produced_by="t", produced_at=1)
    Decoder(SPEC, emit=Emit.FIELD).run(first, second, produced_by="t", produced_at=1)
    assert_conformant(first, source)
    assert_conformant(second, first)
    assert {r.comment for r in read_records(second)} == {"t.tag", "t.body"}


# --- timestamps ------------------------------------------------------------


def test_a_run_takes_its_segments_completion_time(tmp_path: Path):
    """Q2: chunks() coalesces a run and its ts is already the last contributor's."""
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE[:2], 1001), (2000, MESSAGE[2:], 1003)])
    Decoder(SPEC).run(source, sink, produced_by="t", produced_at=1)
    records = read_records(sink)
    assert len(records) == 1
    assert records[0].timestamp == 2000


# --- decode_stream(): the lower-level entry point --------------------------


def test_decode_stream_can_be_driven_by_hand(tmp_path: Path):
    """§6's seam for mixing spec-driven and hand-written logic in one stage."""
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE, 1001)])
    decoder = Decoder(SPEC)
    with zpf.decode_stage(
        source,
        sink,
        decoder=("t", "1.0"),
        produced_by="by hand",
        produced_at=1,
    ) as stage:
        for stream in stage.streams():
            decoder.decode_stream(stage, stream)
    assert_conformant(sink, source)
    assert len(read_records(sink)) == 1


# --- the read side ---------------------------------------------------------


def test_content_registry_reads_messages_back_as_trees(tmp_path: Path):
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    write_transport(source, [(1000, MESSAGE, 1001)])
    decoder = Decoder(SPEC)
    decoder.run(source, sink, produced_by="t", produced_at=1)

    # The kwarg is `content=`, and `dec:` resolves through the *reader*: its
    # token is namespaced by the decoder's name, which only the file knows.
    with zpf.open(sink, content=decoder.content_registry()) as handle:
        trees = [
            handle.content(record)
            for session in handle.sessions()
            for record in session.records()
        ]
    assert len(trees) == 1
    assert trees[0].find("tag").value == 0x1234
    assert trees[0].find("body").value == 0x5678


def test_a_pointer_owes_no_seam(tmp_path: Path):
    """A pointer cites bytes; it never names a hole, so nothing is owed.

    §5 asks for a break after a **hole**-class region. A pointer produces no
    undecoded region at all when it resolves, and `undecodable` — which is what
    every way of failing to follow one produces — is bytes-class. The one route
    to a false hole was a target read running short and reporting `truncated`,
    which the decoder converts precisely so this stays true.
    """
    spec = Spec.from_yaml("""
name: p
version: "1.0"
entry: message
input: either
units:
  message:
    fields:
      - {name: blob, type: {bytes: {size: 2}}}
      - {name: pos, type: {int: {bits: 8}}}
      - {name: seen, type: {pointer: {at: "pos", type: {int: {bits: 16}}}}}
""")
    source, sink = tmp_path / "in.zpf", tmp_path / "out.zpf"
    # Three messages: one resolving, one whose target does not decode, one
    # resolving again — so a false hole would land between real records.
    datagrams(source, [b"\xaa\xbb\x00", b"\xaa\xbb\x02", b"\xaa\xbb\x00"])
    Decoder(spec).run(source, sink, produced_by="t", produced_at=1)
    assert_conformant(sink, source)
    assert [b for b in read_blocks(sink) if isinstance(b, zpf.Discontinuity)] == []
    reasons = {b.reason for b in read_blocks(sink) if isinstance(b, zpf.Undecoded)}
    assert reasons <= {"undecodable", "skipped"}, f"a pointer named a hole: {reasons}"
