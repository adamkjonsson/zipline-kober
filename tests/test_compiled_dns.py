"""The compiler's target, checked against the interpreter and against `zpf`.

``compiled_dns.py`` is stage 1 of the compiler phase: the module
``kober compile examples/dns.yaml`` should produce, written by hand so that the
design can be run before a generator exists. These tests are what make it a
settlement rather than a sketch.

Two claims are worth more than the rest:

**It agrees with the interpreter, record for record.** Every emission and every
undecoded region the hand-written decoder produces is compared against
:func:`kober.emit.plan` over the same input — same payloads, same content
types, same byte ranges, same paths, same reasons. That is the differential
test of stage 7, run early against one spec, and it is the only thing that
proves direct emission reproduces what the tree-walking emitter decides rather
than merely something plausible.

**Its output is conformant.** The records go through a real decode stage and
past ``ConformanceChecker`` and ``check_coverage``, because coverage is a
promise about a file and nothing short of writing one settles it.

The buffers are slices of real DNS traffic, kept inline for the reason
``test_examples.py`` gives: the captures live in a sibling checkout this suite
does not depend on.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING

import compiled_dns
import pytest
import zpf
from compiled_dns import decode, decode_message

from kober.decoder import Decoder
from kober.emit import Emission, Unclaimed, plan
from kober.runtime import span
from kober.spec import Emit, Spec

if TYPE_CHECKING:
    from collections.abc import Callable

#: The spec the module under test was compiled from.
EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "dns.yaml"

# A real query: one question, `example.com`, type A, class IN.
QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

# Its reply. The answer's owner name is the compression pointer 0xc00c, which
# is exactly why `dns.yaml` decodes no further than the question section.
ANSWER = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
RESPONSE = (
    struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
    + ANSWER
)


class RecordingSink:
    """A sink that keeps what it is told, and optionally writes it to a stage.

    It speaks :class:`kober.emit.Emission` and :class:`kober.emit.Unclaimed` so
    that what a generated decoder emits can be compared with what
    :func:`kober.emit.plan` decides, without translating between two
    vocabularies first.

    Adjacent regions sharing a reason are coalesced, which ``plan`` also does.
    A generated decoder emits in decode order and never revisits, so one
    pending region is all the buffering that needs.
    """

    def __init__(
        self,
        stage: zpf.DecodeStage | None = None,
        stream: object = None,
        ts: int = 0,
    ) -> None:
        self.records: list[Emission] = []
        self.regions: list[Unclaimed] = []
        self._stage = stage
        self._stream = stream
        self._ts = ts
        self._pending: Unclaimed | None = None

    def record(
        self,
        payload: bytes,
        content_type: str,
        off_start: int,
        off_end: int,
        comment: str | None,
    ) -> None:
        """Keep one record, and write it if there is a stage to write to."""
        self._flush()
        self.records.append(Emission(payload, content_type, off_start, off_end, comment))
        if self._stage is not None:
            self._stage.record(
                self._stream,
                payload,
                ts=self._ts,
                content_type=content_type,
                cites=(off_start, off_end),
                comment=comment,
            )

    def undecoded(self, off_start: int, off_end: int, reason: str) -> None:
        """Keep one undecoded region, coalescing it with the last if it abuts."""
        if off_end <= off_start:
            return
        pending = self._pending
        if pending is not None and pending.reason == reason and pending.off_end >= off_start:
            self._pending = Unclaimed(pending.off_start, max(pending.off_end, off_end), reason)
            return
        self._flush()
        self._pending = Unclaimed(off_start, off_end, reason)

    def finish(self) -> None:
        """Write out whatever is still pending. Call once per message."""
        self._flush()

    def _flush(self) -> None:
        if self._pending is None:
            return
        region = self._pending
        self._pending = None
        self.regions.append(region)
        if self._stage is not None:
            self._stage.undecoded(
                self._stream, region.off_start, region.off_end, reason=region.reason
            )


def spec() -> Spec:
    """Load the shipped example the module was compiled from."""
    return Spec.from_file(EXAMPLE)


def merged(regions: list[Unclaimed]) -> list[Unclaimed]:
    """Coalesce adjacent regions sharing a reason, as a sink does.

    The interpreter writes its tail through a second call to the driver rather
    than through ``plan``, so it can leave two adjacent regions with one reason
    where a sink leaves one. That is a difference in how many calls were made,
    not in what either says about a byte, so both sides are coalesced before
    being compared.
    """
    sink = RecordingSink()
    for region in regions:
        sink.undecoded(region.off_start, region.off_end, region.reason)
    sink.finish()
    return sink.regions


def interpreted(data: bytes, emit: Emit, base: int = 0) -> tuple[list[Emission], list[Unclaimed]]:
    """Return what the interpreter would write for ``data``, tail included.

    ``plan`` deliberately stops at how far the decode got and leaves the rest
    to the driver, so the driver's part is done here — otherwise the two sides
    would be compared over different amounts of input.
    """
    loaded = spec()
    tree = Decoder(loaded).decode_bytes(data, base=base)
    emissions, unclaimed = plan(loaded, tree, data, emit=emit, base=base)
    end = base + len(data)
    if tree.off_end < end:
        reason = "skipped" if tree.status.value == "ok" else tree.status.value
        unclaimed.append(Unclaimed(tree.off_end, end, reason))
    return emissions, merged(unclaimed)


def emitted(
    data: bytes, entry: Callable[..., object] = decode, base: int = 0
) -> tuple[list[Emission], list[Unclaimed]]:
    """Return what the compiled module emits for ``data``."""
    sink = RecordingSink()
    entry(data, base=base, sink=sink)
    sink.finish()
    return sink.records, sink.regions


# --- the typed API ---------------------------------------------------------


def test_a_real_query_decodes_into_typed_objects():
    message = decode(QUERY)
    assert message is not None
    assert message.id == 0x1234
    assert message.qdcount == 1
    assert message.flags.rd == 1
    assert message.flags.qr == 0
    assert [label.text for label in message.questions[0].qname.labels] == ["example", "com", ""]
    assert message.questions[0].qtype == 1


def test_the_typed_api_needs_no_sink():
    """A caller who wants objects and no records passes nothing."""
    assert decode(QUERY) is not None


def test_an_absent_conditional_field_is_none_rather_than_empty():
    message = decode(QUERY)
    assert message is not None
    assert message.resource_records is None
    message = decode(RESPONSE)
    assert message is not None
    assert message.resource_records == ANSWER


def test_an_enum_is_a_lookup_rather_than_a_type():
    """A value with no label is normal on the wire, so the field stays an int."""
    message = decode(QUERY)
    assert message is not None
    assert compiled_dns.OPCODE[message.flags.opcode] == "query"
    assert compiled_dns.RRTYPE[message.questions[0].qtype] == "a"
    assert 3 not in compiled_dns.OPCODE


def test_every_object_knows_which_bytes_it_came_from():
    message = decode(QUERY)
    assert message is not None
    assert span(message) == (0, len(QUERY))
    assert span(message, "id") == (0, 2)
    assert span(message, "qdcount") == (4, 6)
    question = message.questions[0]
    assert span(question) == (12, 29)
    assert span(question, "qtype") == (25, 27)
    assert span(question.qname.labels[0], "text") == (13, 20)


def test_a_sub_byte_field_cites_the_byte_holding_it():
    """§1: spans are byte offsets, so overlapping citations are the normal case."""
    message = decode(QUERY)
    assert message is not None
    assert span(message, "flags") == (2, 4)
    assert span(message.flags, "qr") == (2, 3)
    assert span(message.flags, "rcode") == (3, 4)


def test_an_absent_field_cites_nothing():
    message = decode(QUERY)
    assert message is not None
    start, end = span(message, "resource_records")
    assert start == end == len(QUERY)


def test_span_refuses_a_name_that_is_not_a_field():
    message = decode(QUERY)
    assert message is not None
    with pytest.raises(KeyError):
        span(message, "qname")


# --- the same records as the interpreter -----------------------------------


#: The inputs both implementations must agree on. Between them they reach
#: every construct `dns.yaml` uses: a repetition by count and one by `until`, a
#: conditional field, `emit: none`, a message that runs out, and one that does
#: not fill its datagram.
INPUTS = {
    "a query": QUERY,
    "a response whose answer section is skipped": RESPONSE,
    "a message cut short": QUERY[:5],
    "a message with a byte after it": QUERY + b"\xff",
}


@pytest.mark.parametrize(
    ("entry", "emit"),
    [(decode, Emit.FIELD), (decode_message, Emit.MESSAGE)],
    ids=["field", "message"],
)
@pytest.mark.parametrize("data", list(INPUTS.values()), ids=list(INPUTS))
def test_the_compiled_module_writes_what_the_interpreter_writes(
    data: bytes, entry: Callable[..., object], emit: Emit
):
    """The differential claim, and the reason to keep both implementations."""
    assert emitted(data, entry) == interpreted(data, emit)


def test_a_skipped_section_is_named_rather_than_claimed():
    """`emit: none` on a conditional field: the answer section."""
    assert emitted(RESPONSE)[1] == [Unclaimed(29, len(RESPONSE), "skipped")]


def test_a_truncated_message_keeps_what_it_read_before_the_trouble():
    records, regions = emitted(QUERY[:5])
    assert [record.comment for record in records[:2]] == ["dns.id", "dns.flags.qr"]
    assert regions == [Unclaimed(4, 5, "truncated")]


def test_a_truncated_message_is_never_written_as_a_message():
    records, regions = emitted(QUERY[:5], decode_message)
    assert records == []
    assert regions == [Unclaimed(0, 5, "truncated")]


def test_the_offsets_are_absolute():
    """A run does not begin at zero, and every citation says so."""
    records, regions = emitted(QUERY, base=1000)
    assert (records, regions) == interpreted(QUERY, Emit.FIELD, base=1000)
    assert records[0].off_start == 1000


def test_every_byte_is_cited_or_named_and_never_both():
    for data in INPUTS.values():
        for entry in (decode, decode_message):
            records, regions = emitted(data, entry)
            cited: set[int] = set()
            for record in records:
                cited.update(range(record.off_start, record.off_end))
            named: set[int] = set()
            for region in regions:
                named.update(range(region.off_start, region.off_end))
            assert cited & named == set(), f"{data!r} cited and named the same byte"
            assert cited | named == set(range(len(data))), f"{data!r} left a byte unaccounted for"


# --- through a real decode stage -------------------------------------------


def write_transport(path: Path, *payloads: bytes) -> None:
    """Write a transport file carrying each payload as one UDP datagram."""
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="dns.pcap")
        with writer.begin_session(proto="udp", key="10.0.0.1:51000 <-> 10.0.0.2:53") as session:
            client = session.participant("10.0.0.1:51000")
            for index, payload in enumerate(payloads):
                session.record(client, ts=1000 + index, payload=payload)
            session.end(reason="closed")


def run_stage(source: Path, sink: Path, entry: Callable[..., object]) -> None:
    """Decode a transport file with the compiled module, one datagram at a time."""
    with zpf.decode_stage(
        source,
        sink,
        decoder=(compiled_dns.NAME, compiled_dns.VERSION),
        produced_by="kober compiler spike",
        produced_at=1_700_000_000,
    ) as stage:
        for stream in stage.streams():
            for datagram in stream.datagrams():
                writer = RecordingSink(stage, stream, datagram.ts)
                entry(datagram.data, base=datagram.off_start, sink=writer)
                writer.finish()


def assert_conformant(path: Path, source: Path) -> None:
    """Fail unless the file passes conformance and accounts for its input."""
    checker = zpf.ConformanceChecker()
    with zpf.open(path) as handle:
        checker.check(handle.blocks())
    checker.finish()
    assert checker.coverage_findings() == []
    assert zpf.check_coverage(path, source) == []


@pytest.mark.parametrize("entry", [decode, decode_message], ids=["field", "message"])
def test_a_capture_decodes_into_a_conformant_file(tmp_path: Path, entry: Callable[..., object]):
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY, RESPONSE)
    sink = tmp_path / "decoded.zpf"
    run_stage(source, sink, entry)
    assert_conformant(sink, source)


@pytest.mark.parametrize("entry", [decode, decode_message], ids=["field", "message"])
def test_a_truncated_capture_still_covers_every_byte(
    tmp_path: Path, entry: Callable[..., object]
):
    source = tmp_path / "partial.zpf"
    write_transport(source, QUERY[:5])
    sink = tmp_path / "partial-decoded.zpf"
    run_stage(source, sink, entry)
    assert_conformant(sink, source)


def test_the_written_records_read_back_named_and_typed(tmp_path: Path):
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY)
    sink = tmp_path / "fields.zpf"
    run_stage(source, sink, decode)

    seen: dict[str, object] = {}
    with zpf.open(sink) as handle:
        for session in handle.sessions():
            for record in session.records():
                if record.content_type.startswith("prim:"):
                    token = record.content_type.split(":", 1)[1]
                    seen[record.comment] = zpf.decode_prim(record.payload, token)

    assert seen["dns.id"] == 0x1234
    assert seen["dns.flags.rd"] == 1
    assert seen["dns.questions[0].qname.labels[0].length"] == 7
    # The anonymous field is written, and has nowhere to be named but its path.
    assert seen["dns.flags._"] == 0


def test_a_message_record_reads_back_through_the_decoder(tmp_path: Path):
    """A `dec:` type means whatever its decoder documents, and this one still reads it."""
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY)
    sink = tmp_path / "messages.zpf"
    run_stage(source, sink, decode_message)

    payloads = []
    with zpf.open(sink) as handle:
        for session in handle.sessions():
            payloads.extend(
                record.payload
                for record in session.records()
                if record.content_type == compiled_dns.MESSAGE_CONTENT_TYPE
            )
    assert payloads == [QUERY]
    assert decode(payloads[0]) is not None
