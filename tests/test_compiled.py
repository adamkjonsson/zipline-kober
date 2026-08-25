"""A generated decoder must agree with the interpreter, field for field.

The reason to keep both implementations, tested at the level stage 4 reaches:
**the same values and the same byte ranges**. The interpreter walks the spec and
builds a tree; the generated module runs straight-line code and builds typed
objects. Nothing checks that they mean the same thing except a comparison of
what they produced, so that comparison is done here over every field of every
unit, recursively.

The sweep is worth more than the examples. Every prefix of a real message is
decoded both ways, which walks truncation across every field boundary — and
across the middle of a bitfield word, where a compiled decoder is most likely to
stop somewhere the interpreter does not. Where a decode fails, the two must fail
at the same offset for the same reason, because that offset is what stage 5 marks
undecoded and a difference there is a difference in the output file.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import struct
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest
import zpf
from fuzzing import DNS_RESPONSE, POINTER_SPEC, SEEDS, cases, pointer_cases, variants
from zpf.blocks import UNDECODED_REASONS, Record, Undecoded

from kober.cli import main
from kober.decoder import Decoder
from kober.emit import Emission, Unclaimed, plan
from kober.errors import CompileError, EvalError, TruncatedRead, Undecodable
from kober.node import Node, NodeStatus
from kober.ops import Plan
from kober.pygen import Names, render
from kober.runtime import Cursor, span
from kober.spec import Emit, Spec
from kober.stage import run_compiled

if TYPE_CHECKING:
    from kober.ops import ObjectPlan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

#: What a generated decoder raises, and the reason the interpreter records for
#: the same outcome. ``ZeroDivisionError`` is Python's own: a compiled
#: expression is arithmetic, and Python refuses to divide by zero before any of
#: this project's code is reached.
REASONS = {
    TruncatedRead: NodeStatus.TRUNCATED.value,
    Undecodable: NodeStatus.UNDECODABLE.value,
    EvalError: NodeStatus.UNDECODABLE.value,
    ZeroDivisionError: NodeStatus.UNDECODABLE.value,
}

QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

RESPONSE = QUERY[:6] + struct.pack(">H", 1) + QUERY[8:] + b"\xc0\x0c\x00\x01"

HTTP = b"GET / HTTP/1.1\r\nHost: httpforever.com\r\nAccept: */*\r\n\r\nbody"


#: Modules already compiled, by source. A prefix sweep compiles one spec once.
_MODULES: dict[str, ModuleType] = {}


def compiled(spec: Spec, emit: Emit = Emit.MESSAGE) -> ModuleType:
    """Compile a spec and import the module, without going through a file.

    Registered in ``sys.modules`` because ``dataclasses`` looks a class's module
    up there while working out which annotations are ``ClassVar`` — which is
    also true of a generated module a consumer imports normally, so nothing is
    being papered over.
    """
    source = render(Plan.from_spec(spec), emit=emit)
    if source in _MODULES:
        return _MODULES[source]
    name = f"compiled_{spec.name}_{len(_MODULES)}"
    module = ModuleType(name)
    sys.modules[name] = module
    exec(compile(source, f"<{name}>", "exec"), module.__dict__)  # noqa: S102
    _MODULES[source] = module
    return module


def example(name: str) -> Spec:
    """Load one of the shipped example specs."""
    return Spec.from_file(EXAMPLES / f"{name}.yaml")


def inline(source: str) -> Spec:
    """Load a spec written inline."""
    return Spec.from_yaml(source)


# --- comparing the two ------------------------------------------------------


class RecordingSink:
    """A sink that keeps what it is told, and optionally writes it to a stage.

    It speaks :class:`kober.emit.Emission` and :class:`kober.emit.Unclaimed`,
    which is the whole reason a generated decoder and the interpreter's emitter
    can be compared: they are two producers for one contract.

    Adjacent regions sharing a reason are coalesced, which ``plan`` also does. A
    generated decoder emits in decode order and never revisits, so one pending
    region is all the buffering that needs.
    """

    def __init__(
        self, stage: zpf.DecodeStage | None = None, stream: object = None, ts: int = 0
    ) -> None:
        self.records: list[Emission] = []
        self.regions: list[Unclaimed] = []
        #: The timestamp records get, which a driver sets per datagram.
        self.ts = ts
        self._stage = stage
        self._stream = stream
        self._pending: Unclaimed | None = None
        self._seam: zpf.Seam | None = None

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
                ts=self.ts,
                content_type=content_type,
                cites=(off_start, off_end),
                comment=comment,
                seam=self._seam,
            )
            self._seam = None

    def undecoded(self, off_start: int, off_end: int, reason: str) -> None:
        """Keep one region, coalescing it with the last if it abuts."""
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
            # A seam is owed after a *hole* — bytes that never existed — because
            # content either side of one does not run on. The classification is
            # read from `zpf` rather than restated, as `kober.stage` does.
            if UNDECODED_REASONS.get(region.reason) == "hole":
                self._seam = zpf.Seam(reason=region.reason)


def merged(regions: list[Unclaimed]) -> list[Unclaimed]:
    """Coalesce adjacent regions sharing a reason, the way a sink does.

    The interpreter writes its tail through a second call to the driver rather
    than through ``plan``, so it can leave two adjacent regions with one reason
    where a sink leaves one. That is a difference in how many calls were made,
    not in what either says about a byte.
    """
    sink = RecordingSink()
    for region in regions:
        sink.undecoded(region.off_start, region.off_end, region.reason)
    sink.finish()
    return sink.regions


def interpreted(
    spec: Spec, data: bytes, emit: Emit, base: int = 0
) -> tuple[list[Emission], list[Unclaimed]]:
    """Return what the interpreter would write for ``data``, tail included.

    ``plan`` stops at how far the decode got and leaves the rest to the driver,
    so the driver's part is done here — otherwise the two sides would be compared
    over different amounts of input.
    """
    tree = Decoder(spec).decode_bytes(data, base=base)
    emissions, unclaimed = plan(spec, tree, data, emit=emit, base=base)
    end = base + len(data)
    if tree.off_end < end:
        reason = "skipped" if tree.status is NodeStatus.OK else tree.status.value
        unclaimed.append(Unclaimed(tree.off_end, end, reason))
    return emissions, merged(unclaimed)


def emitted(
    spec: Spec, data: bytes, emit: Emit, base: int = 0
) -> tuple[list[Emission], list[Unclaimed]]:
    """Return what the generated module writes for ``data``."""
    sink = RecordingSink()
    compiled(spec, emit).decode(data, base=base, sink=sink)
    sink.finish()
    return sink.records, sink.regions


def writes(spec: Spec, data: bytes, emit: Emit, base: int = 0) -> None:
    """Require both implementations to write the same thing for ``data``."""
    assert emitted(spec, data, emit, base) == interpreted(spec, data, emit, base)


def compare(spec: Spec, data: bytes, base: int = 0) -> None:
    """Decode ``data`` both ways and require the results to be the same.

    Either both succeed and every field agrees on its value and its byte range,
    or both fail at the same offset with the same reason.
    """
    plan = Plan.from_spec(spec)
    names = Names(plan)
    module = compiled(spec)
    tree = Decoder(spec).decode_bytes(data, base=base)

    cur = Cursor(data, base)
    try:
        value = module.decode_from(cur)
    except tuple(REASONS) as exc:
        stopped = base + (cur.tell() + 7) // 8
        assert tree.status is not NodeStatus.OK, (
            f"the interpreter decoded {data!r} and the generated module raised {exc!r}"
        )
        assert REASONS[type(exc)] == tree.status.value, f"different reasons for {data!r}"
        assert stopped == tree.off_end, f"stopped at {stopped}, interpreter at {tree.off_end}"
        return

    assert tree.status is NodeStatus.OK, (
        f"the generated module decoded {data!r} and the interpreter said {tree.status.value}"
    )
    assert module.decode(data, base=base) is not None
    same(plan, names, plan.entry, value, tree, "")


def same(plan: Plan, names: Names, unit: str, value: object, node: Node, where: str) -> None:
    """Require one decoded object and one tree node to say the same thing."""
    assert span(value) == (node.off_start, node.off_end), f"{where or unit}: different extent"
    obj: ObjectPlan = plan.object(unit)
    for item in obj.fields:
        if item.name is None:
            # Anonymous: read and cited, but with nothing to compare — the typed
            # model has no attribute for it, which is the whole point.
            continue
        attribute = names.attribute_of(unit, item.name)
        path = f"{where}.{attribute}" if where else attribute
        held = getattr(value, attribute)
        child = node.find(item.name)
        if child is None:
            assert held is None, f"{path}: the interpreter has no such field"
            continue
        if item.repeated:
            assert held is not None, f"{path}: the interpreter decoded {len(child.children)}"
            assert len(held) == len(child.children), f"{path}: different element counts"
            for index, (element, twin) in enumerate(zip(held, child.children, strict=True)):
                nested(plan, names, item, element, twin, f"{path}[{index}]")
            assert span(value, attribute) == (child.off_start, child.off_end), (
                f"{path}: different extent for the repetition"
            )
            continue
        nested(plan, names, item, held, child, path)
        assert span(value, attribute) == (child.off_start, child.off_end), (
            f"{path}: different extent"
        )


def nested(
    plan: Plan, names: Names, item: Any, value: object, node: Node, where: str
) -> None:
    """Compare one value, descending into it if it is a decoded object."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        unit = node.unit
        assert unit is not None, f"{where}: the interpreter has no unit here"
        same(plan, names, unit, value, node, where)
        return
    assert value == node.value, f"{where}: {value!r} against {node.value!r}"


# --- the examples, at every length ------------------------------------------


@pytest.mark.parametrize(("name", "data"), [("dns", QUERY), ("dns", RESPONSE), ("http", HTTP)])
def test_a_whole_message_decodes_the_same_way(name: str, data: bytes):
    compare(example(name), data)


@pytest.mark.parametrize(("name", "data"), [("dns", QUERY), ("http", HTTP)])
def test_every_prefix_of_a_message_decodes_the_same_way(name: str, data: bytes):
    """Truncation at every field boundary, and everywhere between them."""
    spec = example(name)
    for length in range(len(data) + 1):
        compare(spec, data[:length])


@pytest.mark.parametrize("name", ["dns", "http"])
def test_offsets_stay_absolute(name: str):
    compare(example(name), QUERY if name == "dns" else HTTP, base=4096)


def test_a_message_with_bytes_after_it_stops_in_the_same_place():
    compare(example("dns"), QUERY + b"\xff\xff")


# --- one construct at a time ------------------------------------------------


def test_a_switch_dispatches_the_same_way():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: kind, type: {int: {bits: 8}}}
              - name: body
                type:
                  switch:
                    on: kind
                    cases:
                      1: {int: {bits: 16}}
                      2: {bytes: {size: {fixed: 3}}}
                    default: {bytes: {size: {remaining: true}}}
    """)
    for kind in (1, 2, 7):
        compare(spec, bytes([kind]) + b"abcd")


def test_a_switch_with_no_case_is_undecodable_in_both():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: kind, type: {int: {bits: 8}}}
              - name: body
                type:
                  switch:
                    on: kind
                    cases:
                      1: {int: {bits: 16}}
    """)
    compare(spec, b"\x01\x00\x02")
    compare(spec, b"\x09\x00\x02")


def test_a_guard_refuses_the_same_input():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            confirm: "magic == 42"
            reject: "size > 100"
            fields:
              - {name: magic, type: {int: {bits: 8}}}
              - {name: size, type: {int: {bits: 8}}}
    """)
    compare(spec, b"\x2a\x05")
    compare(spec, b"\x01\x05")
    compare(spec, b"\x2a\xff")


def test_a_unit_parameter_is_passed_the_same_way():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: body, type: {unit: {name: chunk, args: ["n * 2"]}}}
          chunk:
            params: [{name: size, type: int}]
            fields:
              - {name: raw, type: {bytes: {size: {expr: "size"}}}}
    """)
    compare(spec, b"\x02abcd")
    compare(spec, b"\x09abcd")


def test_a_parent_reference_reaches_the_same_value():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: body, type: {unit: chunk}}
          chunk:
            fields:
              - {name: raw, type: {bytes: {size: {expr: "parent.n"}}}}
    """)
    compare(spec, b"\x03abcd")


def test_a_root_reference_reaches_the_same_value():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: body, type: {unit: outer}}
          outer:
            fields:
              - {name: inner, type: {unit: chunk}}
          chunk:
            fields:
              - {name: raw, type: {bytes: {size: {expr: "root.n"}}}}
    """)
    compare(spec, b"\x03abcd")


def test_a_recursive_spec_stops_at_the_same_depth():
    """Both implementations must refuse the same input, not merely refuse it."""
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: more, type: {unit: m}, condition: "n > 0"}
    """)
    compare(spec, b"\x01\x00")
    compare(spec, bytes([1] * 40) + b"\x00")
    compare(spec, bytes([1] * 200) + b"\x00")


def test_a_negative_count_is_refused_in_both():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8, signed: true}}}
              - {name: items, type: {int: {bits: 8}}, repeat: {count: "n"}}
    """)
    compare(spec, b"\x02ab")
    compare(spec, b"\xfeab")


def test_a_negative_size_is_refused_in_both():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8, signed: true}}}
              - {name: raw, type: {bytes: {size: {expr: "n"}}}}
    """)
    compare(spec, b"\x02ab")
    compare(spec, b"\xfeab")


def test_a_repetition_that_consumes_nothing_is_refused_in_both():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: items, type: {bytes: {size: {fixed: 0}}}, repeat: {count: 3}}
    """)
    compare(spec, b"abc")


def test_repeating_to_the_end_stops_in_the_same_place():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: items, type: {int: {bits: 8}}, repeat: {to_end: true}}
    """)
    for length in range(6):
        compare(spec, b"abcde"[:length])


def test_a_little_endian_field_reads_the_same_value():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: big, type: {int: {bits: 16}}}
              - {name: small, type: {int: {bits: 16, endian: little}}}
              - {name: signed, type: {int: {bits: 16, endian: little, signed: true}}}
    """)
    compare(spec, b"\x01\x02\x03\x04\xff\xfe")


def test_a_computed_field_computes_the_same_value():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: words, type: {int: {bits: 8}}}
              - {name: octets, type: {computed: "words * 4"}}
              - {name: empty, type: {computed: "words == 0"}}
              - {name: raw, type: {bytes: {size: {expr: "octets"}}}}
    """)
    compare(spec, b"\x01abcd")
    compare(spec, b"\x00")


def test_a_division_by_zero_is_undecodable_in_both():
    """Python raises where the interpreter checks, and both mean the same thing."""
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: raw, type: {bytes: {size: {expr: "8 / n"}}}}
    """)
    compare(spec, b"\x02abcdefgh")
    compare(spec, b"\x00abcdefgh")


def test_a_shift_stays_bounded_in_both():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: raw, type: {bytes: {size: {expr: "1 << n"}}}}
    """)
    compare(spec, b"\x02abcdefgh")
    compare(spec, b"\xffabcdefgh")


def test_an_unterminated_value_truncates_in_both():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: line, type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}}
              - {name: rest, type: {bytes: {size: {remaining: true}}}}
    """)
    compare(spec, b"one\r\ntwo")
    compare(spec, b"no terminator here")


def test_an_optional_terminator_reads_to_the_end_in_both():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - name: line
                type:
                  string:
                    size: {terminated: {delimiter: "\\n", required: false, consume: false}}
    """)
    compare(spec, b"one\ntwo")
    compare(spec, b"no terminator")


def test_a_malformed_string_decodes_the_same_way():
    """A fact about the input, not a failure: both replace and both account for it."""
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: text, type: {string: {size: {fixed: 3}}}}
    """)
    compare(spec, b"\xff\xfe\xfd")


# --- the same records as the interpreter ------------------------------------

#: The inputs both implementations must agree about. Between them they reach a
#: whole message, a skipped section, a message that runs out inside a nested
#: unit, and one that does not fill its datagram.
DNS_INPUTS = [QUERY, RESPONSE, QUERY[:3], QUERY[:5], QUERY + b"\xff"]


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE, Emit.NONE], ids=lambda e: e.value)
@pytest.mark.parametrize("data", DNS_INPUTS, ids=lambda d: str(len(d)))
def test_the_same_records_are_written_for_dns(data: bytes, emit: Emit):
    """Q1's claim, tested rather than argued: direct emission reproduces ``plan``."""
    writes(example("dns"), data, emit)


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_the_same_records_are_written_for_http(emit: Emit):
    writes(example("http"), HTTP, emit)


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_every_prefix_writes_the_same_records(emit: Emit):
    """Where a decode stops is where a region starts, so every stop is checked."""
    spec = example("dns")
    for length in range(len(QUERY) + 1):
        writes(spec, QUERY[:length], emit)


def test_offsets_in_records_stay_absolute():
    writes(example("dns"), QUERY, Emit.FIELD, base=4096)


def test_a_skipped_section_is_named_rather_than_claimed():
    """`emit: none` on a conditional field: the answer section."""
    records, regions = emitted(example("dns"), RESPONSE, Emit.FIELD)
    assert regions == [Unclaimed(29, len(RESPONSE), "skipped")]
    assert all(record.off_end <= 29 for record in records)


def test_a_truncated_message_keeps_what_it_read_before_the_trouble():
    records, regions = emitted(example("dns"), QUERY[:5], Emit.FIELD)
    assert [record.comment for record in records[:2]] == ["dns.id", "dns.flags.qr"]
    assert regions == [Unclaimed(4, 5, "truncated")]


def test_a_truncated_message_is_never_written_as_a_message():
    records, regions = emitted(example("dns"), QUERY[:5], Emit.MESSAGE)
    assert records == []
    assert regions == [Unclaimed(0, 5, "truncated")]


def test_a_repeated_leaf_names_each_element():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: items, type: {int: {bits: 8}}, repeat: {to_end: true}}
    """)
    records, _ = emitted(spec, b"abc", Emit.FIELD)
    assert [record.comment for record in records] == ["t.items[0]", "t.items[1]", "t.items[2]"]
    writes(spec, b"abc", Emit.FIELD)


def test_a_switch_labels_the_record_by_what_it_decoded():
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: kind, type: {int: {bits: 8}}}
              - name: body
                type:
                  switch:
                    on: kind
                    cases:
                      1: {int: {bits: 16}}
                      2: {bytes: {size: {fixed: 2}}}
    """)
    for kind, content in ((1, "prim:u16"), (2, "prim:bytes")):
        records, _ = emitted(spec, bytes([kind]) + b"ab", Emit.FIELD)
        assert records[1].content_type == content
        writes(spec, bytes([kind]) + b"ab", Emit.FIELD)


def test_a_computed_field_cites_the_fields_it_read():
    """§3.2: it consumed nothing, so its own position would say nothing."""
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: words, type: {int: {bits: 8}}}
              - {name: pad, type: {int: {bits: 8}}}
              - {name: octets, type: {computed: "words * 4"}}
    """)
    records, _ = emitted(spec, b"\x02\x00", Emit.FIELD)
    computed = records[-1]
    assert computed.comment == "t.octets"
    assert (computed.off_start, computed.off_end) == (0, 1)
    writes(spec, b"\x02\x00", Emit.FIELD)


def test_a_computed_integer_is_sized_by_its_value():
    """Nothing declares a width for it, so the token comes from the number."""
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: big, type: {computed: "n * 100000"}}
    """)
    records, _ = emitted(spec, b"\x02", Emit.FIELD)
    assert records[-1].content_type == "prim:u32"
    writes(spec, b"\x02", Emit.FIELD)


def test_a_unit_reached_at_two_granularities_is_refused():
    """The interpreter resolves this per node; a compiler would have to emit twice."""
    spec = inline("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: a, type: {unit: part}}
              - {name: b, type: {unit: part}, emit: none}
          part:
            fields: [{name: x, type: {int: {bits: 8}}}]
    """)
    with pytest.raises(CompileError, match="granularity"):
        compiled(spec, Emit.FIELD)


# --- through a real decode stage --------------------------------------------


def write_transport(path: Path, *payloads: bytes) -> None:
    """Write a transport file carrying each payload as one UDP datagram."""
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="dns.pcap")
        with writer.begin_session(proto="udp", key="10.0.0.1:51000 <-> 10.0.0.2:53") as session:
            client = session.participant("10.0.0.1:51000")
            for index, payload in enumerate(payloads):
                session.record(client, ts=1000 + index, payload=payload)
            session.end(reason="closed")


def run_stage(spec: Spec, emit: Emit, source: Path, sink: Path) -> None:
    """Decode a transport file with a generated module, through the shipped driver."""
    run_compiled(
        compiled(spec, emit),
        source,
        sink,
        produced_by="kober compiler",
        produced_at=1_700_000_000,
    )


def blocks(path: Path) -> list[tuple[object, ...]]:
    """Return what a decoded file says, in file order.

    Records and undecoded regions both, since a difference in either is a
    difference in the file. Read from the raw block stream rather than the
    session views, because the order the two implementations write in is part of
    what is being compared.
    """
    out: list[tuple[object, ...]] = []
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, Record):
                spans = tuple((s.off_start, s.off_end) for s in block.spans)
                out.append(("record", block.content_type, block.comment, block.payload, spans))
            elif isinstance(block, Undecoded):
                out.append(("undecoded", block.reason, block.off_start, block.off_end))
    return out


def assert_conformant(path: Path, source: Path) -> None:
    """Fail unless the file passes conformance and accounts for its input."""
    checker = zpf.ConformanceChecker()
    with zpf.open(path) as handle:
        checker.check(handle.blocks())
    checker.finish()
    assert checker.coverage_findings() == []
    assert zpf.check_coverage(path, source) == []


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_a_capture_decodes_into_a_conformant_file(tmp_path: Path, emit: Emit):
    """Acceptance 1: coverage is a promise about a file, so a file is written."""
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY, RESPONSE)
    sink = tmp_path / "decoded.zpf"
    run_stage(example("dns"), emit, source, sink)
    assert_conformant(sink, source)


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_a_truncated_capture_still_covers_every_byte(tmp_path: Path, emit: Emit):
    source = tmp_path / "partial.zpf"
    write_transport(source, QUERY[:5], QUERY[:3])
    sink = tmp_path / "partial-decoded.zpf"
    run_stage(example("dns"), emit, source, sink)
    assert_conformant(sink, source)


def test_the_written_records_read_back_named_and_typed(tmp_path: Path):
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY)
    sink = tmp_path / "fields.zpf"
    run_stage(example("dns"), Emit.FIELD, source, sink)

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
    """A `dec:` type means whatever its decoder documents, and this one reads it."""
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY)
    sink = tmp_path / "messages.zpf"
    run_stage(example("dns"), Emit.MESSAGE, source, sink)

    module = compiled(example("dns"), Emit.MESSAGE)
    payloads = []
    with zpf.open(sink) as handle:
        for session in handle.sessions():
            payloads.extend(
                record.payload
                for record in session.records()
                if record.content_type == module.MESSAGE_CONTENT_TYPE
            )
    assert payloads == [QUERY]
    assert module.decode(payloads[0]) is not None


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_a_generated_module_writes_the_file_the_interpreter_writes(tmp_path: Path, emit: Emit):
    """The differential at its strongest: not the same records, the same *file*.

    Both go through the same driver — gaps, seams, tails and all — so what is
    left to differ is what each decided to write, which is the thing being
    checked. Acceptance criterion 2, one capture at a time.
    """
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY, RESPONSE, QUERY[:5], QUERY + b"\xff")
    spec = example("dns")

    compiled_out = tmp_path / "compiled.zpf"
    run_stage(spec, emit, source, compiled_out)

    interpreted_out = tmp_path / "interpreted.zpf"
    Decoder(spec, emit=emit).run(
        source, interpreted_out, produced_by="kober compiler", produced_at=1_700_000_000
    )

    assert blocks(compiled_out) == blocks(interpreted_out)
    assert_conformant(compiled_out, source)


def test_the_shipped_driver_is_what_makes_a_generated_module_runnable(tmp_path: Path):
    """Acceptance 1, spelled as the plan spells it: compile, then decode a capture."""
    out = tmp_path / "dns.py"
    assert main(["compile", str(EXAMPLES / "dns.yaml"), "-o", str(out), "--emit", "field"]) == 0

    module = imported(out)
    source = tmp_path / "transport.zpf"
    write_transport(source, QUERY, RESPONSE)
    decoded = tmp_path / "decoded.zpf"
    run_compiled(module, source, decoded, produced_by="kober", produced_at=1_700_000_000)
    assert_conformant(decoded, source)


def imported(path: Path) -> ModuleType:
    """Import a generated module from a file, the way a consumer would."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[path.stem]
    return module


# --- the same answers over adversarial input --------------------------------

#: Specs chosen to reach the parts of the compiler an example does not. Between
#: them: bitfields that end on a byte and bitfields that do not divide one, a
#: word split across two bytes, a switch whose cases differ in width, a repeat
#: by count and one to the end, a computed value, a conditional field, every
#: size a spec can write, a back-reference, and the two functions.
AWKWARD: dict[str, str] = {
    "bitfields": """
        name: bits
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: a, type: {int: {bits: 3}}}
              - {name: b, type: {int: {bits: 5}}}
              - {name: c, type: {int: {bits: 1}}}
              - {name: d, type: {int: {bits: 7}}}
              - {name: e, type: {int: {bits: 12}}}
              - {name: f, type: {int: {bits: 4}}}
              - {name: rest, type: {bytes: {size: {remaining: true}}}}
    """,
    "signed and wide": """
        name: wide
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: small, type: {int: {bits: 4, signed: true}}}
              - {name: also, type: {int: {bits: 4, signed: true}}}
              - {name: big, type: {int: {bits: 32, signed: true}}}
              - {name: little, type: {int: {bits: 16, endian: little}}}
              - {name: huge, type: {int: {bits: 64}}}
    """,
    "nested at an offset": """
        name: nested
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: kind, type: {int: {bits: 8}}}
              - {name: head, type: {unit: head}}
              - {name: tail, type: {unit: head}}
          head:
            fields:
              - {name: hi, type: {int: {bits: 4}}}
              - {name: lo, type: {int: {bits: 4}}}
              - {name: word, type: {int: {bits: 16}}}
    """,
    "switch of differing widths": """
        name: switched
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: kind, type: {int: {bits: 8}}}
              - name: body
                type:
                  switch:
                    on: kind
                    cases:
                      1: {int: {bits: 8}}
                      2: {int: {bits: 32}}
                      3: {bytes: {size: {fixed: 3}}}
                      4: {unit: inner}
                    default: {bytes: {size: {remaining: true}}}
              - {name: after, type: {int: {bits: 8}}}
          inner:
            fields:
              - {name: x, type: {int: {bits: 16}}}
    """,
    "repeats": """
        name: repeated
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: count, type: {int: {bits: 8}}}
              - {name: words, type: {int: {bits: 16}}, repeat: {count: "count"}}
              - {name: pairs, type: {unit: pair}, repeat: {to_end: true}}
          pair:
            fields:
              - {name: hi, type: {int: {bits: 8}}}
              - {name: lo, type: {int: {bits: 8}}}
    """,
    "sizes": """
        name: sized
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: fixed, type: {bytes: {size: {fixed: 2}}}}
              - {name: counted, type: {bytes: {size: {expr: "n"}}}}
              - {name: line, type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}}
              - name: loose
                type:
                  string:
                    size: {terminated: {delimiter: "\\n", required: false, consume: false}}
              - {name: rest, type: {bytes: {size: {remaining: true}}}}
    """,
    "computed and conditional": """
        name: derived
        version: "1"
        entry: m
        units:
          m:
            confirm: "words < 200"
            fields:
              - {name: words, type: {int: {bits: 8}}}
              - {name: octets, type: {computed: "words * 4"}}
              - {name: shifted, type: {computed: "1 << words"}}
              - {name: half, type: {computed: "128 / words"}}
              - {name: body, type: {bytes: {size: {expr: "octets"}}}, condition: "words > 0"}
              - {name: rest, type: {bytes: {size: {remaining: true}}}}
    """,
}

#: What each awkward spec is fuzzed from. Long enough that a truncation lands
#: somewhere different every time.
AWKWARD["back-reference"] = """
    name: ptr
    version: "1"
    entry: m
    units:
      m:
        fields:
          - {name: blob, type: {bytes: {size: 4}}}
          - {name: pos, type: {int: {bits: 8}}}
          - {name: seen, type: {pointer: {at: "pos", type: {int: {bits: 16}}}}}
          - {name: deep, type: {pointer: {at: "pos", type: {unit: inner}}}}
          - {name: rest, type: {bytes: {size: {remaining: true}}}}
      inner:
        fields:
          - {name: a, type: {int: {bits: 8}}}
          - {name: back, type: {pointer: {at: "0", type: {int: {bits: 8}}}}}
"""

AWKWARD["text arithmetic"] = """
    name: text
    version: "1"
    entry: m
    units:
      m:
        fields:
          - {name: size, type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}}
          - {name: body, type: {bytes: {size: {expr: "to_int(size, 16)"}}}}
          - name: tail
            type: {bytes: {size: {remaining: true}}}
            condition: "lower(size) == size"
"""

AWKWARD_SEEDS: dict[str, bytes] = {
    "bitfields": bytes(range(1, 12)),
    "signed and wide": bytes(range(0x80, 0x90)),
    "nested at an offset": bytes(range(1, 12)),
    "switch of differing widths": bytes([2, 0, 0, 0, 1, 9, 9, 9]),
    "repeats": bytes([3, 0, 1, 0, 2, 0, 3, 7, 7, 7, 7]),
    "sizes": b"\x03abcdefline\r\nloose\nrest",
    "computed and conditional": bytes([2, *range(20)]),
    # `pos` is 1, so both pointers land inside `blob` — the partial overlap a
    # real owner name makes when it points into an earlier record's rdata.
    "back-reference": bytes([0xAA, 0xBB, 0xCC, 0xDD, 1, 9, 9, 9]),
    "text arithmetic": b"1a\r\n" + b"x" * 26 + b"rest",
}


def awkward(name: str) -> Spec:
    """Load one of the specs chosen to be hard to compile."""
    return inline(AWKWARD[name])


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
@pytest.mark.parametrize("name", sorted(SEEDS))
@pytest.mark.parametrize("seed", [1, 2])
def test_the_two_agree_over_mutated_input(name: str, seed: int, emit: Emit):
    """Stage 7's headline: every example spec, every fuzz case, both ways.

    Values, byte ranges, records, regions. A disagreement here is a bug in one
    of them and this does not say which — but it says *which input*, which is
    the part that is hard to find.
    """
    spec = example(name.removesuffix(".yaml"))
    for data in cases(name, seed):
        try:
            compare(spec, data)
            writes(spec, data, emit)
        except AssertionError as exc:
            exc.add_note(f"disagreed: {name} {emit.value} seed={seed} on {data!r}")
            raise


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
@pytest.mark.parametrize("name", sorted(AWKWARD))
def test_the_two_agree_on_the_awkward_specs(name: str, emit: Emit):
    """The constructs an example does not reach, over adversarial input.

    Sub-byte fields that do not divide a byte, a word straddling two, a switch
    whose branches are different widths — every place the compiler's arithmetic
    about *where a field is* could be wrong while the examples stayed right.
    """
    spec = awkward(name)
    for data in variants(AWKWARD_SEEDS[name], seed=11, rounds=40):
        try:
            compare(spec, data)
            writes(spec, data, emit)
        except AssertionError as exc:
            exc.add_note(f"disagreed: {name!r} {emit.value} on {data!r}")
            raise


@pytest.mark.parametrize("name", [*sorted(SEEDS), *sorted(AWKWARD)])
def test_a_generated_decode_never_raises(name: str):
    """The promise a generated decoder inherits: failure is a result, not an exception.

    A decoder that raises leaves its input unaccounted for, and coverage is a
    promise about output (§2). The compiled entry point catches everything the
    generated code can raise, so anything escaping is something the generator
    did not know it could produce.
    """
    spec = example(name.removesuffix(".yaml")) if name in SEEDS else awkward(name)
    seeds = SEEDS[name] if name in SEEDS else AWKWARD_SEEDS[name]
    module = compiled(spec, Emit.FIELD)
    for data in variants(seeds, seed=12, rounds=40):
        sink = RecordingSink()
        try:
            module.decode(data, sink=sink)
        except Exception as exc:
            exc.add_note(f"escaped a generated decode: {name} on {data!r}")
            raise


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE, Emit.NONE], ids=lambda e: e.value)
@pytest.mark.parametrize("name", [*sorted(SEEDS), *sorted(AWKWARD)])
def test_a_generated_decode_accounts_for_every_byte_exactly_once(name: str, emit: Emit):
    """Cited or named, never both, never outside the input — over anything.

    The property a real bug violated in the interpreter, asserted again on the
    other implementation. It is the whole coverage guarantee in one line, and
    the only one that cannot be checked by reading the code.
    """
    spec = example(name.removesuffix(".yaml")) if name in SEEDS else awkward(name)
    seeds = SEEDS[name] if name in SEEDS else AWKWARD_SEEDS[name]
    allowed = {member.value for member in NodeStatus}
    for data in variants(seeds, seed=13, rounds=40):
        records, regions = emitted(spec, data, emit)
        cited: set[int] = set()
        for record in records:
            assert record.off_end <= len(data), f"{name}: a record ran past {data!r}"
            cited.update(range(record.off_start, record.off_end))
        named: set[int] = set()
        for region in regions:
            assert region.off_end <= len(data), f"{name}: a region ran past {data!r}"
            assert region.reason in allowed, f"{name}: unknown reason {region.reason!r}"
            named.update(range(region.off_start, region.off_end))
        assert not cited & named, f"{name} {emit.value}: cited and named on {data!r}"
        assert cited | named == set(range(len(data))), (
            f"{name} {emit.value}: {len(data) - len(cited | named)} byte(s) "
            f"unaccounted for on {data!r}"
        )


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_a_fuzzed_capture_decodes_into_a_conformant_file(tmp_path: Path, emit: Emit):
    """The pipeline that found the seam bug, run against a generated decoder.

    Records and regions from many messages in one file, which is where the rules
    a single message cannot exercise live: a seam owed after a hole, and a
    region joining the tail of one datagram to the head of the next.
    """
    source = tmp_path / "fuzzed.zpf"
    write_transport(source, *variants(QUERY, seed=14, rounds=24))
    sink = tmp_path / "decoded.zpf"
    run_stage(example("dns"), emit, source, sink)
    assert_conformant(sink, source)


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_a_fuzzed_capture_decodes_the_same_way_both_ways(tmp_path: Path, emit: Emit):
    """And the two implementations write the same file for it, block for block."""
    source = tmp_path / "fuzzed.zpf"
    write_transport(source, *variants(QUERY, seed=15, rounds=24))
    spec = example("dns")

    from_compiler = tmp_path / "compiled.zpf"
    run_stage(spec, emit, source, from_compiler)
    from_interpreter = tmp_path / "interpreted.zpf"
    Decoder(spec, emit=emit).run(
        source, from_interpreter, produced_by="kober compiler", produced_at=1_700_000_000
    )
    assert blocks(from_compiler) == blocks(from_interpreter)


def test_the_empty_and_tiny_inputs_agree():
    """The edges the mutators reach rarely, made certain, on both."""
    for name in sorted(AWKWARD):
        spec = awkward(name)
        for data in (b"", b"\x00", b"\xff", b"\x00" * 3, b"\xff" * 9):
            compare(spec, data)
            writes(spec, data, Emit.FIELD)


def write_stream(path: Path, records: list[tuple[int, bytes, int]]) -> None:
    """Write a byte-oriented transport file from ``(ts, payload, seq_start)`` triples.

    A sequence number that skips leaves a hole the reader reports as a ``Gap``,
    which is the structure a datagram file cannot have and the one the seam
    rules exist for.
    """
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="fuzz.pcap")
        with writer.begin_session(proto="tcp", key="10.0.0.1:51000 <-> 10.0.0.2:53") as session:
            client = session.participant("10.0.0.1:51000", isn=1000)
            for ts, payload, seq in records:
                session.record(client, ts=ts, payload=payload, seq_start=seq)
            session.end(reason="fin")


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
def test_a_fuzzed_stream_with_a_hole_in_it_decodes_the_same_way(tmp_path: Path, emit: Emit):
    """The structure only a byte stream has, over adversarial input.

    Several messages in one run, a lost region between two of them, and messages
    that do not end where the run does. It is the shape the seam rules exist for
    — and where the bug that fuzzing found in the interpreter lived — so a
    generated decoder driven over it has to produce the same file.
    """
    variants_ = variants(QUERY, seed=16, rounds=8)
    first = b"".join(variants_[:4])
    second = b"".join(variants_[4:])
    source = tmp_path / "stream.zpf"
    write_stream(source, [(1000, first, 1001), (2000, second, 1001 + len(first) + 64)])
    spec = example("dns")

    from_compiler = tmp_path / "compiled.zpf"
    run_stage(spec, emit, source, from_compiler)
    from_interpreter = tmp_path / "interpreted.zpf"
    Decoder(spec, emit=emit).run(
        source, from_interpreter, produced_by="kober compiler", produced_at=1_700_000_000
    )
    assert blocks(from_compiler) == blocks(from_interpreter)
    assert_conformant(from_compiler, source)


# --- back-references --------------------------------------------------------


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_the_two_follow_a_pointer_the_same_way(seed: int, emit: Emit):
    """Mutated *real* traffic, against a spec that follows compression pointers.

    The awkward-spec entry above is hand-built to reach the compiler's corners;
    this is the other kind of evidence — bytes nobody simplified first, and the
    corpus every finding in this project has come from.
    """
    spec = Spec.from_yaml(POINTER_SPEC)
    for data in pointer_cases(seed):
        try:
            compare(spec, data)
            writes(spec, data, emit)
        except AssertionError as exc:
            exc.add_note(f"disagreed: pointers {emit.value} seed={seed} on {data!r}")
            raise


def test_the_two_follow_the_real_response_the_same_way():
    """The unmutated capture, at both granularities."""
    spec = Spec.from_yaml(POINTER_SPEC)
    compare(spec, DNS_RESPONSE)
    for emit in (Emit.FIELD, Emit.MESSAGE):
        writes(spec, DNS_RESPONSE, emit)


def test_a_field_path_carries_the_specs_own_name_not_the_backends():
    """Found by the differential, and it was the compiler that was wrong.

    ``class`` is a Python keyword, so the attribute holding it is ``class_``.
    The *path* is what a consumer reads out of the file, and the interpreter
    has only the spec's spelling to offer — so the two disagreed on every
    record for that field until the backend stopped using its own identifier.
    """
    spec = inline("""
        name: k
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: class, type: {int: {bits: 8}}}
    """)
    records, _ = emitted(spec, b"\x01", Emit.FIELD)
    assert [record.comment for record in records] == ["k.class"]
    writes(spec, b"\x01", Emit.FIELD)


@pytest.mark.parametrize(
    ("fragment", "source"),
    [
        (
            "switch under a pointer",
            """
            name: a
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: p, type: {int: {bits: 8}}}
                  - name: t
                    type:
                      pointer:
                        at: "p"
                        type: {switch: {on: "p", cases: {0: {int: {bits: 8}}}}}
            """,
        ),
        (
            "pointer in only some cases",
            """
            name: b
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: p, type: {int: {bits: 8}}}
                  - name: t
                    type:
                      switch:
                        on: "p"
                        cases:
                          0: {int: {bits: 8}}
                          1: {pointer: {at: "0", type: {int: {bits: 8}}}}
            """,
        ),
        (
            "repeated pointer",
            """
            name: c
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: p, type: {int: {bits: 8}}}
                  - name: t
                    type: {pointer: {at: "0", type: {int: {bits: 8}}}}
                    repeat: {count: "p"}
            """,
        ),
    ],
)
def test_the_shapes_the_backend_refuses_say_so(fragment: str, source: str):
    """Each decodes under the interpreter; only the compilation is refused.

    A `CompileError` naming the shape beats generating something subtly
    different from what the interpreter does, which is the one outcome the
    differential could not catch — it would never see the spec.
    """
    spec = inline(source)
    assert Decoder(spec) is not None
    with pytest.raises(CompileError, match=fragment):
        compiled(spec)
