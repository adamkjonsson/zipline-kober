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
import struct
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest

from kober.decoder import Decoder
from kober.errors import EvalError, TruncatedRead, Undecodable
from kober.node import Node, NodeStatus
from kober.ops import Plan
from kober.pygen import Names, render
from kober.runtime import Cursor, span
from kober.spec import Spec

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


def compiled(spec: Spec) -> ModuleType:
    """Compile a spec and import the module, without going through a file.

    Registered in ``sys.modules`` because ``dataclasses`` looks a class's module
    up there while working out which annotations are ``ClassVar`` — which is
    also true of a generated module a consumer imports normally, so nothing is
    being papered over.
    """
    source = render(Plan.from_spec(spec))
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
