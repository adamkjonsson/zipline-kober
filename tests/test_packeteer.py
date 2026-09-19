"""The shared dialect, tested rather than claimed.

[packeteer](https://github.com/adamkjonsson/packeteer) describes the same kind
of protocol with a dialect its reference calls a **superset of kober's**, and
says a kober spec loads there. `plans/PACKETEER-ALIGNMENT.md` §2 tested that and
found it false in both directions — and §5.3 records why nobody noticed: the
claim was a sentence in two references with no test behind it.

This is that test, from this side. It loads packeteer's own shipped specs and
asserts what happens to each: **loaded, and decoded**, with every key kober has
no meaning for **declined by name**. Silence is what it exists to prevent —
either project's dialect drifting without the other finding out.

The specs are copies in ``tests/packeteer/``, not paths into a sibling
checkout; see the README beside them. Both are in the short form packeteer
adopted at its 0.13.0 — the release that took kober's shorthands and renamed
its switch key to ``dispatch`` — so loading them *is* the test that the
shorthands transfer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kober.check import Severity, check
from kober.decoder import Decoder
from kober.loader import FOREIGN_KEYS, from_file
from kober.node import NodeStatus
from kober.spec import Foreign

SPECS = Path(__file__).resolve().parent / "packeteer"

#: One well-formed ``sensor`` datagram: the header, then two samples. Built
#: here rather than captured, since what is being tested is that kober reads
#: the *spec*, not that it reads any particular traffic.
SENSOR_MESSAGE = (
    bytes([0x53, 0x45])  # magic, which the spec's own `const` checks
    + bytes([1])  # version
    + bytes([2])  # count
    + bytes([0, 3])
    + b"abc"
    + (-12).to_bytes(4, "little", signed=True)
    + bytes([1, 2])
    + b"xy"
    + (40).to_bytes(4, "little", signed=True)
)


def warnings_for(name: str) -> list[str]:
    spec = from_file(SPECS / name)
    return [f.message for f in check(spec) if f.severity is Severity.WARNING]


# --- sensor.yaml: loads --------------------------------------------------


def test_a_packeteer_spec_loads():
    """The finding that started this: it used to be refused as typos."""
    spec = from_file(SPECS / "sensor.yaml")
    assert spec.name == "sensor"
    assert set(spec.units) == {"reading", "sample"}


def test_it_has_no_errors():
    spec = from_file(SPECS / "sensor.yaml")
    assert not [f for f in check(spec) if f.severity is Severity.ERROR]


def test_every_foreign_key_is_recorded_with_where_it_was():
    spec = from_file(SPECS / "sensor.yaml")
    assert list(spec.foreign) == [
        Foreign(key="over", where="sensor"),
        Foreign(key="ports", where="sensor"),
        Foreign(key="derive", where="sensor.reading.count"),
        Foreign(key="derive", where="sensor.sample.length"),
        Foreign(key="sensitive", where="sensor.sample.value"),
    ]


def test_each_one_is_a_warning_naming_packeteer_and_why():
    found = warnings_for("sensor.yaml")
    assert len(found) == 5
    for message in found:
        assert "is a packeteer key and has no meaning here" in message
    assert any("choosing one by port" in message for message in found)
    assert any("has no redaction step" in message for message in found)


def test_a_foreign_key_is_a_warning_and_not_an_error():
    """Ignoring any of them changes no decode, which is the whole superset claim."""
    spec = from_file(SPECS / "sensor.yaml")
    assert all(f.severity is Severity.WARNING for f in check(spec))


def test_the_warnings_carry_the_line_they_are_on():
    spec = from_file(SPECS / "sensor.yaml")
    by_path = {f.where.path: f.where for f in check(spec)}
    assert by_path["sensor.sample.value"].line == 25
    assert by_path["sensor.sample.value"].source.endswith("sensor.yaml")


def test_it_decodes_a_message():
    """Loading is not the claim. Decoding the same messages is."""
    spec = from_file(SPECS / "sensor.yaml")
    tree = Decoder(spec).decode_bytes(SENSOR_MESSAGE)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(SENSOR_MESSAGE)
    values = {node.name: node.value for node in tree.walk() if node.value is not None}
    assert values["magic"] == 0x5345
    assert values["reading"] == 40


def test_its_const_still_refuses_the_wrong_traffic():
    """The sibling project's own key, doing its own job, under kober's verdict."""
    spec = from_file(SPECS / "sensor.yaml")
    tree = Decoder(spec).decode_bytes(b"\x99\x99" + SENSOR_MESSAGE[2:])
    assert tree.status is NodeStatus.UNDECODABLE


# --- rpc.yaml: the construct that was blocked -------------------------------
#
# Until packeteer 0.13.0 this spec was refused on its switch key: kober had
# renamed ``on`` to ``dispatch`` at 0.1.0 (YAML 1.1 reads an unquoted ``on:``
# as ``true``) and packeteer still required ``on``. The test here asserted the
# refusal "so that it fails when packeteer moves" — and could not, since a
# vendored copy only moves when someone re-copies it. packeteer moved on
# 2026-09-10 (packeteer#143); the copy moved on 2026-09-19. So the test now
# exercises the construct that was blocked, as ``sensor.yaml``'s does its
# ``const``: the drift detector is the README's version pin, kept by hand.

#: One ``rpc`` read request: magic, a header byte whose low nibble is the
#: opcode, a request id, then the ``read`` body the opcode selects.
RPC_READ = (
    bytes([0x52, 0x50])  # magic
    + bytes([0b0000_0010])  # is_reply=0 urgent=0 reserved=0 op=2 (read)
    + bytes([0x00, 0x07])  # request_id
    + bytes([0x00, 0x00, 0x10, 0x00])  # read.offset
    + bytes([0x00, 0x04])  # read.length
)


def test_the_other_spec_loads_now():
    spec = from_file(SPECS / "rpc.yaml")
    assert spec.name == "rpc"
    assert set(spec.units) == {"message", "header", "ping", "read", "write"}


def test_it_reports_exactly_the_foreign_keys_and_the_switch_without_a_default():
    """Four keys declined by name, and one warning that is kober's own."""
    spec = from_file(SPECS / "rpc.yaml")
    findings = check(spec)
    assert all(f.severity is Severity.WARNING for f in findings)
    assert list(spec.foreign) == [
        Foreign(key="over", where="rpc"),
        Foreign(key="ports", where="rpc"),
        Foreign(key="derive", where="rpc.write.length"),
        Foreign(key="sensitive", where="rpc.write.data"),
    ]
    own = [f for f in findings if "packeteer key" not in f.message]
    assert [(f.where.path, f.where.line) for f in own] == [("rpc.message.body", 23)]
    assert "switch has no default" in own[0].message


def test_it_decodes_a_switch_dispatched_message():
    """The construct that was blocked, exercised: `dispatch` chooses the body."""
    spec = from_file(SPECS / "rpc.yaml")
    tree = Decoder(spec).decode_bytes(RPC_READ)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(RPC_READ)
    values = {node.name: node.value for node in tree.walk() if node.value is not None}
    assert values["magic"] == 0x5250
    assert values["op"] == 2
    assert values["request_id"] == 7
    assert (values["offset"], values["length"]) == (0x1000, 4)
    body = next(node for node in tree.walk() if node.name == "body")
    assert body.unit == "read"


def test_an_opcode_with_no_arm_is_undecodable_not_an_error():
    """No default, so an unknown opcode is a region the spec declines to read."""
    spec = from_file(SPECS / "rpc.yaml")
    unknown = RPC_READ[:2] + bytes([0b0000_1111]) + RPC_READ[3:]
    tree = Decoder(spec).decode_bytes(unknown)
    assert tree.status is NodeStatus.UNDECODABLE


# --- the table itself ------------------------------------------------------


def test_const_is_not_among_the_foreign_keys():
    """It is packeteer's key and kober's too now, which is why it is implemented."""
    assert "const" not in FOREIGN_KEYS


@pytest.mark.parametrize("key", sorted(FOREIGN_KEYS))
def test_every_foreign_key_says_why_it_has_no_meaning_here(key: str):
    """A key declined without a reason is indistinguishable from one forgotten."""
    assert FOREIGN_KEYS[key].startswith("kober ")
