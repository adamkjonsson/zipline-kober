"""The shared dialect, tested rather than claimed.

[packeteer](https://github.com/adamkjonsson/packeteer) describes the same kind
of protocol with a dialect its reference calls a **superset of kober's**, and
says a kober spec loads there. `plans/PACKETEER-ALIGNMENT.md` §2 tested that and
found it false in both directions — and §5.3 records why nobody noticed: the
claim was a sentence in two references with no test behind it.

This is that test, from this side. It loads packeteer's own shipped specs and
asserts what happens to each: **loaded, or declined by name**. Silence is what
it exists to prevent — either project's dialect drifting without the other
finding out.

The specs are copies in ``tests/packeteer/``, not paths into a sibling
checkout; see the README beside them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kober.check import Severity, check
from kober.decoder import Decoder
from kober.errors import SpecError
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


# --- rpc.yaml: declined by name ------------------------------------------


def test_the_other_spec_is_still_blocked_by_the_dispatch_key():
    """The one disagreement recognising keys cannot fix.

    kober renamed the switch dispatch key from ``on`` to ``dispatch`` at
    ``0.1.0`` and deleted the boolean repair, because YAML 1.1 reads an
    unquoted ``on:`` as ``true``. packeteer still requires ``on``. That is one
    construct with two spellings rather than a key one side lacks, so it is
    packeteer's to move — see `plans/PACKETEER-ALIGNMENT.md` §5.1.

    Asserted rather than skipped, so that this **fails when packeteer moves**
    and the remaining half of the claim can be turned on.
    """
    with pytest.raises(SpecError) as caught:
        from_file(SPECS / "rpc.yaml")
    assert "the switch dispatch key is 'dispatch'" in str(caught.value)
    assert "rpc.yaml:27" in str(caught.value)


# --- the table itself ------------------------------------------------------


def test_const_is_not_among_the_foreign_keys():
    """It is packeteer's key and kober's too now, which is why it is implemented."""
    assert "const" not in FOREIGN_KEYS


@pytest.mark.parametrize("key", sorted(FOREIGN_KEYS))
def test_every_foreign_key_says_why_it_has_no_meaning_here(key: str):
    """A key declined without a reason is indistinguishable from one forgotten."""
    assert FOREIGN_KEYS[key].startswith("kober ")
