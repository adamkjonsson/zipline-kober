"""Adversarial input must not break the decoder's promises.

`kober.decoder` promises that **failure never escapes a decode**: a decoder
that raises leaves its input unaccounted for, and coverage is a promise about
output (``DESIGN.md`` §2). `kober.emit` promises that a byte is never both
cited and marked undecoded. Neither promise is testable by example — they are
claims about *all* input — so this fuzzes.

**Why this exists.** The technique came from `packeteer`, whose ``fuzz`` verb
generates adversarial variants for exactly this. Run end to end
(``packeteer fuzz`` → ``zpfwire convert`` → ``kober run``) it found a real
conformance bug the whole hand-built suite had missed: a seam rule that fired
on `Gap` only, where `zpf` needs one after any *hole*-class region. See
``plans/REAL-CAPTURE-PHASE-PLAN.md`` §13.5 and the README for that pipeline,
which is deeper than this file and needs both sibling checkouts.

What is here is the part that should run every time, so it depends on nothing
outside the standard library. By the time bytes reach the decoder the transport
layers are gone and what is left is payload, so the mutations that actually
reach it are the payload-level ones — truncate, extend, flip, replace — and
those are cheap to generate directly.

Seeded, so a failure is reproducible from the case it prints rather than being
a story about a run that happened once.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

import pytest

from kober.decoder import Decoder
from kober.emit import plan
from kober.node import Node, NodeStatus
from kober.spec import Emit, Spec

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

#: How many mutations per seed case. Small enough to keep the suite fast,
#: large enough that each run covers every mutation kind several times.
ROUNDS = 60

DNS_QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

HTTP_REQUEST = b"GET / HTTP/1.1\r\nHost: httpforever.com\r\nAccept: */*\r\n\r\n"

SEEDS: dict[str, bytes] = {"dns.yaml": DNS_QUERY, "http.yaml": HTTP_REQUEST}


def mutate(data: bytes, rng: random.Random) -> bytes:
    """Return one adversarial variant of ``data``.

    The kinds `packeteer` calls truncate, extend, bit-flip, and boundary,
    plus wholesale replacement — the payload-level subset, since that is what
    survives the transport layers to reach a decoder.
    """
    kind = rng.randrange(6)
    if not data:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(8)))
    if kind == 0:  # truncate
        return data[: rng.randrange(len(data))]
    if kind == 1:  # extend
        tail = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 32)))
        return data + tail
    if kind == 2:  # bit flip
        index = rng.randrange(len(data))
        out = bytearray(data)
        out[index] ^= 1 << rng.randrange(8)
        return bytes(out)
    if kind == 3:  # boundary value in one byte
        index = rng.randrange(len(data))
        out = bytearray(data)
        out[index] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF))
        return bytes(out)
    if kind == 4:  # a run of bytes replaced
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        out = bytearray(data)
        for index in range(start, end):
            out[index] = rng.randrange(256)
        return bytes(out)
    return bytes(rng.randrange(256) for _ in range(rng.randrange(64)))


def cases(name: str, seed: int) -> list[bytes]:
    """Build one reproducible batch of variants for a spec's seed input."""
    rng = random.Random(seed)
    base = SEEDS[name]
    return [mutate(base, rng) for _ in range(ROUNDS)]


def check_tree(tree: Node, data: bytes) -> None:
    """Assert the structural invariants a tree must hold whatever the input."""
    for node in tree.walk():
        assert node.off_start <= node.off_end, f"{node.name}: inverted range"
        assert node.off_start >= 0, f"{node.name}: negative start"
        assert node.off_end <= len(data), (
            f"{node.name}: claims [{node.off_start}, {node.off_end}) "
            f"past the input's {len(data)} bytes"
        )
        assert isinstance(node.status, NodeStatus)


@pytest.mark.parametrize("name", sorted(SEEDS))
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_decoding_never_raises(name: str, seed: int):
    """The promise `kober.decoder` makes: failure becomes a status, not an exception."""
    decoder = Decoder(Spec.from_file(EXAMPLES / name))
    for data in cases(name, seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            # Re-raised rather than swallowed: the traceback is the finding,
            # and the note carries the bytes that reproduce it.
            exc.add_note(f"escaped a decode: {name} seed={seed} on {data!r}")
            raise
        check_tree(tree, data)


@pytest.mark.parametrize("name", sorted(SEEDS))
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_a_decode_never_claims_more_than_it_was_given(name: str, seed: int):
    """Where a decode stops is inside the input, always."""
    decoder = Decoder(Spec.from_file(EXAMPLES / name))
    for data in cases(name, seed):
        tree = decoder.decode_bytes(data)
        assert tree.off_end <= len(data), f"{name}: {tree.off_end} > {len(data)} on {data!r}"


@pytest.mark.parametrize("name", sorted(SEEDS))
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_planning_never_raises(name: str, emit: Emit):
    """The emitter runs on whatever the engine produced, including failures."""
    spec = Spec.from_file(EXAMPLES / name)
    decoder = Decoder(spec)
    for data in cases(name, 4):
        tree = decoder.decode_bytes(data)
        try:
            plan(spec, tree, data, emit=emit)
        except Exception as exc:
            exc.add_note(f"escaped the emitter: {name} {emit.value} on {data!r}")
            raise


@pytest.mark.parametrize("name", sorted(SEEDS))
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_no_byte_is_both_cited_and_undecoded(name: str, emit: Emit):
    """The one rule the coverage checker enforces, over adversarial input.

    This is the property a real bug violated: marking a failed unit's whole
    range reclaimed bytes its successful fields had already cited. It passed
    every example-based test.
    """
    spec = Spec.from_file(EXAMPLES / name)
    decoder = Decoder(spec)
    for data in cases(name, 5):
        tree = decoder.decode_bytes(data)
        emissions, unclaimed = plan(spec, tree, data, emit=emit)
        cited: set[int] = set()
        for record in emissions:
            cited.update(range(record.off_start, record.off_end))
        named: set[int] = set()
        for region in unclaimed:
            named.update(range(region.off_start, region.off_end))
        overlap = cited & named
        assert not overlap, (
            f"{name} {emit.value}: {len(overlap)} byte(s) both cited and "
            f"undecoded on {data!r}"
        )


@pytest.mark.parametrize("name", sorted(SEEDS))
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_nothing_is_claimed_outside_the_input(name: str, emit: Emit):
    """A record citing bytes that do not exist would fail check_coverage."""
    spec = Spec.from_file(EXAMPLES / name)
    decoder = Decoder(spec)
    for data in cases(name, 6):
        tree = decoder.decode_bytes(data)
        emissions, unclaimed = plan(spec, tree, data, emit=emit)
        for record in emissions:
            assert record.off_end <= len(data), f"{name}: record past the input on {data!r}"
        for region in unclaimed:
            assert region.off_end <= len(data), f"{name}: region past the input on {data!r}"


@pytest.mark.parametrize("name", sorted(SEEDS))
def test_undecoded_regions_use_the_documented_vocabulary(name: str):
    """Every reason must be one `zpf` classifies, or a seam decision is unmakeable."""
    spec = Spec.from_file(EXAMPLES / name)
    decoder = Decoder(spec)
    allowed = {member.value for member in NodeStatus}
    for data in cases(name, 7):
        tree = decoder.decode_bytes(data)
        _, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
        for region in unclaimed:
            assert region.reason in allowed, f"{name}: unknown reason {region.reason!r}"


def test_empty_and_tiny_inputs():
    """The edges the mutators reach rarely, made certain."""
    for name in sorted(SEEDS):
        decoder = Decoder(Spec.from_file(EXAMPLES / name))
        for data in (b"", b"\x00", b"\xff", b"\x00" * 3):
            tree = decoder.decode_bytes(data)
            check_tree(tree, data)
            assert tree.off_end <= len(data)
