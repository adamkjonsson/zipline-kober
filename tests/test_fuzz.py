"""Adversarial input must not break the *interpreter's* promises.

`kober.decoder` promises that **failure never escapes a decode**: a decoder
that raises leaves its input unaccounted for, and coverage is a promise about
output (``DESIGN.md`` §2). `kober.emit` promises that a byte is never both
cited and marked undecoded. Neither promise is testable by example — they are
claims about *all* input — so this fuzzes.

The same promises are made by a decoder the compiler wrote, and
``test_compiled.py`` holds it to them with the same mutations, from
:mod:`fuzzing`. Sharing the inputs is the point: the two implementations must
agree about the awkward ones, and they cannot be compared over inputs that
differ.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fuzzing import (
    SEEDS,
    SELECT_SPEC,
    cases,
    framing_cases,
    pointer_cases,
    select_cases,
)

from kober.cursor import Cursor
from kober.decoder import Decoder
from kober.emit import plan
from kober.node import Node, NodeStatus
from kober.spec import Emit, Field, Select, Spec

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


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


# --- pointers --------------------------------------------------------------
#
# A pointer is the one construct that reads somewhere other than where the
# cursor stands, so it is the one that can break coverage in a new way. These
# run the same promises over mutated *real* traffic, against the shipped DNS
# spec — which follows pointers, so the query in `SEEDS` reaches none of this
# and a real response is the seed that does.


def pointer_spec() -> Spec:
    return Spec.from_file(EXAMPLES / "dns.yaml")


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_following_pointers_never_raises(seed: int):
    """Including cycles, forward references, and offsets past the end."""
    decoder = Decoder(pointer_spec())
    for data in pointer_cases(seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode: pointers seed={seed} on {data!r}")
            raise
        check_tree(tree, data)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_a_pointer_never_makes_a_byte_both_cited_and_undecoded(seed: int, emit: Emit):
    """The half of the coverage guarantee a pointer could plausibly break.

    Overlap is legal — a pointed-at region is cited twice — but *contradiction*
    is not, and a construct that cites bytes nothing walked over is exactly
    where the two could be confused.
    """
    spec = pointer_spec()
    decoder = Decoder(spec)
    for data in pointer_cases(seed):
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
            f"pointers {emit.value}: {len(overlap)} byte(s) both cited and "
            f"undecoded on {data!r}"
        )


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_pointer_never_cites_outside_the_input(seed: int):
    """A resolved offset is still an offset into bytes we were given."""
    spec = pointer_spec()
    decoder = Decoder(spec)
    for data in pointer_cases(seed):
        tree = decoder.decode_bytes(data)
        emissions, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
        for record in emissions:
            assert 0 <= record.off_start <= record.off_end <= len(data), (
                f"record [{record.off_start}, {record.off_end}) outside {len(data)} "
                f"bytes on {data!r}"
            )
        for region in unclaimed:
            assert 0 <= region.off_start <= region.off_end <= len(data)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_pointer_never_reaches_outside_its_own_message(seed: int):
    """Two messages in one run must not read each other's bytes.

    The rule Q1 settled, and the one conformance cannot see: a pointer with the
    wrong origin still cites *some* region in range, so coverage stays clean
    while the decode is wrong. Only the offsets say so.
    """
    spec = pointer_spec()
    decoder = Decoder(spec)
    for data in pointer_cases(seed):
        cursor = Cursor(data + data, 0)
        first = decoder.decode_one(cursor)
        if first.status is not NodeStatus.OK or cursor.at_end():
            continue
        start = cursor.byte_offset()
        second = decoder.decode_one(cursor)
        for node in second.walk():
            assert node.off_start >= start, (
                f"a node at [{node.off_start}, {node.off_end}) reached back "
                f"before its message at {start} on {data!r}"
            )


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_whole_message_decodes_the_same_whatever_follows_it(seed: int):
    """The ceiling is the message's high-water mark, not the run's end.

    Only for a message that decoded **completely**: one that ran out of input
    is entitled to decode further when given more, and that is not what this
    is about. What a pointer must not do is resolve differently because of
    bytes belonging to whatever comes next in the run — which it did, before
    the ceiling replaced a run-wide bound.
    """
    decoder = Decoder(pointer_spec())
    compared = 0
    for data in pointer_cases(seed):
        alone = decoder.decode_one(Cursor(data, 0))
        if alone.status is NodeStatus.TRUNCATED:
            # It stopped because the input did — `truncated` is exactly that
            # claim. Being given more is entitled to take it further, and that
            # is not what this is about. Note the extent is *not* the test: a
            # read that runs out leaves the position before the last byte.
            continue
        compared += 1
        followed = decoder.decode_one(Cursor(data + b"\xff" * 32, 0))
        assert alone.render() == followed.render(), (
            f"trailing bytes changed a decode that had already ended on {data!r}"
        )
    assert compared, "no case ended before its input did, so nothing was compared"


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_no_node_reaches_past_the_message_it_belongs_to(seed: int):
    """A message is self-contained, pointers included.

    The containment a run-wide ceiling would break: a pointer could resolve
    into bytes belonging to whatever follows, and the message would cite them
    while claiming to end before them.
    """
    decoder = Decoder(pointer_spec())
    for data in pointer_cases(seed):
        tree = decoder.decode_one(Cursor(data, 0))
        for node in tree.walk():
            assert node.off_end <= tree.off_end, (
                f"{node.name} cites [{node.off_start}, {node.off_end}) past the "
                f"message's own end at {tree.off_end} on {data!r}"
            )


# --- select ----------------------------------------------------------------
#
# A select asks about a repetition rather than reading input, so the promise it
# could plausibly break is not "did it read too much" but "did it read at all".
# That one is invisible to every coverage-shaped invariant: a select that
# consumed a byte would leave coverage whole, the byte simply being covered by
# whatever followed. So it is asserted directly, and checked against an
# implementation that does consume.


def select_spec() -> Spec:
    return Spec.from_yaml(SELECT_SPEC)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_selecting_never_raises(seed: int):
    """Including an unevaluable predicate, which must become a status not an escape."""
    decoder = Decoder(select_spec())
    for data in select_cases(seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode: select seed={seed} on {data!r}")
            raise
        check_tree(tree, data)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_a_select_never_makes_a_byte_both_cited_and_undecoded(seed: int, emit: Emit):
    """It cites an element it did not itself read, which is where the two could confuse."""
    spec = select_spec()
    decoder = Decoder(spec)
    for data in select_cases(seed):
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
            f"select {emit.value}: {len(overlap)} byte(s) both cited and "
            f"undecoded on {data!r}"
        )


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_select_never_moves_the_read_position(seed: int):
    """§2.1's claim, asserted at the seam where it is made.

    Not derivable from any invariant above: see this section's note. Held to it
    over adversarial input as well as the examples, because the interesting
    case is the one where the predicate fails part-way and the walk unwinds.
    """
    decoder = Decoder(select_spec())
    moved: list[tuple[str | None, int, int]] = []
    original = Decoder._select

    def watched(
        self: Decoder, item: Field, kind: Select, frame: Any,
        cursor: Cursor, mark: int,
    ) -> Node:
        before = cursor.tell()
        node = original(self, item, kind, frame, cursor, mark)
        if cursor.tell() != before:
            moved.append((item.name, before, cursor.tell()))
        return node

    Decoder._select = watched
    try:
        for data in select_cases(seed):
            decoder.decode_bytes(data)
    finally:
        Decoder._select = original
    assert not moved, f"select moved the position: {moved[:4]}"


def test_the_position_check_catches_a_select_that_consumes():
    """The assertion above must fail against a consuming select, or it proves nothing."""
    decoder = Decoder(select_spec())
    original = Decoder._select
    moved: list[tuple[int, int]] = []

    def greedy(
        self: Decoder, item: Field, kind: Select, frame: Any,
        cursor: Cursor, mark: int,
    ) -> Node:
        node = original(self, item, kind, frame, cursor, mark)
        before = cursor.tell()
        if cursor.remaining_bytes() > 0:
            cursor.read_bytes(1)
        if cursor.tell() != before:
            moved.append((before, cursor.tell()))
        return node

    Decoder._select = greedy
    try:
        for data in select_cases(1):
            decoder.decode_bytes(data)
    finally:
        Decoder._select = original
    assert moved, "the consuming implementation was never reached"


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_select_uses_the_documented_vocabulary(seed: int):
    """An unevaluable predicate is `undecodable`, never a reason `zpf` does not know."""
    spec = select_spec()
    decoder = Decoder(spec)
    allowed = {member.value for member in NodeStatus if member is not NodeStatus.OK}
    for data in select_cases(seed):
        tree = decoder.decode_bytes(data)
        _, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
        for region in unclaimed:
            assert region.reason in allowed, f"{region.reason!r} on {data!r}"


# --- http's framing arms ---------------------------------------------------
#
# `SEEDS["http.yaml"]` has no framing header, so every variant of it takes the
# third path and neither arm that does the work is entered. That is the gap
# that let a wrong `chunked` comparison live through five stages — the corpus
# with 2000 real messages has no chunked message in it either — so the arms get
# seeds of their own, exactly as pointers did.


def http_spec() -> Spec:
    return Spec.from_file(EXAMPLES / "http.yaml")


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_framing_a_body_never_raises(seed: int):
    """Including a `Content-Length` mutated into something `to_int` refuses."""
    decoder = Decoder(http_spec())
    for data in framing_cases(seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode: framing seed={seed} on {data!r}")
            raise
        check_tree(tree, data)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_framing_never_makes_a_byte_both_cited_and_undecoded(seed: int, emit: Emit):
    spec = http_spec()
    decoder = Decoder(spec)
    for data in framing_cases(seed):
        tree = decoder.decode_bytes(data)
        emissions, unclaimed = plan(spec, tree, data, emit=emit)
        cited: set[int] = set()
        for record in emissions:
            cited.update(range(record.off_start, record.off_end))
        named: set[int] = set()
        for region in unclaimed:
            named.update(range(region.off_start, region.off_end))
        overlap = cited & named
        assert not overlap, f"framing {emit.value}: {len(overlap)} byte(s) on {data!r}"


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_framed_body_never_reaches_past_what_it_was_given(seed: int):
    """A length off the wire is the obvious way to claim bytes that are not there."""
    decoder = Decoder(http_spec())
    for data in framing_cases(seed):
        tree = decoder.decode_bytes(data)
        body = tree.find("body")
        if body is not None:
            assert body.off_end <= len(data), f"{body.off_end} past {len(data)}"


def test_the_framing_seeds_reach_every_arm():
    """Or the sweep above proves nothing, which is how this got missed before.

    Asserted rather than assumed: the point of these seeds is the arms they
    enter, and a mutation set that stopped entering them would go unnoticed
    exactly as `SEEDS["http.yaml"]` did.
    """
    decoder = Decoder(http_spec())
    arms = {"chunks": 0, "body": 0, "neither": 0}
    for data in framing_cases(1):
        tree = decoder.decode_bytes(data)
        if tree.status is not NodeStatus.OK:
            continue
        if tree.find("chunks") is not None:
            arms["chunks"] += 1
        elif tree.find("body") is not None:
            arms["body"] += 1
        else:
            arms["neither"] += 1
    assert all(count > 0 for count in arms.values()), arms
