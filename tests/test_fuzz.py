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

import itertools
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fuzzing import (
    CONST_SPEC,
    FILL_SPEC,
    FILL_TRAILING,
    SEEDS,
    SELECT_SPEC,
    STARVED_SPECS,
    cases,
    const_cases,
    fill_cases,
    framing_cases,
    mutate,
    pointer_cases,
    select_cases,
    starved_cases,
    variants,
)
from zpf.reassembly import Gap

from kober import stage
from kober.cursor import Cursor
from kober.decoder import Decoder
from kober.emit import plan
from kober.node import Node, NodeStatus
from kober.pygen import render_spec
from kober.runtime import Held
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


# --- fill --------------------------------------------------------------------
#
# A `fill` is the one size whose extent is decided by fields it has not read —
# the ones *after* it — so the promise it could break is a boundary, and a
# boundary is exactly what a well-formed decode cannot demonstrate. Two things
# have to hold over adversarial input: the fill must never read into the
# trailer, and the trailer must always be cited.


def fill_spec() -> Spec:
    return Spec.from_yaml(FILL_SPEC)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_filling_never_raises(seed: int):
    """Including inputs shorter than the trailer, which must be a status."""
    decoder = Decoder(fill_spec())
    for data in fill_cases(seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode: fill seed={seed} on {data!r}")
            raise
        check_tree(tree, data)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_fill_never_reads_into_the_trailer(seed: int):
    """The construct's whole claim, stated as the arithmetic it rests on.

    A fill that took one byte too many would still leave coverage whole — the
    byte would simply be cited by the fill instead of by the trailer — so no
    coverage-shaped invariant can see this. It is asserted against the extent
    directly: whatever the input, the fill ends at least ``FILL_TRAILING``
    bytes before the end of what the message decoded.
    """
    spec = fill_spec()
    decoder = Decoder(spec)
    for data in fill_cases(seed):
        tree = decoder.decode_bytes(data)
        for node in tree.walk():
            if node.name != "data" or not node.width:
                continue
            assert node.off_end <= len(data) - FILL_TRAILING, (
                f"a fill ending at {node.off_end} left less than {FILL_TRAILING} "
                f"byte(s) for the trailer of {len(data)} on {data!r}"
            )


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_fill_never_makes_a_byte_both_cited_and_undecoded(seed: int):
    """The general invariant, over the one size that computes its own end."""
    spec = fill_spec()
    decoder = Decoder(spec)
    for data in fill_cases(seed):
        tree = decoder.decode_bytes(data)
        emissions, unclaimed = plan(spec, tree, data, emit=Emit.FIELD)
        cited: set[int] = set()
        for record in emissions:
            cited.update(range(record.off_start, record.off_end))
        named: set[int] = set()
        for region in unclaimed:
            named.update(range(region.off_start, region.off_end))
        overlap = cited & named
        assert not overlap, (
            f"fill: {len(overlap)} byte(s) both cited and undecoded on {data!r}"
        )


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_whole_fill_decode_cites_the_trailer(seed: int):
    """Where the message decoded, the fields after the fill must have read.

    The failure this rules out is the quiet one: a fill that swallowed the
    trailer would leave the trailing fields with nothing, and a decode that
    still reported ``ok`` would have named the trailer's bytes as body.
    """
    decoder = Decoder(fill_spec())
    whole = 0
    for data in fill_cases(seed):
        tree = decoder.decode_bytes(data)
        if tree.status is not NodeStatus.OK:
            continue
        whole += 1
        names = {node.name for node in tree.walk() if node.width}
        assert {"footer", "checksum"} <= names, f"trailer not read on {data!r}"
    assert whole, "no variant decoded whole, so the assertion never ran"


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


# --- constants -------------------------------------------------------------
#
# `const` is the one construct in 0.2.0 that reaches a decode, and what it does
# on disagreement is a *verdict*, not an exception — which is exactly the
# promise adversarial input is needed to hold it to. A mutation anywhere in the
# seed lands on a constant sooner or later, and every one of those must come
# back as `undecodable` rather than as anything escaping the decode.


def const_spec() -> Spec:
    return Spec.from_yaml(CONST_SPEC)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_disagreeing_constant_never_raises(seed: int):
    decoder = Decoder(const_spec())
    for data in const_cases(seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode: const seed={seed} on {data!r}")
            raise
        check_tree(tree, data)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_disagreeing_constant_is_undecodable_and_not_some_other_reason(seed: int):
    """`undecodable` is *tried and could not*, which is what a wrong magic is."""
    decoder = Decoder(const_spec())
    seen = False
    for data in const_cases(seed):
        tree = decoder.decode_bytes(data)
        for node in tree.walk():
            if node.detail is not None and node.detail.startswith("expected "):
                assert node.status is NodeStatus.UNDECODABLE, (
                    f"a disagreeing constant said {node.status.value} on {data!r}"
                )
                seen = True
    assert seen, "no mutation disagreed with a constant; the corpus proves nothing"


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_a_constant_never_makes_a_byte_both_cited_and_undecoded(seed: int, emit: Emit):
    """A refused field's bytes are real and were read; they must be accounted for once."""
    spec = const_spec()
    decoder = Decoder(spec)
    for data in const_cases(seed):
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
            f"const {emit.value}: {len(overlap)} byte(s) both cited and marked "
            f"undecoded on {data!r}"
        )


# --- a spec the terminal rule refuses, run anyway (#43) ----------------------


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
@pytest.mark.parametrize("name", sorted(STARVED_SPECS))
def test_a_message_read_to_its_end_is_never_called_truncated(name: str, seed: int):
    """Once a field has read to the end of the message, the input was not short.

    Whatever runs out after it ran out because the spec gave its bytes away, so
    ``truncated`` — a claim that bytes never arrived — would be false for every
    such input. The invariant is asserted over the mutated batch rather than one
    example because the guard that decides it (the starved field started with
    nothing left) is a claim about every input, and the batch is checked to have
    reached the case at all, so the test cannot pass by never getting there.
    """
    source, _, terminal = STARVED_SPECS[name]
    decoder = Decoder(Spec.from_yaml(source), check=False)
    reached = 0
    for data in starved_cases(seed):
        tree = decoder.decode_bytes(data)
        if not any(node.name == terminal and node.status is NodeStatus.OK for node in tree.walk()):
            continue
        reached += 1
        assert tree.status is not NodeStatus.TRUNCATED, (
            f"{name}: {terminal!r} read to the end and the message still said "
            f"truncated on {data!r}: {tree.detail}"
        )
    assert reached, f"{name}: no variant decoded {terminal!r} whole"


#: A repetition whose count and ``until`` both divide by a value off the wire.
FAILING_REPEAT = """
name: failing_repeat
version: "1"
entry: m
units:
  m:
    fields:
      - {name: n, type: {int: {bits: 8}}}
      - {name: counted, type: {int: {bits: 8}}, repeat: {count: "12 / n"}}
      - {name: ended, type: {int: {bits: 8}}, repeat: {until: "12 % n == ended"}}
"""


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_repetitions_own_expressions_never_raise(seed: int):
    """A count or an ``until`` that cannot be computed is a verdict, like any other.

    The two expression sites the corpus never reached, until one of them was
    found raising out of a decode.
    """
    decoder = Decoder(Spec.from_yaml(FAILING_REPEAT))
    for data in variants(bytes([0, 1, 2, 3, 4, 5]), seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode: seed={seed} on {data!r}")
            raise
        check_tree(tree, data)


# --- the stage driver: stream confirmation (#32) ---------------------------
#
# The first fuzzing of the driver in the suite. It needs streams — runs, gaps,
# datagrams — rather than one buffer, so they are built as the small objects
# the driver reads, and the driver writes to a stage that only records what it
# was told. The reference is 0.3.0's driver loop, kept here: what a stream that
# confirms writes must not have changed at all.

TOY = """
name: toy
version: "1"
entry: m
input: either
units:
  m:
    fields:
      - {name: version, type: {int: {bits: 8}}}
      - {name: magic, type: {int: {bits: 8}}, const: 0x42}
      - {name: body, type: {int: {bits: 8}}}
"""
TOY_MESSAGES = (bytes([1, 0x42, 7]), bytes([1, 0, 7]), bytes([1, 0x42]))


@dataclass
class _Chunk:
    data: bytes
    off_start: int
    ts: int


@dataclass
class _Datagram:
    data: bytes
    off_start: int
    off_end: int
    ts: int


@dataclass
class _Stream:
    is_stream_oriented: bool
    items: list[object]

    def chunks(self) -> list[object]:
        return self.items

    def datagrams(self) -> list[object]:
        return self.items


class _Recording:
    """A stage that keeps what the driver wrote, in order."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def record(self, stream: object, payload: bytes, **kwargs: Any) -> None:
        self.calls.append(("record", payload, tuple(sorted(kwargs.items(), key=str))))

    def undecoded(
        self, stream: object, off_start: int, off_end: int, *, reason: str, comment: Any = None
    ) -> None:
        self.calls.append(("undecoded", off_start, off_end, reason, comment))


def _toy_stream(rng: random.Random) -> _Stream:
    """Build one random stream: runs or datagrams of good, foreign and short messages."""
    oriented = rng.random() < 0.5
    items: list[object] = []
    offset = 0
    for index in range(rng.randint(1, 6)):
        if oriented and items and rng.random() < 0.3:
            width = rng.randint(1, 4)
            items.append(Gap(offset, offset + width))
            offset += width
            continue
        parts = [rng.choice(TOY_MESSAGES) for _ in range(rng.randint(1, 3) if oriented else 1)]
        data = b"".join(parts)
        if rng.random() < 0.2:
            data = mutate(data, rng) or b"\x00"
        if oriented:
            items.append(_Chunk(data, offset, 1000 + index))
        else:
            items.append(_Datagram(data, offset, offset + len(data), 1000 + index))
        offset += len(data)
    return _Stream(oriented, items)


def _reference(step: Any, writer: Any, stream: _Stream, verdicts: list[str]) -> None:
    """0.3.0's driver loop: try every run and every datagram, whatever came before.

    With #49's rule for a run after a gap, whose start nothing said: its first
    message is written only if it decodes whole, and if it does not, the run
    is one ``undecodable`` region with no record from the attempt. That attempt
    is recorded as ``lost``, which neither confirms nor declines. The toy spec
    has no field whose cut-off read knows where the message ends, so #49's
    other rule, resuming at a known end, never applies here.
    """
    ok, undecodable, skipped = "ok", NodeStatus.UNDECODABLE.value, NodeStatus.SKIPPED.value

    def run_of(data: bytes, base: int, *, after_gap: bool) -> None:
        cursor = Cursor(data, base)
        end = base + len(data)
        while not cursor.at_end():
            before = cursor.tell()
            held = Held(writer) if after_gap else None
            verdict = step(cursor, held or writer, data, base)
            if verdict is None and cursor.tell() == before:
                verdict = stage._Verdict(undecodable, "a message consumed no input")
            if held is not None:
                after_gap = False
                if verdict is not None:
                    verdicts.append("lost")
                    writer.note(base, end, undecodable, stage.LOST_COMMENT)
                    return
                held.release()
            verdicts.append(ok if verdict is None else verdict.reason)
            if verdict is not None:
                writer.undecoded(stage._stopped_at(cursor, base), end, verdict.reason)
                return

    after_gap = False
    for item in stream.items:
        if isinstance(item, Gap):
            writer.undecoded(item.off_start, item.off_end, stage.GAP_REASON)
            after_gap = True
        elif stream.is_stream_oriented:
            writer.ts = item.ts
            run_of(item.data, item.off_start, after_gap=after_gap)
            after_gap = False
        else:
            writer.ts = item.ts
            cursor = Cursor(item.data, item.off_start)
            verdict = step(cursor, writer, item.data, item.off_start)
            verdicts.append(ok if verdict is None else verdict.reason)
            reason = skipped if verdict is None else verdict.reason
            writer.undecoded(stage._stopped_at(cursor, item.off_start), item.off_end, reason)
    writer.flush()


def _declines(verdicts: list[str]) -> bool:
    """Whether a stream with these verdicts, in order, is one #32 declines.

    A ``lost`` attempt, the first after a gap (#49), neither confirms nor
    declines, but it was an attempt: a stream of nothing else is declined at
    its end.
    """
    for verdict in verdicts:
        if verdict == "lost":
            continue
        if verdict == "ok":
            return False
        if verdict == NodeStatus.UNDECODABLE.value:
            return True
    return bool(verdicts)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_stream_is_declined_exactly_when_it_should_be_and_otherwise_unchanged(seed: int):
    """The promises #32 makes, over every shape of stream the driver meets.

    A stream that confirms — a whole message before any ``undecodable`` —
    writes exactly what 0.3.0 wrote. A stream that does not is declined: no
    record, every byte ``undecodable``, ``skipped`` or ``gap``, ``skipped``
    only after the attempt, and every non-gap region saying why. Both drivers
    write the same thing.
    """
    spec = Spec.from_yaml(TOY)
    module = ModuleType(f"toy_fuzz_{seed}")
    sys.modules[module.__name__] = module
    exec(render_spec(spec), module.__dict__)
    steps = (stage._interpreted(Decoder(spec)), stage._compiled(module))
    rng = random.Random(seed)
    declined = confirmed = 0
    for _ in range(300):
        stream = _toy_stream(rng)
        outputs = []
        for step in steps:
            sink = _Recording()
            stage._drive(step, stage._Writer(sink, stream, "toy"), stream)
            outputs.append(sink.calls)
        assert outputs[0] == outputs[1], f"the drivers disagree on {stream!r}"
        written = outputs[0]

        reference, verdicts = _Recording(), []
        writer = stage._Writer(reference, stream, "toy")
        writer.confirm()
        _reference(steps[0], writer, stream, verdicts)

        if not _declines(verdicts):
            confirmed += 1
            assert written == reference.calls, f"a confirmed stream changed: {stream!r}"
            continue
        declined += 1
        assert [c for c in written if c[0] == "record"] == [], f"a record from {stream!r}"
        regions = [c for c in written if c[0] == "undecoded"]
        assert {r[3] for r in regions} <= {"undecodable", "skipped", "gap"}, stream
        assert all(r[4] and r[4].startswith("not toy: ") for r in regions if r[3] != "gap")
        tried = [r[1] for r in regions if r[3] == "undecodable"]
        assert all(r[1] > min(tried) for r in regions if r[3] == "skipped"), stream
        extent = sum(
            len(item.data) if isinstance(item, _Chunk) else item.off_end - item.off_start
            for item in stream.items
        )
        assert sum(r[2] - r[1] for r in regions) == extent, f"bytes unnamed in {stream!r}"
    assert declined and confirmed, "the batch did not reach both outcomes"



# --- after a gap: resume where a cut message ends (#49) ----------------------

FRAMED = """
name: framed
version: "1"
entry: message
units:
  message:
    fields:
      - {name: magic, type: {int: {bits: 8}}, const: 0x42}
      - {name: length, type: {int: {bits: 8}}}
      - {name: body, type: {bytes: {size: {expr: "length"}}}}
"""
#: Body bytes never equal the magic, so an attempt from inside a body cannot
#: pass for a message start: every phantom this could write is a bug.
_BODY_BYTES = bytes(b for b in range(256) if b != 0x42)


def _framed_stream(
    rng: random.Random, alphabet: bytes = _BODY_BYTES
) -> tuple[_Stream, list[tuple[int, int]]]:
    """Build framed messages with gaps cut at random, and where each message is.

    ``alphabet`` is what bodies are made of. Small values make an attempt from
    inside a body read a small length, and so decode whole.
    """
    data = bytearray()
    messages: list[tuple[int, int]] = []
    for _ in range(rng.randint(2, 8)):
        body = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
        messages.append((len(data), len(data) + 2 + len(body)))
        data += bytes([0x42, len(body)]) + body
    cuts = sorted(rng.sample(range(1, len(data)), min(len(data) - 1, 2 * rng.randint(1, 3))))
    items: list[object] = []
    at = 0
    for index in range(0, len(cuts) - 1, 2):
        start, end = cuts[index], cuts[index + 1]
        items.append(_Chunk(bytes(data[at:start]), at, 1000 + index))
        items.append(Gap(start, end))
        at = end
    items.append(_Chunk(bytes(data[at:]), at, 9999))
    return _Stream(is_stream_oriented=True, items=items), messages


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_run_after_a_gap_resumes_where_a_cut_message_ends(seed: int):
    """#49's promise with a known end, over gaps cut anywhere in a stream.

    Both drivers write the same thing; no message start is ever cited anywhere
    but at a real message start; and where a gap cut a body whose length was
    already read and ended before that message did, every message that arrived
    whole in the next run is decoded, with the bytes before the first of them
    ``skipped`` as the rest of the cut message.
    """
    spec = Spec.from_yaml(FRAMED)
    module = ModuleType(f"framed_fuzz_{seed}")
    sys.modules[module.__name__] = module
    exec(render_spec(spec, emit=Emit.FIELD), module.__dict__)
    steps = (stage._interpreted(Decoder(spec, emit=Emit.FIELD)), stage._compiled(module))
    rng = random.Random(seed)
    resumed = 0
    for _ in range(200):
        stream, messages = _framed_stream(rng)
        outputs = []
        for step in steps:
            sink = _Recording()
            stage._drive(step, stage._Writer(sink, stream, "framed"), stream)
            outputs.append(sink.calls)
        assert outputs[0] == outputs[1], f"the drivers disagree on {stream!r}"
        written = outputs[0]
        cites = [dict(call[2]) for call in written if call[0] == "record"]
        magics = {c["cites"][0] for c in cites if c["role"] == "framed.magic"}
        heads = {start for start, _ in messages}
        assert magics <= heads, f"a message start cited inside a message: {stream!r}"

        # Follow what the driver can know: the first run starts at a message;
        # a later one does when the run before it did and ended inside a body
        # whose length it had read, and the gap ended before that message did.
        # A run lying wholly inside that body passes the knowledge on.
        declined = any(
            call[0] == "undecoded" and str(call[4]).startswith("not framed")
            for call in written
        )
        runs = [item for item in stream.items if isinstance(item, _Chunk)]
        known, open_end = True, None
        for before, after in itertools.pairwise(runs):
            cut_at = before.off_start + len(before.data)
            if open_end is None or open_end <= before.off_start:
                cut = (
                    next(
                        (
                            m
                            for m in messages
                            if before.off_start <= m[0] and m[0] + 2 <= cut_at < m[1]
                        ),
                        None,
                    )
                    if known
                    else None
                )
                open_end = None if cut is None else cut[1]
            known = open_end is not None and after.off_start <= open_end
            if not known:
                open_end = None
                continue
            resumed += 1
            end = after.off_start + len(after.data)
            whole = [m for m in messages if open_end <= m[0] and m[1] <= end]
            assert {m[0] for m in whole} <= magics, f"a whole message lost: {stream!r}"
            if not declined and after.off_start < open_end:
                stop = min(open_end, end)
                expected = ("undecoded", after.off_start, stop, "skipped", stage.CUT_COMMENT)
                assert expected in written, f"the rest of a cut message unnamed: {stream!r}"
            if open_end <= end:
                open_end = None
    assert resumed, "the batch never cut a body with its length known"


FRAMED_GUARDED = """
name: guarded
version: "1"
entry: message
units:
  message:
    confirm: "magic == 0x42"
    fields:
      - {name: magic, type: {int: {bits: 8}}}
      - {name: length, type: {int: {bits: 8}}}
      - {name: body, type: {bytes: {size: {expr: "length"}}}}
"""


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_refused_attempt_after_a_gap_is_retried_where_it_stopped(seed: int, emit: Emit):
    """#49 amended with #50: after a gap, a refused attempt is skipped, not the run.

    The magic is checked by a `confirm` here rather than a `const`, so an
    attempt from inside a body decodes whole and is then refused. The driver
    tries again where it stopped. Both drivers write the same thing, no record
    ever starts a message anywhere but at a real message start, and the batch
    must actually have retried and landed on a real message.

    Bodies are small values, so an attempt from inside one reads a small
    length and decodes whole to be refused; random bytes would mostly run out
    of input instead, which loses the rest of the run and never retries.
    """
    spec = Spec.from_yaml(FRAMED_GUARDED)
    module = ModuleType(f"guarded_fuzz_{seed}_{emit.value}")
    sys.modules[module.__name__] = module
    exec(render_spec(spec, emit=emit), module.__dict__)
    steps = (stage._interpreted(Decoder(spec, emit=emit)), stage._compiled(module))
    rng = random.Random(seed)
    retried = 0
    for _ in range(200):
        stream, messages = _framed_stream(rng, bytes(range(1, 12)))
        outputs = []
        for step in steps:
            sink = _Recording()
            stage._drive(step, stage._Writer(sink, stream, "guarded"), stream)
            outputs.append(sink.calls)
        assert outputs[0] == outputs[1], f"the drivers disagree on {stream!r}"
        written = outputs[0]
        heads = {start for start, _ in messages}
        for call in written:
            if call[0] != "record":
                continue
            fields = dict(call[2])
            if fields.get("role") in (None, "guarded.magic"):
                assert fields["cites"][0] in heads, f"a start inside a message: {stream!r}"
        # A retry that worked leaves a lost region ending at a real message
        # inside its run; one that ends where the run does was never retried.
        ends = {
            item.off_start + len(item.data) for item in stream.items if isinstance(item, _Chunk)
        }
        retried += sum(
            1
            for call in written
            if call[0] == "undecoded"
            and call[4] == stage.LOST_COMMENT
            and call[2] in heads
            and call[2] not in ends
        )
    assert retried, "the batch never retried after a refusal"
