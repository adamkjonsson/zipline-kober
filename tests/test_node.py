"""Tests for the in-memory decode tree."""

from __future__ import annotations

import pytest

from kober.node import Node, NodeStatus


def leaf(name: str, value: object, start: int, end: int, **kwargs: object) -> Node:
    return Node(name=name, value=value, off_start=start, off_end=end, **kwargs)  # type: ignore[arg-type]


def sample() -> Node:
    return Node(
        name="message",
        unit="message",
        off_start=0,
        off_end=6,
        children=(
            leaf("id", 4660, 0, 2),
            Node(
                name="flags",
                unit="flags",
                off_start=2,
                off_end=4,
                children=(leaf("qr", 0, 2, 3), leaf("opcode", 0, 2, 3)),
            ),
            leaf("qdcount", 1, 4, 6),
        ),
    )


# --- shape -----------------------------------------------------------------


def test_defaults():
    node = Node(name="x")
    assert node.value is None
    assert node.status is NodeStatus.OK
    assert node.children == ()
    assert node.width == 0


def test_width():
    assert leaf("id", 1, 4, 6).width == 2


def test_leaf_and_container():
    assert leaf("id", 1, 0, 2).is_leaf
    assert not sample().is_leaf


def test_anonymous_node():
    assert Node(name=None).name is None


def test_backwards_range_is_refused():
    with pytest.raises(ValueError, match="ends at 2 before it starts at 6"):
        Node(name="x", off_start=6, off_end=2)


def test_empty_range_is_allowed():
    """A Computed field consumes nothing and still has a position."""
    assert Node(name="derived", value=20, off_start=4, off_end=4).width == 0


def test_frozen():
    with pytest.raises(AttributeError):
        sample().name = "other"  # type: ignore[misc]


# --- walking ---------------------------------------------------------------


def test_walk_is_depth_first_in_decode_order():
    names = [node.name for node in sample().walk()]
    assert names == ["message", "id", "flags", "qr", "opcode", "qdcount"]


def test_leaves_skips_containers():
    names = [node.name for node in sample().leaves()]
    assert names == ["id", "qr", "opcode", "qdcount"]


def test_walk_of_a_leaf_is_just_itself():
    node = leaf("id", 1, 0, 2)
    assert list(node.walk()) == [node]


def test_find_direct_child():
    tree = sample()
    assert tree.find("id") is not None
    assert tree.find("qr") is None  # a grandchild, not a child
    assert tree.find("absent") is None


# --- statuses map onto the design's vocabulary -----------------------------


def test_status_values_are_the_zpf_reasons():
    """The emitter turns a status into reason= with no mapping table."""
    values = {member.value for member in NodeStatus}
    assert values == {"ok", "undecodable", "truncated", "gap", "skipped"}


def test_non_ok_status_carries_detail():
    node = Node(
        name="body",
        off_start=6,
        off_end=29,
        status=NodeStatus.TRUNCATED,
        detail="ran past the end",
    )
    assert node.status is NodeStatus.TRUNCATED
    assert node.detail == "ran past the end"


# --- rendering -------------------------------------------------------------


def test_render_shows_values_ranges_and_nesting():
    text = sample().render()
    lines = text.splitlines()
    assert lines[0] == "message  [0, 6)"
    assert lines[1] == "  id = 4660  [0, 2)"
    assert lines[3] == "    qr = 0  [2, 3)"


def test_render_shows_status_and_detail():
    node = Node(name="body", status=NodeStatus.UNDECODABLE, detail="no case matched")
    assert "undecodable" in node.render()
    assert "(no case matched)" in node.render()


def test_render_names_an_anonymous_field():
    assert "(anonymous)" in Node(name=None).render()
