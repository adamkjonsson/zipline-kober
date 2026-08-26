"""The format reference must not drift from the loader it documents.

A reference page that quietly falls behind the schema is worse than no
reference, because it is believed. These tests read the loader's own key sets
and assert every one of them is documented, so adding a key without writing it
up fails the suite rather than the reader.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kober import expr, loader

DOCS = Path(__file__).resolve().parent.parent / "docs"
FORMAT = DOCS / "format"
README = DOCS.parent / "README.md"


def format_text() -> str:
    """Return every format page's text, lowercased."""
    return "\n".join(path.read_text() for path in sorted(FORMAT.glob("*.md"))).lower()


def test_the_format_pages_exist():
    assert {path.name for path in FORMAT.glob("*.md")} == {
        "index.md",
        "document.md",
        "types.md",
        "expressions.md",
    }


@pytest.mark.parametrize(
    ("group", "keys"),
    [
        ("spec", loader._SPEC_KEYS),
        ("unit", loader._UNIT_KEYS),
        ("field", loader._FIELD_KEYS),
        ("int", loader._INT_KEYS),
        ("string", loader._STRING_KEYS),
        ("switch", loader._SWITCH_KEYS),
        ("terminated", loader._TERMINATED_KEYS),
        ("param", loader._PARAM_KEYS),
        ("enum", loader._ENUM_KEYS),
    ],
)
def test_every_schema_key_is_documented(group: str, keys: frozenset[str]):
    text = format_text()
    missing = sorted(key for key in keys if f"`{key}`" not in text)
    assert not missing, f"{group}: undocumented key(s) {missing}"


@pytest.mark.parametrize(
    ("group", "kinds"),
    [
        ("type", loader._TYPE_KINDS),
        ("size", loader._SIZE_KINDS),
        ("repeat", loader._REPEAT_KINDS),
    ],
)
def test_every_kind_is_documented(group: str, kinds: frozenset[str]):
    text = format_text()
    missing = sorted(kind for kind in kinds if f"`{kind}`" not in text)
    assert not missing, f"{group}: undocumented kind(s) {missing}"


def test_every_accepted_suffix_is_documented():
    text = format_text()
    missing = sorted(s for s in loader.SUFFIXES if f"`{s}`" not in text)
    assert not missing, f"undocumented suffix(es) {missing}"


def test_the_undecoded_vocabulary_is_documented():
    """All four reasons, since the difference between them is the point."""
    from kober.node import NodeStatus

    text = format_text()
    missing = [m.value for m in NodeStatus if m.value != "ok" and f"`{m.value}`" not in text]
    assert not missing, f"undocumented reason(s) {missing}"


def test_the_worked_example_is_the_shipped_one():
    """types.md quotes examples/dns.yaml; it must still say what it quotes."""
    shipped = (DOCS.parent / "examples" / "dns.yaml").read_text()
    quoted = 'repeat: {until: "labels.length == 0 or labels.length >= 192"}'
    assert quoted in shipped, "examples/dns.yaml no longer matches the doc's quote"
    assert quoted in (FORMAT / "types.md").read_text()


def test_every_builtin_is_documented():
    """A function that works but is written up nowhere is a function nobody uses."""
    text = format_text()
    for name in expr.BUILTINS:
        assert f"{name}(" in text, f"{name}() is not in the format reference"


# --- the README ------------------------------------------------------------
#
# It enumerates the field types and counts the builtins, which is the same
# drift risk the pages above are guarded against — and the same guard caught a
# construct missing from the format reference once already.


def test_the_readme_lists_every_field_type():
    """A reader's first sight of the language must not be missing a construct.

    Checked against the *table rows*, not the whole file. A first attempt looked
    anywhere in the README and passed a deliberately broken table, because the
    prose underneath happens to name the same constructs — which is the failure
    mode this whole module exists to prevent, one level up.
    """
    rows = [
        line for line in README.read_text().splitlines() if line.startswith("| `")
    ]
    listed = {
        name.strip().strip("`")
        for line in rows
        for name in line.split("|")[1].split(",")
    }
    missing = sorted(loader._TYPE_KINDS - listed)
    assert not missing, f"README's field-type table is missing {missing}"


def test_the_readme_counts_the_builtins_correctly():
    """It says how many there are in words, which a table cannot check for it."""
    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}
    spelled = words[len(expr.BUILTINS)]
    text = README.read_text()
    assert f"closed table of {spelled} functions" in text, (
        f"README should say 'closed table of {spelled} functions'; "
        f"there are {len(expr.BUILTINS)}"
    )


def test_the_readme_states_the_integer_width_the_model_allows():
    from kober.spec import MAX_INT_BITS

    assert f"1 to {MAX_INT_BITS} bits" in README.read_text()
