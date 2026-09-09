"""The format reference must not drift from the loader it documents.

A reference page that quietly falls behind the schema is worse than no
reference, because it is believed. These tests read the loader's own key sets
and assert every one of them is documented, so adding a key without writing it
up fails the suite rather than the reader.
"""

from __future__ import annotations

import ast
import re
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
        "concepts.md",
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
    quoted = 'until: "labels.length == 0 or labels.length >= 192"'
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


# --- the concepts page's worked example ------------------------------------
#
# It shows one spec four ways — as a shape, a tree, a Python class, and a set
# of records — and every one of those is real output. A page that shows what a
# tool prints has to keep printing it.

CONCEPTS = FORMAT / "concepts.md"


def worked_spec() -> str:
    """Return the toy spec the concepts page teaches units with."""
    found = re.search(r"```yaml\n(name: greeting.*?)```", CONCEPTS.read_text(), re.S)
    assert found, "the concepts page no longer carries its worked spec"
    return found.group(1)


def test_the_worked_spec_still_loads_and_checks_clean():
    """A reader's first spec must not be one the checker rejects."""
    from kober.check import Severity, check
    from kober.spec import Spec

    findings = check(Spec.from_yaml(worked_spec()))
    assert [f for f in findings if f.severity is Severity.ERROR] == []


@pytest.mark.parametrize("verb", ["show", "try"])
def test_the_console_output_on_the_concepts_page_is_what_the_tool_prints(
    verb: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Not "close to" — the same text, or the page is teaching a fiction."""
    from kober.cli import main

    path = tmp_path / "greeting.yaml"
    path.write_text(worked_spec())
    arguments = [verb, str(path)]
    if verb == "try":
        arguments += ["--hex", "0203416e6e054368726973"]
    main(arguments)
    printed = capsys.readouterr().out.rstrip()

    page = CONCEPTS.read_text()
    quoted = re.search(rf"\$ kober {verb} greeting\.yaml.*?\n(.*?)```", page, re.S)
    assert quoted, f"the page no longer shows `kober {verb}`"
    assert printed == quoted.group(1).rstrip()


def test_the_dns_excerpt_is_the_shipped_spec():
    """The parameters example quotes `examples/dns.yaml`; it must still say it."""
    page = CONCEPTS.read_text()
    shipped = (DOCS.parent / "examples" / "dns.yaml").read_text()
    block = re.search(r"```yaml\n(      - name: rest.*?)```", page, re.S)
    assert block, "the concepts page no longer quotes dns.yaml"
    for line in block.group(1).splitlines():
        if line.strip():
            assert line in shipped, f"not in examples/dns.yaml: {line!r}"


# --- the construct checklist -----------------------------------------------
#
# `contributing.md` names fourteen exact places a new construct has to be
# wired into. A checklist pointing at a renamed function is worse than none —
# it reads as authoritative and sends someone to a symbol that is not there.

CONTRIBUTING = DOCS / "dev" / "contributing.md"

#: Every hook the checklist names, as (module, dotted symbol). Both directions
#: are asserted: the symbol must exist, and the guide must still name it.
CONSTRUCT_HOOKS = [
    ("kober.spec", "FieldType"),
    ("kober.loader", "_TYPE_KINDS"),
    ("kober.loader", "_field_type"),
    ("kober.check", "_Checker._check_type"),
    ("kober.check", "_Scope._type_of"),
    ("kober.decoder", "Decoder._value"),
    ("kober.emit", "UNDECLARED_WIDTH"),
    ("kober.emit", "_leaf"),
    ("kober.ops", "_value"),
    ("kober.ops", "_kind_exprs"),
    ("kober.ops", "_referenced"),
    ("kober.ops", "_kind_consumes"),
    ("kober.ops", "_types"),
    ("kober.pygen", "_Function.read"),
    ("kober.pygen", "_Function.record"),
    ("kober.cli", "_render_type"),
]


@pytest.mark.parametrize(
    ("module", "symbol"), CONSTRUCT_HOOKS, ids=lambda v: v.rsplit(".", 1)[-1]
)
def test_every_hook_the_checklist_names_still_exists(module: str, symbol: str):
    """Rename one of these and the guide starts lying; this fails first."""
    import importlib

    target = importlib.import_module(module)
    for part in symbol.split("."):
        assert hasattr(target, part), f"{module}.{symbol} — {part!r} is gone"
        target = getattr(target, part)


@pytest.mark.parametrize(
    ("module", "symbol"), CONSTRUCT_HOOKS, ids=lambda v: v.rsplit(".", 1)[-1]
)
def test_the_checklist_still_names_every_hook(module: str, symbol: str):
    """And the other direction: a hook dropped from the guide fails too."""
    text = CONTRIBUTING.read_text()
    name = symbol.split(".")[-1]
    assert f"`{name}`" in text or f"`{symbol}`" in text, (
        f"contributing.md no longer names {symbol}"
    )


def test_the_checklist_names_the_module_that_was_missed_twice():
    """The whole reason the checklist exists, so it should not quietly go."""
    text = CONTRIBUTING.read_text()
    assert "cli.py" in text
    assert "missed twice" in text


# --- the package surface ----------------------------------------------------

#: Modules whose public names ``kober`` re-exports wholesale. Not every module:
#: ``kober.cursor``, ``kober.decoder``, ``kober.check`` and the rest publish a
#: few names each and ``__init__`` picks them, but these five *are* the public
#: surface and an omission from them is an omission from the package.
RE_EXPORTING = ["kober.spec", "kober.stage", "kober.ops", "kober.pygen", "kober.runtime"]


def defined_in(module: str) -> set[str]:
    """Return the public classes and functions ``module`` itself defines.

    Read from the source rather than from :func:`dir`, which cannot tell a name
    a module *defined* from one it merely imported — every module here imports
    several of the others' classes, and those are somebody else's to export.

    Module-level constants are deliberately out of scope. Whether
    ``pygen.ELEMENT_LOCAL`` is package API is a judgement per constant, and
    answering it wrong in either direction is noise; a construct or an entry
    point is never a judgement call.
    """
    import importlib

    target = importlib.import_module(module)
    tree = ast.parse(Path(target.__file__).read_text())
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))
        and not node.name.startswith("_")
    }


@pytest.mark.parametrize("module", RE_EXPORTING)
def test_every_public_name_is_re_exported_from_the_package(module: str):
    """A construct added in one phase must reach ``kober`` in the same one.

    ``Pointer`` and ``Select`` were added in two separate phases and neither
    reached ``__init__.py``, so ``kober.FieldType`` was a published union naming
    two classes that could not be imported from the same place;
    ``run_compiled`` was the compiler's half of an exported pair. Nothing
    guarded ``__all__``, which is why three omissions survived three phases.
    """
    import kober

    missing = sorted(name for name in defined_in(module) if name not in kober.__all__)
    assert not missing, f"{module}: not re-exported from kober: {missing}"


def design_section_six() -> ast.Module:
    """Return the Python in ``DESIGN.md`` §6, parsed. Nothing executes it.

    ``...`` stands for "and the rest of the keywords" in a call, which reads
    correctly and does not parse, so it is dropped before parsing. That is the
    only liberty taken: every name in the blocks survives to be checked.
    """
    design = DOCS.parent / "DESIGN.md"
    section = re.search(r"^## 6\..*?(?=^## 7\.)", design.read_text(), re.S | re.M)
    assert section is not None, "DESIGN.md has no §6"
    blocks = re.findall(r"```python\n(.*?)```", section.group(0), re.S)
    assert blocks, "§6 carries no Python"
    source = re.sub(r",\s*\.\.\.(?=\s*\))", "", "\n".join(blocks))
    return ast.parse(source)


def test_the_api_design_names_only_things_that_exist():
    """§6 is a contract nothing runs, so its names are checked instead.

    ``Spec.as_decoder()`` was written down here and never built, so following
    §6 verbatim raised ``AttributeError`` — and the escape hatch §11.5 leans on
    was the thing that did not work as documented. Resolving the names catches
    that the day it is written, without running a block that wants real files.
    """
    import kober

    tree = design_section_six()
    imported = {
        name.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("kober")
        for name in node.names
    }
    assert imported, "§6 imports nothing from kober"
    unexported = sorted(name for name in imported if name not in kober.__all__)
    assert not unexported, f"DESIGN.md §6 imports names kober does not export: {unexported}"

    # Attribute calls on the two objects §6 builds, against the real classes.
    owners = {"spec": kober.Spec, "decoder": kober.Decoder}
    missing = sorted(
        f"{node.func.value.id}.{node.func.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in owners
        and not hasattr(owners[node.func.value.id], node.func.attr)
    )
    assert not missing, f"DESIGN.md §6 calls methods that do not exist: {missing}"
