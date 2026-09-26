"""The checker's rules for `transform`, `concat`, `transforms:` and `params:` (Stage 2).

Every rule here is decided from the spec alone: nothing consults a registry, so
`check` answers the same way whatever a process has bound (the transform
plan's Q3 and Q7).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from kober.check import Severity, check, message_tail_fields
from kober.cli import main
from kober.errors import CompileError
from kober.loader import from_yaml
from kober.pygen import render_spec
from kober.spec import Spec

#: A message whose body may be framed two ways, and a transform over it. Each
#: test replaces a piece of it.
BASE = """
name: t
version: "1"
entry: message
{top}
units:
  message:
    fields:
      - {{name: chunked, bits: 8}}
      - {{name: n, bits: 8}}
      - {{name: chunks, unit: chunk, until: "chunks.size == 0", condition: "chunked == 1"}}
      - name: body
        switch:
          dispatch: chunked
          cases:
            1: {{concat: chunks.data}}
          default: {{bytes: {{size: {{expr: n}}}}}}
{fields}
  chunk:
    fields:
      - {{name: size, bits: 8}}
      - {{name: data, bytes: {{size: {{expr: size}}}}}}
  document:
    fields:
      - {{name: text, string: {{size: {{remaining: true}}}}}}
"""

CONTENT = """\
      - name: content
        transform: {from: body, with: gzip, limit: 65536, type: {unit: document}}"""


def spec(fields: str = CONTENT, top: str = "") -> Spec:
    """Build the base spec with these trailing fields and top-level keys."""
    body = textwrap.indent(textwrap.dedent(fields).strip("\n"), "      ")
    return from_yaml(BASE.format(fields=body, top=textwrap.dedent(top)))


def errors(built: Spec) -> list[str]:
    return [f.message for f in check(built) if f.severity is Severity.ERROR]


def warnings(built: Spec) -> list[str]:
    return [f.message for f in check(built) if f.severity is Severity.WARNING]


def only_error(built: Spec) -> str:
    found = errors(built)
    assert len(found) == 1, f"expected exactly one error, got {found}"
    return found[0]


# --- what is accepted ------------------------------------------------------------


def test_a_transform_over_a_body_framed_two_ways_is_valid():
    """The spike's shape: one field holds the body however it was framed."""
    built = spec()
    assert errors(built) == []
    assert not any("never referenced" in w for w in warnings(built))


def test_a_transform_may_follow_a_field_that_reads_to_the_end():
    """It reads nothing where it stands, so the terminal rule does not apply to it."""
    built = spec(
        """
        - {name: rest, bytes: {size: {remaining: true}}}
        - name: plain
          transform: {from: rest, with: deflate-raw, limit: 100}
        """
    )
    assert errors(built) == []


def test_a_typeless_transform_may_label_its_output():
    built = spec(
        """
        - name: plain
          transform: {from: body, with: gzip, limit: 100, content_type: "mime:application/json"}
        """
    )
    assert errors(built) == []


def test_a_transform_output_and_a_concat_are_referenceable():
    """A type-less output and a concat are bytes; a typed output is what it decodes as."""
    built = spec(
        """
        - name: raw
          transform: {from: body, with: gzip, limit: 100}
        - name: again
          transform: {from: raw, with: deflate, limit: 100}
        - {name: has_text, computed: "content.text == 'x'"}
        - name: content
          transform: {from: body, with: gzip, limit: 100, type: {unit: document}}
        - {name: check_text, computed: "content.text == 'x'"}
        """
    )
    found = errors(built)
    assert len(found) == 1, found
    assert "'content' is declared later" in found[0]


def test_an_extended_name_is_valid_once_declared():
    built = spec(CONTENT.replace("with: gzip", "with: br"), top="transforms: {br: {}}")
    assert errors(built) == []


def test_a_declared_cipher_takes_typed_arguments_from_fields_and_document_params():
    built = spec(
        """
        - name: plain
          transform:
            from: body
            with: aes-gcm
            limit: 1500
            args: {key: key, nonce: "n", aad: key}
        """,
        top="""
        transforms:
          aes-gcm: {params: {key: bytes, nonce: int, aad: bytes}}
        params:
          key: {type: bytes, secret: true}
        """,
    )
    assert errors(built) == []


def test_a_transform_may_read_a_bytes_document_param():
    built = spec(
        """
        - name: plain
          transform: {from: blob, with: gzip, limit: 100}
        """,
        top="params: {blob: bytes}",
    )
    assert errors(built) == []


def test_a_transforms_output_unit_is_checked_like_any_other():
    """Reachable through the transform, and an unknown one is an error."""
    built = spec(CONTENT.replace("unit: document", "unit: nowhere"))
    assert "unknown unit 'nowhere'" in only_error(built)


def test_the_body_before_a_transform_is_the_message_tail():
    """#49's analysis sees through a transform: it reads nothing after the body."""
    tails = message_tail_fields(spec())
    assert ("message", 3) in tails


# --- which transform --------------------------------------------------------------


def test_an_undeclared_name_is_refused():
    message = only_error(spec(CONTENT.replace("with: gzip", "with: rot13")))
    assert "'rot13' is neither a core transform nor declared" in message


@pytest.mark.parametrize("name", ["br", "zstd", "bzip2", "xz"])
def test_an_extended_name_must_be_declared(name: str):
    message = only_error(spec(CONTENT.replace("with: gzip", f"with: {name}")))
    assert f"'{name}' is a well-known extended name" in message
    assert "declares it under 'transforms:'" in message


def test_a_well_known_name_takes_no_parameters():
    built = spec(top="transforms: {gzip: {params: {level: int}}}")
    found = errors(built)
    wanted = "well-known transform, defined by RFC 1952, and takes no parameters"
    assert any(wanted in e for e in found)


def test_a_declared_transform_nothing_uses_is_a_warning():
    built = spec(top="transforms: {br: {}}")
    assert "transform 'br' is declared and never used" in warnings(built)


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        ("{key: key}", "argument 'nonce' is not supplied"),
        ("{key: key, nonce: n, colour: n}", "no parameter 'colour'"),
        ("{key: n, nonce: n}", "argument 'key' must be bytes, got int"),
    ],
)
def test_arguments_are_typed_against_the_declaration(args: str, fragment: str):
    built = spec(
        f"""
        - name: plain
          transform: {{from: body, with: cipher, limit: 100, args: {args}}}
        """,
        top="""
        transforms: {cipher: {params: {key: bytes, nonce: int}}}
        params: {key: bytes}
        """,
    )
    assert fragment in only_error(built)


# --- where the bytes come from ---------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "fragment"),
    [
        (
            "- name: plain\n  transform: {from: nothing, with: gzip, limit: 9}",
            "unknown name 'nothing'",
        ),
        (
            "- name: plain\n  transform: {from: later, with: gzip, limit: 9}\n"
            "- {name: later, bytes: 4}",
            "'later' is declared later",
        ),
        (
            "- name: plain\n  transform: {from: n, with: gzip, limit: 9}",
            "'n' is not bytes on every branch",
        ),
        (
            "- name: plain\n  transform: {from: chunks, with: gzip, limit: 9}",
            "'chunks' is repeated; join it with a concat",
        ),
    ],
    ids=["unknown", "later", "not-bytes", "repeated"],
)
def test_a_transform_reads_an_earlier_bytes_field(fields: str, fragment: str):
    assert fragment in only_error(spec(fields))


def test_a_switch_that_is_not_bytes_on_every_branch_is_not_a_source():
    built = spec(
        """
        - name: either
          switch: {dispatch: chunked, cases: {1: {bytes: 2}}, default: {bits: 8}}
        - name: plain
          transform: {from: either, with: gzip, limit: 9}
        """
    )
    assert "'either' is not bytes on every branch" in only_error(built)


def test_a_non_bytes_document_param_is_not_a_source():
    built = spec(
        "- name: plain\n  transform: {from: level, with: gzip, limit: 9}",
        top="params: {level: int}",
    )
    assert "parameter 'level' is int, and a transform reads bytes" in only_error(built)


def test_a_source_with_emit_none_is_refused():
    """The run would raise at close: a byte both cited and `skipped` (the plan's Stage 1)."""
    built = spec(
        """
        - {name: raw, bytes: 4, emit: none}
        - name: plain
          transform: {from: raw, with: gzip, limit: 9}
        """
    )
    assert "'raw' has emit: none" in only_error(built)


# --- the output --------------------------------------------------------------------


def test_a_content_type_on_a_typed_output_is_refused():
    typed = "type: {unit: document}"
    built = spec(CONTENT.replace(typed, f"{typed}, content_type: prim:bytes"))
    assert "content_type labels an output kept as bytes" in only_error(built)


@pytest.mark.parametrize("label", ["json", "mime:json", "prim:", "application/json"])
def test_a_malformed_content_type_is_refused(label: str):
    labelled = f'{{from: body, with: gzip, limit: 9, content_type: "{label}"}}'
    built = spec(f"- name: plain\n  transform: {labelled}")
    assert "is not a label the format has" in only_error(built)


@pytest.mark.parametrize(
    "construct", ["transform: {from: body, with: gzip, limit: 9}", "concat: chunks.data"]
)
def test_a_transform_or_concat_cannot_repeat(construct: str):
    built = spec(f"- name: many\n  {construct}\n  count: 2")
    assert "cannot repeat: it reads nothing where it stands" in only_error(built)


# --- concat ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "fragment"),
    [
        ("- {name: j, concat: missing.data}", "unknown name 'missing'"),
        ("- {name: j, concat: n.data}", "'n' is not repeated"),
        ("- {name: j, concat: chunks.nothing}", "unit 'chunk' has no field 'nothing'"),
        ("- {name: j, concat: chunks.size}", "'size' must be a single bytes field"),
    ],
    ids=["unknown", "not-repeated", "no-member", "member-not-bytes"],
)
def test_a_concat_joins_bytes_members_of_an_earlier_repetition(fields: str, fragment: str):
    assert fragment in only_error(spec(fields))


# --- document params ----------------------------------------------------------------


def test_a_document_param_is_in_scope_in_every_unit():
    built = spec(
        "- {name: scaled, computed: 'n * level'}",
        top="params: {level: int}",
    )
    assert errors(built) == []


def test_a_document_param_may_not_share_a_name_with_a_field():
    built = spec(top="params: {body: bytes}")
    assert "parameter 'body' has the name of a field" in only_error(built)


# --- show and compile --------------------------------------------------------------


def test_show_renders_a_transform_and_a_concat(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    path = tmp_path / "t.yaml"
    path.write_text(
        BASE.format(
            top="",
            fields=textwrap.indent(
                textwrap.dedent(CONTENT)
                + "\n- name: raw\n  transform: {from: body, with: gzip, limit: 9}"
                + "\n- {name: joined, concat: chunks.data}",
                "      ",
            ),
        )
    )
    assert main(["show", str(path)]) == 0
    out = capsys.readouterr().out
    assert "content: gzip(body) → document, at most 65536 bytes" in out
    assert "raw: gzip(body) → bytes, at most 9 bytes" in out
    assert "joined: concat chunks.data" in out
    assert "text: string[remaining] utf-8" in out, "the output unit is expanded in place"
    assert "<unrendered" not in out
    assert "not reachable" not in out


def test_the_compiler_compiles_a_transform_and_a_concat():
    """Both are compiled: a unit output, a bytes output, and a join."""
    source = render_spec(
        spec(
            textwrap.dedent(CONTENT)
            + "\n- name: raw\n  transform: {from: body, with: gzip, limit: 9}"
            + "\n- {name: joined, concat: chunks.data}"
        )
    )
    assert "run_transform(" in source
    assert "concat(" in source


def test_the_compiler_refuses_a_transform_whose_type_is_not_a_unit():
    """Its output is decoded by calling a unit's function; a scalar has none."""
    built = spec("""\
        - name: content
          transform: {from: body, with: gzip, limit: 64, type: {string: {size: {remaining: true}}}}
        """)
    assert errors(built) == [], "the interpreter decodes it: the spec is valid"
    with pytest.raises(CompileError, match="only as a unit"):
        render_spec(built)
