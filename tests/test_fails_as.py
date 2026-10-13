"""A transform's declared ``fails_as``: what its source is named when it fails.

The WireGuard example plan's Q2. A cipher's failure is ``decrypt-failed``, as
the specification's tunnel vector writes it, rather than the ``undecodable``
every other failure is. Declared beside the transform's parameters, checked
against the format's classes, and carried by both backends into the regions
they plan.

Into the file too: a reason outside the canonical four must state its
``reason_class``, which ``zpf`` 0.5.2's ``DecodeStage.undecoded`` passes on
(python-zipline#79), and a ``fails_as`` is always of the ``bytes`` class.
"""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest
from test_compiled import interpreted, writes
from test_stage import write_transport
from test_stage_transforms import decode, regions

from kober.check import Severity, check
from kober.errors import SpecError
from kober.loader import from_yaml
from kober.spec import Emit, Spec

SPEC = """
name: t
version: "1"
entry: m
transforms:
  deflate: {{{declaration}}}
units:
  m:
    fields:
      - {{name: n, bits: 8}}
      - {{name: body, bytes: {{size: {{expr: n}}}}{emit}}}
      - name: out
        transform: {{from: body, with: deflate, limit: 64, content_type: "prim:bytes"}}
      - {{name: after, bits: 8}}
"""


def spec(declaration: str = "fails_as: inflate-failed", emit: str = "") -> Spec:
    return from_yaml(SPEC.format(declaration=declaration, emit=emit))


def message(body: bytes) -> bytes:
    return bytes([len(body)]) + body + b"\x7e"


GOOD = message(zlib.compress(b"hello"))
BAD = message(b"not deflate at all")


def errors(built: Spec) -> list[str]:
    return [f.message for f in check(built) if f.severity is Severity.ERROR]


# --- the declaration -------------------------------------------------------------------


def test_a_declaration_carries_its_failure_reason():
    assert spec().transforms["deflate"].fails_as == "inflate-failed"
    assert spec("").transforms["deflate"].fails_as is None


def test_a_reason_is_text():
    with pytest.raises(SpecError, match="fails_as"):
        spec("fails_as: 3")


@pytest.mark.parametrize("reason", ["decrypt-failed", "inflate-failed", "dropped", "undecodable"])
def test_a_bytes_class_reason_checks(reason: str):
    assert errors(spec(f"fails_as: {reason}")) == []


@pytest.mark.parametrize(
    ("reason", "fragment"),
    [
        ("gap", "fails_as 'gap' is a 'hole'-class reason"),
        ("truncated", "fails_as 'truncated' is a 'hole'-class reason"),
        ("Decrypt-Failed", "lower-case words joined by hyphens"),
        ("decrypt failed", "lower-case words joined by hyphens"),
        ("-failed", "lower-case words joined by hyphens"),
        ("", "lower-case words joined by hyphens"),
    ],
)
def test_a_reason_must_be_spelled_as_the_formats_and_be_bytes_class(reason: str, fragment: str):
    (found,) = errors(spec(f"fails_as: {reason!r}"))
    assert fragment in found


# --- the regions both backends plan ------------------------------------------------------


def test_a_failed_transforms_source_is_named_with_its_declared_reason():
    _, unclaimed = interpreted(spec(), BAD, Emit.FIELD)
    assert [(r.off_start, r.off_end, r.reason) for r in unclaimed] == [
        (1, len(BAD) - 1, "inflate-failed")
    ]


def test_undeclared_it_is_undecodable_as_before():
    _, unclaimed = interpreted(spec(""), BAD, Emit.FIELD)
    assert [r.reason for r in unclaimed] == ["undecodable"]


def test_a_transform_that_succeeds_names_nothing():
    _, unclaimed = interpreted(spec(), GOOD, Emit.FIELD)
    assert unclaimed == []


def test_emit_none_is_skipped_whatever_the_declaration_says():
    """``fails_as`` names a failure; a source nobody asked to see is not one."""
    built = from_yaml(
        SPEC.format(declaration="fails_as: inflate-failed", emit="").replace(
            "      - name: out\n", "      - name: out\n        emit: none\n"
        )
    )
    _, unclaimed = interpreted(built, BAD, Emit.FIELD)
    assert [r.reason for r in unclaimed] == ["skipped"]


@pytest.mark.parametrize("data", [GOOD, BAD], ids=["decodes", "fails"])
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_both_backends_plan_the_same_regions(data: bytes, emit: Emit):
    writes(spec(), data, emit)


def test_a_concat_sources_members_are_each_named_with_the_reason():
    """A chunked body has no bytes of its own; its members carry the failure."""
    built = from_yaml(
        """
name: t
version: "1"
entry: m
transforms:
  deflate: {fails_as: inflate-failed}
units:
  m:
    fields:
      - {name: chunks, unit: chunk, until: "chunks.size == 0"}
      - {name: body, concat: chunks.data}
      - name: out
        transform: {from: body, with: deflate, limit: 64, content_type: "prim:bytes"}
  chunk:
    fields:
      - {name: size, bits: 8}
      - {name: data, bytes: {size: {expr: size}}}
"""
    )
    data = bytes([3]) + b"abc" + bytes([2]) + b"de" + bytes([0])
    _, unclaimed = interpreted(built, data, Emit.FIELD)
    assert [(r.off_start, r.off_end, r.reason) for r in unclaimed] == [
        (1, 4, "inflate-failed"),
        (5, 7, "inflate-failed"),
    ]
    writes(built, data, Emit.FIELD)


# --- the file ------------------------------------------------------------------------------


def test_the_file_names_the_failure_with_its_declared_reason_and_class(tmp_path: Path):
    """Both drivers write it, conformant, saying the bytes existed (python-zipline#79)."""
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, GOOD + BAD, 1001)])
    written = decode(spec(), source, tmp_path)
    start = len(GOOD) + 1
    assert regions(written) == [(start, len(GOOD) + len(BAD) - 1, "inflate-failed", None)]
    (region,) = [block for block in written if block[0] == "undecoded"]
    assert region[5] == "bytes"


def test_a_canonical_reason_states_no_class(tmp_path: Path):
    """It implies its own, so a file written before ``fails_as`` is written the same."""
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, GOOD + BAD, 1001)])
    written = decode(spec(""), source, tmp_path)
    (region,) = [block for block in written if block[0] == "undecoded"]
    assert (region[1], region[5]) == ("undecodable", None)
