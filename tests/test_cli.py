"""Tests for the command line."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from kober.cli import FAILED, OK, build_parser, main

if TYPE_CHECKING:
    from pathlib import Path

GOOD = """
name: dns
version: "1.0"
entry: message
input: either
enums:
  opcode: {0: query, 1: iquery}
units:
  message:
    fields:
      - name: id
        type: {int: {bits: 16}}
        doc: Matches replies to requests.
      - name: flags
        type: {unit: flags}
      - name: qdcount
        type: {int: {bits: 16}}
      - name: rest
        type: {bytes: {size: {expr: "qdcount * 4"}}}
        repeat: {count: "qdcount"}
  flags:
    fields:
      - name: qr
        type: {int: {bits: 1}}
      - name: opcode
        type: {int: {bits: 4, enum: opcode}}
      - {name: null, type: {int: {bits: 2}}}
"""

WARNS_ONLY = """
name: warny
version: "1.0"
entry: message
units:
  message:
    fields:
      - name: id
        type: {int: {bits: 8}}
  orphan:
    fields:
      - name: x
        type: {int: {bits: 8}}
"""

HAS_ERRORS = """
name: bad
version: "1.0"
entry: message
units:
  message:
    fields:
      - name: body
        type: {bytes: {size: {expr: "length"}}}
      - name: length
        type: {int: {bits: 16, enum: nope}}
"""


def write(tmp_path: Path, text: str, name: str = "spec.yaml") -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# --- check -----------------------------------------------------------------


def test_check_accepts_a_valid_spec(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["check", write(tmp_path, GOOD)]) == OK
    assert "dns 1.0: ok" in capsys.readouterr().out


def test_check_reports_errors_and_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["check", write(tmp_path, HAS_ERRORS)]) == FAILED
    captured = capsys.readouterr()
    assert "declared later" in captured.err
    assert "unknown enum 'nope'" in captured.err
    assert "2 error(s)" in captured.out


def test_errors_go_to_stderr_and_warnings_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    main(["check", write(tmp_path, WARNS_ONLY)])
    captured = capsys.readouterr()
    assert "never referenced" in captured.out
    assert captured.err == ""


def test_warnings_alone_pass(tmp_path: Path):
    assert main(["check", write(tmp_path, WARNS_ONLY)]) == OK


def test_strict_makes_warnings_fail(tmp_path: Path):
    assert main(["check", "--strict", write(tmp_path, WARNS_ONLY)]) == FAILED


def test_strict_still_passes_a_clean_spec(tmp_path: Path):
    assert main(["check", "--strict", write(tmp_path, GOOD)]) == OK


def test_check_reads_json(tmp_path: Path):
    document: dict[str, Any] = {
        "name": "dns",
        "version": "1.0",
        "entry": "message",
        "units": {"message": {"fields": [{"name": "id", "type": {"int": {"bits": 16}}}]}},
    }
    path = write(tmp_path, json.dumps(document), name="spec.json")
    assert main(["check", path]) == OK


# --- failures --------------------------------------------------------------


def test_malformed_spec_fails_with_a_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert main(["check", write(tmp_path, "name: x\n")]) == FAILED
    assert "missing required key 'version'" in capsys.readouterr().err


def test_missing_file_fails_with_a_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert main(["check", str(tmp_path / "absent.yaml")]) == FAILED
    assert "cannot read" in capsys.readouterr().err


def test_unknown_suffix_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["check", write(tmp_path, GOOD, name="spec.txt")]) == FAILED
    assert "cannot tell the format" in capsys.readouterr().err


# --- show ------------------------------------------------------------------


def test_show_renders_the_field_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["show", write(tmp_path, GOOD)]) == OK
    out = capsys.readouterr().out
    assert "dns 1.0 — input: either, entry: message" in out
    assert "enum opcode: 0=query, 1=iquery" in out
    assert "id: u16" in out
    assert "Matches replies to requests." in out
    # The nested unit is expanded in place.
    assert "flags: → flags" in out
    assert "qr: u1" in out
    assert "opcode: u4 enum opcode" in out
    assert "(anonymous): u2" in out


def test_show_renders_sizes_repeats_and_conditions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    main(["show", write(tmp_path, GOOD)])
    out = capsys.readouterr().out
    assert "bytes[(qdcount * 4)]" in out
    assert "×qdcount" in out


def test_show_guards_against_recursion(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    document = """
    name: r
    version: "1.0"
    entry: message
    units:
      message:
        fields:
          - name: n
            type: {int: {bits: 8}}
          - name: next
            type: {unit: message}
            condition: "n > 0"
    """
    assert main(["show", write(tmp_path, document)]) == OK
    assert "recurses into message" in capsys.readouterr().out


def test_show_names_unreachable_units(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    main(["show", write(tmp_path, WARNS_ONLY)])
    assert "not reachable from message: orphan" in capsys.readouterr().out


def test_show_reports_a_missing_entry_unit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    document = """
    name: e
    version: "1.0"
    entry: absent
    units:
      message:
        fields: []
    """
    assert main(["show", write(tmp_path, document)]) == FAILED
    assert "does not exist" in capsys.readouterr().err


# --- the parser itself -----------------------------------------------------


def test_version_flag(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == OK
    assert "kober" in capsys.readouterr().out


def test_a_verb_is_required():
    with pytest.raises(SystemExit) as caught:
        main([])
    assert caught.value.code == 2


def test_unimplemented_verbs_are_absent_rather_than_refusing():
    """A verb that exists and refuses is worse than one honestly missing."""
    with pytest.raises(SystemExit) as caught:
        main(["run", "spec.yaml"])
    assert caught.value.code == 2


def test_help_mentions_the_verbs_still_to_come():
    assert "not implemented yet" in build_parser().format_help()
