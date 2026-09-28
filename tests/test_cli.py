"""Tests for the command line."""

from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import zpf
from cipher import seal

from kober import transforms as transforms_module
from kober.cli import FAILED, OK, build_parser, main
from kober.transforms import Registry

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
      - {name: null, type: {int: {bits: 3}}}
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
    assert "(anonymous): u3" in out


def test_show_renders_sizes_repeats_and_conditions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    main(["show", write(tmp_path, GOOD)])
    out = capsys.readouterr().out
    assert "bytes[qdcount * 4]" in out
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


# --- run -------------------------------------------------------------------


def transport(tmp_path: Path, payload: bytes) -> str:
    """Write a one-record transport file and return its path."""
    path = tmp_path / "in.zpf"
    with zpf.create(path, tick_hz=1_000_000) as writer:
        writer.add_source("capture", uri="x.pcap")
        with writer.begin_session(proto="tcp", key="a <-> b") as session:
            client = session.participant("10.0.0.1:51000", isn=1000)
            session.record(client, ts=1000, payload=payload, hints=zpf.Hints(seq_start=1001))
            session.end(reason="fin")
    return str(path)


RUNNABLE = """
name: r
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: tag, type: {int: {bits: 16}}}
      - {name: body, type: {int: {bits: 16}}}
"""


def test_run_writes_a_decode_stage(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    spec = write(tmp_path, RUNNABLE)
    source = transport(tmp_path, b"\x12\x34\x56\x78")
    out = tmp_path / "out.zpf"
    assert main(["run", spec, source, "-o", str(out)]) == OK
    assert out.exists()
    assert "1 record(s)" in capsys.readouterr().out


def test_run_at_field_granularity(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    spec = write(tmp_path, RUNNABLE)
    source = transport(tmp_path, b"\x12\x34\x56\x78")
    out = tmp_path / "out.zpf"
    assert main(["run", spec, source, "-o", str(out), "--emit", "field"]) == OK
    assert "2 record(s)" in capsys.readouterr().out


def test_run_output_is_conformant(tmp_path: Path):
    spec = write(tmp_path, RUNNABLE)
    source = transport(tmp_path, b"\x12\x34\x56\x78")
    out = tmp_path / "out.zpf"
    main(["run", spec, source, "-o", str(out)])
    checker = zpf.ConformanceChecker()
    with zpf.open(out) as handle:
        checker.check(handle.blocks())
    checker.finish()
    assert zpf.check_coverage(out, source) == []


def test_run_records_the_producer(tmp_path: Path):
    spec = write(tmp_path, RUNNABLE)
    source = transport(tmp_path, b"\x12\x34\x56\x78")
    out = tmp_path / "out.zpf"
    main(["run", spec, source, "-o", str(out), "--produced-by", "my-tool 9"])
    with zpf.open(out) as handle:
        header = next(b for b in handle.blocks() if isinstance(b, zpf.FileHeader))
    assert header.produced_by == "my-tool 9"


def test_run_succeeds_despite_undecodable_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """An undecodable region is a conformant result, not a failure."""
    spec = write(tmp_path, RUNNABLE)
    source = transport(tmp_path, b"\x12\x34\x56\x78\x99")
    out = tmp_path / "out.zpf"
    assert main(["run", spec, source, "-o", str(out)]) == OK
    captured = capsys.readouterr().out
    assert "undecoded region(s)" in captured
    assert "truncated" in captured


def test_run_reports_a_missing_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    spec = write(tmp_path, RUNNABLE)
    out = tmp_path / "out.zpf"
    with pytest.raises((OSError, zpf.ZpfError)):
        main(["run", spec, str(tmp_path / "absent.zpf"), "-o", str(out)])


def test_run_refuses_an_invalid_spec(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Decoder checks its spec, and a spec that cannot run is a failure."""
    spec = write(tmp_path, HAS_ERRORS)
    source = transport(tmp_path, b"\x12\x34")
    out = tmp_path / "out.zpf"
    assert main(["run", spec, source, "-o", str(out)]) == FAILED
    assert "error" in capsys.readouterr().err


def test_run_requires_an_output(tmp_path: Path):
    spec = write(tmp_path, RUNNABLE)
    source = transport(tmp_path, b"\x12\x34")
    with pytest.raises(SystemExit) as caught:
        main(["run", spec, source])
    assert caught.value.code == 2


# --- compile ---------------------------------------------------------------


def test_compile_writes_a_module(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "dns.py"
    assert main(["compile", write(tmp_path, GOOD), "-o", str(out)]) == OK
    assert "2 unit(s), message granularity" in capsys.readouterr().out
    assert out.read_text().startswith('"""Decoder for the ``dns`` specification')


def test_compile_writes_to_standard_output_when_asked_for_no_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert main(["compile", write(tmp_path, GOOD)]) == OK
    assert "def decode(" in capsys.readouterr().out


def test_compile_takes_the_granularity_it_compiles_for(tmp_path: Path):
    """A compile-time choice, so it is a compile-time flag."""
    field = tmp_path / "field.py"
    message = tmp_path / "message.py"
    main(["compile", write(tmp_path, GOOD), "-o", str(field), "--emit", "field"])
    main(["compile", write(tmp_path, GOOD), "-o", str(message), "--emit", "message"])
    assert "sink.record(" in field.read_text()
    assert "MESSAGE_CONTENT_TYPE" in message.read_text()
    assert "MESSAGE_CONTENT_TYPE" not in field.read_text()


def test_compile_refuses_an_invalid_spec(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Errors move to build time: that is half of what compiling buys."""
    out = tmp_path / "dns.py"
    assert main(["compile", write(tmp_path, HAS_ERRORS), "-o", str(out)]) == FAILED
    assert "nothing written" in capsys.readouterr().err
    assert not out.exists()


def test_compile_reports_warnings_and_still_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    out = tmp_path / "warned.py"
    assert main(["compile", write(tmp_path, WARNS_ONLY), "-o", str(out)]) == OK
    assert "warning" in capsys.readouterr().err
    assert out.exists()


def test_a_compiled_module_imports_and_decodes(tmp_path: Path):
    """The end of the line for `kober compile`: a module that reads bytes."""
    out = tmp_path / "dns.py"
    main(["compile", write(tmp_path, GOOD), "-o", str(out), "--emit", "field"])
    spec = importlib.util.spec_from_file_location("compiled_cli", out)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["compiled_cli"] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules["compiled_cli"]
    message = module.decode(b"\x12\x34\x00\x00\x00")
    assert message is not None
    assert message.id == 0x1234


# --- try -------------------------------------------------------------------


def test_try_prints_the_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    spec = write(tmp_path, RUNNABLE)
    assert main(["try", spec, "--hex", "12345678"]) == OK
    out = capsys.readouterr().out
    assert "tag = 4660" in out
    assert "body = 22136" in out
    assert "4 of 4 byte(s) decoded: ok" in out


def test_try_accepts_spaced_and_separated_hex(tmp_path: Path):
    spec = write(tmp_path, RUNNABLE)
    assert main(["try", spec, "--hex", "12 34 56 78"]) == OK
    assert main(["try", spec, "--hex", "12:34:56:78"]) == OK
    assert main(["try", spec, "--hex", "12-34-56-78"]) == OK


def test_try_fails_on_an_incomplete_decode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Answering whether a spec reads these bytes is the point of the verb."""
    spec = write(tmp_path, RUNNABLE)
    assert main(["try", spec, "--hex", "1234"]) == FAILED
    assert "truncated" in capsys.readouterr().out


def test_try_fails_when_bytes_are_left_over(tmp_path: Path):
    """A spec that reads only part of the buffer has not read the buffer."""
    spec = write(tmp_path, RUNNABLE)
    assert main(["try", spec, "--hex", "1234567899"]) == FAILED


def test_try_reports_bad_hex(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    spec = write(tmp_path, RUNNABLE)
    assert main(["try", spec, "--hex", "zz"]) == FAILED
    assert "not valid hex" in capsys.readouterr().err


def test_try_requires_hex(tmp_path: Path):
    spec = write(tmp_path, RUNNABLE)
    with pytest.raises(SystemExit) as caught:
        main(["try", spec])
    assert caught.value.code == 2


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


def test_every_designed_verb_is_registered():
    """DESIGN.md §6 lists four; all four now exist."""
    help_text = build_parser().format_help()
    for verb in ("check", "show", "run", "try"):
        assert verb in help_text


def test_help_explains_when_a_partial_decode_is_a_failure():
    assert "conformant result, not an error" in build_parser().format_help()


# --- the shipped examples, through every verb ------------------------------
#
# Nothing here ran a verb against `examples/`, and the inline specs above use
# none of the constructs those examples are written to demonstrate. So `show`
# crashed on a `pointer` from the phase that added one, and went on crashing
# until a `select` hit the same line — both of them falling off the end of an
# `isinstance` chain that ended by *assuming* `switch`.

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SHIPPED = sorted(path.name for path in EXAMPLES.glob("*.yaml"))


def test_there_are_shipped_examples_to_check():
    """Or the sweep below passes by having nothing to do."""
    assert SHIPPED


@pytest.mark.parametrize("name", SHIPPED)
@pytest.mark.parametrize("verb", ["check", "show"])
def test_a_shipped_example_survives_every_verb_that_reads_it(
    verb: str, name: str, capsys: pytest.CaptureFixture[str]
):
    assert main([verb, str(EXAMPLES / name)]) == OK
    assert capsys.readouterr().out.strip()


@pytest.mark.parametrize("name", SHIPPED)
def test_show_renders_every_field_type_a_shipped_example_uses(
    name: str, capsys: pytest.CaptureFixture[str]
):
    """A type the renderer does not know says so, rather than raising.

    Asserted against the marker rather than against a crash, because the point
    of the fix is that an unhandled type is *named*: a traceback and a silent
    mislabel are both worse than a line saying which type went unrendered.
    """
    main(["show", str(EXAMPLES / name)])
    assert "<unrendered" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("{int: {bits: 8}}", "u8"),
        ("{bytes: {size: 2}}", "bytes[2]"),
        ('{string: {size: {terminated: {delimiter: ":"}}}}', "until b':'"),
        (
            '{string: {size: {terminated: {delimiter: ":", within: "\\r\\n"}}}}',
            "within b'\\r\\n'",
        ),
        ('{computed: "a"}', "computed a"),
        ('{pointer: {at: "a", type: {int: {bits: 8}}}}', "pointer at a: u8"),
        ('{switch: {dispatch: "a", cases: {1: {int: {bits: 8}}}}}', "switch on a"),
    ],
)
def test_show_renders_each_field_type(
    kind: str, expected: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Every branch of the renderer, so none can go unreached again."""
    document = f"""
name: t
version: "1.0"
entry: m
units:
  m:
    fields:
      - {{name: a, type: {{int: {{bits: 8}}}}}}
      - {{name: b, type: {kind}}}
"""
    main(["show", write(tmp_path, document)])
    printed = capsys.readouterr().out
    assert expected in printed
    assert "<unrendered" not in printed


def test_show_renders_a_select(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    document = """
name: t
version: "1.0"
entry: m
units:
  m:
    fields:
      - {name: n, type: {int: {bits: 8}}}
      - {name: items, type: {unit: i}, repeat: {count: "n"}}
      - name: picked
        type:
          select: {from: items, where: "items.tag == 7", value: "items.tag", default: "0"}
  i:
    fields:
      - {name: tag, type: {int: {bits: 8}}}
"""
    main(["show", write(tmp_path, document)])
    printed = capsys.readouterr().out
    assert "select from items where items.tag == 7 → items.tag else 0" in printed
    assert "<unrendered" not in printed


def test_show_keeps_the_tree_intact_through_a_multi_paragraph_doc(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """A `doc:` of more than one line used to start its second at column zero.

    Which is not an exotic shape: a spec is authored in YAML so that a field
    can carry a paragraph of RFC citation, and the shipped HTTP example does.
    """
    document = """
name: t
version: "1.0"
entry: m
units:
  m:
    fields:
      - name: a
        type: {int: {bits: 8}}
        doc: >
          The first paragraph, which is long enough to need folding across
          more than one line of the source it is written in.

          The second, which must not appear.
      - {name: b, type: {int: {bits: 8}}}
"""
    main(["show", write(tmp_path, document)])
    body = capsys.readouterr().out.split("\n")
    doc_lines = [line for line in body if "paragraph" in line or "folding" in line]
    assert doc_lines, "the documentation vanished"
    for line in doc_lines:
        assert line.startswith("│"), f"line escaped the tree: {line!r}"
    assert any("(+1 more paragraph)" in line for line in body)
    assert "The second, which must not appear." not in "\n".join(body)


def test_show_counts_a_unit_reached_only_through_a_pointer_as_reachable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """A pointer's target is reached, as `check` and the decoder both agree.

    `show` walked switch cases and nothing else, so it reported the target's
    unit unreachable.
    """
    document = """
    name: p
    version: "1"
    entry: m
    units:
      m:
        fields:
          - {name: at, type: {int: {bits: 8}}}
          - {name: target, type: {pointer: {at: "0", type: {unit: label}}}}
      label:
        fields:
          - {name: size, type: {int: {bits: 8}}}
    """
    main(["show", write(tmp_path, document)])
    assert "not reachable" not in capsys.readouterr().out


# --- --param (transforms, Stage 5) ------------------------------------------------------

PARAMS_SPEC = """
name: p
version: "1"
entry: m
params:
  salt: bytes
  shift: int
  loud: bool
  label: str
units:
  m:
    fields:
      - {name: n, bits: 8}
      - {name: body, bytes: {size: {expr: n}}}
      - name: inflated
        transform: {from: body, with: gzip, limit: 100, type: {string: {size: {remaining: true}}}}
      - {name: scaled, computed: "n + shift"}
      - {name: tagged, computed: "loud and label == 'x' and salt == salt"}
"""


def test_try_reads_each_param_as_its_declared_type(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    body = gzip.compress(b"hello", mtime=0)
    salt = tmp_path / "salt.bin"
    salt.write_bytes(b"\x01\x02")
    code = main(
        [
            "try", write(tmp_path, PARAMS_SPEC), "--hex", (bytes([len(body)]) + body).hex(),
            "--param", f"salt=file:{salt}", "--param", "shift=10",
            "--param", "loud=true", "--param", "label=x",
        ]
    )
    out = capsys.readouterr().out
    assert code == OK, out
    assert "inflated = 'hello'" in out
    assert f"scaled = {len(body) + 10}" in out
    assert "tagged = True" in out


@pytest.mark.parametrize(
    ("param", "fragment"),
    [
        ("salt=0102", "a bytes value is hex:… or file:PATH"),
        ("salt=hex:zz", "--param salt: not valid hex"),
        ("shift=ten", "--param shift: not a decimal integer"),
        ("loud=yes", "--param loud: a bool is true or false"),
        ("colour=red", "declares no such parameter"),
        ("noequals", "--param takes NAME=VALUE"),
    ],
)
def test_a_malformed_param_is_refused_without_quoting_its_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], param: str, fragment: str
):
    code = main(["try", write(tmp_path, PARAMS_SPEC), "--hex", "00", "--param", param])
    err = capsys.readouterr().err
    assert code == FAILED
    assert fragment in err
    value = param.partition("=")[2]
    if value and value not in fragment:
        assert value not in err, "a value may be a secret and is never quoted"


def test_a_missing_param_is_refused_before_any_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    code = main(["try", write(tmp_path, PARAMS_SPEC), "--hex", "00", "--param", "shift=1"])
    assert code == FAILED
    assert "needs parameter(s) 'label', 'loud', 'salt'" in capsys.readouterr().err


# --- --load-transforms --------------------------------------------------------------------

TUNNEL_SPEC = """
name: tunnel
version: "1"
entry: datagram
transforms:
  xor: {params: {key: bytes, nonce: bytes}}
params:
  key: {type: bytes, secret: true}
units:
  datagram:
    fields:
      - {name: nonce, bytes: 8}
      - {name: sealed, bytes: {size: {remaining: true}}}
      - name: inner
        transform: {from: sealed, with: xor, limit: 1500, args: {key: key, nonce: nonce}}
"""


@pytest.fixture
def fresh_registry(monkeypatch: pytest.MonkeyPatch) -> Registry:
    """Give the test a default registry of its own, so its registrations stay its own."""
    registry = Registry.standard()
    monkeypatch.setattr(transforms_module, "DEFAULT", registry)
    return registry


def test_load_transforms_runs_a_module_that_registers_a_cipher(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fresh_registry: Registry
):
    module = tmp_path / "ciphers.py"
    module.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(Path(__file__).parent)!r})\n"
        "from cipher import xor_open\n"
        "from kober.transforms import register\n"
        "register('xor', xor_open)\n"
    )
    key = bytes(range(16))
    datagram = b"nonce-01" + seal(b"inner", key=key, nonce=b"nonce-01")
    code = main(
        [
            "try", write(tmp_path, TUNNEL_SPEC), "--hex", datagram.hex(),
            "--param", f"key=hex:{key.hex()}", "--load-transforms", str(module),
        ]
    )
    out = capsys.readouterr().out
    assert code == OK, out
    assert "inner = b'inner'" in out
    assert fresh_registry.lookup("xor") is not None


def test_without_the_module_the_spec_says_what_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fresh_registry: Registry
):
    code = main(["try", write(tmp_path, TUNNEL_SPEC), "--hex", "00", "--param", "key=hex:00"])
    assert code == FAILED
    assert "'xor' is the spec's own and nothing is registered" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("source", "fragment"),
    [(None, "FileNotFoundError"), ("raise RuntimeError('broken')", "RuntimeError: broken")],
    ids=["missing", "raises"],
)
def test_a_module_that_cannot_load_is_a_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fresh_registry: Registry,
    source: str | None,
    fragment: str,
):
    module = tmp_path / "broken.py"
    if source is not None:
        module.write_text(source)
    code = main(
        [
            "try", write(tmp_path, TUNNEL_SPEC), "--hex", "00",
            "--param", "key=hex:00", "--load-transforms", str(module),
        ]
    )
    err = capsys.readouterr().err
    assert code == FAILED
    assert f"--load-transforms {module}" in err
    assert fragment in err
