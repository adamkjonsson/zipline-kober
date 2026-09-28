"""What a generated module does with a transform, beyond agreeing with the interpreter.

The differential is in ``test_compiled.py`` (the adversarial corpus) and
``test_stage_transforms.py`` (whole files, both drivers). This holds the parts
only a generated module has: the typed value a failure leaves, the parameters
its entry points take, and binding when it is imported.
"""

from __future__ import annotations

import gzip
import sys
import zlib
from types import ModuleType

import pytest
from cipher import seal, xor_open
from fuzzing import HOSTILE_SPEC, hostile, hostile_cases
from test_compiled import interpreted, writes

from kober import transforms
from kober.decoder import Decoder
from kober.errors import ParameterError, UnboundTransformError
from kober.loader import from_yaml
from kober.node import NodeStatus
from kober.pygen import render_spec
from kober.runtime import TransformFailed
from kober.spec import Emit, Spec
from kober.transforms import Registry

TUNNEL = """
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
KEY = bytes(range(16))
NONCE = b"nonce-01"

GZIPPED = """
name: gz
version: "1"
entry: message
units:
  message:
    fields:
      - {name: n, bits: 8}
      - {name: body, bytes: {size: {expr: n}}}
      - name: content
        transform: {from: body, with: gzip, limit: 64, type: {unit: document}}
      - {name: after, bits: 8}
  document:
    fields:
      - {name: length, bits: 8}
      - {name: text, string: {size: {expr: length}}}
"""


def imported(built: Spec, registry: Registry | None = None) -> ModuleType:
    """Import a generated module, binding its transforms in ``registry``."""
    module = ModuleType(f"t_{built.name}_{len(sys.modules)}")
    sys.modules[module.__name__] = module
    default = transforms.DEFAULT
    if registry is not None:
        transforms.DEFAULT = registry
    try:
        exec(render_spec(built, emit=Emit.FIELD), module.__dict__)
    finally:
        transforms.DEFAULT = default
    return module


def tunnel() -> ModuleType:
    registry = Registry.standard()
    registry.register("xor", xor_open)
    return imported(from_yaml(TUNNEL), registry)


def framed(body: bytes) -> bytes:
    return bytes([len(body)]) + body + b"\x7e"


# --- the typed value --------------------------------------------------------------------


def test_a_typed_output_is_the_units_object():
    module = imported(from_yaml(GZIPPED))
    message = module.decode(framed(gzip.compress(b"\x05hello", mtime=0)))
    assert message is not None
    assert message.content.text == "hello"
    assert message.after == 0x7E


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        (b"not gzip", "gzip: not valid compressed data"),
        (
            gzip.compress(b"\x09hi", mtime=0),
            "gzip output does not decode: it ends before its type does",
        ),
        (
            gzip.compress(b"\x05hello??", mtime=0),
            "gzip output has 2 byte(s) its type does not read",
        ),
    ],
    ids=["codec", "short-output", "unread-tail"],
)
def test_a_failed_transform_leaves_a_transform_failed_and_the_message_whole(
    body: bytes, detail: str
):
    """*Decided* 1: the message is returned, and the field says why it holds nothing."""
    module = imported(from_yaml(GZIPPED))
    message = module.decode(framed(body))
    assert message is not None, "a failed transform does not fail its message"
    assert message.content == TransformFailed(detail)
    assert message.after == 0x7E


# --- parameters ----------------------------------------------------------------------------


def test_a_module_takes_the_documents_parameters():
    datagram = NONCE + seal(b"inner packet", key=KEY, nonce=NONCE)
    message = tunnel().decode(datagram, params={"key": KEY})
    assert message is not None
    assert message.inner == b"inner packet"


def test_the_wrong_key_fails_the_transform_and_never_shows_the_key():
    datagram = NONCE + seal(b"inner packet", key=KEY, nonce=NONCE)
    wrong = bytes(16)
    message = tunnel().decode(datagram, params={"key": wrong})
    assert message is not None
    assert message.inner == TransformFailed("xor: the transform raised ValueError")
    assert wrong.hex() not in repr(message)


@pytest.mark.parametrize(
    ("params", "fragment"),
    [
        ({}, "'key'"),
        ({"key": KEY, "extra": 1}, "'extra'"),
        ({"key": "not bytes"}, "'key'"),
    ],
    ids=["missing", "undeclared", "wrong-type"],
)
def test_parameters_are_checked_before_any_input(params: dict[str, object], fragment: str):
    with pytest.raises(ParameterError, match=fragment):
        tunnel().decode(b"", params=params)


# --- binding --------------------------------------------------------------------------------


def test_a_transform_nothing_binds_fails_the_import():
    """Once, when the module is set up, rather than every message (Q6)."""
    with pytest.raises(UnboundTransformError, match="xor"):
        imported(from_yaml(TUNNEL))


def test_a_module_binds_what_was_registered_when_it_was_imported():
    module = tunnel()
    assert module.TRANSFORMS["xor"] is xor_open


# --- a caller's transform that misbehaves ---------------------------------------------------


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
@pytest.mark.parametrize("seed", [1, 2])
def test_the_two_agree_on_a_transform_that_misbehaves(seed: int, emit: Emit):
    """Every way a caller's callable fails is contained, and worded alike in both."""
    registry = Registry.standard()
    registry.register("hostile", hostile)
    spec = from_yaml(HOSTILE_SPEC)
    for data in hostile_cases(seed):
        try:
            writes(spec, data, emit, registry=registry)
        except AssertionError as exc:
            exc.add_note(f"disagreed: hostile {emit.value} on {data!r}")
            raise


# --- an expression reading a transform's output ------------------------------------------------

READS_OUTPUT = """
name: reads
version: "1"
entry: m
units:
  m:
    fields:
      - {name: n, bits: 8}
      - {name: body, bytes: {size: {expr: n}}}
      - {name: doc, transform: {from: body, with: deflate, limit: 64, type: {unit: d}}}
      - {name: raw, transform: {from: body, with: deflate, limit: 64}}
      - {name: next, computed: "doc.v + 1"}
      - {name: same, computed: "raw == body"}
      - {name: after, bits: 8}
  d:
    fields:
      - {name: v, bits: 8}
"""


def reads_output(inner: bytes | None) -> bytes:
    """Frame a body inflating to ``inner``, or one that does not inflate at all."""
    body = b"bad" if inner is None else zlib.compress(inner)
    return bytes([len(body)]) + body + b"\x07"


@pytest.mark.parametrize("emit", [Emit.FIELD, Emit.MESSAGE], ids=lambda e: e.value)
@pytest.mark.parametrize("inner", [b"\x05", None], ids=["inflates", "fails"])
def test_an_expression_reading_an_output_agrees_in_both(emit: Emit, inner: bytes | None):
    """A failed transform makes the expression unevaluable, and nothing escapes."""
    writes(from_yaml(READS_OUTPUT), reads_output(inner), emit)


def test_an_expression_through_a_failed_transform_says_it_failed():
    """Not that `v` is not a field of `doc`, which would blame the spec."""
    tree = Decoder(from_yaml(READS_OUTPUT)).decode_bytes(reads_output(None))
    assert tree.status is NodeStatus.UNDECODABLE
    assert tree.detail == "doc.v: 'doc' failed: deflate: not valid compressed data"


def test_a_value_read_from_an_output_cites_the_transforms_range():
    """An output's offsets name no input byte, so the transform's range is the evidence."""
    spec = from_yaml(READS_OUTPUT)
    data = reads_output(b"\x05")
    records, _ = interpreted(spec, data, Emit.FIELD)
    cites = {record.role: (record.off_start, record.off_end) for record in records}
    assert cites["reads.next"] == (1, len(data) - 1) == cites["reads.doc.v"]
