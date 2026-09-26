"""What a stage writes for a transform, and what the driver does with one (Stage 5).

Every file is written twice, by the interpreter and by a generated module
(Stage 6), and the two must be the same file. Every file here must be
conformant and account for every input byte.
"""

from __future__ import annotations

import gzip
import sys
from pathlib import Path
from types import ModuleType

import pytest
from cipher import seal, xor_open
from test_stage import datagrams, write_transport
from zpfcompare import assert_conformant, blocks

from kober import stage, transforms
from kober.cursor import Cursor
from kober.decoder import Decoder
from kober.loader import from_yaml
from kober.pygen import render_spec
from kober.spec import Emit, Spec
from kober.transforms import Registry

MESSAGE = """
name: t
version: "1"
entry: message
units:
  message:
    fields:
      - {{name: n, bits: 8}}
      - {{name: body, bytes: {{size: {{expr: n}}}}}}
      - name: content
        transform: {{from: body, with: gzip, limit: 4096, {output}}}{emit}
      - {{name: after, bits: 8}}
  document:
    fields:
      - {{name: length, bits: 8}}
      - {{name: text, string: {{size: {{expr: length}}}}}}
"""


def spec(output: str = "type: {unit: document}", emit: str = "") -> Spec:
    return from_yaml(MESSAGE.format(output=output, emit=emit))


def message(document: bytes = b"\x05hello", *, corrupt: bool = False) -> bytes:
    body = bytearray(gzip.compress(document, mtime=0))
    if corrupt:
        for index in range(12, 18):
            body[index] ^= 0x5A
    return bytes([len(body)]) + bytes(body) + b"\x7e"


def compiled(built: Spec, emit: Emit, registry: Registry | None) -> ModuleType:
    """Import a generated module, binding its transforms in ``registry``.

    A module binds when it is imported, from :data:`kober.transforms.DEFAULT`,
    so a caller's registry stands in for it while that happens.
    """
    module = ModuleType(f"t_{built.name}_{emit.value}_{len(sys.modules)}")
    sys.modules[module.__name__] = module
    default = transforms.DEFAULT
    if registry is not None:
        transforms.DEFAULT = registry
    try:
        exec(render_spec(built, emit=emit), module.__dict__)
    finally:
        transforms.DEFAULT = default
    return module


def decode(
    built: Spec,
    source: Path,
    tmp_path: Path,
    emit: Emit = Emit.FIELD,
    *,
    params: dict[str, object] | None = None,
    transforms: Registry | None = None,
) -> list[tuple[object, ...]]:
    """Decode with both drivers, require the same file, and return what it says."""
    sink = tmp_path / f"out.{emit.value}.zpf"
    Decoder(built, emit=emit, params=params, transforms=transforms).run(
        source, sink, produced_by="t", produced_at=1
    )
    assert_conformant(sink, source)
    other = tmp_path / f"compiled.{emit.value}.zpf"
    module = compiled(built, emit, transforms)
    stage.run_compiled(module, source, other, produced_by="t", produced_at=1, params=params)
    written = blocks(sink)
    assert blocks(other) == written
    return [block for block in written if block[0] != "participant"]


def records(written: list[tuple[object, ...]]) -> list[tuple[object, object]]:
    """Return each record as ``(role, spans)``."""
    return [(block[2], block[4]) for block in written if block[0] == "record"]


def regions(written: list[tuple[object, ...]]) -> list[tuple[object, ...]]:
    """Return each region as ``(start, end, reason, comment)``."""
    return [(b[2], b[3], b[1], b[4]) for b in written if b[0] == "undecoded"]


# --- what a successful transform writes -----------------------------------------------------


def test_an_outputs_records_cite_the_source_and_the_source_is_not_written_itself(
    tmp_path: Path,
):
    """*Decided* 1a: the output speaks for its source's bytes."""
    data = message()
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, data, 1001)])
    written = decode(spec(), source, tmp_path)
    body = (1, len(data) - 1)
    assert records(written) == [
        ("t.n", ((0, 1),)),
        ("t.content.length", (body,)),
        ("t.content.text", (body,)),
        ("t.after", ((len(data) - 1, len(data)),)),
    ]
    assert regions(written) == []


def test_a_typeless_outputs_record_carries_its_content_type(tmp_path: Path):
    data = message()
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, data, 1001)])
    written = decode(spec(output='content_type: "mime:application/octet-stream"'), source, tmp_path)
    content = [block for block in written if block[0] == "record" and block[2] == "t.content"]
    assert len(content) == 1
    assert content[0][1] == "mime:application/octet-stream"
    assert content[0][3] == b"\x05hello"
    assert content[0][4] == ((1, len(data) - 1),)


def test_emit_none_on_a_transform_names_its_source_skipped(tmp_path: Path):
    data = message()
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, data, 1001)])
    written = decode(spec(emit="\n        emit: none"), source, tmp_path)
    assert (1, len(data) - 1, "skipped", None) in regions(written)
    assert all(not str(role).startswith("t.content") for role, _ in records(written))


def test_message_granularity_writes_the_message_whole(tmp_path: Path):
    """At this granularity a failed body is below the file's resolution (*Decided* 1d)."""
    good, bad = message(), message(corrupt=True)
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, good + bad, 1001)])
    written = decode(spec(), source, tmp_path, emit=Emit.MESSAGE)
    assert [spans for _, spans in records(written)] == [
        ((0, len(good)),),
        ((len(good), len(good) + len(bad)),),
    ]
    assert regions(written) == []


# --- a transform that fails (Decided 1) ---------------------------------------------------------


def test_a_failed_transform_names_its_source_and_the_stream_goes_on(tmp_path: Path):
    good, bad = message(), message(corrupt=True)
    stream = good + bad + good
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, stream, 1001)])
    written = decode(spec(), source, tmp_path)
    start = len(good)
    assert regions(written) == [(start + 1, start + len(bad) - 1, "undecodable", None)]
    texts = [spans for role, spans in records(written) if role == "t.content.text"]
    assert len(texts) == 2, "the message after the failure is decoded"
    afters = [spans for role, spans in records(written) if role == "t.after"]
    assert len(afters) == 3, "the failed message's framing is written"


def test_a_first_message_whose_transform_fails_does_not_decline_the_stream(tmp_path: Path):
    """It neither confirms nor declines: the next whole message confirms it."""
    bad, good = message(corrupt=True), message()
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, bad + good, 1001)])
    written = decode(spec(), source, tmp_path)
    assert regions(written) == [(1, len(bad) - 1, "undecodable", None)]
    assert ("t.n", ((0, 1),)) in records(written), "the held first message is released"


def test_a_stream_where_every_transform_fails_is_declined_saying_so(tmp_path: Path):
    """*Decided* 1e: what a wrong key looks like, worded as what was seen."""
    bad = message(corrupt=True)
    source = tmp_path / "in.zpf"
    write_transport(source, [(1000, bad + bad, 1001)])
    written = decode(spec(), source, tmp_path)
    assert records(written) == []
    assert {region[3] for region in regions(written)} == {
        "not t: every message that decoded had a transform fail; the first: "
        "gzip: not valid compressed data"
    }


def test_the_interpreted_step_reports_a_failed_transform_as_its_own_verdict():
    class Sink:
        def record(self, *_: object) -> None: ...
        def undecoded(self, *_: object) -> None: ...

    data = message(corrupt=True)
    verdict = stage._interpreted(Decoder(spec()))(Cursor(data, 0), Sink(), data, 0)
    assert verdict is not None
    assert verdict.reason == stage.TRANSFORM_FAILED


# --- a cipher over datagrams: the tunnel's shape (acceptance 2) ---------------------------------

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
        transform:
          from: sealed
          with: xor
          limit: 1500
          args: {key: key, nonce: nonce}
          content_type: "dec:ip-packet"
"""
KEY = bytes(range(16))


def sealed(payload: bytes, index: int, *, corrupt: bool = False) -> bytes:
    nonce = f"nonce-{index:02d}".encode()
    body = bytearray(seal(payload, key=KEY, nonce=nonce))
    if corrupt:
        body[0] ^= 0xFF
    return nonce + bytes(body)


@pytest.mark.parametrize("corrupt", [0, 2], ids=["first-corrupt", "third-corrupt"])
def test_a_tunnel_writes_one_plaintext_per_datagram_citing_the_datagram(
    tmp_path: Path, corrupt: int
):
    """One record per datagram, citing the datagram; a failed one named; the next decoded."""
    registry = Registry.standard()
    registry.register("xor", xor_open)
    payloads = [f"packet {i}".encode() for i in range(4)]
    wire = [sealed(p, i, corrupt=i == corrupt) for i, p in enumerate(payloads)]
    source = tmp_path / "in.zpf"
    datagrams(source, wire)
    written = decode(
        from_yaml(TUNNEL), source, tmp_path, params={"key": KEY}, transforms=registry
    )
    offsets = [sum(len(d) for d in wire[:i]) for i in range(len(wire) + 1)]
    plain = [(b[3], b[4]) for b in written if b[0] == "record" and b[2] == "tunnel.inner"]
    assert plain == [
        (payloads[i], ((offsets[i], offsets[i + 1]),)) for i in range(4) if i != corrupt
    ]
    assert regions(written) == [
        (offsets[corrupt] + 8, offsets[corrupt + 1], "undecodable", None)
    ]
    assert KEY.hex() not in repr(written)
