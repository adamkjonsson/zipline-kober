"""The interpreter decodes `concat` and `transform` (the transform plan's Stage 4)."""

from __future__ import annotations

import gzip
import zlib

import pytest
from cipher import seal, xor_open

from kober.decoder import Decoder
from kober.emit import plan
from kober.errors import ParameterError, UnboundTransformError
from kober.loader import from_yaml
from kober.node import Node, NodeStatus
from kober.spec import Emit, Spec
from kober.transforms import Registry

#: A message framing its body two ways, and a transform over it: the shape the
#: spike found `http.yaml` needs.
MESSAGE = """
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
      - name: content
        transform: {{from: body, with: {codec}, limit: {limit}, {output}}}
      - {{name: after, bits: 8}}
  chunk:
    fields:
      - {{name: size, bits: 8}}
      - {{name: data, bytes: {{size: {{expr: size}}}}}}
  document:
    fields:
      - {{name: length, bits: 8}}
      - {{name: text, string: {{size: {{expr: length}}}}}}
"""

DOCUMENT = b"\x05hello"


def spec(
    codec: str = "gzip",
    limit: int = 4096,
    output: str = "type: {unit: document}",
    top: str = "",
) -> Spec:
    return from_yaml(MESSAGE.format(codec=codec, limit=limit, output=output, top=top))


def framed(body: bytes, after: int = 0x7E) -> bytes:
    """Frame ``body`` by its length, as a message."""
    return bytes([0, len(body)]) + body + bytes([after])


def chunked(body: bytes, sizes: list[int], after: int = 0x7E) -> bytes:
    """Frame ``body`` in chunks cut at ``sizes``, as a message."""
    out = bytearray([1, 0])
    at = 0
    for size in sizes:
        out += bytes([size]) + body[at : at + size]
        at += size
    out += bytes([0])
    return bytes(out) + bytes([after])


def content(tree: Node) -> Node:
    found = tree.find("content")
    assert found is not None, tree.render()
    return found


# --- decoding ---------------------------------------------------------------------------


def test_a_gzip_body_is_decoded_as_its_type_in_its_own_offset_space():
    body = gzip.compress(DOCUMENT, mtime=0)
    tree = Decoder(spec()).decode_bytes(framed(body), base=1000)
    assert tree.status is NodeStatus.OK, tree.render()
    node = content(tree)
    assert not node.failed
    assert (node.off_start, node.off_end) == (1002, 1002 + len(body)), "it cites its source"
    text = node.find("text")
    assert text is not None
    assert text.value == "hello"
    assert (text.off_start, text.off_end, text.space) == (1, 6, "content")


def test_a_chunked_body_is_joined_and_then_transformed():
    body = zlib.compress(DOCUMENT)
    tree = Decoder(spec(codec="deflate")).decode_bytes(chunked(body, [3, 4, len(body) - 7]))
    assert tree.status is NodeStatus.OK, tree.render()
    assert content(tree).find("text").value == "hello"


def test_a_concat_cites_its_non_empty_members_and_not_the_last_size_line():
    body = zlib.compress(DOCUMENT)
    data = chunked(body, [3, len(body) - 3])
    tree = Decoder(spec(codec="deflate")).decode_bytes(data)
    joined = tree.find("body")
    first_data = 2 + 1
    last_data_end = 2 + 1 + 3 + 1 + (len(body) - 3)
    assert (joined.off_start, joined.off_end) == (first_data, last_data_end)
    assert joined.value == body


def test_the_position_does_not_move_across_a_transform():
    """A transform reads nothing where it stands: the field after it reads the next byte."""
    body = gzip.compress(DOCUMENT, mtime=0)
    tree = Decoder(spec()).decode_bytes(framed(body, after=0x42))
    after = tree.find("after")
    assert after.value == 0x42
    assert after.off_start == 2 + len(body)
    assert tree.off_end == 2 + len(body) + 1


def test_a_typeless_transform_holds_its_output_as_bytes():
    body = gzip.compress(DOCUMENT, mtime=0)
    tree = Decoder(spec(output='content_type: "prim:bytes"')).decode_bytes(framed(body))
    assert content(tree).value == DOCUMENT


def test_a_scalar_typed_output_is_the_value_itself():
    body = gzip.compress(b"hello", mtime=0)
    built = spec(output="type: {string: {size: {remaining: true}}}")
    node = content(Decoder(built).decode_bytes(framed(body)))
    assert node.value == "hello"
    assert (node.off_start, node.off_end) == (2, 2 + len(body))


def test_a_pointer_in_an_output_is_measured_from_the_outputs_first_byte():
    """The output is a message of its own: its first byte is offset 0, wherever it came from."""
    built = from_yaml(
        MESSAGE.format(codec="gzip", limit=100, output="type: {unit: back}", top="")
        + """
  back:
    fields:
      - {name: tag, bits: 8}
      - {name: again, pointer: {at: "0", type: {bits: 8}}}
"""
    )
    tree = Decoder(built).decode_bytes(framed(gzip.compress(b"\x2a", mtime=0)), base=500)
    node = content(tree)
    assert not node.failed, node.render()
    again = node.find("again")
    assert again.value == 0x2A
    assert (again.off_start, again.space) == (0, "content")


# --- failure is contained (Decided 1) --------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "limit", "fragment"),
    [
        (b"not gzip at all", 4096, "gzip: not valid compressed data"),
        (gzip.compress(b"x" * 200, mtime=0), 100, "gzip: output passes its limit of 100 bytes"),
        (gzip.compress(b"\x09hi", mtime=0), 4096, "gzip output does not decode"),
        (
            gzip.compress(DOCUMENT + b"??", mtime=0),
            4096,
            "gzip output has 2 byte(s) its type does not read",
        ),
    ],
    ids=["codec", "limit", "short-output", "unread-tail"],
)
def test_a_failed_transform_leaves_its_message_whole(data: bytes, limit: int, fragment: str):
    """The message decodes whole; the transform node carries the failure (*Decided* 1, 2)."""
    tree = Decoder(spec(limit=limit)).decode_bytes(framed(data, after=0x42))
    assert tree.status is NodeStatus.OK, tree.render()
    node = content(tree)
    assert node.failed
    assert node.status is NodeStatus.OK
    assert node.value is None
    assert node.children == ()
    assert fragment in (node.detail or "")
    assert tree.find("after").value == 0x42, "the message goes on after it"


def test_a_short_read_inside_the_output_is_never_truncated():
    """`truncated` would claim the input was cut short, and it arrived whole (§11.5)."""
    tree = Decoder(spec()).decode_bytes(framed(gzip.compress(b"\x09hi", mtime=0)))
    assert all(node.status is not NodeStatus.TRUNCATED for node in tree.walk()), tree.render()


# --- arguments, parameters and a caller's cipher --------------------------------------------------

CIPHER = """
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


def cipher_decoder(key: bytes = KEY) -> Decoder:
    registry = Registry.standard()
    registry.register("xor", xor_open)
    return Decoder(from_yaml(CIPHER), params={"key": key}, transforms=registry)


def test_a_cipher_takes_its_key_from_a_document_param_and_its_nonce_from_a_field():
    datagram = NONCE + seal(b"inner packet", key=KEY, nonce=NONCE)
    tree = cipher_decoder().decode_bytes(datagram)
    assert tree.status is NodeStatus.OK, tree.render()
    assert tree.find("inner").value == b"inner packet"


def test_a_transform_cites_its_source_and_the_fields_its_arguments_read():
    """The nonce is the header, so the plaintext cites the whole datagram (*Decided* 3)."""
    datagram = NONCE + seal(b"inner packet", key=KEY, nonce=NONCE)
    inner = cipher_decoder().decode_bytes(datagram, base=40).find("inner")
    assert (inner.off_start, inner.off_end) == (40, 40 + len(datagram))


def test_the_wrong_key_fails_the_transform_and_never_shows_the_key():
    datagram = NONCE + seal(b"inner packet", key=KEY, nonce=NONCE)
    wrong = bytes(16)
    tree = cipher_decoder(wrong).decode_bytes(datagram)
    inner = tree.find("inner")
    assert inner.failed
    assert inner.detail == "xor: the transform raised ValueError"
    assert wrong.hex() not in tree.render()


@pytest.mark.parametrize(
    ("params", "error", "fragment"),
    [
        ({}, ParameterError, "needs parameter(s) 'key'"),
        ({"key": KEY, "colour": b"x"}, ParameterError, "'colour' are not declared"),
        ({"key": "not bytes"}, ParameterError, "parameter 'key' must be bytes, got str"),
    ],
    ids=["missing", "unknown", "wrong-type"],
)
def test_document_params_are_checked_before_any_input(params: dict, error: type, fragment: str):
    registry = Registry.standard()
    registry.register("xor", xor_open)
    with pytest.raises(error, match=fragment.replace("(", r"\(").replace(")", r"\)")):
        Decoder(from_yaml(CIPHER), params=params, transforms=registry)


def test_a_transform_nothing_binds_fails_when_the_decoder_is_built():
    """Once, before any input, not as an `undecodable` message after message (Q6)."""
    with pytest.raises(UnboundTransformError, match="'xor' is the spec's own"):
        Decoder(from_yaml(CIPHER), params={"key": KEY})


# --- the emitter, until Stage 5 -------------------------------------------------------------


def test_a_node_in_an_output_never_names_a_region_of_the_input():
    """The spike's false `truncated`: an inner node spanning as many bytes as the message.

    A message at offset 0 whose inner decode fails over exactly its own width
    was written `truncated` over bytes that arrived whole, because the region's
    reason was taken from the narrowest failing node over it, inner nodes
    included. Inner offsets mean nothing against the input.
    """
    built = from_yaml("""
name: t
version: "1"
entry: m
units:
  m:
    fields:
      - {name: n, bits: 8}
      - {name: body, bytes: {size: {expr: n}}}
      - {name: tag, bits: 8, const: 1}
""")
    data = bytes([2]) + b"ab" + bytes([9])
    tree = Decoder(built).decode_bytes(data)
    inner = Node("fake", off_start=0, off_end=4, status=NodeStatus.TRUNCATED, space="content")
    tree = Node(
        tree.name, off_start=tree.off_start, off_end=tree.off_end, status=tree.status,
        children=(*tree.children, inner), unit=tree.unit, detail=tree.detail,
    )
    _, regions = plan(built, tree, data, emit=Emit.MESSAGE)
    assert {region.reason for region in regions} == {"undecodable"}
