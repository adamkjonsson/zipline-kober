"""HTTP responses with compressed bodies, as packeteer messages.

packeteer's own HTTP payload cannot carry them: ``stream --payload http``
ignores ``--protocol-messages`` (packeteer#169). So the bytes go through a
one-field protocol of our own, ``blob.yaml``, and since a custom protocol's
message is always one TCP segment, the stream is cut into pieces here, which
is ``--mss`` done by hand and what puts a loss in the middle of a body.

``blob`` sends from one side only, so a stream is one direction of a
connection: responses, which is where a compressed body is. The first response
is a length-framed gzip body, so a stream's confirmation turns on one.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import zlib
from dataclasses import dataclass

#: The port the ``blob`` protocol claims: one packeteer's ``http`` does not.
PORT = 9480


@dataclass(frozen=True)
class Response:
    """One response in a generated stream, and what its body inflates to.

    Attributes:
        coding: ``gzip``, ``deflate`` (zlib, as HTTP means it) or ``identity``.
        framing: ``length`` or ``chunked``.
        document: The body before encoding.

    """

    coding: str
    framing: str
    document: bytes

    @property
    def digest(self) -> str:
        """The SHA-256 of the document, to compare an inflated body with."""
        return hashlib.sha256(self.document).hexdigest()


def _document(rng: random.Random) -> bytes:
    """Return a JSON document of a random size, some many pieces long."""
    rows = rng.choice([1, 3, 10, 40, 150])
    items = [
        {"id": index, "name": f"item-{rng.randrange(10**6)}", "v": rng.random()}
        for index in range(rows)
    ]
    return json.dumps(items).encode() + b"\n"


def _encode(coding: str, document: bytes) -> bytes:
    if coding == "gzip":
        return gzip.compress(document, mtime=0)
    if coding == "deflate":
        return zlib.compress(document)
    return document


def _chunked(body: bytes, rng: random.Random, *, trailer: bool) -> bytes:
    """Frame ``body`` in chunks of random sizes, with a trailer section or none."""
    out = bytearray()
    at = 0
    while at < len(body):
        size = min(rng.randint(8, 400), len(body) - at)
        out += f"{size:x}\r\n".encode() + body[at : at + size] + b"\r\n"
        at += size
    out += b"0\r\n"
    if trailer:
        out += b"X-Checksum: " + hashlib.sha256(body).hexdigest()[:16].encode() + b"\r\n"
    return bytes(out + b"\r\n")


def build(count: int, seed: int) -> tuple[bytes, list[Response]]:
    """Return a stream of ``count`` responses, and what each carries.

    Args:
        count: How many responses.
        seed: For the random choices, so a stream is the same every run.

    Returns:
        The bytes, and the responses in order.

    """
    rng = random.Random(seed)
    stream = bytearray()
    responses: list[Response] = []
    for index in range(count):
        document = _document(rng)
        coding = rng.choice(["gzip", "gzip", "deflate", "identity"])
        framing = rng.choice(["length", "chunked"])
        if index == 0:
            coding, framing = "gzip", "length"
        trailer = framing == "chunked" and rng.random() < 0.5
        encoded = _encode(coding, document)
        head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        if coding != "identity":
            head += f"Content-Encoding: {coding}\r\n"
        if framing == "chunked":
            head += "Transfer-Encoding: chunked\r\n"
            body = _chunked(encoded, rng, trailer=trailer)
        else:
            head += f"Content-Length: {len(encoded)}\r\n"
            body = encoded
        stream += head.encode() + b"\r\n" + body
        responses.append(Response(coding, framing, document))
    return bytes(stream), responses


def messages(stream: bytes, piece: int = 200) -> list[dict[str, str]]:
    """Cut a stream into ``blob`` messages of at most ``piece`` bytes.

    Args:
        stream: The bytes.
        piece: The most bytes per message, and so per TCP segment.

    Returns:
        packeteer's ``--protocol-messages`` sections, in order.

    """
    return [{"data": stream[at : at + piece].hex()} for at in range(0, len(stream), piece)]
