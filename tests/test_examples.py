"""The shipped example specs must stay valid and keep decoding.

These are the specs a reader is pointed at, so they are worth more than a
comment. The captures they were written against live in a sibling checkout of
``python-zipline-wire``, which this suite deliberately does not depend on — the
buffers below are representative slices of that real traffic, kept inline so
the tests stand alone.
"""

from __future__ import annotations

import gzip
import struct
import zlib
from pathlib import Path

import pytest

from kober.check import Severity, check
from kober.decoder import Decoder
from kober.emit import plan
from kober.node import NodeStatus
from kober.spec import Emit, Spec

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

# A real query from python-zipline-wire's dns_example.pcapng, shortened to one
# label so it stays readable.
DNS_QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

HTTP_REQUEST = b"GET / HTTP/1.1\r\nHost: httpforever.com\r\nAccept: */*\r\n\r\n"


def load(name: str) -> Spec:
    return Spec.from_file(EXAMPLES / name)


def names() -> list[str]:
    return sorted(path.name for path in EXAMPLES.glob("*.yaml"))


def test_there_are_examples():
    assert names(), "examples/ should not be empty"


@pytest.mark.parametrize("name", names())
def test_every_example_checks_clean(name: str):
    """An example that does not check is worse than no example."""
    findings = check(load(name))
    errors = [f for f in findings if f.severity is Severity.ERROR]
    assert errors == [], f"{name}: {[str(f) for f in errors]}"


@pytest.mark.parametrize("name", names())
def test_every_example_has_documentation(name: str):
    """These are read as much as run."""
    spec = load(name)
    assert spec.doc, f"{name} has no doc"


# --- dns.yaml --------------------------------------------------------------


def test_dns_decodes_a_real_query():
    spec = load("dns.yaml")
    tree = Decoder(spec).decode_bytes(DNS_QUERY)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(DNS_QUERY)
    assert tree.find("id").value == 0x1234
    assert tree.find("flags").find("rd").value == 1
    assert tree.find("qdcount").value == 1


def test_dns_decodes_a_name_as_labels():
    spec = load("dns.yaml")
    tree = Decoder(spec).decode_bytes(DNS_QUERY)
    question = tree.find("questions").children[0]
    labels = question.find("qname").find("labels").children
    assert [label.find("rest").value for label in labels] == ["example", "com", ""]


def test_dns_field_paths_are_readable():
    """Real nesting: a repeated question holding a repeated label."""
    spec = load("dns.yaml")
    tree = Decoder(spec).decode_bytes(DNS_QUERY)
    emissions, _ = plan(spec, tree, DNS_QUERY, emit=Emit.FIELD)
    paths = [record.role for record in emissions]
    assert "dns.flags.qr" in paths
    assert "dns.questions[0].qname.labels[0].rest" in paths
    assert not any("questions.questions" in path for path in paths)


def test_dns_covers_every_byte():
    spec = load("dns.yaml")
    tree = Decoder(spec).decode_bytes(DNS_QUERY)
    emissions, unclaimed = plan(spec, tree, DNS_QUERY, emit=Emit.FIELD)
    seen: set[int] = set()
    for record in emissions:
        seen.update(range(record.off_start, record.off_end))
    for region in unclaimed:
        seen.update(range(region.off_start, region.off_end))
    assert seen == set(range(len(DNS_QUERY)))


# --- http.yaml -------------------------------------------------------------


def test_http_decodes_a_real_request():
    spec = load("http.yaml")
    tree = Decoder(spec).decode_bytes(HTTP_REQUEST)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(HTTP_REQUEST)
    assert tree.find("start_line").value == "GET / HTTP/1.1"


def test_http_reads_headers_up_to_the_blank_line():
    spec = load("http.yaml")
    tree = Decoder(spec).decode_bytes(HTTP_REQUEST)
    pairs = [
        (h.find("name").value, h.find("value").value)
        for h in tree.find("headers").children
    ]
    assert pairs == [("Host", " httpforever.com"), ("Accept", " */*"), ("", "")]


def test_http_trims_the_whitespace_a_field_value_is_allowed():
    """Regression, and the one "no undecoded regions" could not have caught.

    RFC 7230 §3.2.3 permits optional whitespace after the colon, so the value
    read is ``" chunked"``. `to_int` strips it on the way past, which is why a
    length needs nothing — but a string *comparison* has nothing to strip it,
    and without `trim` this answered false on every real chunked message.

    What made it hide is worth keeping in view: the spec still accounted for
    every byte, because the driver read the unframed chunk body as further
    messages and those cited it. Coverage stayed whole while the decode was
    wrong, which is why this asserts the *shape* and not the byte count.
    """
    spec = load("http.yaml")
    for spacing in (b"", b" ", b"   "):
        message = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding:" + spacing + b"chunked\r\n\r\n"
            b"4\r\nabcd\r\n0\r\n\r\n"
        )
        tree = Decoder(spec).decode_bytes(message)
        assert tree.find("chunked").value is True, spacing
        assert tree.off_end == len(message), spacing
        assert [c.find("length").value for c in tree.find("chunks").children] == [4, 0]


def test_http_reads_a_whole_chunked_response_and_nothing_after_it():
    """The acceptance criterion a record count cannot state.

    A message that stops early leaves its body to the driver, which decodes it
    as more messages — every byte cited, nothing marked undecoded, and the
    decode nonsense. So this asserts that one message consumed the whole thing.
    """
    spec = load("http.yaml")
    body = b"".join(
        f"{len(part):x}\r\n".encode() + part + b"\r\n"
        for part in (b"x" * 0x1A, b"y" * 3)
    )
    message = (
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: keep-alive\r\n\r\n" + body + b"0\r\n\r\n"
    )
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(message), "the body was left to the driver"
    assert [c.find("data").value for c in tree.find("chunks").children] == [
        b"x" * 0x1A,
        b"y" * 3,
        b"",
    ]


def test_http_frames_a_chunked_body():
    """Chosen, not assumed: the spec asks whether any header said `chunked`."""
    spec = load("http.yaml")
    head = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    body = b"1a\r\n" + b"x" * 0x1A + b"\r\n" + b"0\r\n\r\n"
    tree = Decoder(spec).decode_bytes(head + body)
    assert tree.status is NodeStatus.OK
    assert tree.find("chunked").value is True
    chunks = tree.find("chunks").children
    assert [chunk.find("length").value for chunk in chunks] == [0x1A, 0]
    assert chunks[0].find("data").value == b"x" * 0x1A
    assert tree.find("body").value == b"x" * 0x1A, "the body is the chunks' data, joined"


def test_http_frames_a_body_by_its_content_length():
    """The case the spec could not read at all until it could ask the headers."""
    spec = load("http.yaml")
    message = b"POST /x HTTP/1.1\r\nContent-Length: 4\r\nHost: h\r\n\r\nbody"
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.find("content_length").value == 4
    assert tree.find("body").value == b"body"
    assert tree.off_end == len(message)


def test_http_reads_no_body_when_no_header_declares_one():
    """Two fifths of real traffic, and the case that used to invent a hole.

    A body that is not chunk-formatted has no size line, so the read for one
    came back `truncated` — a **hole**-class reason, which says the stream had
    a gap when it did not. Nothing is read now, because nothing said there was
    anything to read.
    """
    spec = load("http.yaml")
    tree = Decoder(spec).decode_bytes(HTTP_REQUEST)
    assert tree.status is NodeStatus.OK
    assert tree.find("content_length").value == -1
    assert tree.find("chunked").value is False
    assert tree.find("body") is None
    assert tree.find("chunks") is None
    assert tree.off_end == len(HTTP_REQUEST)


def test_http_tells_a_declared_empty_body_from_no_declaration():
    """Why the sentinel is -1 and not 0: `Content-Length: 0` is a real header."""
    spec = load("http.yaml")
    declared = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    tree = Decoder(spec).decode_bytes(declared)
    assert tree.find("content_length").value == 0
    assert Decoder(spec).decode_bytes(HTTP_REQUEST).find("content_length").value == -1


def test_http_lets_chunked_win_over_a_content_length():
    """RFC 7230 §3.3.3, and reading the length instead is the smuggling reading."""
    spec = load("http.yaml")
    message = (
        b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"
    )
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.find("body").value == b"abcd", "the length framed the body"
    assert [c.find("length").value for c in tree.find("chunks").children] == [4, 0]
    assert tree.off_end == len(message)


def test_http_reads_a_trailer_section_after_the_last_chunk():
    """Regression, and the second bug of exactly the shape coverage cannot see.

    RFC 7230 §4.1 ends a chunked body with `trailer-part CRLF`, and the
    terminating chunk carries no CRLF of its own. The spec read two bytes after
    every chunk's data, so on a body with trailers it ate the first two bytes of
    the first trailer line and left the rest to the driver, which decoded it as
    further messages. Every byte stayed cited, nothing was marked undecoded, and
    the decode was nonsense.

    Found by `packeteer` 0.9.0's `--trailer-rate`, which is traffic no capture in
    reach could supply — the sixteen real ones hold one chunked message between
    them, and it has no trailer.
    """
    spec = load("http.yaml")
    message = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
        b"Trailer: X-Checksum\r\n\r\n"
        b"4\r\nabcd\r\n0\r\nX-Checksum: deadbeef\r\n\r\n"
    )
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(message), "the trailer was left to the driver"
    assert [c.find("length").value for c in tree.find("chunks").children] == [4, 0]
    pairs = [
        (f.find("name").value, f.find("value").value)
        for f in tree.find("trailers").find("fields").children
    ]
    assert pairs == [("X-Checksum", " deadbeef"), ("", "")]


def test_http_reads_a_chunked_body_whose_trailer_section_is_empty():
    """The common case, and what makes the terminating CRLF need no special case.

    With no trailers the section is one empty element and the two bytes it
    consumes are the body's final CRLF. This is the half that used to work by
    coincidence — the chunk CRLF happened to swallow exactly those two bytes —
    so it is worth pinning now that the coincidence is gone.
    """
    spec = load("http.yaml")
    message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(message)
    pairs = [
        (f.find("name").value, f.find("value").value)
        for f in tree.find("trailers").find("fields").children
    ]
    assert pairs == [("", "")]


def test_http_reads_no_trailer_section_on_a_counted_body():
    """The section belongs to chunked framing, so a counted message has none."""
    spec = load("http.yaml")
    message = b"POST /x HTTP/1.1\r\nContent-Length: 4\r\nHost: h\r\n\r\nbody"
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.find("trailers") is None
    assert tree.off_end == len(message)


def test_http_matches_a_header_name_whatever_its_case():
    """RFC 7230 §3.2 says the names are case-insensitive, so the spec says `lower`."""
    spec = load("http.yaml")
    for spelling in (b"Content-Length", b"content-length", b"CONTENT-LENGTH"):
        message = b"POST / HTTP/1.1\r\n" + spelling + b": 2\r\n\r\nhi"
        tree = Decoder(spec).decode_bytes(message)
        assert tree.find("body").value == b"hi", spelling


def test_http_keeps_a_header_whose_value_is_empty_apart_from_the_blank_line():
    """Which is why the repeat tests both halves rather than the name alone."""
    spec = load("http.yaml")
    tree = Decoder(spec).decode_bytes(b"GET / HTTP/1.1\r\nX-Trace:\r\n\r\n")
    assert tree.status is NodeStatus.OK
    pairs = [
        (h.find("name").value, h.find("value").value)
        for h in tree.find("headers").children
    ]
    assert pairs == [("X-Trace", ""), ("", "")]


def test_http_decodes_several_messages_from_one_run():
    """Real captures pipeline fifty to a run, and exact framing is what allows it."""
    spec = load("http.yaml")
    from kober.cursor import Cursor

    second = b"POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody"
    run = HTTP_REQUEST + second + HTTP_REQUEST
    cursor = Cursor(run)
    decoder = Decoder(spec)
    ends = []
    while not cursor.at_end():
        tree = decoder.decode_one(cursor)
        assert tree.status is NodeStatus.OK
        ends.append(tree.off_end)
    assert ends == [
        len(HTTP_REQUEST),
        len(HTTP_REQUEST) + len(second),
        len(run),
    ]


# --- the start line, and chunked as the last coding (#50) --------------------


@pytest.mark.parametrize(
    "value",
    [b"chunked", b"gzip, chunked", b"gzip,chunked", b" Gzip,  Chunked ", b"x-custom, chunked"],
)
def test_http_reads_chunked_when_it_is_the_last_coding(value: bytes):
    """RFC 7230 §3.3.1: `chunked` is the final coding, and may follow others.

    `gzip, chunked` used to read as unframed, because saying *ends with* needed
    a function the language did not have (#50).
    """
    spec = load("http.yaml")
    message = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: " + value + b"\r\n\r\n"
        b"4\r\nabcd\r\n0\r\n\r\n"
    )
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.find("chunked").value is True, value
    assert tree.off_end == len(message), value


@pytest.mark.parametrize("value", [b"xchunked", b"chunked, gzip", b"gzip"])
def test_http_does_not_read_chunked_when_it_is_not_the_last_coding(value: bytes):
    """A coding that merely ends in the same letters, or chunked not last, is not chunked."""
    spec = load("http.yaml")
    message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: " + value + b"\r\n\r\n"
    tree = Decoder(spec).decode_bytes(message)
    assert tree.find("chunked").value is False, value


@pytest.mark.parametrize(
    "line",
    [b"HTTP/1.1 200 OK", b"HTTP/1.0 404 Not Found", b"GET / HTTP/1.1", b"POST /x?y HTTP/1.0"],
)
def test_http_believes_a_start_line_that_looks_like_one(line: bytes):
    tree = Decoder(load("http.yaml")).decode_bytes(line + b"\r\n\r\n")
    assert tree.status is NodeStatus.OK, line


@pytest.mark.parametrize(
    "line",
    [b"19", b"", b'"v": 0.29}, {"id": 27}', b"\x13*FIC HTTP/1.1 200 OK x", b"GET / HTTP/2"],
)
def test_http_refuses_a_start_line_that_does_not_look_like_one(line: bytes):
    """What a run after a gap starts with: a chunk size, a blank line, a body's tail.

    Each decodes whole as a message with no headers, so without the `confirm`
    it was believed and written (#49's remaining phantoms). HTTP/2 has no text
    start line to recognise, and is refused with them.
    """
    tree = Decoder(load("http.yaml")).decode_bytes(line + b"\r\n\r\n")
    assert tree.status is NodeStatus.UNDECODABLE, line
    assert tree.detail == "unit 'message' did not confirm"


# --- the content a Content-Encoding compressed (the transform phase) ------------------


def encoded(coding: bytes, body: bytes, *, chunked: bool = False) -> bytes:
    """Frame an HTTP response carrying ``body`` under ``coding``, by length or in chunks."""
    head = b"HTTP/1.1 200 OK\r\nContent-Encoding: " + coding + b"\r\n"
    if not chunked:
        return head + b"Content-Length: %d\r\n\r\n" % len(body) + body
    half = len(body) // 2
    parts = b"".join(b"%x\r\n" % len(p) + p + b"\r\n" for p in (body[:half], body[half:]))
    return head + b"Transfer-Encoding: chunked\r\n\r\n" + parts + b"0\r\n\r\n"


HTML = b"<html><body>hello, inflated world</body></html>"


@pytest.mark.parametrize("chunked", [False, True], ids=["length", "chunked"])
@pytest.mark.parametrize(
    ("coding", "body"),
    [
        (b"gzip", gzip.compress(HTML, mtime=0)),
        (b"x-gzip", gzip.compress(HTML, mtime=0)),
        (b" Gzip", gzip.compress(HTML, mtime=0)),
        (b"deflate", zlib.compress(HTML)),
    ],
    ids=["gzip", "x-gzip", "spaced-and-cased", "deflate"],
)
def test_http_inflates_the_content_however_the_body_was_framed(
    coding: bytes, body: bytes, chunked: bool
):
    """HTTP's `deflate` is zlib (RFC 1950), which is the transform `deflate` too."""
    message = encoded(coding, body, chunked=chunked)
    tree = Decoder(load("http.yaml")).decode_bytes(message)
    assert tree.status is NodeStatus.OK, tree.render()
    assert tree.off_end == len(message)
    assert tree.find("body").value == body
    content = tree.find("content")
    assert not content.failed, content.detail
    assert content.value == HTML


def test_http_content_speaks_for_the_body_at_field_granularity():
    """The body's record is taken over; the content's cites the body's bytes."""
    spec = load("http.yaml")
    body = gzip.compress(HTML, mtime=0)
    message = encoded(b"gzip", body)
    records, regions = plan(spec, Decoder(spec).decode_bytes(message), message, emit=Emit.FIELD)
    roles = {record.role: record for record in records}
    assert "http.body" not in roles
    assert roles["http.content"].payload == HTML
    start = len(message) - len(body)
    assert (roles["http.content"].off_start, roles["http.content"].off_end) == (start, len(message))
    assert regions == []


@pytest.mark.parametrize("chunked", [False, True], ids=["length", "chunked"])
def test_http_names_a_body_that_does_not_inflate_and_goes_on(chunked: bool):
    """*Decided* 1: the message decodes whole, the body's bytes are `undecodable`."""
    spec = load("http.yaml")
    message = encoded(b"gzip", b"this is not gzip data", chunked=chunked)
    tree = Decoder(spec).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.off_end == len(message)
    assert tree.find("content").detail == "gzip: not valid compressed data"
    records, regions = plan(spec, tree, message, emit=Emit.FIELD)
    assert all(region.reason == "undecodable" for region in regions)
    assert sum(r.off_end - r.off_start for r in regions) == len(b"this is not gzip data")
    assert not any(r.role.endswith(".data") or r.role == "http.body" for r in records)


@pytest.mark.parametrize(
    "message",
    [
        b"HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
    ],
    ids=["no-body", "empty-body"],
)
def test_http_inflates_nothing_where_there_is_no_body(message: bytes):
    """A `304` or a `HEAD` reply states the coding of a body it does not send."""
    tree = Decoder(load("http.yaml")).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.find("content") is None


@pytest.mark.parametrize("coding", [b"br", b"zstd", b"gzip, br", b"identity"])
def test_http_leaves_a_coding_it_does_not_decode_as_it_arrived(coding: bytes):
    """`br` is extended and unbound here; a list of codings is not one coding."""
    message = encoded(coding, b"opaque bytes")
    tree = Decoder(load("http.yaml")).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.find("content") is None
    assert tree.find("body").value == b"opaque bytes"


def test_http_reads_two_transfer_encoding_headers_as_one_list():
    """RFC 7230 §3.3.1: `gzip` then `chunked` is `gzip, chunked`, so the body is chunked."""
    message = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\nabcd\r\n0\r\n\r\n"
    )
    tree = Decoder(load("http.yaml")).decode_bytes(message)
    assert tree.status is NodeStatus.OK
    assert tree.find("framing").value == "chunked"
    assert tree.find("body").value == b"abcd"
