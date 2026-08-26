"""The shipped example specs must stay valid and keep decoding.

These are the specs a reader is pointed at, so they are worth more than a
comment. The captures they were written against live in a sibling checkout of
``python-zipline-wire``, which this suite deliberately does not depend on — the
buffers below are representative slices of that real traffic, kept inline so
the tests stand alone.
"""

from __future__ import annotations

import struct
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
    paths = [record.comment for record in emissions]
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
    assert tree.find("body") is None


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
    assert tree.find("body") is None, "the length framed the body"
    assert [c.find("length").value for c in tree.find("chunks").children] == [4, 0]
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
