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
    assert [label.find("text").value for label in labels] == ["example", "com", ""]


def test_dns_field_paths_are_readable():
    """Real nesting: a repeated question holding a repeated label."""
    spec = load("dns.yaml")
    tree = Decoder(spec).decode_bytes(DNS_QUERY)
    emissions, _ = plan(spec, tree, DNS_QUERY, emit=Emit.FIELD)
    paths = [record.comment for record in emissions]
    assert "dns.flags.qr" in paths
    assert "dns.questions[0].qname.labels[0].text" in paths
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
    lines = [h.find("line").value for h in tree.find("headers").children]
    assert lines == ["Host: httpforever.com", "Accept: */*", ""]


def test_http_body_is_whatever_remains():
    """Honest for this shape, and wrong in general — see the spec's own doc."""
    spec = load("http.yaml")
    tree = Decoder(spec).decode_bytes(HTTP_REQUEST + b"leftover")
    assert tree.find("body").value == b"leftover"
