"""The deeper pipeline: real and generated captures, through both drivers.

The in-suite tests cannot reach the stage driver with real stream structure —
gaps, truncated messages between whole ones, many records per run — and that is
where the seam bug lived. This script is the release checklist's requirement
(``docs/dev/contributing.md``, *Before a release*) as one command::

    .venv/bin/python tools/pipeline.py

It needs two sibling checkouts with their own virtual environments, neither a
dependency of this project: ``packeteer`` 0.18.0 or later (to fuzz and generate
traffic, a WireGuard tunnel's included) and ``python-zipline-wire`` 0.5.0 or
later (``zpfwire``, to turn captures into ``.zpf``, and a tunnel's decrypted
packets back into conversations).

For each input it builds, it runs every example spec through the interpreter
(:func:`kober.stage.run`) and through a module compiled fresh from the same spec
(:func:`kober.stage.run_compiled`), at message and at field granularity. Every
output must pass ``zpf`` conformance and account for every byte of its input;
every interpreter/compiled pair must be identical block for block, as
``tests/zpfcompare.py`` defines it; and where an input carries a protocol whose
shape can be counted, the counts must be plausible. Coverage alone cannot tell a
chunked body from twenty imaginary messages (``docs/dev/testing.md``, *A byte
count is not a criterion*), so the shape is asserted too — as relations that
survive a change in the generator's bytes, not as remembered totals.

It prints one line per check and exits non-zero if any failed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import zpf
from zpf.blocks import Participant, Record, Undecoded
from zpf.reassembly import Gap

from kober.decoder import Decoder
from kober.errors import SpecError
from kober.pygen import render_spec
from kober.spec import Emit, InputShape, Spec
from kober.stage import run, run_compiled

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent

#: The specs every input is run through, every one over every input: a spec
#: meeting a stream in another protocol is a case the driver has to handle too.
#: WireGuard's is given the input's key log, or an empty table where there is
#: none, so it meets traffic it holds no keys for as well.
SPECS = {
    "dns": ROOT / "examples" / "dns.yaml",
    "http": ROOT / "examples" / "http.yaml",
    "wireguard": ROOT / "examples" / "wireguard" / "wireguard.yaml",
}

#: The WireGuard example, whose transform and tunnel module the pipeline loads.
WIREGUARD = ROOT / "examples" / "wireguard"

#: Requests in the generated HTTP stream, so the shape check knows how many start
#: lines there can be: one request and one response each.
HTTP_REQUESTS = 30

#: What an HTTP/1.x start line looks like: a status line, or a request line
#: ending in the version. Written here, not taken from the spec, so a spec that
#: stops recognising its own start lines is caught rather than trusted.
HTTP_START_LINE = re.compile(rb"^(HTTP/1\.[01] \d{3}( .*)?|[!-~]+ \S+ HTTP/1\.[01])$")

#: Real captures from ``python-zipline-wire``. Only ``http_stream_1`` is one of
#: the example protocols; the other three are there for their loss and
#: reordering, which is driver structure no generated input reproduces as well.
CAPTURES = ("packet_loss", "http_stream_1", "tcp_lossy_ts", "tcp_reorder_ts")

PRODUCED_BY = "kober pipeline"
PRODUCED_AT = 1_700_000_000


# --- the tools --------------------------------------------------------------


@dataclass(frozen=True)
class Tools:
    """Where the sibling checkouts are, and the commands this script runs."""

    packeteer: Path
    wire: Path

    @property
    def packeteer_bin(self) -> Path:
        """The ``packeteer`` executable in its checkout's venv."""
        return self.packeteer / ".venv" / "bin" / "packeteer"

    @property
    def zpfwire_bin(self) -> Path:
        """The ``zpfwire`` executable in its checkout's venv."""
        return self.wire / ".venv" / "bin" / "zpfwire"

    @property
    def captures(self) -> Path:
        """The real captures ``python-zipline-wire`` keeps for its own tests."""
        return self.wire / "tests" / "captures"

    def missing(self) -> list[str]:
        """Return what this script needs and cannot find."""
        wanted = [self.packeteer_bin, self.zpfwire_bin, self.captures]
        return [str(path) for path in wanted if not path.exists()]

    def version(self, binary: Path) -> str:
        """Return what a tool says its version is."""
        return _run([str(binary), "--version"]).strip()

    def packeteer_cmd(self, *args: str) -> None:
        """Run ``packeteer`` with the given arguments."""
        _run([str(self.packeteer_bin), *args])

    def convert(self, capture: Path, out: Path) -> None:
        """Turn a capture into a transport-level ``.zpf``."""
        _run([str(self.zpfwire_bin), "convert", str(capture), "-o", str(out)])

    def sessionize(self, packets: Path, out: Path, content_type: str) -> None:
        """Turn a ``.zpf`` of decrypted packets into the conversations inside (zpfwire#35)."""
        _run(
            [
                str(self.zpfwire_bin), "convert", str(packets), "-o", str(out),
                "--content-type", content_type,
            ]
        )


def _run(argv: list[str]) -> str:
    """Run a command, failing loudly with its output if it fails."""
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        msg = f"{' '.join(argv)} exited {done.returncode}:\n{done.stdout}{done.stderr}"
        raise RuntimeError(msg)
    return done.stdout


# --- the inputs -------------------------------------------------------------


@dataclass(frozen=True)
class Input:
    """One input to the pipeline: how to make its capture, and what it carries.

    Attributes:
        name: A short name, used for its files and in every report line.
        protocol: The example spec whose shape it carries, or ``None`` for a
            capture that is there for its stream structure alone.
        make: Writes the capture to the given path, from the given tools.
        messages: How many messages the capture was generated with, in the
            protocol's own direction and the other together, when that is
            known: over a lossy stream, no more start lines than this may be
            decoded.
        inflates: Whether its bodies are `tools/gzip_http.py`'s compressed
            documents: each ``http.content`` record must be one of them, and a
            lossless capture must hold every one.

    """

    name: str
    protocol: str | None
    make: Callable[[Tools, Path], None]
    messages: int | None = None
    inflates: bool = False


def _fuzzed_dns(tools: Tools, out: Path) -> None:
    """Write adversarial variants of a real DNS capture, compression pointers and all."""
    source = tools.captures / "dns_example.pcapng"
    tools.packeteer_cmd("fuzz", str(source), "--pcap", str(out), "--seed", "1")


def _generated_dns(tools: Tools, out: Path) -> None:
    """Write a lossy DNS stream carrying a compressed response.

    ``raw:`` messages from ``tools/dns-messages.json``, because a response
    packeteer builds from fields writes every name in full and carries no
    pointer at all. The file holds section bodies (``{"raw": …}``), not the
    ``{"dns": {…}}`` shape ``packeteer parse`` writes; the wrapped form is
    accepted in silence and builds an empty header.
    """
    tools.packeteer_cmd(
        "stream", "--payload", "dns", "--protocol", "udp",
        "--protocol-messages", str(ROOT / "tools" / "dns-messages.json"),
        "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
        "--packets", "40", "--packet-loss", "0.05", "--gap-jitter", "0.01",
        "--seed", "5", "--pcap", str(out),
    )


def _generated_http(tools: Tools, out: Path, *, lossy: bool = True) -> None:
    """Write chunked HTTP with trailers, over small segments and, by default, a lossy link.

    ``--mss 200`` puts chunk boundaries across segment boundaries, which is where
    a streaming decoder is likeliest to be wrong; at the default a whole message
    fits in one segment and a loss never lands mid-body. The lossless variant
    is the same traffic with nothing taken away, which is what lets its shape
    be checked exactly (:func:`_reference_http`).
    """
    loss = ["--packet-loss", "0.05"] if lossy else []
    tools.packeteer_cmd(
        "stream", "--payload", "http",
        "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
        "--requests", str(HTTP_REQUESTS),
        "--chunked-rate", "0.5", "--trailer-rate", "0.5",
        "--min-chunk", "8", "--max-chunk", "32",
        "--mss", "200", *loss, "--seed", "3", "--pcap", str(out),
    )


def _clean_http(tools: Tools, out: Path) -> None:
    """Write the generated HTTP stream with no loss at all."""
    _generated_http(tools, out, lossy=False)


#: Responses in each generated stream of compressed bodies (`tools/gzip_http.py`).
GZIP_RESPONSES = 30


def _gzip_http(tools: Tools, out: Path, *, lossy: bool = True) -> None:
    """Write HTTP responses with gzip and deflate bodies, over small segments.

    The bodies are what the transform phase inflates, and they are large, so a
    gap lands inside one routinely, which is where #49 lived. packeteer's own
    HTTP payload cannot carry them, so they go through `tools/blob.yaml`.
    """
    stream, _ = gzip_http.build(GZIP_RESPONSES, seed=7)
    pieces = gzip_http.messages(stream)
    messages = out.with_suffix(".messages.json")
    messages.write_text(json.dumps(pieces))
    module = out.parent / "blob_protocol.py"
    if not module.exists():
        tools.packeteer_cmd(
            "protocol", "compile", str(ROOT / "tools" / "blob.yaml"), "-o", str(module)
        )
    loss = ["--packet-loss", "0.05"] if lossy else []
    tools.packeteer_cmd(
        "--load-protocol", str(module), "stream", "--payload", "blob", "--protocol", "tcp",
        "--server-port", str(gzip_http.PORT), "--protocol-messages", str(messages),
        "--packets", str(len(pieces)),
        "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
        *loss, "--seed", "7", "--pcap", str(out),
    )


def _gzip_http_clean(tools: Tools, out: Path) -> None:
    """Write the compressed-body stream with no loss at all."""
    _gzip_http(tools, out, lossy=False)



#: Inner packets per WireGuard input, and sealed packets per session: four
#: sessions, so every input rekeys.
WIREGUARD_PACKETS = 40
WIREGUARD_REKEY = 10


def _wireguard(*impairment: str) -> Callable[[Tools, Path], None]:
    """Return a maker for DNS through ``wg_seal.py``, with one tunnel impairment or none.

    One impairment per input, so a count that moves says which one moved it.
    The key log and the truth ``wg_seal.py`` writes go beside the capture.
    """

    def make(tools: Tools, out: Path) -> None:
        tools.packeteer_cmd(
            "stream", "--protocol", "udp", "--payload", "dns",
            "--protocol-messages", str(WIREGUARD / "dns.json"),
            "--client-ip", "10.8.0.2", "--server-ip", "10.8.0.1", "--server-port", "53",
            "--packets", str(WIREGUARD_PACKETS),
            "--udp-tunnel", "198.51.100.7", "203.0.113.9", "--tunnel-port", "51820",
            "--tunnel-module", str(WIREGUARD / "wg_seal.py"),
            "--tunnel-arg", f"keylog={out.with_suffix('.keys.json')}",
            "--tunnel-arg", f"truth={out.with_suffix('.truth.jsonl')}",
            "--tunnel-arg", f"rekey_after={WIREGUARD_REKEY}",
            *impairment, "--seed", "7", "--pcap", str(out),
        )

    return make


def _capture(name: str) -> Callable[[Tools, Path], None]:
    """Return a maker that copies one of the real captures."""

    def make(tools: Tools, out: Path) -> None:
        (source,) = tools.captures.glob(f"{name}.pcap*")
        shutil.copyfile(source, out)

    return make


INPUTS = (
    Input("dns_fuzz", "dns", _fuzzed_dns),
    Input("dns_gen", "dns", _generated_dns),
    Input("http_gen", "http", _generated_http, messages=2 * HTTP_REQUESTS),
    Input("http_clean", "http", _clean_http),
    Input("gzip_lossy", "http", _gzip_http, messages=GZIP_RESPONSES, inflates=True),
    Input("gzip_clean", "http", _gzip_http_clean, inflates=True),
    *(
        Input(name, "http" if name.startswith("http") else None, _capture(name))
        for name in CAPTURES
    ),
    Input("wg_clean", "wireguard", _wireguard()),
    Input("wg_loss", "wireguard", _wireguard("--tunnel-packet-loss", "0.15")),
    Input("wg_corrupt", "wireguard", _wireguard("--tunnel-corruption", "0.15")),
    Input("wg_reorder", "wireguard", _wireguard("--tunnel-reorder", "0.3")),
    Input("wg_duplicate", "wireguard", _wireguard("--tunnel-duplicate", "0.15")),
)


# --- checking ---------------------------------------------------------------


def _load(path: Path, name: str) -> ModuleType:
    """Import a Python file as a module, registered under ``name``.

    Registered in ``sys.modules`` because ``dataclasses`` looks a class's module
    up there, as it would for a generated module a consumer imports normally.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        msg = f"cannot import {path}"
        raise ImportError(msg)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: The one definition of "block for block", shared with the suite.
_COMPARE = _load(ROOT / "tests" / "zpfcompare.py", "zpfcompare")
#: The builder of the compressed-body streams, loaded as `zpfcompare` is.
gzip_http = _load(ROOT / "tools" / "gzip_http.py", "gzip_http")


@dataclass
class Report:
    """What has been checked so far, and whether all of it held."""

    failures: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)

    def line(self, ok: bool, what: str, detail: str = "") -> None:
        """Print one check's outcome, and remember it if it failed."""
        self._print("ok  " if ok else "FAIL", what, detail)
        if not ok:
            self.failures.append(what)

    def changed(self, what: str, detail: str) -> None:
        """Print and remember an output that differs from the baseline.

        Not a failure: a release that changes what kober writes changes some
        outputs on purpose, and which ones is for a person to judge.
        """
        self._print("DIFF", what, detail)
        self.changes.append(what)

    @staticmethod
    def _print(mark: str, what: str, detail: str) -> None:
        print(f"{mark}  {what:<44} {detail}".rstrip(), flush=True)


def _summary(path: Path) -> str:
    """Describe a decoded file in one line: records, undecoded bytes, declined streams.

    A declined stream is one the driver decided was not in this protocol: every
    region of it says so in its comment (``not dns: …``). Counted so that a spec
    that starts declining streams it should have decoded — the trade-off stream
    confirmation accepts — shows up as a number rather than as silence.
    """
    records = 0
    undecoded: Counter[str] = Counter()
    declined: set[tuple[int, int]] = set()
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, Record):
                records += 1
            elif isinstance(block, Undecoded):
                undecoded[block.reason] += block.off_end - block.off_start
                if block.comment and block.comment.startswith("not "):
                    declined.add((block.session_id, block.participant_id))
    regions = ", ".join(f"{reason} {size}" for reason, size in sorted(undecoded.items()))
    return (
        f"{records} records; undecoded: {regions or 'none'}; "
        f"{len(declined)} stream(s) declined"
    )


def _roles(path: Path) -> Counter[str]:
    """Count a field-granularity file's records by role, element indices dropped.

    ``http.chunks[3].size`` and ``http.chunks[0].size`` are both
    ``http.chunks[].size``: the shape is how many there are, not where.
    """
    roles: Counter[str] = Counter()
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, Record) and block.role:
                roles[re.sub(r"\[\d+\]", "[]", block.role)] += 1
    return roles


def _start_lines(path: Path) -> list[bytes]:
    """Return every start line a field-granularity HTTP file wrote, in order."""
    with zpf.open(path) as handle:
        return [
            bytes(block.payload)
            for block in handle.blocks()
            if isinstance(block, Record) and block.role == "http.start_line"
        ]


def _pointers(path: Path) -> tuple[int, int]:
    """Count DNS compression pointers followed, and the records read through them.

    A followed pointer is a ``target`` whose first label was read; the records
    under any ``target`` are what was decoded at the other end.
    """
    followed = through = 0
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, Record) and block.role and ".target." in block.role:
                through += 1
                if re.search(r"\.target\.labels\[0\]\.length$", block.role):
                    followed += 1
    return followed, through


def _reference_http(transport: Path) -> Counter[str] | None:
    """Count what a lossless HTTP capture holds, without the spec.

    A deliberately small reader of RFC 7230 message framing — start line,
    header block, then a chunked body with its trailer section or a counted
    one — sharing nothing with ``examples/http.yaml``, so that where the two
    agree on a whole capture the spec's framing is right, and where they differ
    one of them has read a message boundary in the wrong place. Counting is the
    point: coverage cannot see a misframed body, and a count can.

    The counts are named for the records the spec writes: one ``start_line``
    per message, one chunk ``size`` per chunk including the terminating zero,
    and one trailer ``name`` per line of the trailer section including the
    blank line that closes it, which the spec reads as an empty element.

    Args:
        transport: A transport-level capture.

    Returns:
        The counts, or ``None`` when any stream in the capture has a gap:
        what the spec should make of a lost segment is the driver's question,
        and the reference would only be a second opinion on it.

    """
    counts: Counter[str] = Counter()
    with zpf.open(transport) as handle:
        for session in handle.sessions():
            for view in session.reassemble():
                if not view.is_stream_oriented:
                    continue
                runs = list(view.chunks())
                if any(isinstance(run, Gap) for run in runs):
                    return None
                _count_http(b"".join(run.data for run in runs), counts)
    return counts


def _count_http(data: bytes, counts: Counter[str]) -> None:
    """Count the messages in one direction of a lossless HTTP stream."""
    at = 0

    def line() -> bytes:
        nonlocal at
        end = data.index(b"\r\n", at)
        text = data[at:end]
        at = end + 2
        return text

    while at < len(data):
        line()
        counts["http.start_line"] += 1
        headers: dict[bytes, bytes] = {}
        while text := line():
            name, _, value = text.partition(b":")
            headers[name.strip().lower()] = value.strip()
        if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
            while True:
                size = int(line().split(b";")[0], 16)
                counts["http.chunks[].size"] += 1
                if size == 0:
                    break
                at += size + 2
            while True:
                counts["http.trailers.fields[].name"] += 1
                if not line():
                    break
        else:
            at += int(headers.get(b"content-length", b"0"))


def _shape(report: Report, source: Input, path: Path, transport: Path, what: str) -> None:
    """Check that a field-granularity decode of an input has its protocol's shape."""
    if source.protocol == "wireguard":
        _tunnel(report, path, transport, what)
    elif source.protocol == "dns":
        followed, through = _pointers(path)
        report.line(
            followed > 0,
            f"{what} shape",
            f"{followed} pointers followed, {through} records read through them",
        )
    elif source.protocol == "http":
        roles = _roles(path)
        keys = ("http.start_line", "http.chunks[].size", "http.trailers.fields[].name")
        found = tuple(roles[key] for key in keys)
        detail = "{} start lines, {} chunk sizes, {} trailer lines".format(*found)
        reference = _reference_http(transport)
        if reference is not None:
            expected = tuple(reference[key] for key in keys)
            ok = found == expected
            detail += " (reference: {}, {}, {})".format(*expected)
        else:
            # With loss there is nothing exact to compare against, but more
            # start lines than messages sent is still the signature of a message
            # that stopped early and left its tail to be read as further
            # messages — how both HTTP bugs of that kind showed. Loss can only
            # make there be fewer.
            limit = source.messages
            ok = found[0] > 0 and (limit is None or found[0] <= limit)
            detail += f" (lossy: at most {limit} start lines)" if limit else " (lossy)"
        # A count can hide a phantom when a gap also took a real start line, and
        # `http_gen` had two that way from 0.4.0 until #50: so every start line
        # must also look like one.
        phantoms = [line for line in _start_lines(path) if not HTTP_START_LINE.match(line)]
        if phantoms:
            ok = False
            detail += f"; {len(phantoms)} not a start line, e.g. {phantoms[0][:30]!r}"
        report.line(ok, f"{what} shape", detail)
        if source.inflates:
            _inflated(report, source, path, transport, what)


#: What kober's WireGuard decode labels a packet, until the ``zpf`` 0.6 port
#: makes it ``net:ip``.
PACKET_LABEL = "dec:ip-packet"


def _records(path: Path) -> list[Record]:
    with zpf.open(path) as handle:
        return [block for block in handle.blocks() if isinstance(block, Record)]


def _truth(transport: Path) -> list[dict[str, object]]:
    """Return what ``wg_seal.py`` sealed for an input, a line per packet."""
    truth = transport.with_suffix(".truth.jsonl")
    return [json.loads(line) for line in truth.read_text().splitlines()]


def _tunnel(report: Report, path: Path, transport: Path, what: str) -> None:
    """Check a WireGuard decode exactly: what arrived intact opens, and nothing else does.

    The example plan's Q7. A sealed packet whose datagram is on the wire
    unchanged opens once per arrival; every other transport datagram, a
    corrupted one or a copy of one, is one ``decrypt-failed`` region.
    """
    on_wire = Counter(bytes(r.payload) for r in _records(transport) if r.payload[:1] == b"\x04")
    expected: Counter[bytes] = Counter()
    for line in _truth(transport):
        expected[bytes.fromhex(str(line["inner"]))] += on_wire.pop(
            bytes.fromhex(str(line["outer"])), 0
        )
    opened = Counter(bytes(r.payload) for r in _records(path) if r.content_type == PACKET_LABEL)
    with zpf.open(path) as handle:
        failed = sum(
            1
            for block in handle.blocks()
            if isinstance(block, Undecoded) and block.reason == "decrypt-failed"
        )
    ok = opened == expected and failed == sum(on_wire.values())
    detail = (
        f"{sum(opened.values())} packets opened of {sum(expected.values())} that arrived "
        f"intact; {failed} decrypt-failed of {sum(on_wire.values())} other datagrams"
    )
    report.line(ok, f"{what} tunnel", detail)


def _inner(
    report: Report, tools: Tools, dns: Spec, capture: Path, packets: Path, what: str
) -> None:
    """Check the traffic inside the tunnel: the DNS decoded from it is what arrived.

    ``zpfwire`` turns the decrypted packets back into the conversation they
    carried, and ``dns.yaml`` reads it. Each direction's DNS must be, message for
    message, the DNS inside the sealed datagrams that reached the wire unchanged.
    """
    inner = packets.with_suffix(".inner.zpf")
    decoded_path = packets.with_suffix(".inner.dns.zpf")
    tools.sessionize(packets, inner, PACKET_LABEL)
    run(Decoder(dns), inner, decoded_path, produced_by=PRODUCED_BY, produced_at=PRODUCED_AT)
    transport = capture.with_suffix(".zpf")
    on_wire = Counter(bytes(r.payload) for r in _records(transport) if r.payload[:1] == b"\x04")
    expected: dict[str, Counter[bytes]] = {"c2s": Counter(), "s2c": Counter()}
    for line in _truth(transport):
        packet = bytes.fromhex(str(line["inner"]))
        dns_message = packet[(packet[0] & 15) * 4 + 8 :]
        expected[str(line["direction"])][dns_message] += on_wire.get(
            bytes.fromhex(str(line["outer"])), 0
        )
    decoded: dict[str, Counter[bytes]] = {"c2s": Counter(), "s2c": Counter()}
    with zpf.open(decoded_path) as handle:
        blocks = list(handle.blocks())
    endpoints = {
        (b.session_id, b.participant_id): str(b.endpoint)
        for b in blocks
        if isinstance(b, Participant)
    }
    for block in blocks:
        if isinstance(block, Record):
            sender = endpoints[block.session_id, block.sender_pid]
            decoded["c2s" if "10.8.0.2:" in sender else "s2c"][bytes(block.payload)] += 1
    problems = _COMPARE.conformance_problems(decoded_path, inner)
    ok = decoded == expected and not problems
    total = sum(sum(c.values()) for c in decoded.values())
    detail = f"{total} DNS messages, each direction the DNS that arrived intact"
    if problems:
        detail += f"; {problems[0]}"
    report.line(ok, f"{what} inner", detail)


def _inflated(report: Report, source: Input, path: Path, transport: Path, what: str) -> None:
    """Check that every inflated body is a document that was sent, and how many were.

    A digest is the whole claim: an `http.content` record that is not byte for
    byte a document the generator compressed is a body inflated wrong. Without
    loss every compressed body must be inflated; with loss, at least one, since
    a body a gap cut is never read.
    """
    digests = []
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, Record) and block.role == "http.content":
                digests.append(hashlib.sha256(bytes(block.payload)).hexdigest())
    _, responses = gzip_http.build(GZIP_RESPONSES, seed=7)
    sent = {response.digest for response in responses if response.coding != "identity"}
    compressed = sum(1 for response in responses if response.coding != "identity")
    foreign = [digest for digest in digests if digest not in sent]
    lossless = _reference_http(transport) is not None
    ok = not foreign and (len(digests) == compressed if lossless else bool(digests))
    detail = f"{len(digests)} bodies inflated, of {compressed} sent compressed"
    if foreign:
        detail += f"; {len(foreign)} not a document that was sent"
    report.line(ok, f"{what} inflated", detail)


def _compile(spec: Spec, name: str, emit: Emit, work: Path) -> ModuleType:
    """Compile a spec fresh, write the module, and import it from the file."""
    path = work / "modules" / f"{name}_{emit.value}.py"
    path.write_text(render_spec(spec, emit=emit))
    return _load(path, f"pipeline_{name}_{emit.value}")


def pipeline(tools: Tools, work: Path, baseline: Path | None = None) -> Report:
    """Build every input, decode it every way, and check every output.

    Args:
        tools: Where the sibling checkouts are.
        work: A directory to write captures, modules and outputs into.
        baseline: The work directory of an earlier run, to compare every
            output with block for block; ``None`` to compare with nothing.

    Returns:
        What was checked, and what failed.

    """
    report = Report()
    for sub in ("captures", "modules", "out"):
        (work / sub).mkdir(parents=True, exist_ok=True)
    print(f"{tools.version(tools.packeteer_bin)}; {tools.version(tools.zpfwire_bin)}")
    print(f"work directory: {work}\n", flush=True)

    # The cipher is the example's, registered as a user's process would, and
    # before the modules are compiled, since a module binds when it is imported.
    if str(WIREGUARD) not in sys.path:
        sys.path.append(str(WIREGUARD))  # as `--load-transforms` does: wg_crypto beside it
    _load(WIREGUARD / "wg_transforms.py", "wg_transforms")
    specs = {name: Spec.from_file(path) for name, path in SPECS.items()}
    modules = {
        (name, emit): _compile(spec, name, emit, work)
        for name, spec in specs.items()
        for emit in (Emit.MESSAGE, Emit.FIELD)
    }

    for source in INPUTS:
        capture = work / "captures" / f"{source.name}.pcap"
        transport = work / "captures" / f"{source.name}.zpf"
        source.make(tools, capture)
        tools.convert(capture, transport)
        for name, spec in specs.items():
            params = _params(name, capture)
            for emit in (Emit.MESSAGE, Emit.FIELD):
                what = f"{source.name} {name} {emit.value}"
                stem = f"{source.name}.{name}.{emit.value}"
                interpreted = work / "out" / f"{stem}.interpreted.zpf"
                compiled = work / "out" / f"{stem}.compiled.zpf"
                started = time.monotonic()
                decoder = Decoder(spec, emit=emit, params=params)
                refusals = _decode_both(
                    decoder, modules[name, emit], params, transport, interpreted, compiled
                )
                if refusals:
                    # A datagram spec over a byte stream is refused, by design
                    # (`docs/format/document.md`, *input*): both drivers must.
                    ok = len(refusals) == 2 and spec.input is InputShape.DATAGRAM
                    detail = "both drivers refuse a datagram spec over a byte stream"
                    report.line(ok, f"{what} refused", detail if ok else refusals[0])
                    continue
                elapsed = time.monotonic() - started
                for driver, path in (("interpreted", interpreted), ("compiled", compiled)):
                    problems = _COMPARE.conformance_problems(path, transport)
                    detail = "; ".join(problems[:3]) if problems else _summary(path)
                    report.line(not problems, f"{what} {driver}", detail)
                _pair(report, what, interpreted, compiled, elapsed)
                if baseline is not None:
                    for path in (interpreted, compiled):
                        _against(report, path, baseline / "out" / path.name)
                if emit is Emit.FIELD and name == source.protocol:
                    _shape(report, source, interpreted, transport, f"{what} interpreted")
                    _shape(report, source, compiled, transport, f"{what} compiled")
                if emit is Emit.FIELD and name == source.protocol == "wireguard":
                    _inner(report, tools, specs["dns"], capture, interpreted, what)
    return report


def _decode_both(
    decoder: Decoder,
    module: ModuleType,
    params: dict[str, object] | None,
    transport: Path,
    interpreted: Path,
    compiled: Path,
) -> list[str]:
    """Decode an input with both drivers, and return what either refused it for."""
    refusals = []
    try:
        run(decoder, transport, interpreted, produced_by=PRODUCED_BY, produced_at=PRODUCED_AT)
    except SpecError as exc:
        refusals.append(str(exc))
    try:
        run_compiled(
            module,
            transport,
            compiled,
            produced_by=PRODUCED_BY,
            produced_at=PRODUCED_AT,
            params=params,
        )
    except SpecError as exc:
        refusals.append(str(exc))
    return refusals


def _params(name: str, capture: Path) -> dict[str, object] | None:
    """Return the parameters a spec runs with over an input: WireGuard's key log."""
    if name != "wireguard":
        return None
    log = capture.with_suffix(".keys.json")
    if not log.exists():
        return {"keys": {}}
    logged = json.loads(log.read_text())
    return {"keys": {int(index): bytes.fromhex(value[4:]) for index, value in logged.items()}}


def _first_difference(left: Path, right: Path) -> str | None:
    """Return where two decoded files first differ, block for block, or ``None``."""
    ours = _COMPARE.blocks(left)
    theirs = _COMPARE.blocks(right)
    if ours == theirs:
        return None
    index = next(
        (i for i, (a, b) in enumerate(zip(ours, theirs, strict=False)) if a != b),
        min(len(ours), len(theirs)),
    )
    first = ours[index] if index < len(ours) else "<end>"
    second = theirs[index] if index < len(theirs) else "<end>"
    return f"differ at block {index}: {first!r} against {second!r}"


def _pair(report: Report, what: str, interpreted: Path, compiled: Path, elapsed: float) -> None:
    """Check that the two drivers wrote the same file, and say where they part if not."""
    difference = _first_difference(interpreted, compiled)
    if difference is None:
        count = len(_COMPARE.blocks(interpreted))
        report.line(True, f"{what} pair", f"{count} blocks identical ({elapsed:.1f}s)")
    else:
        report.line(False, f"{what} pair", f"interpreted, compiled {difference}")


def _against(report: Report, path: Path, before: Path) -> None:
    """Compare one output with the same output from the baseline run."""
    what = path.name.removesuffix(".zpf").replace(".", " ")
    if not before.exists():
        report.changed(what, f"not in the baseline ({before})")
        return
    difference = _first_difference(before, path)
    if difference is not None:
        report.changed(what, f"baseline, now {difference}")


def main(argv: list[str] | None = None) -> int:
    """Run the pipeline from the command line.

    Args:
        argv: Arguments, without the program name; ``sys.argv`` when omitted.

    Returns:
        The exit status: 0 when every check held, 1 when any failed, 2 when a
        sibling checkout is missing.

    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--packeteer",
        type=Path,
        default=ROOT.parent / "packeteer",
        help="the packeteer checkout, with its .venv (default: ../packeteer)",
    )
    parser.add_argument(
        "--wire",
        type=Path,
        default=ROOT.parent / "python-zipline-wire",
        help="the python-zipline-wire checkout, with its .venv (default: ../python-zipline-wire)",
    )
    parser.add_argument(
        "--work",
        type=Path,
        help="where to write captures, modules and outputs (default: a temporary "
        "directory, removed if every check holds and kept if one fails)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="the --work directory of an earlier run: report every output that "
        "differs from the one it wrote, block for block",
    )
    args = parser.parse_args(argv)

    tools = Tools(packeteer=args.packeteer.resolve(), wire=args.wire.resolve())
    missing = tools.missing()
    if missing:
        print("missing: " + ", ".join(missing), file=sys.stderr)
        return 2

    work = args.work or Path(tempfile.mkdtemp(prefix="kober-pipeline-"))
    report = pipeline(tools, work, args.baseline)
    if args.baseline is not None:
        print(f"\n{len(report.changes)} output(s) differ from the baseline in {args.baseline}")
    if report.failures:
        print(f"\n{len(report.failures)} check(s) failed; files kept in {work}")
        return 1
    print("\nevery check held")
    if args.work is None:
        shutil.rmtree(work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
