"""What every bring-your-own-code example's tests need, written once.

An example in ``examples/<name>/`` brings a spec, a transform of its own, and
usually a packeteer tunnel module that seals generated traffic and writes down
what it sealed (the README's *Conventions*). Testing one is mostly the same work
each time, and this is that work: load its modules as a user's process would,
read its key log exactly as ``--param`` does, check a decode against what was
sealed, run the whole chain through packeteer and ``zpfwire`` and back, fuzz
it, and run it from the command line. An example's own test file then holds
what is its own: its algorithm's known answers, its messages, its corner cases.

Nothing here imports pytest, so ``tools/pipeline.py`` can use the oracle too.
Describe an example once, with :class:`Example`, and pass that.
"""

from __future__ import annotations

import importlib.util
import json
import struct
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import zpf
from test_stage_transforms import decode
from zpf.blocks import Participant, Record, Undecoded

from kober import transforms as transforms_module
from kober.cli import _params as read_params
from kober.cli import main
from kober.decoder import Decoder
from kober.emit import Emit, plan
from kober.node import NodeStatus
from kober.spec import Spec
from kober.transforms import Registry

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

#: The sibling checkouts ``tools/pipeline.py`` uses, with their own venvs.
PACKETEER = ROOT.parent / "packeteer" / ".venv" / "bin" / "packeteer"
ZPFWIRE = ROOT.parent / "python-zipline-wire" / ".venv" / "bin" / "zpfwire"

#: Where generated traffic runs: the inner client and server, and the tunnel's
#: two ends, as the examples' READMEs write them.
CLIENT, SERVER = "10.8.0.2", "10.8.0.1"
TUNNEL_ENDS = ("198.51.100.7", "203.0.113.9")

class Patcher(Protocol):
    """What the kit undoes after a test: pytest's ``MonkeyPatch`` is one."""

    def setattr(self, target: object, name: str, value: object) -> None:
        """Set an attribute until the test ends."""

    def delitem(self, dic: dict[str, object], name: str, raising: bool = True) -> None:
        """Remove an entry until the test ends."""


#: IPv4's protocol number for UDP.
UDP = 17

#: Every reason the format classifies, before an example adds its ``fails_as``.
CANONICAL_REASONS = frozenset(s.value for s in NodeStatus if s is not NodeStatus.OK)


@dataclass(frozen=True)
class Example:
    """One example, described once for every test that needs it.

    Attributes:
        name: Its folder under ``examples/``.
        spec: The spec's file name.
        transforms: The module ``--load-transforms`` loads, by file name.
        packet_role: The record role of what a transform opened, such as
            ``wireguard.body.packet``.
        packet_label: The content type a packet record carries, the one
            ``zpfwire`` selects packets by.
        failure: The spec's ``fails_as``, what a transform that fails is named.
        keys: The map parameter a key log supplies, or ``None`` for an example
            with nothing to supply.
        tunnel: The packeteer tunnel module's file name, or ``None``.
        port: The tunnel's UDP port.
        carries_packet: Whether an outer datagram's payload is one that carries
            a packet, rather than a control message such as a handshake. Only
            those are checked against what was sealed.

    """

    name: str
    spec: str
    transforms: str
    packet_role: str
    packet_label: str
    failure: str
    keys: str | None = None
    tunnel: str | None = None
    port: int = 51820
    carries_packet: Callable[[bytes], bool] = field(default=lambda _payload: True)

    @property
    def folder(self) -> Path:
        """The example's folder."""
        return EXAMPLES / self.name

    def path(self, file: str) -> Path:
        """Return one of the example's files."""
        return self.folder / file

    def model(self) -> Spec:
        """Load the example's spec."""
        return Spec.from_file(self.path(self.spec))

    def module(self, name: str) -> ModuleType:
        """Import one of the example's modules by path, as a user's process would.

        Its folder goes on ``sys.path`` last, as ``--load-transforms`` puts it, so
        it imports the modules beside it.
        """
        if str(self.folder) not in sys.path:
            sys.path.append(str(self.folder))
        spec = importlib.util.spec_from_file_location(name, self.path(f"{name}.py"))
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def registry(self, patch: Patcher) -> Registry:
        """Load the example's transforms into a registry of the caller's own.

        The module registers into kober's default registry when it runs, as a
        user's does, so a fresh one goes there first, and the test's
        registrations stay the test's.
        """
        fresh = Registry.standard()
        patch.setattr(transforms_module, "DEFAULT", fresh)
        self.module(Path(self.transforms).stem)
        return fresh

    def params(self, key_log: Path | None) -> dict[str, object] | None:
        """Return the parameters a key log supplies, read exactly as ``--param`` reads it."""
        if self.keys is None:
            return None
        if key_log is None:
            return {self.keys: {}}
        return dict(read_params(self.model(), [f"{self.keys}=file:{key_log}"]))


# --- what was sealed, and what a decode must find ---


def read_truth(path: Path) -> list[dict[str, object]]:
    """Return a truth file's lines: one per sealed packet, ``inner``, ``outer``, ``direction``."""
    return [json.loads(line) for line in path.read_text().splitlines()]


def payloads(path: Path) -> list[bytes]:
    """Return every record's payload in a ``.zpf``, in file order."""
    with zpf.open(path) as handle:
        return [bytes(b.payload) for b in handle.blocks() if isinstance(b, Record)]


def arrivals(
    example: Example, truth: Sequence[dict[str, object]], outer: Path
) -> tuple[Counter[bytes], Counter[bytes]]:
    """Return what must open, and the packet-carrying datagrams nothing sealed as they are.

    A sealed packet whose datagram reached the wire unchanged opens once per
    arrival, which covers loss, reordering and duplication in one count. What is
    left on the wire, a corrupted datagram or a copy of one, must fail, once each.
    """
    on_wire = Counter(p for p in payloads(outer) if example.carries_packet(p))
    expected: Counter[bytes] = Counter()
    for line in truth:
        expected[bytes.fromhex(str(line["inner"]))] += on_wire.pop(
            bytes.fromhex(str(line["outer"])), 0
        )
    return expected, on_wire


def opened_in(example: Example, path: Path) -> Counter[bytes]:
    """Return the packets a decoded file holds, as a multiset."""
    with zpf.open(path) as handle:
        return Counter(
            bytes(b.payload)
            for b in handle.blocks()
            if isinstance(b, Record) and b.content_type == example.packet_label
        )


def failures_in(example: Example, path: Path) -> int:
    """Return how many regions a decoded file names with the example's failure."""
    with zpf.open(path) as handle:
        return sum(
            1
            for b in handle.blocks()
            if isinstance(b, Undecoded) and b.reason == example.failure
        )


def tunnel_problems(
    example: Example, truth: Sequence[dict[str, object]], outer: Path, decoded: Path
) -> list[str]:
    """Check a decode against what was sealed, exactly; return what is wrong, if anything."""
    expected, left = arrivals(example, truth, outer)
    problems = []
    opened = opened_in(example, decoded)
    if opened != expected:
        problems.append(
            f"opened {sum(opened.values())} packets, where {sum(expected.values())} arrived "
            f"intact: {sum((opened - expected).values())} unexpected, "
            f"{sum((expected - opened).values())} missing"
        )
    failed = failures_in(example, decoded)
    if failed != sum(left.values()):
        problems.append(
            f"{failed} {example.failure} regions, for {sum(left.values())} other datagrams"
        )
    return problems


def messages_by_direction(path: Path) -> dict[str, list[bytes]]:
    """Return a decoded conversation's records, by the inner client's side or the server's."""
    endpoints: dict[tuple[int, int], str] = {}
    found: dict[str, list[bytes]] = {"c2s": [], "s2c": []}
    with zpf.open(path) as handle:
        for block in handle.blocks():
            if isinstance(block, Participant):
                endpoint = block.endpoint
                endpoints[block.session_id, block.participant_id] = (
                    endpoint if isinstance(endpoint, str) else endpoint[0]
                )
            elif isinstance(block, Record):
                sender = endpoints[block.session_id, block.sender_pid]
                side = "c2s" if sender.startswith(f"{CLIENT}:") else "s2c"
                found[side].append(bytes(block.payload))
    return found


def inner_payload(packet: bytes) -> tuple[int | None, bytes]:
    """Return an inner IPv4 packet's TCP sequence number (``None`` for UDP), and payload."""
    header = (packet[0] & 15) * 4
    if packet[9] == UDP:
        return None, packet[header + 8 :]
    tcp = packet[header:]
    return int.from_bytes(tcp[4:8], "big"), tcp[(tcp[12] >> 4) * 4 :]


def expected_inside(
    example: Example, truth: Sequence[dict[str, object]], outer: Path
) -> dict[str, Counter[bytes]]:
    """Return the datagram payloads inside what arrived intact, by direction, as multisets.

    Counted by each sealed packet's own datagram, since the traffic inside can
    repeat itself exactly where the datagrams never do.
    """
    on_wire = Counter(p for p in payloads(outer) if example.carries_packet(p))
    found: dict[str, Counter[bytes]] = {"c2s": Counter(), "s2c": Counter()}
    for line in truth:
        payload = inner_payload(bytes.fromhex(str(line["inner"])))[1]
        found[str(line["direction"])][payload] += on_wire[bytes.fromhex(str(line["outer"]))]
    return found


def sealed_streams(truth: Sequence[dict[str, object]]) -> dict[str, bytes]:
    """Return each direction's inner TCP stream, from the segments that were sealed."""
    segments: dict[str, dict[int, bytes]] = {"c2s": {}, "s2c": {}}
    for line in truth:
        seq, payload = inner_payload(bytes.fromhex(str(line["inner"])))
        if seq is not None and payload:
            segments[str(line["direction"])][seq] = payload  # a retransmission: the same bytes
    return {d: b"".join(found[at] for at in sorted(found)) for d, found in segments.items()}


# --- packets, built here ---


def ip_checksum(header: bytes) -> int:
    """Return an IPv4 header's checksum, its own field zero."""
    total = sum(struct.unpack(f">{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4_header(length: int, ident: int, flags: int, src: str, dst: str) -> bytes:
    header = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, length, ident, flags, 64, UDP, 0,
        bytes(int(part) for part in src.split(".")), bytes(int(part) for part in dst.split(".")),
    )
    return header[:10] + struct.pack(">H", ip_checksum(header)) + header[12:]


def ipv4(body: bytes, ident: int = 0) -> bytes:
    """Return a real IPv4 packet from the inner client, carrying ``body`` to UDP port 53."""
    udp = struct.pack(">HHHH", 40000 + ident % 1000, 53, 8 + len(body), 0) + body
    return _ipv4_header(20 + len(udp), ident, 0, CLIENT, SERVER) + udp


def write_pcap(path: Path, sent: Iterable[tuple[str, bytes]], port: int) -> None:
    """Write a tunnel's datagrams, ``(direction, payload)``, as a pcap between its two ends.

    From first principles, so an outside implementation can read what the
    example's tunnel module returned without packeteer in between.
    """
    ends = {"c2s": TUNNEL_ENDS, "s2c": TUNNEL_ENDS[::-1]}
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for n, (direction, payload) in enumerate(sent):
        udp = struct.pack(">HHHH", port, port, 8 + len(payload), 0) + payload
        ip = _ipv4_header(20 + len(udp), n, 0x4000, *ends[direction])
        frame = b"\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00" + ip + udp
        out += struct.pack("<IIII", 1_700_000_000 + n, 0, len(frame), len(frame)) + frame
    path.write_bytes(out)


# --- the whole chain ---


def _help(binary: Path, *verb: str) -> str:
    if not binary.exists():
        return ""
    return subprocess.run(
        [str(binary), *verb, "--help"], capture_output=True, text=True, check=False
    ).stdout


#: packeteer 0.18.0's ``--udp-tunnel``, and zpfwire 0.5.0's ``.zpf`` input (#35).
HAS_TUNNEL = "--udp-tunnel" in _help(PACKETEER, "stream")
HAS_PACKETS_INPUT = "--content-type" in _help(ZPFWIRE, "convert")


@dataclass(frozen=True)
class Run:
    """One generated capture, and the files the chain writes beside it.

    Attributes:
        folder: Where every file of the run is.
        outer: The capture converted, transport layer.

    """

    folder: Path
    outer: Path

    @property
    def truth(self) -> list[dict[str, object]]:
        """What the tunnel module sealed."""
        return read_truth(self.folder / "truth.jsonl")

    @property
    def key_log(self) -> Path | None:
        """The key log the tunnel module wrote, if it wrote one."""
        log = self.folder / "keys.json"
        return log if log.exists() else None

    @property
    def opened(self) -> Path:
        """The interpreter's decode of the tunnel, once :func:`open_tunnel` ran."""
        return self.folder / "out.field.zpf"


def generate(
    example: Example,
    folder: Path,
    inner: Sequence[str],
    impairments: Sequence[str] = (),
    tunnel_args: Iterable[str] = (),
    seed: int = 7,
) -> Run:
    """Generate traffic through the example's tunnel module, and convert it.

    Args:
        example: The example.
        folder: Where to write the capture, the key log and the truth.
        inner: packeteer's arguments for the traffic inside, after ``stream``.
        impairments: What the tunnel's datagrams suffer, as ``--tunnel-*`` flags.
        tunnel_args: Further ``--tunnel-arg`` values, such as ``rekey_after=10``.
        seed: packeteer's seed.

    Returns:
        The run.

    """
    assert example.tunnel is not None, f"{example.name} has no tunnel module"
    pcap, outer = folder / "tunnel.pcap", folder / "outer.zpf"
    args = [f"truth={folder / 'truth.jsonl'}", *tunnel_args]
    if example.keys is not None:
        args.append(f"keylog={folder / 'keys.json'}")
    subprocess.run(
        [
            str(PACKETEER), "stream", *inner, "--client-ip", CLIENT, "--server-ip", SERVER,
            "--udp-tunnel", *TUNNEL_ENDS, "--tunnel-port", str(example.port),
            "--tunnel-module", str(example.path(example.tunnel)),
            *(item for arg in args for item in ("--tunnel-arg", arg)),
            *impairments, "--seed", str(seed), "--pcap", str(pcap),
        ],
        check=True, capture_output=True,
    )
    subprocess.run([str(ZPFWIRE), "convert", "-q", str(pcap), "-o", str(outer)], check=True)
    return Run(folder, outer)


def open_tunnel(example: Example, run: Run, registry: Registry) -> list[tuple[object, ...]]:
    """Decode the tunnel with both drivers, which must agree; the file is ``run.opened``."""
    return decode(
        example.model(), run.outer, run.folder,
        params=example.params(run.key_log), transforms=registry,
    )


def sessionize(example: Example, run: Run) -> Path:
    """Turn the opened packets back into the conversations they carried: ``inner.zpf``."""
    inner = run.folder / "inner.zpf"
    subprocess.run(
        [
            str(ZPFWIRE), "convert", "-q", str(run.opened), "-o", str(inner),
            "--content-type", example.packet_label,
        ],
        check=True,
    )
    return inner


def decode_inside(spec: Path, inner: Path, folder: Path) -> list[tuple[object, ...]]:
    """Decode the conversations inside with another spec, both drivers, one record a message.

    The file is ``folder / "out.message.zpf"``.
    """
    folder.mkdir(exist_ok=True)
    return decode(Spec.from_file(spec), inner, folder, Emit.MESSAGE)


# --- adversarial input ---


def assert_never_breaks(
    example: Example,
    decoder: Decoder,
    cases: Iterable[bytes],
    emit: Emit,
    secrets: Iterable[bytes] = (),
) -> None:
    """Hold a decode to what every shipped spec promises, over adversarial input.

    It never raises, never cites a byte it also names undecoded, names regions
    only with reasons the format or the spec's ``fails_as`` has, and never shows
    a secret.
    """
    allowed = CANONICAL_REASONS | {example.failure}
    hidden = [secret.hex() for secret in secrets]
    for data in cases:
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode on {data!r}")
            raise
        emissions, unclaimed = plan(decoder.spec, tree, data, emit=emit)
        cited = {at for r in emissions for at in range(r.off_start, r.off_end)}
        named = {at for r in unclaimed for at in range(r.off_start, r.off_end)}
        assert not cited & named, f"both cited and undecoded on {data!r}"
        assert {r.reason for r in unclaimed} <= allowed, data
        shown = tree.render()
        assert all(secret not in shown for secret in hidden), data


def assert_compiled_never_breaks(
    module: ModuleType, cases: Iterable[bytes], params: dict[str, object] | None
) -> None:
    """Hold a generated module to the same: whatever the input, a decode returns."""
    for data in cases:
        try:
            module.decode(data, **({"params": params} if params is not None else {}))
        except Exception as exc:
            exc.add_note(f"escaped a compiled decode on {data!r}")
            raise


# --- the command line ---


def run_cli(
    example: Example,
    source: Path,
    out: Path,
    patch: Patcher,
    key_log: Path | None = None,
) -> int:
    """Run ``kober run`` as the README does: the example's transforms loaded by path.

    The default registry is swapped for a fresh one, and the example's folder
    and every module already imported from it are put out of reach, so the run
    finds its modules the way a user's does.
    """
    patch.setattr(transforms_module, "DEFAULT", Registry.standard())
    patch.setattr(sys, "path", [p for p in sys.path if p != str(example.folder)])
    for name, module in list(sys.modules.items()):
        if Path(getattr(module, "__file__", None) or "/").parent == example.folder:
            patch.delitem(sys.modules, name)
    argv = [
        "run", str(example.path(example.spec)), str(source), "-o", str(out),
        "--emit", "field", "--load-transforms", str(example.path(example.transforms)),
    ]
    if example.keys is not None and key_log is not None:
        argv += ["--param", f"{example.keys}=file:{key_log}"]
    return main(argv)

