"""The PackBits example: its codec, its spec, and the traffic its tunnel packs.

The second example of bringing your own code, written from the first's template
(``plans/WIREGUARD-EXAMPLE-PLAN.md``, Stage 7 D). What every example's tests
need is ``examplekit``'s; what is here is PackBits'.

**The codec is checked against what is not this code.** The module that packs
and the transform that unpacks share ``pb_codec.py``, so a round trip alone
would pass over a codec that is not PackBits. TIFF 6.0 §9 defines the scheme by
its unpacking rules and has no worked example; Apple's Technical Note TN1023,
*Understanding PackBits*, has one, with every flag-counter byte annotated. Both
were extracted from the documents' own text by a script, not typed: TIFF's from
the specification's PDF (RC4-encrypted, LZW-compressed content streams), and
TN1023's from its HTML. No other implementation is at hand in the standard
library, so those two are the outside check.
"""

from __future__ import annotations

import random
import struct
import zlib
from pathlib import Path

import pytest
from examplekit import (
    HAS_PACKETS_INPUT,
    HAS_TUNNEL,
    ZPFWIRE,
    Example,
    Run,
    arrivals,
    assert_compiled_never_breaks,
    assert_never_breaks,
    decode_inside,
    expected_inside,
    generate,
    ipv4,
    messages_by_direction,
    open_tunnel,
    read_truth,
    run_cli,
    sessionize,
    tunnel_problems,
)
from fuzzing import variants
from test_compiled_transforms import imported
from test_stage import datagrams
from test_stage_transforms import decode, records, regions
from zpfcompare import blocks

from kober.check import Severity, check
from kober.cli import OK
from kober.decoder import Decoder
from kober.emit import Emit
from kober.spec import Spec
from kober.transforms import Registry

#: The example, as it describes itself in ``example.json``.
PACKBITS = Example.load("packbits")

codec = PACKBITS.module("pb_codec")
tunnel = PACKBITS.module("pb_tunnel")
unpacking = PACKBITS.module("pb_transforms")


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> Registry:
    """``pb_transforms.py``, loaded into a registry of the test's own."""
    return PACKBITS.registry(monkeypatch)


# --- the outside known answers ------------------------------------------------------------------

#: Apple TN1023, *Using PackBits*: the unpacked data, and what PackBits packs it to.
TN1023 = {
    "unpacked": bytes.fromhex(
        "AA AA AA 80 00 2A AA AA AA AA 80 00 2A 22 AA AA AA AA AA AA AA AA AA AA"
    ),
    "packed": bytes.fromhex("FE AA 02 80 00 2A FD AA 03 80 00 2A 22 F7 AA"),
}


def test_tn1023s_example_packs_and_unpacks():
    assert codec.pack(TN1023["unpacked"]) == TN1023["packed"]
    assert codec.unpack(TN1023["packed"], len(TN1023["unpacked"])) == TN1023["unpacked"]


#: TIFF 6.0 §9's pseudo code, a rule at a time: the rule, packed, unpacked.
TIFF_RULES = [
    ("0 to 127: copy the next n+1 bytes literally", b"\x02abc", b"abc"),
    ("-127 to -1: copy the next byte -n+1 times", b"\xfdz", b"zzzz"),
    ("-128: noop", b"\x80\x00q", b"q"),
    ("the longest literal", b"\x7f" + bytes(range(128)), bytes(range(128))),
    ("the longest replicate", b"\x81\x07", b"\x07" * 128),
]


@pytest.mark.parametrize(("rule", "packed", "unpacked"), TIFF_RULES, ids=[r[0] for r in TIFF_RULES])
def test_tiff_6s_unpacking_rules(rule: str, packed: bytes, unpacked: bytes):
    assert codec.unpack(packed, len(unpacked)) == unpacked, rule


def test_a_long_run_is_more_than_one_replicate_record():
    """TIFF 6.0 §9: a run longer than 128 is encoded as more replicate runs."""
    assert codec.pack(b"\x05" * 300) == b"\x81\x05\x81\x05\xd5\x05"


@pytest.mark.parametrize("seed", range(5))
def test_the_worst_case_is_one_byte_in_128_and_every_packing_unpacks(seed: int):
    """TIFF 6.0 §9: "at most 1 extra byte for every 128 input bytes"."""
    rng = random.Random(seed)
    for _ in range(50):
        data = b"".join(
            bytes([rng.randrange(4)]) * rng.choice((1, 1, 2, 3, 200))
            for _ in range(rng.randrange(60))
        ) + rng.randbytes(rng.randrange(300))
        packed = codec.pack(data)
        assert len(packed) <= len(data) + -(-len(data) // 128)
        assert codec.unpack(packed, len(data)) == data


@pytest.mark.parametrize(
    ("packed", "length", "why"),
    [
        (b"\xfdz", 3, "a record runs past the length"),
        (b"\x02ab", 3, "a literal record past the packed bytes"),
        (b"\xfd", 4, "a replicate record with no byte to repeat"),
        (b"\x00a", 2, "the packed bytes end before the length"),
        (b"\x00a\x00b", 1, "packed bytes left over after the length"),
    ],
)
def test_what_does_not_unpack_to_its_length_is_refused(packed: bytes, length: int, why: str):
    with pytest.raises(codec.UnpackError, match=why):
        codec.unpack(packed, length)


# --- the transform and the tunnel module --------------------------------------------------------


def test_the_transform_checks_the_crc_and_the_limit():
    packet = ipv4(b"inside")
    packed, crc = codec.pack(packet), zlib.crc32(packet)
    assert unpacking.packbits(packed, limit=100, length=len(packet), crc=crc) == packet
    with pytest.raises(ValueError, match="CRC"):
        unpacking.packbits(packed, limit=100, length=len(packet), crc=crc ^ 1)
    with pytest.raises(ValueError, match="limit"):
        unpacking.packbits(packed, limit=10, length=len(packet), crc=crc)


def test_the_tunnel_module_writes_one_datagram_and_one_truth_line(tmp_path: Path):
    wrapper = tunnel.make_wrapper({"truth": str(tmp_path / "truth.jsonl")})
    packet = ipv4(b"\x00" * 40)
    ((direction, outer),) = wrapper.wrap(packet, "s2c", 1.0)
    assert direction == "s2c"
    assert outer[:7] == struct.pack(">BHI", 1, len(packet), zlib.crc32(packet))
    assert len(outer) < 7 + len(packet), "forty zeros pack"
    assert read_truth(tmp_path / "truth.jsonl") == [
        {"direction": "s2c", "inner": packet.hex(), "outer": outer.hex()}
    ]


def test_the_tunnel_module_refuses_an_argument_it_does_not_take(tmp_path: Path):
    with pytest.raises(ValueError, match="keylog"):
        tunnel.make_wrapper({"truth": str(tmp_path / "t"), "keylog": "k.json"})


# --- the spec, over datagrams built here --------------------------------------------------------


def spec() -> Spec:
    return PACKBITS.model()


def test_the_spec_checks_clean():
    assert [f for f in check(spec()) if f.severity is Severity.ERROR] == []
    assert check(spec()) == ()


def packets(written: list[tuple[object, ...]]) -> list[object]:
    return [b[3] for b in written if b[0] == "record" and b[2] == PACKBITS.packet_role]


def test_every_datagram_unpacks_to_its_packet_and_cites_it(tmp_path: Path, registry: Registry):
    inner = [ipv4(f"packet {n}".encode() + b"\x00" * n, n) for n in range(4)]
    wire = [tunnel.datagram(packet) for packet in inner]
    source = tmp_path / "in.zpf"
    datagrams(source, wire)
    written = decode(spec(), source, tmp_path, transforms=registry)
    assert packets(written) == inner
    assert regions(written) == []
    assert records(written)[:2] == [
        ("packbits.version", ((0, 1),)),
        ("packbits.packet", ((1, len(wire[0])),)),
    ]


@pytest.mark.parametrize("fault", ["last byte flipped", "length off by one", "crc wrong"])
def test_a_datagram_that_does_not_unpack_is_unpack_failed_and_the_next_one_opens(
    tmp_path: Path, registry: Registry, fault: str
):
    good, after = ipv4(b"before"), ipv4(b"after", 2)
    bad = bytearray(tunnel.datagram(ipv4(b"broken", 1)))
    if fault == "last byte flipped":
        bad[-1] ^= 0xFF  # where packeteer's --tunnel-corruption lands
    elif fault == "length off by one":
        bad[1:3] = (int.from_bytes(bad[1:3], "big") + 1).to_bytes(2, "big")
    else:
        bad[3] ^= 0x01
    source = tmp_path / "in.zpf"
    datagrams(source, [tunnel.datagram(good), bytes(bad), tunnel.datagram(after)])
    written = decode(spec(), source, tmp_path, transforms=registry)
    assert packets(written) == [good, after]
    start = len(tunnel.datagram(good))
    assert regions(written) == [
        (start + 1, start + 7, "skipped", None),
        (start + 7, start + len(bad), "unpack-failed", None),
    ]


def test_a_version_this_is_not_is_undecodable(tmp_path: Path, registry: Registry):
    source = tmp_path / "in.zpf"
    datagrams(source, [b"\x02" + tunnel.datagram(ipv4(b"x"))[1:]])
    written = decode(spec(), source, tmp_path, transforms=registry)
    assert packets(written) == []
    assert [reason for _, _, reason, _ in regions(written)] == ["undecodable"]


# --- the whole chain: packeteer, zpfwire, kober, zpfwire, kober ---------------------------------

needs_the_chain = pytest.mark.skipif(
    not (HAS_TUNNEL and ZPFWIRE.exists()),
    reason="needs sibling packeteer (0.18.0, --udp-tunnel) and python-zipline-wire checkouts",
)
needs_the_inner_hop = pytest.mark.skipif(
    not (HAS_TUNNEL and HAS_PACKETS_INPUT),
    reason="needs sibling packeteer (0.18.0) and python-zipline-wire (0.5.0, a .zpf of packets)",
)


def impaired(tmp_path: Path) -> Run:
    """Generate the example's own traffic, under the pipeline's impaired input's flags."""
    return generate(PACKBITS, tmp_path, impairments=PACKBITS.inputs["pb_impaired"])


@needs_the_chain
def test_generated_impaired_traffic_unpacks_to_exactly_what_arrived(
    tmp_path: Path, registry: Registry
):
    run = impaired(tmp_path)
    open_tunnel(PACKBITS, run, registry)
    assert tunnel_problems(PACKBITS, run.truth, run.outer, run.opened) == []
    expected, left = arrivals(PACKBITS, run.truth, run.outer)
    assert sum(expected.values()) > 0
    assert sum(left.values()) > 0, "the corpus reaches a corrupted datagram"


@needs_the_inner_hop
def test_the_dns_inside_decodes_to_exactly_what_arrived(tmp_path: Path, registry: Registry):
    run = impaired(tmp_path)
    open_tunnel(PACKBITS, run, registry)
    assert PACKBITS.inside is not None
    decode_inside(PACKBITS.path(PACKBITS.inside), sessionize(PACKBITS, run), tmp_path / "dns")
    decoded = messages_by_direction(tmp_path / "dns" / "out.message.zpf")
    expected = expected_inside(PACKBITS, run.truth, run.outer)
    for direction in ("c2s", "s2c"):
        assert sorted(decoded[direction]) == sorted(expected[direction].elements()), direction
    assert sum(len(found) for found in decoded.values()) > 0


# --- adversarial datagrams -------------------------------------------------------------------


def packbits_cases(seed: int) -> list[bytes]:
    """Return datagrams, then seeded variants of each: cut, extended, flipped."""
    wire = [tunnel.datagram(ipv4(bytes([n]) * (n * 7), n)) for n in range(5)]
    return [*wire, *(data for message in wire for data in variants(message, seed, rounds=12))]


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_a_mangled_datagram_never_breaks_a_decode(registry: Registry, seed: int, emit: Emit):
    decoder = Decoder(spec(), transforms=registry)
    assert_never_breaks(PACKBITS, decoder, packbits_cases(seed), emit)


@pytest.mark.parametrize("seed", [1, 2])
def test_a_mangled_datagram_never_breaks_a_compiled_decode(registry: Registry, seed: int):
    assert_compiled_never_breaks(imported(spec(), registry), packbits_cases(seed), None)


# --- the command line, as the README runs it ---------------------------------------------------


def test_kober_run_unpacks_the_tunnel(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """``--load-transforms`` by path, which imports ``pb_codec`` from beside it; no ``--param``."""
    inner = [ipv4(b"one"), ipv4(b"two", 1)]
    source = tmp_path / "in.zpf"
    datagrams(source, [tunnel.datagram(packet) for packet in inner])
    out = tmp_path / "out.zpf"
    assert run_cli(PACKBITS, source, out, monkeypatch) == OK, capsys.readouterr()
    assert packets([block for block in blocks(out) if block[0] != "participant"]) == inner
