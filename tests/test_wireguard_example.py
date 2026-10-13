"""The WireGuard example: its cipher, its spec, and a decode of datagrams built here.

Stage 3 of ``plans/WIREGUARD-EXAMPLE-PLAN.md``: the kober half, which needs no
other project. Generated traffic is Stage 4's.

**The cipher is checked against RFC 8439's own vectors**, not against itself.
The tunnel wrapper that generates traffic and the transform that opens it share
``wg_crypto.py``, so a fault in it would seal and open consistently, and a
round trip would pass over a cipher that is not ChaCha20-Poly1305 (the plan's
Q4). The vectors below were extracted from the RFC's text by a script, not
typed, and each is cited by section. If ``cryptography`` happens to be
installed, the cipher is also compared with it. A test may use what the
product may not.
"""

from __future__ import annotations

import importlib.util
import json
import random
import struct
import sys
from pathlib import Path
from types import ModuleType

import pytest
from fuzzing import variants
from test_compiled_transforms import imported
from test_stage import datagrams
from test_stage_transforms import decode, records, regions
from zpfcompare import blocks

from kober import transforms as transforms_module
from kober.check import Severity, check
from kober.cli import FAILED, OK, main
from kober.decoder import Decoder
from kober.emit import Emit, plan
from kober.node import NodeStatus
from kober.spec import Spec
from kober.transforms import Registry

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "wireguard"
SPEC = EXAMPLE / "wireguard.yaml"


def _load(name: str) -> ModuleType:
    """Import one of the example's modules by path, as a user's process would."""
    if str(EXAMPLE) not in sys.path:
        sys.path.append(str(EXAMPLE))
    spec = importlib.util.spec_from_file_location(name, EXAMPLE / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


crypto = _load("wg_crypto")


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> Registry:
    """Load ``wg_transforms.py`` into a registry of the test's own.

    The module registers into kober's default registry when it runs, as a user's
    does, so the default is swapped for the test's while it runs.
    """
    fresh = Registry.standard()
    monkeypatch.setattr(transforms_module, "DEFAULT", fresh)
    _load("wg_transforms")
    return fresh


# --- RFC 8439's vectors ------------------------------------------------------------------------

#: RFC 8439 §2.4.2: ChaCha20 encryption.
CHACHA20 = {
    "plaintext": bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"
    ),
    "ciphertext": bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    ),
}

#: RFC 8439 §2.5.2: Poly1305.
POLY1305 = {
    "key": bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
    "message": bytes.fromhex(
        "43727970746f6772617068696320466f72756d2052657365617263682047726f"
        "7570"
    ),
    "tag": bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9"),
}

#: RFC 8439 §2.6.2: the Poly1305 key from ChaCha20.
KEYGEN = {
    "key": bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
    "nonce": bytes.fromhex("000000000001020304050607"),
    "output": bytes.fromhex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"),
}

#: RFC 8439 §2.8.2: AEAD_CHACHA20_POLY1305.
AEAD = {
    "plaintext": bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"
    ),
    "aad": bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    "key": bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
    "iv": bytes.fromhex("4041424344454647"),
    "constant": bytes.fromhex("07000000"),
    "ciphertext": bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    ),
    "tag": bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691"),
}

#: RFC 8439 A.5: decrypting, with a nonce that is not all zero.
DECRYPT = {
    "key": bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
    "ciphertext": bytes.fromhex(
        "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
        "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
        "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
        "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
        "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
        "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
        "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
        "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
        "a6ad5cb4022b02709b"
    ),
    "nonce": bytes.fromhex("000000000102030405060708"),
    "aad": bytes.fromhex("f33388860000000000004e91"),
    "tag": bytes.fromhex("eead9d67890cbb22392336fea1851f38"),
    "plaintext": bytes.fromhex(
        "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
        "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
        "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
        "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
        "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
        "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
        "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
        "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
        "726573732e2fe2809d"
    ),
}


def test_chacha20_encrypts_the_rfcs_plaintext():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    assert crypto.chacha20(key, 1, nonce, CHACHA20["plaintext"]) == CHACHA20["ciphertext"]
    assert crypto.chacha20(key, 1, nonce, CHACHA20["ciphertext"]) == CHACHA20["plaintext"]


def test_poly1305_tags_the_rfcs_message():
    assert crypto.poly1305(POLY1305["key"], POLY1305["message"]) == POLY1305["tag"]


def test_the_one_time_key_is_the_rfcs():
    assert crypto.poly1305_key(KEYGEN["key"], KEYGEN["nonce"]) == KEYGEN["output"]


def test_the_aead_seals_the_rfcs_plaintext():
    nonce = AEAD["constant"] + AEAD["iv"]
    sealed = crypto.seal(AEAD["key"], nonce, AEAD["plaintext"], AEAD["aad"])
    assert sealed == AEAD["ciphertext"] + AEAD["tag"]


def test_the_aead_opens_the_rfcs_message():
    sealed = DECRYPT["ciphertext"] + DECRYPT["tag"]
    opened = crypto.open_sealed(DECRYPT["key"], DECRYPT["nonce"], sealed, DECRYPT["aad"])
    assert opened == DECRYPT["plaintext"]


@pytest.mark.parametrize(
    "spoil",
    ["ciphertext", "tag", "aad", "key", "nonce", "short"],
)
def test_anything_changed_fails_the_tag(spoil: str):
    key, nonce, aad = DECRYPT["key"], DECRYPT["nonce"], DECRYPT["aad"]
    sealed = bytearray(DECRYPT["ciphertext"] + DECRYPT["tag"])
    if spoil == "ciphertext":
        sealed[0] ^= 1
    elif spoil == "tag":
        sealed[-1] ^= 1
    elif spoil == "aad":
        aad = aad[:-1] + b"\x00"
    elif spoil == "key":
        key = bytes(32)
    elif spoil == "nonce":
        nonce = bytes(12)
    else:
        sealed = sealed[: crypto.TAG_SIZE - 1]
    with pytest.raises(crypto.AuthenticationError):
        crypto.open_sealed(key, nonce, bytes(sealed), aad)


def test_a_transport_nonce_is_four_zeros_and_the_counter_little_endian():
    nonce = crypto.transport_nonce(0x0102030405060708)
    assert nonce == bytes.fromhex("000000000807060504030201")


def test_the_cipher_agrees_with_a_reviewed_library():
    """Only where ``cryptography`` is installed: the product never needs it."""
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    rng = random.Random(8439)
    for size in (0, 1, 15, 16, 17, 63, 64, 65, 1400):
        key, nonce = rng.randbytes(32), rng.randbytes(12)
        plaintext, aad = rng.randbytes(size), rng.randbytes(size % 20)
        theirs = aead.ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        assert crypto.seal(key, nonce, plaintext, aad) == theirs
        assert crypto.open_sealed(key, nonce, theirs, aad) == plaintext


# --- the spec --------------------------------------------------------------------------------


def test_the_spec_checks_with_the_one_warning_it_means():
    findings = check(Spec.from_file(SPEC))
    assert [f for f in findings if f.severity is Severity.ERROR] == []
    (warning,) = findings
    assert "switch has no default" in warning.message


def test_the_spec_is_documented():
    spec = Spec.from_file(SPEC)
    assert spec.doc
    assert spec.transforms["wg-transport"].fails_as == "decrypt-failed"


# --- WireGuard messages, built here --------------------------------------------------------------

#: The two peers' indices and keys for two sessions: the second is a rekey.
#: A transport message names the *receiver's* index, so one table covers both
#: directions.
INITIATOR, RESPONDER = 0x11111111, 0x22222222
INITIATOR_2, RESPONDER_2 = 0x33333333, 0x44444444
KEYS = {
    INITIATOR: bytes([0xA1]) * 32,  # to the initiator, session 1
    RESPONDER: bytes([0xB1]) * 32,  # to the responder, session 1
    INITIATOR_2: bytes([0xA2]) * 32,
    RESPONDER_2: bytes([0xB2]) * 32,
}


def spec() -> Spec:
    return Spec.from_file(SPEC)


def header(kind: int) -> bytes:
    return struct.pack("<B3s", kind, b"\x00" * 3)


def initiation(sender: int) -> bytes:
    return header(1) + struct.pack("<I", sender) + bytes(range(140))


def response(sender: int, receiver: int) -> bytes:
    return header(2) + struct.pack("<II", sender, receiver) + bytes(range(80))


def cookie_reply(receiver: int) -> bytes:
    return header(3) + struct.pack("<I", receiver) + bytes(56)


def padded(packet: bytes) -> bytes:
    """Pad a packet to 16 bytes, as WireGuard does before sealing it."""
    return packet + b"\x00" * (-len(packet) % 16)


def transport(receiver: int, counter: int, packet: bytes, key: bytes | None = None) -> bytes:
    used = KEYS[receiver] if key is None else key
    sealed = crypto.seal(used, crypto.transport_nonce(counter), padded(packet))
    return header(4) + struct.pack("<IQ", receiver, counter) + sealed


def test_wireguards_message_sizes():
    """148, 92 and 64, as the protocol fixes them, and 32 for an empty packet."""
    built = [initiation(1), response(2, 1), cookie_reply(1), transport(INITIATOR, 0, b"")]
    assert [len(message) for message in built] == [148, 92, 64, 32]


def conversation() -> tuple[list[bytes], list[bytes]]:
    """Return a tunnel's datagrams, and the plaintexts a decode must recover from them."""
    a, b, c, d = (f"inner packet {n}".encode() for n in "abcd")
    wire = [
        initiation(INITIATOR),
        response(RESPONDER, INITIATOR),
        transport(RESPONDER, 0, a),             # initiator to responder
        transport(INITIATOR, 0, b),             # and back
        transport(RESPONDER, 1, b""),           # a keepalive
        cookie_reply(INITIATOR),
        initiation(INITIATOR_2),                # a rekey: new indices, new keys
        response(RESPONDER_2, INITIATOR_2),
        transport(RESPONDER_2, 0, c),
        transport(INITIATOR_2, 0, d),
    ]
    return wire, [padded(a), padded(b), b"", padded(c), padded(d)]


def plaintexts(written: list[tuple[object, ...]]) -> list[object]:
    return [b[3] for b in written if b[0] == "record" and b[2] == "wireguard.body.packet"]


def test_every_transport_message_opens_under_its_receivers_key(
    tmp_path: Path, registry: Registry
):
    """Both directions, a keepalive, a cookie reply and a rekey, by both drivers."""
    wire, expected = conversation()
    source = tmp_path / "in.zpf"
    datagrams(source, wire)
    written = decode(spec(), source, tmp_path, params={"keys": KEYS}, transforms=registry)
    assert plaintexts(written) == expected
    assert regions(written) == []
    for key in KEYS.values():
        assert key.hex() not in repr(written)


def test_a_transport_message_is_one_record_citing_its_datagram(
    tmp_path: Path, registry: Registry
):
    """The receiver and counter are spoken for: one record per datagram, for a second stage."""
    message = transport(RESPONDER, 7, b"one packet")
    source = tmp_path / "in.zpf"
    datagrams(source, [message])
    written = decode(spec(), source, tmp_path, params={"keys": KEYS}, transforms=registry)
    assert records(written) == [
        ("wireguard.type", ((0, 1),)),
        ("wireguard.reserved", ((1, 4),)),
        ("wireguard.body.packet", ((4, len(message)),)),
    ]


def test_the_handshake_decodes_as_structure(tmp_path: Path, registry: Registry):
    source = tmp_path / "in.zpf"
    datagrams(source, [initiation(INITIATOR), response(RESPONDER, INITIATOR)])
    written = decode(spec(), source, tmp_path, params={"keys": KEYS}, transforms=registry)
    roles = [role for role, _ in records(written)]
    assert "wireguard.body.ephemeral" in roles
    assert "wireguard.body.encrypted_static" in roles
    assert "wireguard.body.encrypted_nothing" in roles
    assert regions(written) == []


@pytest.mark.parametrize("fault", ["tampered", "wrong key", "no key"])
def test_a_message_that_does_not_open_is_decrypt_failed_and_the_next_one_opens(
    tmp_path: Path, registry: Registry, fault: str
):
    good = transport(RESPONDER, 0, b"before")
    if fault == "tampered":
        bad = bytearray(transport(RESPONDER, 1, b"payload"))
        bad[-1] ^= 0x01
        bad = bytes(bad)
    elif fault == "wrong key":
        bad = transport(RESPONDER, 1, b"payload", key=KEYS[INITIATOR])
    else:
        bad = transport(0x99999999, 1, b"payload", key=bytes(32))
    after = transport(RESPONDER, 2, b"after")
    source = tmp_path / "in.zpf"
    datagrams(source, [good, bad, after])
    written = decode(spec(), source, tmp_path, params={"keys": KEYS}, transforms=registry)
    assert plaintexts(written) == [padded(b"before"), padded(b"after")]
    start = len(good)
    assert regions(written) == [
        (start + 4, start + 16, "skipped", None),
        (start + 16, start + len(bad), "decrypt-failed", None),
    ]


def test_a_type_wireguard_does_not_have_is_not_wireguard(tmp_path: Path, registry: Registry):
    source = tmp_path / "in.zpf"
    datagrams(source, [header(9) + bytes(28)])
    written = decode(spec(), source, tmp_path, params={"keys": KEYS}, transforms=registry)
    assert plaintexts(written) == []
    assert [reason for _, _, reason, _ in regions(written)] == ["undecodable"]


# --- adversarial datagrams -------------------------------------------------------------------


def wireguard_cases(seed: int) -> list[bytes]:
    """Return the tunnel's datagrams, then seeded variants of each: cut, extended, flipped."""
    wire, _ = conversation()
    return [*wire, *(data for message in wire for data in variants(message, seed, rounds=12))]


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("emit", [Emit.MESSAGE, Emit.FIELD])
def test_a_mangled_datagram_never_breaks_a_decode(registry: Registry, seed: int, emit: Emit):
    """The promises every shipped spec keeps, over what a lossy, hostile link delivers.

    A decode never raises, never cites a byte it also names undecoded, names
    regions only with reasons the format or the spec's ``fails_as`` has, and
    never shows a key.
    """
    built = spec()
    decoder = Decoder(built, params={"keys": KEYS}, transforms=registry)
    allowed = {status.value for status in NodeStatus if status is not NodeStatus.OK}
    allowed.add("decrypt-failed")
    for data in wireguard_cases(seed):
        try:
            tree = decoder.decode_bytes(data)
        except Exception as exc:
            exc.add_note(f"escaped a decode: seed={seed} on {data!r}")
            raise
        emissions, unclaimed = plan(built, tree, data, emit=emit)
        cited = {at for r in emissions for at in range(r.off_start, r.off_end)}
        named = {at for r in unclaimed for at in range(r.off_start, r.off_end)}
        assert not cited & named, f"both cited and undecoded on {data!r}"
        assert {r.reason for r in unclaimed} <= allowed, data
        shown = tree.render()
        assert all(key.hex() not in shown for key in KEYS.values()), data


@pytest.mark.parametrize("seed", [1, 2])
def test_a_mangled_datagram_never_breaks_a_compiled_decode(registry: Registry, seed: int):
    module = imported(spec(), registry)
    for data in wireguard_cases(seed):
        try:
            module.decode(data, params={"keys": KEYS})
        except Exception as exc:
            exc.add_note(f"escaped a compiled decode: seed={seed} on {data!r}")
            raise


# --- the command line, as the README runs it ---------------------------------------------------


def test_kober_run_opens_the_tunnel_with_a_key_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """``--load-transforms`` by path, which imports ``wg_crypto`` from beside it."""
    monkeypatch.setattr(transforms_module, "DEFAULT", Registry.standard())
    monkeypatch.delitem(sys.modules, "wg_crypto", raising=False)
    monkeypatch.setattr(sys, "path", [p for p in sys.path if p != str(EXAMPLE)])
    wire, expected = conversation()
    source = tmp_path / "in.zpf"
    datagrams(source, wire)
    log = tmp_path / "keys.json"
    log.write_text(json.dumps({str(index): f"hex:{key.hex()}" for index, key in KEYS.items()}))
    out = tmp_path / "out.zpf"
    code = main(
        [
            "run", str(SPEC), str(source), "-o", str(out), "--emit", "field",
            "--load-transforms", str(EXAMPLE / "wg_transforms.py"),
            "--param", f"keys=file:{log}",
        ]
    )
    assert code == OK, capsys.readouterr()
    written = [block for block in blocks(out) if block[0] != "participant"]
    assert plaintexts(written) == expected


def test_without_the_key_log_the_run_does_not_start(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(transforms_module, "DEFAULT", Registry.standard())
    source = tmp_path / "in.zpf"
    datagrams(source, [transport(RESPONDER, 0, b"x")])
    code = main(
        [
            "run", str(SPEC), str(source), "-o", str(tmp_path / "out.zpf"),
            "--load-transforms", str(EXAMPLE / "wg_transforms.py"),
        ]
    )
    assert code == FAILED
    assert "needs parameter(s) 'keys'" in capsys.readouterr().err

