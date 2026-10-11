"""Map parameters and indexing: a key chosen per message from a table a run supplies.

The WireGuard example plan's Q1. A tunnel has one key per direction, a new pair
at every rekey, and one set per peer, and each message names which by a field:
``keys[receiver]``. Loaded, checked, decoded by both drivers, read from the
command line, and part of the configuration's digest, with no value ever
written anywhere.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from cipher import seal, xor_open
from test_cli import write
from test_compiled_transforms import imported
from test_stage import datagrams
from test_stage_transforms import decode, records, regions

from kober.check import Severity, check
from kober.cli import FAILED, OK, main
from kober.decoder import Decoder
from kober.errors import ParameterError, SpecError
from kober.expr import ExprType, MapType
from kober.loader import from_yaml
from kober.spec import Emit, Param, Spec
from kober.transforms import Registry

TUNNEL = """
name: tunnel
version: "1"
entry: datagram
transforms:
  xor: {{params: {{key: bytes, nonce: bytes}}}}
params:
  keys: {{type: {{map: [int, bytes]}}, secret: true}}
units:
  datagram:
    fields:
      - {{name: receiver, bits: 8{receiver_emit}}}
      - {{name: nonce, bytes: 4, emit: none}}
      - {{name: sealed, bytes: {{size: {{remaining: true}}}}}}
      - name: inner
        transform:
          from: sealed
          with: xor
          limit: 1500
          args: {{key: "{key}", nonce: nonce}}
          content_type: "dec:ip-packet"
"""

#: One key per direction: what a tunnel's two receivers are.
KEYS = {1: bytes(range(16)), 2: bytes(range(16, 32))}
NONCE = b"nnnn"


def tunnel(key: str = "keys[receiver]", receiver_emit: str = ", emit: none") -> Spec:
    return from_yaml(TUNNEL.format(key=key, receiver_emit=receiver_emit))


def datagram(receiver: int, payload: bytes, key: bytes | None = None) -> bytes:
    """Seal ``payload`` for ``receiver``, under its own key unless told otherwise."""
    used = KEYS[receiver] if key is None else key
    return bytes([receiver]) + NONCE + seal(payload, key=used, nonce=NONCE)


def registry() -> Registry:
    bound = Registry.standard()
    bound.register("xor", xor_open)
    return bound


def errors(built: Spec) -> list[str]:
    return [f.message for f in check(built) if f.severity is Severity.ERROR]


# --- loading ---------------------------------------------------------------------------


def test_a_map_parameter_loads_as_a_map_type():
    (param,) = tunnel().params
    assert param.type == MapType(ExprType.INT, ExprType.BYTES)
    assert param.type.value == "map[int, bytes]"
    assert param.secret


@pytest.mark.parametrize(
    ("written", "fragment"),
    [
        ("{type: {table: [int, bytes]}}", "unknown key(s) 'table'; allowed here: map"),
        ("{type: {}}", "{map: [key type, value type]}"),
        ("{type: {map: [int]}}", "this lists 1 type(s)"),
        ("{type: {map: [int, bytes, str]}}", "this lists 3 type(s)"),
        ("{type: {map: [bytes, bytes]}}", "a map is keyed by int or str, not bytes"),
        ("{type: {map: [bool, int]}}", "a map is keyed by int or str, not bool"),
        ("{type: {map: [int, list]}}", "unknown value 'list'"),
        ("map", "unknown value 'map'"),
    ],
)
def test_a_malformed_map_type_is_refused(written: str, fragment: str):
    source = TUNNEL.format(key="keys[receiver]", receiver_emit="").replace(
        "keys: {type: {map: [int, bytes]}, secret: true}", f"keys: {written}"
    )
    with pytest.raises(SpecError) as caught:
        from_yaml(source)
    assert fragment in str(caught.value)


# --- checking --------------------------------------------------------------------------


def test_a_map_indexed_by_a_field_checks():
    assert errors(tunnel()) == []


@pytest.mark.parametrize(
    ("key", "fragment"),
    [
        ("keys", "'keys' is a map; an expression reads one entry of it, keys[key]"),
        ("keys[nonce]", "the key of 'keys' needs int, got bytes"),
        ("nonce[receiver]", "'nonce' is not a map parameter"),
        ("tables[receiver]", "unknown map parameter 'tables'; the spec's maps: keys"),
    ],
)
def test_a_map_is_only_ever_indexed_by_its_key_type(key: str, fragment: str):
    (found,) = errors(tunnel(key=key))
    assert fragment in found


def test_a_scalar_parameter_cannot_be_indexed():
    built = from_yaml(
        TUNNEL.format(key="key[receiver]", receiver_emit="").replace(
            "keys: {type: {map: [int, bytes]}, secret: true}", "key: bytes"
        )
    )
    wanted = "'key' is bytes, and only a map parameter can be indexed"
    assert any(wanted in e for e in errors(built))


def test_a_map_is_not_a_transforms_source():
    built = from_yaml(
        TUNNEL.format(key="keys[receiver]", receiver_emit="").replace("from: sealed", "from: keys")
    )
    assert any(
        "parameter 'keys' is map[int, bytes], and a transform reads bytes" in e
        for e in errors(built)
    )


def test_only_a_document_parameter_may_be_a_map():
    """A unit's parameters are bound from expressions, and no expression is a map."""
    built = tunnel()
    unit = built.units["datagram"]
    table = Param(name="table", type=MapType(ExprType.INT, ExprType.BYTES))
    built = dataclasses.replace(
        built, units={**built.units, "datagram": dataclasses.replace(unit, params=(table,))}
    )
    wanted = "parameter 'table' is a map, and only a document parameter"
    assert any(wanted in e for e in errors(built))


# --- decoding, both drivers ------------------------------------------------------------


def test_each_message_is_opened_with_the_key_its_receiver_names(tmp_path: Path):
    """Both directions in one stream, each under its own key, by both drivers."""
    wire = [datagram(1, b"to one"), datagram(2, b"to two"), datagram(1, b"one again")]
    source = tmp_path / "in.zpf"
    datagrams(source, wire)
    written = decode(tunnel(), source, tmp_path, params={"keys": KEYS}, transforms=registry())
    plain = [block[3] for block in written if block[0] == "record"]
    assert plain == [b"to one", b"to two", b"one again"]
    assert regions(written) == []


def test_the_field_that_chose_the_key_is_cited_by_the_output(tmp_path: Path):
    """``receiver`` is read only by the index, and the output still speaks for it."""
    data = datagram(2, b"payload")
    source = tmp_path / "in.zpf"
    datagrams(source, [data])
    written = decode(tunnel(), source, tmp_path, params={"keys": KEYS}, transforms=registry())
    assert records(written) == [("tunnel.inner", ((0, len(data)),))]
    assert regions(written) == [], "an emit: none key is spoken for, not skipped"


def test_a_receiver_with_no_key_fails_its_transform_and_the_stream_goes_on(tmp_path: Path):
    wire = [datagram(1, b"first"), datagram(9, b"nobody's", key=KEYS[1]), datagram(2, b"last")]
    source = tmp_path / "in.zpf"
    datagrams(source, wire)
    written = decode(tunnel(), source, tmp_path, params={"keys": KEYS}, transforms=registry())
    plain = [block[3] for block in written if block[0] == "record"]
    assert plain == [b"first", b"last"]
    start = len(wire[0])
    header = start + 1 + len(NONCE)
    assert regions(written) == [
        # The arguments marked emit: none, the receiver among them, name nothing
        # when the output speaks for them, and are `skipped` when it cannot.
        (start, header, "skipped", None),
        (header, start + len(wire[1]), "undecodable", None),
    ]
    for key in KEYS.values():
        assert key.hex() not in repr(written)
        assert repr(key) not in repr(written)


def test_a_missing_entry_is_worded_alike_by_both_backends():
    data = datagram(9, b"x", key=KEYS[1])
    tree = Decoder(tunnel(), params={"keys": KEYS}, transforms=registry()).decode_bytes(data)
    inner = tree.find("inner")
    assert inner is not None
    assert inner.failed
    module = imported(tunnel(), registry())
    message = module.decode(data, params={"keys": KEYS})
    assert message is not None
    assert "'keys' has no entry for 9" in message.inner.detail
    assert "'keys' has no entry for 9" in (inner.detail or "")


# --- the parameter's value -------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        (b"not a map", "parameter 'keys' must be map[int, bytes], got bytes"),
        ({"1": KEYS[1]}, "parameter 'keys' key must be int, got str"),
        ({True: KEYS[1]}, "parameter 'keys' key must be int, got bool"),
        ({1: KEYS[1].hex()}, "parameter 'keys' value must be bytes, got str"),
    ],
)
def test_a_map_of_the_wrong_types_is_refused_by_both_backends(value: object, fragment: str):
    with pytest.raises(ParameterError) as caught:
        Decoder(tunnel(), params={"keys": value}, transforms=registry())
    assert fragment in str(caught.value)
    module = imported(tunnel(), registry())
    with pytest.raises(ParameterError) as again:
        module.decode(datagram(1, b"x"), params={"keys": value})
    assert str(again.value) == str(caught.value)
    assert KEYS[1].hex() not in str(caught.value)


def test_a_supplied_map_is_copied_so_changing_it_later_changes_nothing():
    keys = dict(KEYS)
    decoder = Decoder(tunnel(), params={"keys": keys}, transforms=registry())
    digest = decoder.params_digest()
    keys[1] = bytes(16)
    keys[3] = bytes(16)
    assert decoder.params_digest() == digest
    inner = decoder.decode_bytes(datagram(1, b"still opens")).find("inner")
    assert inner is not None
    assert inner.value == b"still opens"


def test_the_digest_is_the_tables_not_the_order_it_was_built_in():
    def digest(keys: dict[int, bytes]) -> str:
        return Decoder(tunnel(), params={"keys": keys}, transforms=registry()).params_digest()

    assert digest(KEYS) == digest(dict(reversed(list(KEYS.items()))))
    assert digest(KEYS) != digest({**KEYS, 2: bytes(16)}), "a different key is another run"
    assert digest(KEYS) != digest({1: KEYS[1]}), "so is a missing one"


def test_a_compiled_module_writes_the_interpreters_digest(tmp_path: Path):
    source = tmp_path / "in.zpf"
    datagrams(source, [datagram(1, b"x")])
    written = decode(tunnel(), source, tmp_path, params={"keys": KEYS}, transforms=registry())
    expected = Decoder(
        tunnel(), emit=Emit.FIELD, params={"keys": KEYS}, transforms=registry()
    ).params_digest()
    assert [block[3] for block in written if block[0] == "decoder"] == [expected]


# --- the command line ------------------------------------------------------------------


@pytest.fixture
def ciphers(tmp_path: Path) -> Path:
    """Write a ``--load-transforms`` module that registers the test cipher."""
    module = tmp_path / "ciphers.py"
    module.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(Path(__file__).parent)!r})\n"
        "from cipher import xor_open\n"
        "from kober.transforms import register\n"
        "register('xor', xor_open)\n"
    )
    return module


def key_log(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(document))
    return path


def test_a_map_is_read_from_a_json_key_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], ciphers: Path
):
    log = key_log(tmp_path, {str(index): f"hex:{key.hex()}" for index, key in KEYS.items()})
    code = main(
        [
            "try", write(tmp_path, TUNNEL.format(key="keys[receiver]", receiver_emit="")),
            "--hex", datagram(2, b"hello").hex(),
            "--param", f"keys=file:{log}", "--load-transforms", str(ciphers),
        ]
    )
    out = capsys.readouterr().out
    assert code == OK, out
    assert "inner = b'hello'" in out


@pytest.mark.parametrize(
    ("document", "fragment"),
    [
        (None, "a map is file:PATH, a JSON object"),
        ("not json {", "is not JSON"),
        ([1, 2], "is not a JSON object"),
        ({"1": 5}, "each value in"),
        ({"one": f"hex:{KEYS[1].hex()}"}, "--param keys[one]: not a decimal integer"),
        ({"1": KEYS[1].hex()}, "--param keys[1]: a bytes value is hex:… or file:PATH"),
        ({"1": f"hex:{KEYS[1].hex()}", "01": f"hex:{KEYS[2].hex()}"}, "has key 1 more than once"),
    ],
    ids=["not-a-file", "not-json", "not-an-object", "not-text", "bad-key", "bad-value", "twice"],
)
def test_a_malformed_key_log_is_refused_without_quoting_a_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], document: object, fragment: str
):
    if document is None:
        param = f"keys=hex:{KEYS[1].hex()}"
    elif isinstance(document, str):
        path = tmp_path / "keys.json"
        path.write_text(document)
        param = f"keys=file:{path}"
    else:
        param = f"keys=file:{key_log(tmp_path, document)}"
    code = main(
        [
            "try", write(tmp_path, TUNNEL.format(key="keys[receiver]", receiver_emit="")),
            "--hex", "00", "--param", param,
        ]
    )
    err = capsys.readouterr().err
    assert code == FAILED
    assert fragment in err
    for key in KEYS.values():
        assert key.hex() not in err, "a key is a secret and is never quoted"
