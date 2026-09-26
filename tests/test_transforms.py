"""The Python binding for transforms (the transform plan's Stage 3).

What each well-known name this backend binds does with good input, bad input,
and input built to outgrow its limit; how a caller adds a transform; and what
`bind` says when a spec needs one nothing supplies. The name table itself is
the format's and is checked by `test_check_transforms.py`.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import tracemalloc
import zlib

import pytest
from cipher import seal, xor_open

from kober import transforms
from kober.errors import TransformError, UnboundTransformError
from kober.loader import from_yaml
from kober.transforms import WELL_KNOWN, Registry, Tier, apply

try:
    from compression import zstd
except ImportError:  # before Python 3.14
    zstd = None

TEXT = b'{"id": 1, "name": "item"}\n' * 200
HAS_ZSTD = zstd is not None


def _compress(name: str, data: bytes) -> bytes:
    """Compress with the standard library, as a sender would."""
    if name == "gzip":
        return gzip.compress(data, mtime=0)
    if name == "deflate":
        return zlib.compress(data)
    if name == "deflate-raw":
        engine = zlib.compressobj(wbits=-15)
        return engine.compress(data) + engine.flush()
    if name == "bzip2":
        return bz2.compress(data)
    if name == "xz":
        return lzma.compress(data)
    if name == "zstd" and zstd is not None:
        # With its checksum: a zstd frame without one can decode corrupt data
        # to different bytes without noticing, so it is only as strict as the
        # sender made it. A sender that cares sets it.
        return zstd.compress(data, options={zstd.CompressionParameter.checksum_flag: 1})
    raise AssertionError(name)


STANDARD = ["gzip", "deflate", "deflate-raw", "bzip2", "xz", *(["zstd"] if HAS_ZSTD else [])]
MEMBERED = [name for name in STANDARD if name not in ("deflate", "deflate-raw")]


def run(name: str, data: bytes, limit: int = 1 << 20) -> bytes:
    registry = Registry.standard()
    transformer = registry.lookup(name)
    assert transformer is not None, name
    return apply(name, transformer, data, limit=limit)


# --- what this backend binds ------------------------------------------------------


def test_the_standard_registry_binds_every_core_name():
    """A backend binding the core tier can run any spec that stays inside it."""
    core = {name for name, known in WELL_KNOWN.items() if known.tier is Tier.CORE}
    assert core <= Registry.standard().names()


def test_the_standard_registry_binds_zstd_exactly_where_the_standard_library_has_it():
    assert ("zstd" in Registry.standard().names()) is HAS_ZSTD


def test_the_standard_registry_never_binds_brotli():
    """The standard library has no Brotli, so `br` is the name this backend declines."""
    assert "br" not in Registry.standard().names()


@pytest.mark.parametrize("name", STANDARD)
def test_each_bound_name_inflates_what_its_format_compressed(name: str):
    assert run(name, _compress(name, TEXT)) == TEXT


def test_deflate_is_the_zlib_format_and_deflate_raw_is_not():
    """HTTP's and the browser's `deflate` is RFC 1950; raw RFC 1951 is `deflate-raw`."""
    wrapped = _compress("deflate", TEXT)
    raw = _compress("deflate-raw", TEXT)
    assert run("deflate", wrapped) == TEXT
    assert run("deflate-raw", raw) == TEXT
    with pytest.raises(TransformError):
        run("deflate", raw)
    with pytest.raises(TransformError):
        run("deflate-raw", wrapped)


@pytest.mark.parametrize("name", MEMBERED)
def test_a_format_that_allows_several_members_reads_them_all(name: str):
    assert run(name, _compress(name, b"first ") + _compress(name, b"second")) == b"first second"


# --- failure, in kober's words ----------------------------------------------------------


@pytest.mark.parametrize("name", STANDARD)
def test_corrupt_data_is_refused_in_kobers_words(name: str):
    data = bytearray(_compress(name, TEXT))
    for index in range(len(data) // 2, len(data) // 2 + 8):
        data[index] ^= 0x5A
    with pytest.raises(TransformError) as caught:
        run(name, bytes(data))
    message = str(caught.value)
    assert message.startswith(f"{name}: "), message
    assert "Error -3" not in message, "zlib's own wording must not reach the output"
    assert "raised" not in message, "a shipped codec's failure is worded, not reported by class"


@pytest.mark.parametrize("name", STANDARD)
def test_data_that_ends_early_is_refused(name: str):
    with pytest.raises(TransformError, match="ends early|not valid compressed data"):
        run(name, _compress(name, TEXT)[:-12])


@pytest.mark.parametrize("name", ["deflate", "deflate-raw"])
def test_bytes_after_a_single_member_format_are_refused(name: str):
    with pytest.raises(TransformError, match=r"3 byte\(s\) follow the compressed data"):
        run(name, _compress(name, TEXT) + b"xyz")


@pytest.mark.parametrize("name", STANDARD)
def test_the_limit_is_exact(name: str):
    data = _compress(name, TEXT)
    assert run(name, data, limit=len(TEXT)) == TEXT
    with pytest.raises(TransformError, match=f"output passes its limit of {len(TEXT) - 1} bytes"):
        run(name, data, limit=len(TEXT) - 1)


def test_a_decompression_bomb_stops_at_the_limit_in_bounded_memory():
    """64 MiB of zeros in a few tens of kilobytes, against a 1 MiB limit.

    The output is asked for one byte past the limit at a time, so a crafted
    body costs what the limit allows and no more. Checked by what Python
    allocated at its peak: well under the 64 MiB a decompress-then-check would
    have built.
    """
    engine = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = bytes(1 << 20)
    bomb = b"".join(engine.compress(chunk) for _ in range(64)) + engine.flush()
    assert len(bomb) < 100_000
    tracemalloc.start()
    try:
        with pytest.raises(TransformError, match="passes its limit"):
            run("gzip", bomb, limit=1 << 20)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 << 20, f"peak {peak} bytes"


# --- a caller's transform -------------------------------------------------------------


KEY = bytes(range(16))
NONCE = b"nonce-01"


def test_a_caller_registers_a_cipher_and_runs_it_with_arguments():
    registry = Registry.standard()
    registry.register("xor", xor_open)
    sealed = seal(b"inner datagram", key=KEY, nonce=NONCE)
    opened = apply("xor", xor_open, sealed, limit=100, args={"key": KEY, "nonce": NONCE})
    assert opened == b"inner datagram"
    assert registry.lookup("xor") is xor_open


def test_a_callers_message_never_reaches_the_output():
    """A cipher's error text can hold a key; kober reports only its class (Q4)."""
    sealed = seal(b"inner datagram", key=KEY, nonce=NONCE)
    wrong = bytes(16)
    with pytest.raises(TransformError) as caught:
        apply("xor", xor_open, sealed, limit=100, args={"key": wrong, "nonce": NONCE})
    assert str(caught.value) == "xor: the transform raised ValueError"
    assert wrong.hex() not in str(caught.value)


def test_a_callers_own_transform_error_is_reworded_too():
    def refuses(data: bytes, *, limit: int) -> bytes:
        msg = "secret-looking detail"
        raise TransformError(msg)

    with pytest.raises(TransformError) as caught:
        apply("custom", refuses, b"x", limit=10)
    assert str(caught.value) == "custom: the transform rejected its input"


def test_a_callers_output_is_held_to_the_limit_and_to_bytes():
    def generous(data: bytes, *, limit: int) -> bytes:
        return data * 10

    def textual(data: bytes, *, limit: int) -> str:
        return "text"

    with pytest.raises(TransformError, match="output passes its limit of 5 bytes"):
        apply("generous", generous, b"abc", limit=5)
    with pytest.raises(TransformError, match="returned str, not bytes"):
        apply("textual", textual, b"abc", limit=5)  # type: ignore[arg-type]


def test_rebinding_a_name_needs_to_say_so():
    registry = Registry.standard()
    with pytest.raises(ValueError, match="'gzip' is bound already"):
        registry.register("gzip", xor_open)
    registry.register("gzip", xor_open, replace=True)
    assert registry.lookup("gzip") is xor_open


def test_the_module_level_functions_act_on_the_default_registry(monkeypatch: pytest.MonkeyPatch):
    fresh = Registry.standard()
    monkeypatch.setattr(transforms, "DEFAULT", fresh)
    transforms.register("xor", xor_open)
    assert fresh.lookup("xor") is xor_open
    assert transforms.lookup("xor") is xor_open


# --- binding a spec ---------------------------------------------------------------------


def spec_using(name: str, declared: str = "") -> object:
    return from_yaml(f"""
name: t
version: "1"
entry: m
{declared}
units:
  m:
    fields:
      - {{name: body, bytes: {{size: {{remaining: true}}}}}}
      - name: out
        transform: {{from: body, with: {name}, limit: 100}}
""")


def test_binding_a_spec_that_stays_in_the_core_tier_needs_nothing_registered():
    bound = Registry.standard().bind(spec_using("gzip"))
    assert set(bound) == {"gzip"}


def test_a_well_known_name_this_backend_declines_fails_when_bound_and_says_so():
    """Acceptance 8: `br` is refused *as unbound here*, not as an unknown name."""
    with pytest.raises(UnboundTransformError) as caught:
        Registry.standard().bind(spec_using("br", "transforms: {br: {}}"))
    message = str(caught.value)
    assert "'br' is a well-known extended name (RFC 7932)" in message
    assert "this backend does not bind" in message


def test_a_spec_s_own_name_nothing_registered_fails_when_bound_and_says_so():
    with pytest.raises(UnboundTransformError) as caught:
        Registry.standard().bind(spec_using("cipher", "transforms: {cipher: {}}"))
    assert "'cipher' is the spec's own and nothing is registered" in str(caught.value)


def test_registering_the_missing_name_makes_the_spec_bindable():
    registry = Registry.standard()
    registry.register("br", xor_open)
    assert set(registry.bind(spec_using("br", "transforms: {br: {}}"))) == {"br"}
