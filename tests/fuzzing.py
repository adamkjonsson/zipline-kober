"""Adversarial input, generated the same way for both implementations.

The mutators live here rather than in one test module because the promises they
exist to break are made twice over: the interpreter must not raise and must
account for every byte, and so must a decoder the compiler wrote. Fuzzing them
with *different* inputs would make the two sets of results incomparable, which
is the one thing this project cannot afford — the differential test is what
holds the compiler honest.

**Why this technique.** It came from `packeteer`, whose ``fuzz`` verb generates
adversarial variants. Run end to end (``packeteer fuzz`` → ``zpfwire convert``
→ ``kober run``) it found a real conformance bug the whole hand-built suite had
missed: a seam rule that fired on `Gap` only, where `zpf` needs one after any
*hole*-class region. See ``plans/REAL-CAPTURE-PHASE-PLAN.md`` §13.5 and the
README for that pipeline, which is deeper than this and needs both sibling
checkouts.

What is here is the part that should run every time, so it depends on nothing
outside the standard library. By the time bytes reach a decoder the transport
layers are gone and what is left is payload, so the mutations that actually
reach it are the payload-level ones — truncate, extend, flip, replace.

Seeded, so a failure is reproducible from the case it prints rather than being
a story about a run that happened once.
"""

from __future__ import annotations

import random
import struct

#: How many mutations per seed case. Small enough to keep the suite fast, large
#: enough that each run covers every mutation kind several times.
ROUNDS = 60

DNS_QUERY = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack(">HH", 1, 1)
)

HTTP_REQUEST = b"GET / HTTP/1.1\r\nHost: httpforever.com\r\nAccept: */*\r\n\r\n"

#: The seed input each shipped example is fuzzed from.
SEEDS: dict[str, bytes] = {"dns.yaml": DNS_QUERY, "http.yaml": HTTP_REQUEST}

#: A chunked response and a counted one, for ``examples/http.yaml``.
#:
#: :data:`HTTP_REQUEST` reaches **neither** of that spec's framing arms — it has
#: no framing header, so every variant of it takes the third path and the two
#: that do the work are never entered. That is the same gap that let a wrong
#: `chunked` comparison live through five stages: the corpus with 2000 real
#: messages has no chunked message in it either. These are the seeds that reach
#: the arms, and they exist for the reason :data:`DNS_RESPONSE` does.
HTTP_CHUNKED = (
    b"HTTP/1.1 200 OK\r\nServer: nginx\r\nTransfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n\r\n1a\r\n" + b"x" * 0x1A + b"\r\n0\r\n\r\n"
)

HTTP_COUNTED = (
    b"POST /api/v1/orders HTTP/1.1\r\nHost: api.example.com\r\n"
    b"Content-Type: application/json\r\nContent-Length: 26\r\n\r\n"
    b'{"id": 89163, "ok": false}'
)

#: Every framing arm the shipped example chooses between, so a sweep covers the
#: choice and not only one side of it.
HTTP_FRAMINGS: tuple[bytes, ...] = (HTTP_REQUEST, HTTP_CHUNKED, HTTP_COUNTED)

#: A real DNS response, from `python-zipline-wire`'s ``dns_example.pcapng``.
#: Its answer's owner name is ``c0 0c`` — the compression pointer of RFC 1035
#: §4.1.4, and the reason `Pointer` exists. Inlined rather than read from the
#: sibling checkout, so this suite still stands alone.
#:
#: It is fuzzed against ``examples/dns.yaml``, which follows pointers. The
#: query in :data:`SEEDS` reaches none of that code, so this is the seed that
#: does — mutating it lands offsets past the end, forward references, targets
#: that are not names, and pointers at bytes that were never a pointer.
DNS_RESPONSE = bytes.fromhex(
    "183e818000010001000000001c62726f777365722d696e74616b652d7573352d"
    "64617461646f67687103636f6d0000010001c00c000100010000009f00042295"
    "429a"
)



def mutate(data: bytes, rng: random.Random) -> bytes:
    """Return one adversarial variant of ``data``.

    The kinds `packeteer` calls truncate, extend, bit-flip, and boundary, plus
    wholesale replacement — the payload-level subset, since that is what
    survives the transport layers to reach a decoder.

    Args:
        data: The input to vary.
        rng: The seeded source of randomness, so a failure reproduces.

    Returns:
        One variant, which may be empty and may be longer than the input.

    """
    kind = rng.randrange(6)
    if not data:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(8)))
    if kind == 0:  # truncate
        return data[: rng.randrange(len(data))]
    if kind == 1:  # extend
        tail = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 32)))
        return data + tail
    if kind == 2:  # bit flip
        index = rng.randrange(len(data))
        out = bytearray(data)
        out[index] ^= 1 << rng.randrange(8)
        return bytes(out)
    if kind == 3:  # boundary value in one byte
        index = rng.randrange(len(data))
        out = bytearray(data)
        out[index] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF))
        return bytes(out)
    if kind == 4:  # a run of bytes replaced
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        out = bytearray(data)
        for index in range(start, end):
            out[index] = rng.randrange(256)
        return bytes(out)
    return bytes(rng.randrange(256) for _ in range(rng.randrange(64)))


def variants(base: bytes, seed: int, rounds: int = ROUNDS) -> list[bytes]:
    """Build one reproducible batch of variants of ``base``.

    Args:
        base: The input to vary.
        seed: Which batch, so a failing one can be run again.
        rounds: How many variants.

    Returns:
        The batch, in a fixed order for that seed.

    """
    rng = random.Random(seed)
    return [mutate(base, rng) for _ in range(rounds)]


def cases(name: str, seed: int) -> list[bytes]:
    """Build one batch of variants for a shipped example's seed input.

    Args:
        name: The example's file name, e.g. ``"dns.yaml"``.
        seed: Which batch.

    Returns:
        The batch.

    """
    return variants(SEEDS[name], seed)


def pointer_cases(seed: int) -> list[bytes]:
    """Build one batch of variants of the real response, for ``dns.yaml``.

    Args:
        seed: Which batch.

    Returns:
        The batch.

    """
    return variants(DNS_RESPONSE, seed)


#: A spec whose body is framed by a ``select``, and its seed input.
#:
#: No shipped example uses one until ``examples/http.yaml`` is finished, and the
#: construct's promises need fuzzing before then — so the spec lives here beside
#: the mutators, for the same reason they do: both implementations have to be
#: held to it, over the same inputs.
#:
#: Written to reach the parts that can plausibly break. The projection runs
#: ``to_int`` over text off the wire, so a mutation makes it unevaluable; the
#: predicate runs ``lower``, so a mutation makes it miss and take the default;
#: and the result **sizes a later field**, so a select that returned the wrong
#: number would show up as a claim on bytes rather than as a quiet wrong value.
SELECT_SPEC = """
name: select_probe
version: "1.0"
entry: message
input: either
units:
  message:
    fields:
      - {name: count, type: {int: {bits: 8}}}
      - {name: items, type: {unit: item}, repeat: {count: "count"}}
      - name: size
        type:
          select:
            from: items
            where: "lower(items.key) == 'length'"
            value: "to_int(items.value)"
            default: "0"
      - name: present
        type:
          select:
            from: items
            where: "lower(items.key) == 'length'"
            value: "true"
            default: "false"
      - {name: payload, type: {bytes: {size: {expr: "size"}}}}
      - {name: rest, type: {bytes: {size: {remaining: true}}}}
  item:
    fields:
      - {name: klen, type: {int: {bits: 8}}}
      - {name: key, type: {string: {size: {expr: "klen"}}}}
      - {name: vlen, type: {int: {bits: 8}}}
      - {name: value, type: {string: {size: {expr: "vlen"}}}}
"""


def _item(key: bytes, value: bytes) -> bytes:
    """Encode one length-prefixed key/value pair for :data:`SELECT_MESSAGE`."""
    return bytes([len(key)]) + key + bytes([len(value)]) + value


#: One well-formed message for :data:`SELECT_SPEC`: two items, the second of
#: which the select matches, and a four-byte body it frames.
SELECT_MESSAGE = (
    bytes([2]) + _item(b"Host", b"example") + _item(b"Length", b"4") + b"body" + b"tail"
)


def select_cases(seed: int) -> list[bytes]:
    """Build one batch of variants of the select-framed message.

    Args:
        seed: Which batch.

    Returns:
        The batch.

    """
    return variants(SELECT_MESSAGE, seed)


def framing_cases(seed: int) -> list[bytes]:
    """Build one batch of variants across every HTTP framing arm.

    Args:
        seed: Which batch.

    Returns:
        The batch, the three seeds' variants interleaved in a fixed order.

    """
    out: list[bytes] = []
    for index, base in enumerate(HTTP_FRAMINGS):
        out.extend(variants(base, seed * len(HTTP_FRAMINGS) + index, rounds=ROUNDS))
    return out
