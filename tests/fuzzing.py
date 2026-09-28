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

import gzip
import random
import struct
import zlib

from kober.errors import TransformError

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

_HTML = b"<html><body>hello, inflated world</html>"
_GZIPPED = gzip.compress(_HTML, mtime=0)
_DEFLATED = zlib.compress(_HTML)

#: A gzip body framed by its length, and a deflate one in chunks: the two
#: ways `examples/http.yaml` reaches its `content`. A mutation of either body
#: almost always fails to inflate, so the transform fails far more often than
#: not, and a mutation of the headers leaves it inflating.
HTTP_GZIPPED = (
    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
    + str(len(_GZIPPED)).encode()
    + b"\r\n\r\n"
    + _GZIPPED
)
HTTP_DEFLATED_CHUNKED = (
    b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nTransfer-Encoding: chunked\r\n\r\n"
    + b"%x\r\n" % 9
    + _DEFLATED[:9]
    + b"\r\n"
    + b"%x\r\n" % (len(_DEFLATED) - 9)
    + _DEFLATED[9:]
    + b"\r\n0\r\n\r\n"
)

#: Every framing arm the shipped example chooses between, so a sweep covers the
#: choice and not only one side of it, and both ways it inflates a body.
HTTP_FRAMINGS: tuple[bytes, ...] = (
    HTTP_REQUEST,
    HTTP_CHUNKED,
    HTTP_COUNTED,
    HTTP_GZIPPED,
    HTTP_DEFLATED_CHUNKED,
)

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


#: A spec whose body is sized by ``fill``, and its seed input.
#:
#: No shipped example uses one — DNS and HTTP both frame their bodies another
#: way — and the construct's whole promise is about a *boundary*, which is the
#: kind of claim only adversarial input settles. Two properties matter and
#: neither is visible in a well-formed decode: the fill must never read into
#: the trailer, and the trailer must always be cited.
#:
#: The trailer is deliberately more than one field and includes a nested unit,
#: because summing widths across a unit reference is where a wrong answer would
#: be off by exactly the nested unit's size and still look plausible.
FILL_SPEC = """
name: fill_probe
version: "1.0"
entry: message
input: datagram
units:
  message:
    fields:
      - {name: count, type: {int: {bits: 8}}}
      - {name: data, type: {bytes: {size: {fill: true}}}}
      - {name: footer, type: {unit: footer}}
      - {name: checksum, type: {int: {bits: 16}}}
  footer:
    fields:
      - {name: kind, type: {int: {bits: 8}}}
      - {name: length, type: {int: {bits: 32}}}
"""

#: One well-formed message for :data:`FILL_SPEC`: a byte, a body, and the
#: seven-byte trailer the fill has to leave alone.
FILL_MESSAGE = bytes([3]) + b"HELLO WORLD" + bytes([9]) + b"\x00\x00\x00\x0b" + b"\xab\xcd"

#: What the trailing fields of :data:`FILL_SPEC` claim, as the spec fixes it:
#: one byte, four bytes, and two. Written out so a test can state the boundary
#: rather than recompute it with the code under test.
FILL_TRAILING = 7


def fill_cases(seed: int) -> list[bytes]:
    """Build one batch of variants of the fill-framed message.

    Args:
        seed: Which batch.

    Returns:
        The batch.

    """
    return variants(FILL_MESSAGE, seed)


def framing_cases(seed: int) -> list[bytes]:
    """Build one batch of variants across every HTTP framing arm.

    Args:
        seed: Which batch.

    Returns:
        The batch, each seed's variants in a fixed order.

    """
    out: list[bytes] = []
    for index, base in enumerate(HTTP_FRAMINGS):
        out.extend(variants(base, seed * len(HTTP_FRAMINGS) + index, rounds=ROUNDS))
    return out


#: A spec whose fields carry constants, and its seed input.
#:
#: No shipped example has a magic number — DNS has none, and forcing one into
#: an example would be inventing a protocol. The construct is the one thing in
#: this release that reaches a decode, and the invariant it is most likely to
#: break is the one that cannot be tested by example: a disagreeing constant
#: must make the region *undecodable* and must never raise.
#:
#: Every kind that can carry one is here, because each compares differently: an
#: integer, text, and raw bytes. A constant on a repeated field is included
#: because it constrains every element, so a mutation anywhere in the run has
#: to end the repetition rather than spin or escape.
CONST_SPEC = """
name: const_probe
version: "1.0"
entry: message
input: datagram
units:
  message:
    fields:
      - {name: magic, type: {int: {bits: 16}}, const: 21317}
      - {name: null, type: {int: {bits: 8}}, const: 0}
      - {name: verb, type: {string: {size: 3}}, const: "GET"}
      - {name: sig, type: {bytes: {size: 2}}, const: [137, 80]}
      - {name: count, type: {int: {bits: 8}}}
      - {name: marks, type: {int: {bits: 8}}, const: 255, count: count}
      - {name: rest, type: {bytes: {size: {remaining: true}}}}
"""

#: One well-formed message for :data:`CONST_SPEC`, with every constant held.
CONST_MESSAGE = (
    bytes([0x53, 0x45]) + bytes([0]) + b"GET" + bytes([137, 80]) + bytes([3, 255, 255, 255]) + b"xy"
)


def const_cases(seed: int) -> list[bytes]:
    """Build one batch of variants of the constant-bearing message.

    Args:
        seed: Which batch.

    Returns:
        The batch.

    """
    return variants(CONST_MESSAGE, seed)


#: Specs ``check`` refuses under the terminal rule, run anyway with
#: ``check=False``: each has a field decoded after one that reads to the end of
#: the message. Named for the shape, with the explanation the starved field must
#: report and the name of the node that reads to the end.
STARVED_SPECS: dict[str, tuple[str, str, str]] = {
    "remaining not last": (
        """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: a, type: {int: {bits: 8}}}
              - {name: body, type: {bytes: {size: {remaining: {}}}}}
              - {name: crc, type: {int: {bits: 16}}}
        """,
        "'crc' has no bytes left: 'body' reads to the end of the message",
        "body",
    ),
    "fill referenced early": (
        """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: inner, type: {unit: in}}
              - {name: trailer, type: {int: {bits: 16}}}
          in:
            fields:
              - {name: data, type: {bytes: {size: {fill: {}}}}}
              - {name: tag, type: {int: {bits: 8}}}
        """,
        "'trailer' has no bytes left: 'inner' is unit 'in', which reads to the end of "
        "the message through 'data'",
        "inner",
    ),
    "repeated terminal unit": (
        """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: n, type: {int: {bits: 8}}}
              - {name: recs, type: {unit: rec}, repeat: {count: "2"}}
          rec:
            fields:
              - {name: tag, type: {int: {bits: 8}}}
              - {name: data, type: {bytes: {size: {remaining: {}}}}}
        """,
        "the elements of 'recs' after the first have no bytes left: 'recs' is unit "
        "'rec', which reads to the end of the message through 'data'",
        "recs[0]",
    ),
}


#: What every :data:`STARVED_SPECS` spec is fuzzed from: long enough that the
#: field reading to the end has something to take.
STARVED_MESSAGE = bytes.fromhex("0102030405")


def starved_cases(seed: int) -> list[bytes]:
    """Build one batch of variants for the specs the terminal rule refuses.

    Args:
        seed: Which batch.

    Returns:
        The batch.

    """
    return variants(STARVED_MESSAGE, seed)


#: A body framed by its length or in chunks, joined, inflated, and decoded as a
#: unit in its own offset space; and a second kept as bytes, in a unit of its
#: own so neither function passes ruff's branch limit. A mutation of the
#: compressed bytes is almost always a failed transform, so this reaches the
#: take-over — the source named ``undecodable`` in place of its record — far
#: more often than a success. No example spec has a transform yet, and a
#: concat's hull overlapping its members' records on failure went unseen
#: until this did.
TRANSFORM_SPEC = """
name: xform
version: "1"
entry: m
units:
  m:
    fields:
      - {name: chunked, type: {int: {bits: 8}}}
      - {name: n, type: {int: {bits: 8}}}
      - name: chunks
        type: {unit: chunk}
        until: "chunks.size == 0"
        condition: "chunked == 1"
      - name: body
        switch:
          dispatch: chunked
          cases:
            1: {concat: chunks.data}
          default: {bytes: {size: {expr: n}}}
      - name: content
        transform: {from: body, with: deflate, limit: 64, type: {unit: doc}}
      - {name: rest, type: {unit: tail}}
  tail:
    fields:
      - {name: m2, type: {int: {bits: 8}}}
      - {name: raw, type: {bytes: {size: {expr: m2}}}}
      - name: plain
        transform: {from: raw, with: deflate-raw, limit: 16, content_type: "prim:bytes"}
      - {name: after, type: {int: {bits: 8}}}
  chunk:
    fields:
      - {name: size, type: {int: {bits: 8}}}
      - {name: data, type: {bytes: {size: {expr: size}}}}
  doc:
    fields:
      - {name: length, type: {int: {bits: 8}}}
      - {name: text, type: {string: {size: {expr: length}}}}
"""

_DOCUMENT = zlib.compress(b"\x05hello")
_RAW = zlib.compress(b"abc")[2:-4]  # raw deflate: no header, no checksum
_TAIL = bytes([len(_RAW)]) + _RAW + bytes([0x7E])

#: Well-formed messages for :data:`TRANSFORM_SPEC`: chunked, then by length.
TRANSFORM_MESSAGES = (
    bytes([1, 0, 4])
    + _DOCUMENT[:4]
    + bytes([len(_DOCUMENT) - 4])
    + _DOCUMENT[4:]
    + bytes([0])
    + _TAIL,
    bytes([0, len(_DOCUMENT)]) + _DOCUMENT + _TAIL,
)


def _raw(data: bytes) -> bytes:
    """Compress ``data`` as raw deflate: no header, no checksum."""
    return zlib.compress(data)[2:-4]


_BOMB = zlib.compress(b"\xc7" + b"a" * 199)
_RAW_BOMB = _raw(b"a" * 100)
_OVERLONG = zlib.compress(b"\x05hello!!")

#: Messages every correct decode of :data:`TRANSFORM_SPEC` fails a transform
#: on, each in a way an implementation could get wrong by succeeding. Both
#: outputs of the first pass their limits (200 bytes against 64, and 100
#: against 16), and would decode whole without them. The second's output
#: decodes with two bytes left over, which its type does not read.
TRANSFORM_ADVERSE = (
    bytes([0, len(_BOMB)]) + _BOMB + bytes([len(_RAW_BOMB)]) + _RAW_BOMB + bytes([0x7E]),
    bytes([0, len(_OVERLONG)]) + _OVERLONG + _TAIL,
)


def transform_cases(seed: int) -> list[bytes]:
    """Build one batch of variants of every transform message, adverse ones included.

    Args:
        seed: Which batch.

    Returns:
        The batch.

    """
    messages = (*TRANSFORM_MESSAGES, *TRANSFORM_ADVERSE)
    return [*messages, *(data for message in messages for data in variants(message, seed))]


#: A caller's transform that misbehaves in every way a callable can, chosen by
#: its input's first byte: it raises an arbitrary exception, raises kober's
#: own with a secret in the message, returns something that is not bytes,
#: ignores its limit, recurses too deep, or works. What it raises must never
#: escape a decode, and its messages must never reach the file.
HOSTILE_SPEC = """
name: hostile
version: "1"
entry: m
transforms:
  hostile: {}
units:
  m:
    fields:
      - {name: n, type: {int: {bits: 8}}}
      - {name: body, type: {bytes: {size: {expr: n}}}}
      - name: out
        transform: {from: body, with: hostile, limit: 8, type: {unit: doc}}
      - {name: after, type: {int: {bits: 8}}}
  doc:
    fields:
      - {name: length, type: {int: {bits: 8}}}
      - {name: text, type: {string: {size: {expr: length}}}}
"""

#: What :func:`hostile` puts in the messages it raises, which must never be
#: seen again.
HOSTILE_SECRET = "hunter2"


def hostile(data: bytes, *, limit: int) -> object:
    """Misbehave according to ``data[0]``: see :data:`HOSTILE_SPEC`.

    Args:
        data: The source's bytes.
        limit: The most bytes the output may have, which it may ignore.

    Returns:
        Something, usually not what a transform should.

    Raises:
        KeyError: Or another exception, according to ``data[0]``.

    """
    mode = data[0] % 7 if data else 6
    if mode == 0:
        raise KeyError(HOSTILE_SECRET)
    if mode == 1:
        raise TransformError(HOSTILE_SECRET)
    if mode == 2:
        return HOSTILE_SECRET
    if mode == 3:
        return b"\x01" * (limit + 1)
    if mode == 4:
        raise RecursionError(HOSTILE_SECRET)
    if mode == 5:
        return bytearray(data[1:])
    return data[1:]


#: One message per behaviour of :func:`hostile`, the working ones decoding.
HOSTILE_MESSAGES = tuple(
    bytes([len(body), *body, 0x7E])
    for body in (
        b"\x00",
        b"\x01",
        b"\x02",
        b"\x03",
        b"\x04",
        b"\x05\x02hi",
        b"\x06\x03abc",
        b"\x06\x09ab",
        b"\x06\x01a??",
    )
)


def hostile_cases(seed: int) -> list[bytes]:
    """Build one batch of variants of every :data:`HOSTILE_MESSAGES`.

    Args:
        seed: Which batch.

    Returns:
        The batch, the messages themselves first.

    """
    return [
        *HOSTILE_MESSAGES,
        *(data for message in HOSTILE_MESSAGES for data in variants(message, seed, rounds=10)),
    ]
