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
