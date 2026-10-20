# Phase plan: a WireGuard tunnel, as the worked example of bringing your own code

**State: Stages 0 to 6 done (2026-10-16); acceptance 1 waits on the `zpf` 0.6 port; Stage 7 (the example as a template) is next.** `0.6.0.dev0`, with the
pipeline baseline taken on the unchanged `0.5.0` code in
`../kober-baselines/v0.5.0`, outside the repository. Map parameters and
`keys[receiver]` landed in both backends (*Stage 1 — done*). `fails_as` is
declared, checked, planned by both backends, and written with its
`reason_class` since `zpf` 0.5.2 released
[python-zipline#79](https://github.com/adamkjonsson/python-zipline/issues/79)
(*Stage 2 — done*). `examples/wireguard/` holds the spec, the cipher and the
transform, decoding datagrams built in the tests (*Stage 3 — done*), and
`wg_seal.py` seals packeteer's generated traffic with a real handshake, which
Wireshark opens (*Stage 4 — done*). The traffic inside comes back out
through zpfwire#35 and decodes to exactly what was sealed (*Stage 5 — done*).
Ready for `net:ip`, with `len` and a keepalive label, ahead of the `zpf` 0.6
port (*The port to `zpf` 0.6*). The pipeline runs it, a guide walks through it,
and a fresh venv runs its README (*Stage 6*).

> **Written 2026-10-11** against `0.5.0`, `zpf` 0.5.1 (spec 0.21), packeteer
> 0.17.0, `zpfwire` 0.4.0. The prompt: *make a demo that decodes a VPN tunnel,
> WireGuard, with keys and cleartexts known so the decode can be checked, and
> with packeteer generating the traffic under impairments of the author's
> choosing.* A follow-up widened it: the demo is to be **the** example of
> implementing a protocol that needs the user's own transform code, test
> material included. So no WireGuard-specific code goes into kober,
> packeteer, `python-zipline` or `zpfwire`. Each gets a general seam instead,
> and how easy that seam is to use counts as a design goal in its own right.

```
  packeteer stream (DNS, later HTTP)                        ← inner traffic, generated
      │  inner impairments (TCP: loss, retransmission, …)
      ▼
  wg_seal.py  — the user's tunnel wrapper (packeteer#197)   ← handshake, counters, keys
      │  outer impairments: loss, corruption, reorder, duplicate (#194, #196)
      ▼
  wg.pcap ──zpfwire convert──▶ outer.zpf
      │
      ▼  kober run wireguard.yaml --load-transforms wg_transforms.py --param keys=file:keys.json
  packets.zpf   one dec:ip-packet per datagram; a bad tag is decrypt-failed
      │
      ▼  zpfwire convert packets.zpf (zpfwire#35)
  inner.zpf ──kober run dns.yaml──▶ dns.zpf
      │
      ▼
  checked against truth.jsonl, which wg_seal.py wrote as it sealed
```

This is `../zipline/vectors/tunnel/` built from real traffic rather than by
hand, and it is the first time that chain would run end to end.

## Why this phase

**Decryption is the half of the transform phase that was never shown on a
real protocol.** `0.5.0` proved `transform` with gzip and deflate on HTTP, and
proved the tunnel *shape* with `tests/cipher.py`, an XOR with a CRC "tag". No
real cipher, real framing, real key handling, or traffic that was not built in
a test. The `transforming-protocols` goal, compression **and** encryption,
is half met.

**Every user who has a protocol of their own will do the same steps.** They
write a transform kober cannot ship (`CLAUDE.md`: stdlib only, no cipher),
write a generator packeteer cannot ship, and wire the two to a spec. Today
each step is possible but awkward, and nothing shows how the pieces fit. One
example worked through completely, with the awkward parts fixed upstream, is
worth more than a section of prose.

**It is affordable now.** The 2026-10-11 investigation ran a prototype end to
end. It used a stdlib ChaCha20-Poly1305 that passes RFC 8439 §2.8.2 at about
6 ms per 1400-byte packet, a sketch `wireguard.yaml` that passes `kober check`
on `0.5.0` unchanged, and packeteer → `zpfwire` → `kober run --emit field`.
Every plaintext came back as one `dec:ip-packet` record citing its datagram.
What did not work is the subject of this plan.

## What the prototype found

1. **The spec language is enough for the framing.** The four message types
   are a `switch` on `type`. The transport message is `receiver`, `counter`
   (both little-endian, `emit: none`) and `sealed`, then a declared transform
   `wg-transport: {params: {key: bytes, counter: int}}`. The handshake decodes
   as structure. Its encrypted fields stay opaque bytes, because Noise IK
   carries state from initiation to response and a transform keeps none
   (`DESIGN.md` §11.5; transform plan Q8). That is a line this phase keeps,
   not one it moves.
2. **Picking the key is where it breaks.** Each direction has its own key, and
   a transport message names the *receiver's* index. With no conditional
   expression, the sketch dispatched on `receiver ^ initiator_index` to two
   `switch` cases, one per key. It works, but it reads like a trick, and it
   cannot survive a rekey, which brings new indices and keys. Because
   `receiver` is read only by the dispatch, it is written as `skipped`,
   although it chose the key.
3. **A failed tag is written `undecodable`.** The vector, and any reader, would
   say `decrypt-failed`. `zpf` already carries that reason in its open
   vocabulary, with `reason_class` saying how to treat it.
4. **packeteer's UDP path dropped every impairment in silence**
   ([packeteer#194](https://github.com/adamkjonsson/packeteer/issues/194)).
   It also sends everything client to server (#195), and `--gap-jitter` cannot
   reorder it (#196). So this pipeline's own "lossy DNS" corpus has never
   been lossy. That is worth a line in the CHANGELOG when #194 lands and the
   pipeline baseline moves. *(All three fixed in packeteer 0.18.0.dev1; see
   What it waits for.)*
5. **Nothing turns decrypted packets into sessions.** `zpfwire` reads captures
   only ([zpfwire#35](https://github.com/adamkjonsson/python-zipline-wire/issues/35)).

## What it waits for

**Delivered in packeteer 0.18.0, not yet released.** Implemented across
0.18.0.dev1 to dev3 and verified here on 2026-10-12, each against the repro it
was filed with and against WireGuard-shaped traffic. The example needs
packeteer 0.18.0 or later, and is developed against the dev build until it
ships. The issues close at that release, by packeteer's own rule.

| Issue | What it gives | Verified |
| --- | --- | --- |
| [packeteer#194](https://github.com/adamkjonsson/packeteer/issues/194) | UDP loss and corruption that apply | dev1: loss drops datagrams; corruption flips the last byte, which fails a Poly1305 tag |
| [packeteer#195](https://github.com/adamkjonsson/packeteer/issues/195) | Datagrams in both directions | dev1: `"direction"` beside a wrapped section; a parsed capture's directions inferred from its ports |
| [packeteer#196](https://github.com/adamkjonsson/packeteer/issues/196) | Reordering, duplication | dev1: a real overtake per direction, reaching further with `--reorder-depth`; exact copies |
| [packeteer#197](https://github.com/adamkjonsson/packeteer/issues/197) | A tunnel whose payload is the user's code, in wire order | dev2: see Stage 4 |
| [packeteer#200](https://github.com/adamkjonsson/packeteer/issues/200) | Corruption that lands on the payload in a short frame | dev2: found in the dev1 review; the padding is untouched and the checksum fails |
| [packeteer#202](https://github.com/adamkjonsson/packeteer/issues/202) | A seeded run reproduces as a file; `--start-time` | dev2: two seeded tunnel runs write identical pcaps and key logs |
| [packeteer#203](https://github.com/adamkjonsson/packeteer/issues/203) | A `--tunnel-module` (and `--load-protocol` module) can import the modules beside it, its directory appended to `sys.path` | dev4 (2026-10-13): the issue's repro loads; a decoy `colorsys.py` beside it is never imported; a tunnel module beside the example's `wg_crypto.py` sealed DNS both ways and kober, with the example's `wg_transforms.py`, opened every packet |

**Delivered and released: `zpf` 0.5.2** (2026-10-13), and kober's floor now.

| Issue | What it gives | Verified |
| --- | --- | --- |
| [python-zipline#79](https://github.com/adamkjonsson/python-zipline/issues/79) | `DecodeStage.undecoded(reason_class=)`; a refused region no longer counted as covered | On 0.5.2.dev0, unchanged in the release: both drivers write `decrypt-failed` and `inflate-failed` with class `bytes`, conformant and `zpf validate` clean |

**Still open:**

| Issue | What it gives | What it blocks here | Until it lands |
| --- | --- | --- | --- |
| [zpfwire#35](https://github.com/adamkjonsson/python-zipline-wire/issues/35) | Sessions from a `.zpf` of IP packets | *Delivered in zpfwire 0.5.0.dev0, verified 2026-10-16 (Stage 5); closes at 0.5.0's release* | — |

*Corrected in Stage 2:* this said nothing was needed from `python-zipline`.
#79 was found writing the first reason outside the canonical four: the stage
API cannot pass the class one needs, and the writer refuses the region.

**Stages 1–3 depend on none of them**, and are worth landing first: they are
the kober half, and they are testable with datagrams built in the test.

## Design questions

### Q1 — How does a spec choose a key? *(language addition)*

**Leaning: a map-typed document parameter, read by indexing.**

```yaml
params:
  keys: {type: {map: [int, bytes]}, secret: true}
...
      - name: packet
        transform:
          from: sealed
          with: wg-transport
          limit: 65535
          args: {key: "keys[receiver]", counter: counter}
          content_type: "dec:ip-packet"
```

- **It is what the protocol does.** A WireGuard peer finds a session by the
  receiver index in the message. The same table holds both directions, every
  rekey and every peer. TLS key logs, ESP SAs keyed by SPI, and OpenVPN peer
  IDs have the same shape, so this is not a WireGuard feature.
- **`check` stays static.** `keys[receiver]` is typed from the declaration:
  the index must be `int`, and the result is `bytes`. Indexing is only allowed
  on a map-typed **parameter**. There is no list type, and none is added
  (`concepts.md`, *What a spec cannot say*).
- **A missing index is the existing rule.** An argument that cannot be
  evaluated fails the transform, its source is named (Q2), and the message
  goes on. That is correct for a session whose key nobody logged.
- **Citation comes free.** `receiver` becomes an argument, and an output cites
  its arguments, so the `skipped` quirk of finding 2 is gone.
- **From the CLI**, `--param keys=file:keys.json` reads a JSON object mapping
  each key's text form (`"1234"`) to the value's text form (`"hex:…"`), the
  same per-type rules `--param` uses now. From Python, a `dict`. The tunnel
  wrapper writes `keys.json` in exactly that form, so generator and decoder
  meet with no glue. This is the ergonomic point, and it should be
  demonstrated, not just possible.
- **Digest.** A secret map is hashed whole, in a canonical order, and nothing
  of it is written, as a secret `bytes` is now.

Allowed map types: keys `int` or `str`, values any scalar. Also
`ast.Subscript`, which `expr.py` currently refuses by name, admitted only
when its value is a map parameter. The refusal message for every other
subscript stays.

*Considered and not leaned on:*

- **A conditional expression** (`a if c else b`). It is cheaper and generally
  useful, but it picks between keys known when the spec is written, so it
  fails the moment there is a rekey. It is worth having on its own merits, but
  it is not this phase's answer.
- **`switch` cases keyed by parameters.** It is the trick made official, and
  it has the same rekey problem.

### Q2 — What does a failed decryption write?

**Leaning: the declaration names it.**

```yaml
transforms:
  wg-transport: {params: {key: bytes, counter: int}, fails_as: decrypt-failed}
```

The region is written with that reason and `reason_class: bytes`, and the
discontinuity carries it too, which is the vector's shape. Undeclared, it
stays `undecodable`. A name that `zpf` classifies otherwise must agree with
it, and `check` refuses `fails_as: gap`, since a failed transform's bytes
did exist. The fuzz invariant *every reason is one `zpf` classifies* widens
to *one `zpf` classifies, or a declared `fails_as` with its class*, and gets
a fuzz test of its own (`CLAUDE.md`, *Testing*).

Open: whether a core codec's failure should then be `decompress-failed` by
the same route. Not this phase. The key is general enough to allow it later.

### Q3 — Where does the user's code live?

**In `examples/wireguard/`, never in `src/kober`.** It is the example, and it is
what a user copies:

| File | What it is |
| --- | --- |
| `wireguard.yaml` | The spec. |
| `wg_crypto.py` | ChaCha20-Poly1305, and for Q5 X25519, stdlib only. |
| `wg_handshake.py` | *Added in Stage 4:* the Noise IK handshake, both peers' sides, kept out of `wg_crypto.py` because it is protocol rather than primitive. |
| `wg_transforms.py` | Registers `wg-transport`. It is what `--load-transforms` loads, and it is ten lines, which is the point. |
| `wg_seal.py` | The packeteer tunnel wrapper (#197): handshake, counters, `keys.json`, `truth.jsonl`. |
| `README.md` | How to run it, and what each file teaches. |

`examples/` has held only specs until now. `test_examples.py` and the docs'
example loader must skip the `.py` files rather than read them as specs.

### Q4 — How is the cipher itself verified?

**Independently of the code that seals.** `wg_seal.py` and `wg_transforms.py`
share `wg_crypto.py`. A bug in it would seal and open consistently, and the
whole demo would pass over a cipher that is not ChaCha20-Poly1305. So:

- **Known-answer tests**: RFC 8439 §2.8.2 (AEAD), §2.5.2 (Poly1305), §2.4.2
  (ChaCha20) and RFC 7748 §5.2/§6.1 (X25519).
- **A WireGuard known answer**: a handshake and first transport message whose
  bytes come from outside this code, so the framing and the key derivation are
  checked, not only the primitives. Where it comes from is open: a capture with
  logged keys is the obvious candidate, and `../python-zipline-wire/tests/captures/`
  has none.
- **An optional cross-check**: if `cryptography` happens to be installed, open
  everything with it too. Skipped otherwise. A test may use what the product
  may not.

### Q5 — A real handshake, or chosen transport keys?

**Leaning: real.** `wg_seal.py` runs Noise IK from chosen static and ephemeral
private keys, so the capture is genuine WireGuard. Wireshark, given the same
keys, should decrypt it. That is the outside check that example tests cannot
give (`CLAUDE.md`: example-based tests verify the code against its author's
reading). The "known keys" a user chooses are then the four private keys, and
`keys.json` is derived. It costs about 100 more lines of stdlib code in the
example: X25519 and the handshake. Chosen transport keys with a handshake of
random bytes would decode identically in kober, and would teach less.

### Q6 — What is inside the tunnel?

**DNS first, over UDP:** one inner packet is one message, so Stage 5 has a
fallback that needs no reassembly. **HTTP over TCP second**, once zpfwire#35
lands. It is the case where inner impairments (retransmission) and outer ones
(loss of a sealed datagram) interact, and where #197's "seal in wire order"
pays off.

### Q7 — What is the oracle?

`truth.jsonl`, written by the wrapper as it seals, **and the capture itself.**
Each truth line holds the session, direction, receiver index and counter, the
inner packet, and the sealed outer payload.

*Answered by #197 (2026-10-12):* the wrapper cannot know a datagram's fate,
and does not need to. packeteer applies the outer impairments after `wrap`,
from an RNG of its own, so what happened to a datagram is read off the
capture: a sealed payload on the wire unchanged arrived, as many times as it
appears; one whose bytes arrive with only the last changed was corrupted; one
not on the wire at all was lost. The dev2 prototype checked a decode this way
over five sessions and all four impairments.

The assertions are shape first (`CLAUDE.md`: *assert the shape*):

- the plaintext records are, as a multiset, the inner packets of the truth
  lines whose sealed payloads reached the wire unchanged, once per arrival.
  That one assertion covers loss, reordering and duplication together. It
  must be a multiset even with no impairment at all: `zpfwire` writes each
  direction as a participant of its own, and kober decodes one stream after
  the other, so the output holds every client-to-server packet before any
  server-to-client one (seen in the dev4 check);
- every other transport datagram on the wire, a duplicated corrupt one
  included, is exactly one `decrypt-failed` region;
- a handshake message decodes as structure, and its corruption is not
  detected, since kober checks no handshake MAC (Q5). The example says so.

### Q8 — Replays and duplicates

A duplicated datagram decrypts twice. Kober keeps nothing between messages, so
it cannot do what WireGuard's replay window does. The example says so in its
README rather than leaving it to be discovered. It is the same line as Q8 of
the transform plan.

## Stages

### Stage 0 — `0.6.0.dev0`, and a baseline

Version bump. Run `tools/pipeline.py` and keep its output as the
`--baseline` for this phase.

### Stage 1 — map parameters and indexing (Q1)

Model (`spec.py`: `Param.type` gains a map type), loader, `check` (indexing
only on a map parameter; key type matches; result typed), the interpreter
(`expr.py`), the compiler (`pygen.py`), `--param` parsing from `file:` JSON
(`cli.py`), and `params_digest` canonical over a map. Fuzz: an index that is
missing never raises, and fails the transform. Docs: `types.md`,
`document.md#params`, `expressions.md` (*What cannot be referenced* gains its
exception). CHANGELOG under `Added`.

#### Stage 1 — done

As Q1 leaned, with these choices made on the way:

- **Spelling.** `{type: {map: [K, V]}}`, long form only, since a map has no
  short form that does not collide with a parameter's long one. A map's type
  spells itself `map[K, V]` (`MapType.value`, named like an `ExprType`'s), and
  that string is the contract between the backends: a generated module's
  `PARAMS` holds it, and `document_params` reads it back.
- **The node.** `kober.expr.Index(table, key)`, where the table is a name and
  never an expression. `Scope` gains `resolve_map` and `Environment`
  `lookup_map`, which is a change to two public protocols, recorded under
  `Changed`. The plan gains `Kind.MAP` and `ParamPlan.entries`, so it stays
  language-neutral.
- **One helper, two backends.** `kober.expr.map_entry` is the interpreter's
  lookup and what generated code calls, as `shift_left` is, so a missing entry
  is worded `'keys' has no entry for 9` by both.
- **A supplied map is copied**, read-only, when the decode is set up, so the
  digest and the decode cannot drift from each other if the caller changes
  their `dict`.
- **On failure the receiver is `skipped`.** The output cites the key's
  fields when it succeeds. When it fails, an `emit: none` argument is
  `skipped`, the rule `0.5.0` already had, so the receiver and nonce of a
  datagram with no key are one `skipped` region before the `undecodable`
  ciphertext.
- **The fuzz invariant runs against two broken lookups in the suite**, one
  that lets a miss escape and one that quotes the table, as `testing.md`
  requires of every check.

`DESIGN.md` is at revision 13, which says why this does not reopen §3.2's
refused keyed repeat: that was a map built from the input, and this one is
supplied whole by the run. The pipeline differs from the baseline in 0 of 80
outputs.

### Stage 2 — `fails_as` (Q2)

Declaration key, `check` against `zpf.blocks.UNDECODED_REASONS`, emission in
both drivers (`emit.py`, `runtime.py`, `stage.py`), the discontinuity's
reason, the widened fuzz invariant. CHANGELOG under `Added`.

#### Stage 2 — done

`fails_as` is declared, loaded, checked, and planned by both backends, a concat
source's members included, and fuzzed. Four things the design questions did
not foresee:

- **`zpf` cannot write it yet.** `DecodeStage.undecoded` takes no
  `reason_class`, and a reason outside the canonical four without one is
  refused by the writer as it is written, not at conformance:
  [python-zipline#79](https://github.com/adamkjonsson/python-zipline/issues/79).
  Decided 2026-10-11: build everything short of the write, with the stage
  driver's `_writable` the one place a declared reason became `undecodable`.
  Decided 2026-10-13: land the write only once 0.5.2 was released, not
  against its dev build, since it moves the `zpf` floor. *Landed 2026-10-13:*
  `_writable` became `_reason_class`, `None` for a canonical reason and
  `bytes` for any other; the pinned test became the test that the file says
  `inflate-failed` with class `bytes`; `tests/zpfcompare.py` compares a
  region's `reason_class` too, now that one can differ; and the floor is
  `zpf>=0.5.2,<0.6`. The pipeline moved no output for it.
- **Q2's "the discontinuity carries it too" was wrong.** A `bytes`-class region
  owes no seam: its bytes existed, and content either side still runs on
  (`stage._seam_for`). The tunnel's first stage is at field granularity,
  whose output is a unit sequence, which takes no seams at all. The vector's
  `discontinuity` belongs to a stage that writes its plaintext as a
  contiguous stream of its own, and kober does not.
- **Any declared name may have one, a core one included**, `deflate:
  {fails_as: inflate-failed}`. That made the differential and the fuzz possible
  with no cipher at all, and it is the route Q2 left open for
  `decompress-failed`.
- **The spelling is checked**: lower-case words joined by hyphens, as every
  reason the format and its vectors use is spelled. `zpf`'s vocabulary is
  open; this is kober's own line, so a typo is a finding rather than a new
  reason.

`zpf` stays imported in `stage.py` only: `check` reaches the class table
through `kober.stage.canonical_class`, lazily, as the decoder reaches the
stage. The pipeline differs from the baseline in 0 of 80 outputs.

### Stage 3 — the example, decoded from datagrams built in the test

`examples/wireguard/` without `wg_seal.py`: spec, crypto, transforms, the
known-answer tests of Q4. A stage test builds datagrams in Python, both
directions and a rekey, through both drivers, with the `tests/cipher.py` tests
as the template. **This proves the kober half without any upstream issue.**

#### Stage 3 — done

`examples/wireguard/` holds `wireguard.yaml`, `wg_crypto.py`,
`wg_transforms.py` and a README, and `tests/test_wireguard_example.py` holds
them to account. What the plan did not foresee, or decided on the way:

- **A subdirectory sidesteps Q3's worry.** Every loader of `examples/` globs
  `*.yaml` at the top level, so nothing reads `wireguard.yaml` or the `.py`
  files as a shipped spec by accident. In exchange, the example's own tests
  hold the spec to what `test_examples.py` asks of the others: it checks with
  no error and the one warning it means (a switch with no default: a type
  outside the four is not WireGuard), it is documented, and it is fuzzed, with
  the corpus shown to reach a packet that opens, one that fails, a handshake,
  a truncation and an unknown type.
- **The RFC's vectors were extracted, not typed.** A script read RFC 8439's
  text and pulled §2.4.2, §2.5.2, §2.6.2, §2.8.2 and A.5 out of its hex dumps,
  so the test constants are the RFC's bytes. All five pass, and every change to
  a sealed message (ciphertext, tag, AAD, key, nonce, length) fails the tag.
  The cross-check against `cryptography` is in place and skips where it is not
  installed, as here. **Still open from Q4: a WireGuard known answer**, which
  needs the handshake and its key derivation, so it moves to Stage 4 with
  them, as does X25519 against RFC 7748.
- **`--load-transforms` now lets a module import the modules beside it**, so
  `wg_transforms.py` imports `wg_crypto.py` with a plain `import` and no path
  tricks for a user to copy. Its directory is appended to `sys.path`, never
  put first: a test puts a decoy `colorsys.py` beside the module and fails if
  it is ever imported. That is a kober change (CHANGELOG, `types.md`), and
  the one the example needed that no stage named.
- **The spec confirms `reserved == 0`**, and a keepalive's empty plaintext is
  written as a conformant zero-length record. The plaintext stays padded; the
  README says so, with what else a decode cannot do (open the handshake,
  detect a replay).
- **Datagrams carry both directions in one participant** here, since kober
  chooses a key by the receiver index a message carries, not by direction.
  Two participants come with Stage 4's generated captures.
- **For Stage 4: packeteer's `--tunnel-module` has the same gap.** Checked
  against 0.18.0.dev3: a tunnel module importing a sibling fails with
  `ModuleNotFoundError`, so `wg_seal.py` could not import `wg_crypto.py`. It
  wants the same rule in `packeteer.generate.udp_tunnel.load_wrapper`: filed
  as [packeteer#203](https://github.com/adamkjonsson/packeteer/issues/203),
  2026-10-13, and implemented in 0.18.0.dev4, verified the same day.

### Stage 4 — generated traffic

`examples/wireguard/wg_seal.py` is a packeteer tunnel module (#197, 0.18.0):
it defines `make_wrapper(args)`, returning an object whose `wrap(inner,
direction, timestamp)` returns the outer datagrams to send. packeteer
generates the inner traffic and calls it once per inner packet actually sent,
in wire order. The wrapper:

- runs the handshake of Q5 on the first call, one message each way, and again
  at every rekey, which brings new receiver indices and keys;
- seals each inner packet as a transport message under its direction's key
  and counter, with `wg_crypto.py`;
- writes `keys.json`, receiver index to `hex:` key, which is exactly what
  `--param keys=file:keys.json` reads (Q1), and `truth.jsonl` (Q7).

Paths and the seed come in as `--tunnel-arg`. One command makes a capture:

```console
packeteer stream --protocol udp --payload dns --protocol-messages dns.json \
    --client-ip 10.8.0.2 --server-ip 10.8.0.1 --server-port 53 --packets 60 \
    --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 51820 \
    --tunnel-module examples/wireguard/wg_seal.py \
    --tunnel-arg seed=11 --tunnel-arg rekey_after=12 \
    --tunnel-arg keylog=keys.json --tunnel-arg truth=truth.jsonl \
    --tunnel-packet-loss 0.15 --tunnel-corruption 0.15 \
    --tunnel-reorder 0.3 --tunnel-duplicate 0.1 --seed 7 --pcap wg.pcap
```

The inner stream keeps its own impairments (`--packet-loss`,
`--retransmit-lost` on TCP), separate from the tunnel's (`--tunnel-*`). Its
DNS messages go both ways with a `"direction"` key beside each section (#195).
A seeded run reproduces the pcap and the key log byte for byte (#202), so the
pipeline can pin one.

**What the dev2 prototype established (2026-10-12)**, in the scratchpad, with
real ChaCha20-Poly1305 and framing-only handshakes:

- DNS inside, 60 packets over 5 sessions, 10 lost, 8 corrupted, 8
  duplicated: kober recovered exactly the 47 plaintexts Q7's rule expects.
- TCP inside with `--packet-loss 0.2 --retransmit-lost`: the wrapper sealed
  exactly the 60 packets the inner stream put on the wire. Lost segments were
  never sealed, each retransmission was sealed once with a fresh counter, and
  no counter repeated in a session. All 60 decrypted.
- The spec caught a framing bug in the prototype's own wrapper: an initiation
  of 144 bytes where WireGuard's is 148, written `truncated`. That is the
  example doing its job, and the README should say a user's wrapper is
  checked the same way.

What is left for this stage is the real Noise IK handshake (Q5), the tests:
the pipeline corpus of Stage 6, and a suite test that runs one small seeded
capture through `stream` if a packeteer is on the path, skipped if not. There
is no interim script: #197 shipped before this stage started.

#### Stage 4 — done

`wg_crypto.py` gained X25519, `wg_handshake.py` is new, and `wg_seal.py` is
the tunnel module. What was decided or found:

- **The handshake is real, both sides of it (Q5).** Written step for step
  against https://www.wireguard.com/protocol/. `wg_seal.py` plays both peers,
  and each reads the other's message as it would on the wire rather than being
  handed the keys, so the two halves check each other where they can.
- **Q4's WireGuard known answer is Wireshark, not a fixed capture.** `tshark`
  is installed here, and given the keys `wg_seal.py` logs for it
  (`wireshark_keylog`), it opens the capture: the initiator's static key out of
  the initiation, `handshake_ok` on every response, and every transport
  message, byte for byte against what was sealed. That is an implementation
  that is not this one checking X25519, the KDF chain, the handshake and the
  AEAD at once, and it is better than a capture of someone else's, which would
  check only the opening half. The test writes its own pcap, so it needs no
  packeteer, and skips without `tshark`. **Shown to matter:** swapping the two
  transport keys inside the shared derivation passes every other test,
  kober's decode included, and fails this one. RFC 7748's vectors (§5.2 single
  and iterated to 1000, §6.1's key agreement) were extracted from the RFC as
  RFC 8439's were.
- **The whole chain is a suite test**, skipped without the sibling checkouts:
  packeteer generates DNS both ways through `wg_seal.py` with loss,
  corruption, reordering and duplication, `zpfwire` converts it, and both
  drivers decode it. Q7's rule holds exactly: what reached the wire unchanged
  opens once per arrival, and every other transport datagram is one
  `decrypt-failed` region.
- **Two things a decode shows that the plan did not say.** A corrupted
  datagram also fails its UDP checksum, since packeteer#200, and `zpfwire`
  keeps it by default; `--checksum drop` turned it into a loss, until zpfwire
  `81c4453` (2026-10-19) made `drop` drop TCP only, as the format requires, so
  it is `decrypt-failed` under either policy now. And Wireshark
  strips WireGuard's padding by the inner IP header's length, where kober's
  record keeps it, which the README already says.
- **Not done, deliberately:** cookies (`mac2` is always zero), a pre-shared
  key, and WireGuard's timers: the responder sends as soon as the handshake
  ends, where a real one waits for the initiator's first packet. Nothing that
  reads the capture can tell.
- The README's commands were run as written, from the repository root.

### Stage 5 — the inner traffic

With zpfwire#35: `packets.zpf` → `inner.zpf` → `examples/dns.yaml`, checked
against `truth.jsonl`. First check that kober's tunnel output has the shape #35
expects (`vectors/tunnel/packets.jsonl`: its own session, `dec:ip-packet`).
That is unverified today. Fallback until #35: a second-stage spec that reads
IPv4 and UDP headers and then DNS from each plaintext record, which needs no
reassembly. Whether it lives on as an example after #35 is decided then.

*Decided 2026-10-13:* wait for zpfwire#35 rather than take the fallback.
Stage 5 starts when #35 lands in a `zpfwire` build to verify.

#### Stage 5 — done

zpfwire#35 landed in 0.5.0.dev0 (`zpfwire convert packets.zpf`), and was
verified here on 2026-10-16 before it is released, which the tests need no
pin for: `zpfwire` is a sibling checkout, not a dependency, and they skip
without its `.zpf` input. The fallback spec was never written.

- **The shape check passed.** kober's field-granularity output, a unit
  sequence with the WireGuard field records beside the packets, is what #35
  reads: it selects the packets by label, coalesces across the unit
  sequence's seams, and marks everything else it does not cite `skipped`,
  with coverage of `packets.zpf` clean. Until the `zpf` 0.6 port relabels the
  packets `net:ip`, it needs `--content-type dec:ip-packet`.
- **DNS, under every tunnel impairment, is exact.** The DNS `dns.yaml` decodes
  from `inner.zpf` is, message for message and in its own direction, the DNS
  inside the sealed datagrams that reached the wire unchanged.
- **HTTP, under inner loss with recovery, is exact.** Each direction's messages
  join to exactly the TCP stream `wg_seal.py` sealed, retransmissions and all:
  Q6's case, where sealing in wire order pays off.
- **HTTP under tunnel loss has holes, honestly.** A lost sealed datagram is a
  segment the inner connection never knew to resend, so `inner.zpf` has a
  `gap`, and every message decoded is a piece of the sealed stream; none is
  invented. That is checked by shape, the way the pipeline checks a lossy
  HTTP corpus.
- `zpfwire pcap` exports the decrypted packets as a capture, and Wireshark reads
  them as the DNS inside: the README shows both.
- **Left as #35 left it:** an IP datagram fragmented inside the tunnel is
  `undecodable` rather than reassembled (zipline#166). Nothing here generates
  one.

The tests break on a one-byte cut in the transform's padding trim, all three.

### Stage 6 — the pipeline and the walkthrough

- `tools/pipeline.py` gains the WireGuard corpus: clean, and each impairment
  alone, so a moved count says which one moved it.
- The lossy DNS corpus is re-baselined once packeteer 0.18.0 is released.
  Against the 0.5.0 baseline, dev1, dev2 and dev3 each moved exactly the
  eight `dns_gen` outputs, now 35 of 40 messages, with every check holding;
  dev2 and dev3 wrote the same outputs block for block. The CHANGELOG says the
  corpus was never lossy before.
- A docs page, *Bringing your own code: a WireGuard tunnel*. It is written for
  a user with a protocol of their own and walks through the five files, the
  two commands, and the decisions (Q1, Q2, Q4, Q8). It is linked from
  `types.md#transform`, which today only says a cipher is the caller's.
- `run` it as a user would, from the README, in a clean venv.

#### Stage 6 — the pipeline: done (2026-10-16)

Five inputs, `wg_clean` and one per tunnel impairment, DNS both ways through
`wg_seal.py` with a rekey every ten packets. `wireguard.yaml` joins the specs
run over **every** input, with the input's key log or an empty table, and two
checks run over the WireGuard inputs, both exact against what was sealed: the
tunnel (Q7's rule) and the traffic inside (`zpfwire` back to the DNS
conversation, then `dns.yaml`). 271 checks, up from 138, every one holding.
A datagram spec over a byte stream is refused, by design, so the check there
is that both drivers refuse it, which is how the bug below was found.

#### Stage 6 — the walkthrough and the clean run: done (2026-10-16)

- **The walkthrough is `docs/guides/your-own-code.md`**, the first page of a
  new *Guides* section, since the format pages are reference and pinned by
  `test_docs.py`. It follows the order a user with another protocol would
  build theirs in, each step shown in the example: declare the transform,
  supply the parameters, write the transform, tell apart what decodes
  differently, generate traffic, check your own code against an outside
  source, check the decode against what was sealed, and go inside. Linked from
  the index and from `types.md#transform`.
- **The clean run found the README's first command could not run**:
  `--protocol-messages dns.json` named a file the repository did not ship.
  `examples/wireguard/dns.json` is now that file, and the tests and the
  pipeline read it rather than each holding a copy.
- **Acceptance 1 cannot pass until the `zpf` 0.6 port.** In a fresh venv,
  kober (`zpf>=0.5.2,<0.6`) and `zpfwire` 0.5.0 (`zpf>=0.6.0.dev0`) do not
  resolve, and separate venvs would not help: `zpfwire` 0.5.0 writes format
  0.23, which kober on `zpf` 0.5 refuses to read. With kober installed past its
  pin and nothing else changed, every README command runs as written, from
  generation to the DNS inside and the pcap for Wireshark. The port's first
  item clears it.

#### Acceptance, as it stands

1. Met (2026-10-20), on the released packeteer 0.18.0, `zpf` 0.6.0 and
   `zpfwire` 0.5.0: see *The port, done* below.
2. Met: the pipeline's five WireGuard inputs decode exactly to what was sealed,
   under each impairment, both directions and four sessions each.
3. Met: one `decrypt-failed` region per corrupted datagram, class `bytes`, and
   the next decodes.
4. Met: no key in any output (tested); the digest moves with any key.
5. Met: nothing under `src/kober` names WireGuard, and no upstream project
   gained WireGuard code; what they gained is general (packeteer#194–#197,
   #200, #202, #203; python-zipline#79; zpfwire#35).
6. Met: RFC 8439's and RFC 7748's vectors, and Wireshark.
7. Written; whether it is the page a user with another protocol would follow is
   a reader's judgement, and the one reader whose judgement settles it is not
   its author.

### Stage 7 — the example as a template

*Added 2026-10-16.* The example is meant to serve as a template for writers of
other transforms, not only as a worked example of one. Read that way, its parts
are right and its pattern is buried:

- **WireGuard dominates the folder.** About 600 of its 1,050 lines are
  WireGuard's own cryptography and handshake, which no other protocol reuses,
  and nothing tells a writer which files to replace, keep or delete.
- **The reusable test machinery is written in WireGuard's terms.** The chain
  runner, the truth oracle, the outside-check pattern, the fuzz invariants and
  the command-line run are general, but they name `wg_seal.py`,
  `keys[receiver]` and DNS, so a second example would copy and edit them.
- **The conventions are implicit**: the key log's shape, `truth.jsonl`'s
  fields, the tunnel module's arguments.
- **The pipeline knows it by name**: `_params` tests for `"wireguard"`, and
  `_tunnel` and `_inner` assume DNS inside.
- **It is tunnel-shaped**, and nothing says which steps a protocol of another
  shape needs.
- **It is one instance.** A template drawn from one example is a guess about
  what is general.

Four parts, in order, with D allowed to revise A–C, since it is what tests them:

- **A. Adapting this example.** A README section with a checklist per file
  (replace, keep, delete) and the conventions written down as a contract: the
  key log, the truth file, the tunnel module's arguments. The guide gains *which
  steps your protocol needs*, by shape: a tunnel with keys, a tunnel without, a
  transformed field inside a protocol with no generator of its own.
- **B. A shared test kit.** The reusable machinery out of
  `tests/test_wireguard_example.py` into a module of its own, parameterised by
  an example's description: its spec, its transforms module, its tunnel module,
  its parameters (if any), what its packets are labelled and what its failure
  is called, and what is inside. WireGuard's test file then holds only what is
  WireGuard's, and a new example's starts short.
- **C. A data-driven pipeline hook.** An example says what inputs it
  generates and what is inside them, and `tools/pipeline.py` reads that rather
  than naming the example: adding one is a file in its folder, not an edit to
  the pipeline.
- **D. A second, minimal example, built from the template.** Written by
  following A's checklist and B's kit, with every place they did not fit
  recorded and fed back into them.

#### Stage 7, A — done (2026-10-16)

The README gains *Adapting this to your own protocol*: a row per file
(`wg_crypto.py` replace, `wg_handshake.py` delete unless the protocol agrees
keys, `wg_seal.py` replace or delete, the test file's shape to copy) and
*Conventions*, the three contracts a new example keeps. The truth file's
contract is the three fields every check reads, `inner`, `outer` and
`direction`; WireGuard's others are for a reader. The guide gains *Which steps
your protocol needs*, by shape, with the two shortcuts: a codec kober already
knows needs no code, and the check against something that is not your code is
never optional. The test and pipeline rows describe them as they are; B and C
rewrite those rows when they change.

#### Stage 7, B — done (2026-10-16)

`tests/examplekit.py` holds what any example's tests need, parameterised by an
`Example`: its folder, spec, transforms module, tunnel module and port, the
map parameter its key log fills (or none), the role and label of an opened
packet, its `fails_as`, and which outer datagrams carry a packet (WireGuard's
type 4; everything, by default). From it: loading by path with the folder
appended to `sys.path`; the registry swap; `params`, which reads a key log
through `kober.cli._params` so the convention is exactly the CLI's; the truth
file; the exact Q7 oracle (`arrivals`, `tunnel_problems`) and the inner one
(`expected_inside`, `sealed_streams`, `messages_by_direction`); the chain
(`generate`, `open_tunnel`, `sessionize`, `decode_inside`); the fuzz
invariants for both drivers; `run_cli`, which also puts the example's already
imported modules out of reach; and the packet builders `ipv4` and
`write_pcap`. It imports no pytest, for C.

The test file kept its 59 tests and went from 1042 lines to 860; what is left
is WireGuard's: the vectors, the handshake, the tunnel module's own tests, the
Wireshark check, the spec and its messages, and the conversation the fuzzing
mangles. Mutation-checked through the kit: the padding trim one byte short
fails the Q7 and inner-DNS tests and the CLI run; `--load-transforms` no longer
appending its folder fails both CLI tests.

**Found on the way:** counting what must decode inside by *inner* packet
multiplied the arrivals, since every DNS query in the corpus is the same bytes;
the oracle counts by each sealed packet's own datagram, as the original did,
and its docstring says why.

#### Stage 7, C — done (2026-10-16)

An example describes itself once, in `examples/<name>/example.json`, and
`Example.load` reads it: every attribute of B's `Example`, plus what C needed,
`tunnel_args`, `packet_prefix` (hex; what was a callable in B could not be
data), `inside` and `traffic` (the traffic inside, `{folder}` standing for the
example's folder), and `inputs`, a name and its `--tunnel-*` flags for each. A
key the kit does not know is refused, since a misspelt one would be a default
the writer never chose. The WireGuard test file loads it too, so the
description exists once, and `packet_label` moves to `dec:`/`net:` in one place
when the zpf 0.6 port comes.

`tools/pipeline.py` names no example: it finds every `example.json`, adds its
spec to those run over every input, loads its transforms, generates its inputs
through `stream_args` (the kit's, shared with the tests' `generate`), reads its
key log through `Example.params`, and checks the tunnel and the traffic inside
with the kit's oracles. The input names are the description's, so a baseline
carries over: against the Stage 6 run, 0 outputs differ and every check holds
(271). Mutation-checked: the padding trim one byte short fails all 15 tunnel
and inner checks; a failing tunnel line now carries the oracle's own words
("34 unexpected, 34 missing"), where the counts alone read as a pass.
`tests/test_examplekit.py` checks every description against its folder and
spec, so a `failure` that drifts from the spec's `fails_as` fails there.

**What D tests here:** the inside check is exact only for datagram traffic,
which `traffic` must be; a TCP inside stays a test-file matter, as HTTP is for
WireGuard. And the tunnel ends, the inner addresses, and seed 7 are the kit's,
not the description's.

#### Q-D — which protocol is the second example?

**Leaning: a tunnel of PackBits-compressed datagrams.** It has to differ from
WireGuard where the template might be wrong, and still exercise everything that
makes this an example of *your own code*:

- **It needs the writer's code.** PackBits, the run-length scheme TIFF uses, is
  not in the standard library, unlike `deflate`, which a spec names with no code
  at all and so would test nothing here.
- **It has no keys and no handshake**, so it takes the parameter-free path
  WireGuard never does, and a template that assumed a key log shows it.
- **It still has an outside known answer**: the TIFF 6.0 specification's worked
  PackBits example, extracted as RFC 8439's vectors were, so the template's
  *check your code against something that is not your code* step is exercised,
  not skipped.
- **Its failure is different**: a run that overruns its declared length, which
  names a failure (`fails_as`) without any key in it.
- **It is small**: a codec of a few dozen lines, a spec, a transforms module and a
  tunnel module, so the template's overhead is visible rather than hidden
  behind cryptography.

#### Stage 7, D — done (2026-10-16)

`examples/packbits/`: a made-up tunnel, one IP packet per datagram, PackBits-
packed, behind a header of version, unpacked length and CRC-32. A codec of 109
lines, a transform of 49, a tunnel module of 65, a spec of 50, and
`tests/test_packbits_example.py` at 304 lines, of which the chain, the oracle,
the fuzzing and the command line are a few lines each, calling the kit. It
reached the pipeline as `pb_clean` and `pb_impaired` with no edit to
`tools/pipeline.py`: 383 checks hold, and against C's run the 60 outputs that
differ are all new, none changed.

**Where A–C did not fit, and what changed:**

- **The oracle assumed every datagram is unique**, as a cipher's nonce makes
  it. A codec sends the same packet as the same bytes, so `expected_inside`
  credited each of twenty identical DNS queries with every arrival of all
  twenty (361 too many). Now the kit counts what is on the wire by direction
  and bytes, read from which tunnel end sent it, and each truth line consumes
  its datagram's count once; the first line for a datagram takes every
  arrival, which is sound because the same bytes decode to the same packet.
  WireGuard's results are unchanged. The test failed before the fix.
- **The oracle assumes a corrupted datagram fails.** That is the Q7 rule, and
  a cipher's tag guarantees it; PackBits checks nothing, and a flipped literal
  byte unpacks to a wrong packet of the right length. Not a kit change but a
  protocol one: the datagram carries a CRC-32, and the guide's *tunnel without
  keys* row now says an algorithm that checks nothing needs a check of its own.
- **The kit's tunnel port defaulted to WireGuard's 51820.** No default could
  be every protocol's, so a tunnel's `port` is required, and
  `tests/test_examplekit.py` checks it.
- **The plan's outside known answer was wrong.** TIFF 6.0 §9 defines PackBits
  by its unpacking rules and has no worked example (found by extracting the
  section from the specification's PDF: RC4-encrypted, LZW-compressed content
  streams, decoded with the standard library). The worked example is Apple's
  Technical Note TN1023's, extracted from its HTML. The tests take both: TN1023's
  example both ways, and TIFF's rules one at a time. No second implementation
  is in the standard library, so there is no equivalent of the Wireshark check.
  Proven to matter: a replicate count off by one in both `pack` and `unpack`
  passes every round trip and the whole chain, and fails exactly those four.
- **packeteer's DNS payload needs a messages file**, so the example ships its
  own `dns.json`, a copy of WireGuard's: an example is copied whole, and one
  that reached into another's folder would not survive that.

**What fit unchanged:** `example.json` and `Example.load`; `params` returning
`None` and `run_cli` with no `--param`; `registry` and `module`; the chain
helpers; the fuzz invariants with no secrets; the README's truth convention;
and the pipeline, which needed nothing.

#### Acceptance for Stage 7

1. A writer can tell, from the README alone, which of the example's files to
   replace, keep or delete, and what each convention requires.
2. The second example's test file is mostly about its own protocol: the kit
   carries the chain, the oracle, the fuzz invariants and the command-line run.
3. The second example reaches the pipeline without an edit to
   `tools/pipeline.py`'s code.
4. Every place A–C did not fit D is recorded here, with what was changed.

## python-zipline's review of the documentation (2026-10-18)

`plans/reviews/kober-wireguard-docs-review.md`, at `2225371`: the README and
the guide serve a VPN whose messages carry what opens them, and not HTTPS,
which learns only at the end that it does not fit. What was done, by its
numbering:

1. **A fit check first**, in both: a transform keeps nothing between
   messages, so a protocol fits when each message carries its key's index and
   its nonce. Two of the review's examples were corrected rather than copied:
   ESP fits only *without* extended sequence numbers, whose high half is never
   sent, and DTLS 1.2 fits where DTLS 1.3, which shortens and protects its
   record numbers, does not. What to do instead: a stage of one's own with
   `zpf.decode_stage`, keeping the citation to the capture, or an outside tool
   that follows the connection, losing it. The review's "wait for the
   extension point §11.5 describes" is half right: §11.5 does name a transform
   kept for a whole stream as the natural extension, deferred with no date, so
   the docs say not to wait for it.
2. **Real captures.** A WireGuard endpoint never writes its transport keys
   down, so this was more than documentation: `examples/wireguard/wg_keylog.py`
   reads the key log Wireshark reads, which wireguard-tools'
   `contrib/extract-handshakes` writes (fetched and confirmed: a heading per
   session, indented `NAME = base64` lines, `PRESHARED_KEY` included), and
   replays each of a capture's handshakes as whichever side logged it, to the
   transport keys `--param keys=file:…` reads. `wg_handshake.py` gains a
   pre-shared key and `own_initiation`, an initiator's state rebuilt from what
   it sent. A derivation is taken only when the capture confirms it: the
   initiation decrypts to the logged static key and the response opens, or, as
   the responder, the response is rebuilt byte for byte. Tested from either
   endpoint's half of `wg_seal.py`'s Wireshark log to exactly the keys sealed
   with, then through `kober run`. Mutation-checked: keys written under each
   other's index fail four tests; the responder trusting its derivation
   unconfirmed passed every test until a pre-shared key the log lacks was
   tested from both sides. ESP's mapping (`ip xfrm state`, `keys[spi]`) is
   documented, not built.
3. **Two audiences**: the README is now *using kober with your own transform*,
   then *Adding an example to this repository* (`example.json`, the tests, the
   conventions).
4. **Terms first**: *How the pieces meet* moved up, before any step, and now
   explains `limit`, `fails_as` and `emit: none`; the copying table links the
   guide's step 1.
5. **Small things**: the not-an-IP-packet case said plainly, in the README and
   `wg_transforms.py`; the stray wrap reflowed; the `net:ip` sentence dropped,
   since the zpf 0.6 port rewrites those lines anyway. The review itself moved
   from `docs/guides/` to `plans/reviews/`: outside any toctree it failed the
   `-W` docs build.

## Found on the way: the compiled driver decoded a datagram spec over a byte stream

The interpreter refuses a `datagram` spec a byte stream, since it has no framing
to find messages with there and would write a confident decode of the wrong
bytes. The compiled driver did not check, and wrote one. Nothing ran a datagram
spec through the pipeline before `wireguard.yaml`. A generated module now
carries its spec's `INPUT`, and the compiled driver applies the interpreter's
check; a module from before `INPUT` is not checked, as one from before
`SPEC_DIGEST` writes no digest. Every generated module gains the constant,
`tests/compiled_dns.py` included.

## The port to `zpf` 0.6 and spec 0.23

python-zipline 0.6.0.dev0 implements spec 0.23, reviewed here on 2026-10-15:
**ready from kober's side.** The suite passes on it unchanged, the pipeline's
138 checks hold, and against the 0.21 baseline, read with a throwaway `zpf`
0.5.2, 72 of the 80 outputs are the same block for block; the other 8 are the
`dns_gen` ones packeteer 0.18.0 made lossy. #84 and #85 do not reach kober,
which passes `decode_stage` a decoder name and writes the decoded layer.

**`net:ip` is the label the spec's tunnel vector now gives a decrypted packet**,
and the one a generic sessionization stage recognises. It means *exactly one*
IP packet, which kober's WireGuard records were not: they kept WireGuard's
padding, and a keepalive was an empty record under the same label. *Decided
2026-10-16*, after weighing a length function, a no-record-for-empty-output
rule, and a separate label: a length function and a separate label, together.
The rule was refused because a keepalive's bytes were decoded, and with no
record citing them they would need a region no reason fits.

Done now, since none of it needs the release:

- `len(b)` in the expression language, both backends.
- `wireguard.yaml` switches on `len(sealed)`: 16 bytes is a keepalive, opened
  like any message and labelled `dec:wireguard-keepalive`; anything else is a
  packet. A `switch` of two transforms over the same source works at field
  granularity, through both drivers, which was the one thing not yet known.
- `wg_transforms.py` cuts a packet where its IP header says it ends, as a
  WireGuard receiver does, and refuses a plaintext that is not IP.

Waits for `zpf` 0.6.0's release, as #79's follow-up did:

1. `pyproject.toml` to `zpf>=0.6.0,<0.7`, and the Specification link to v0.23.
   kober pins one `zpf` minor, so this is kober 0.6.0's.
2. `kober check` accepts `net:`, with the tokens `zpf.NET_LINK_TYPES` has, read
   through `kober.stage` as the reason classes are.
3. `wireguard.yaml`'s packet label from `dec:ip-packet` to `net:ip`; the
   keepalive keeps `dec:`.
4. The pipeline says a baseline is in an older format rather than raising,
   and the baseline is taken again on 0.23.
5. zpfwire#35 should key on `net:ip`, and `zpf`'s `sessionize_stage` (#76) is
   the hop it describes.

### The port, done (2026-10-20)

packeteer 0.18.0, python-zipline 0.6.0 and python-zipline-wire 0.5.0 were
released. Since the 0.6.0.dev0 review only #91 (an input measured once, output
unchanged) and documentation landed, so the list above was the whole of it,
and on 0.6.0 the suite passed unchanged before any of it was done.

1. Done: `zpf>=0.6.0,<0.7`, and the Specification link at v0.23.
2. Done: `kober check` accepts `net:ip` and `net:ethernet`, read from
   `zpf.NET_LINK_TYPES` through `kober.stage.net_tokens`, and refuses any
   other `net:` name, naming the two; mutation-checked both ways.
3. Done, in both examples, with one thing the list did not foresee: the
   format never checks a `net:` payload against its label, so the label is a
   promise the transform has to keep. WireGuard's already did, cutting its
   padding by the IP header and refusing what is not IP; PackBits' did not,
   and a datagram that unpacked, CRC and all, to something that is not IP
   would have been labelled one. It is `unpack-failed` now, tested and
   mutation-checked. `--content-type` is gone from every command: `zpfwire`
   0.5.0 takes `net:ip` and `net:ethernet` as packets by default. The test kit
   still passes an example's own label, which stays right for one whose
   packets are something else.
4. Done: a `--baseline` the installed `zpf` cannot read is refused before the
   run, exit 2, saying it is from another format; checked with a file whose
   header says 0.21. The new baseline is the 2026-10-20 run: 383 checks, every
   one holding, the tunnel and inner counts as before.
5. Done upstream: `zpfwire` 0.5.0 defaults to `net:ip` and `net:ethernet`.

**Acceptance 1, run:** a fresh venv with only the four released projects
installed, kober with its `yaml` extra, and every console command of both
example READMEs run as written. One fault found: neither README said to
install `kober[yaml]`, and without it `kober run` stops at the spec. Each now
says what to install. With it, everything ran, the WireGuard key-log converter
deriving exactly the keys `wg_seal.py` sealed with from the Wireshark-format
log.

**packeteer 0.18.0:** `dns_gen` is lossy at last (packeteer#194), and the
changelog says it was not before.

## Found on the way: a compiled field could hide what its function calls

Found 2026-10-16 adding `len`: a field is a local of its unit's generated
function, so one named `to_int` (or `present`, `len`, any helper or built-in)
hid that name from the code calling it, and the compiled decode raised where
the interpreter answered. *Decided:* rename the calls, not the field. A pass
over the rendered module renames a helper or built-in to an underscore alias
wherever a function has a local of that name, and only there, by exact source
position, since a helper is only ever called, raised, caught or given to
`isinstance` while a field is only ever a value. A module with no clash is
unchanged; `tests/compiled_dns.py` pins that. A local named like a class or
constant the module defines is read as a value, cannot be told apart, and is
refused. Refusing every name a helper has was weighed and rejected: it would
have refused `present`, `span` and `decode` where nothing clashed.

## Found on the way: a `gzip` transfer-coding is framed but not inflated

Found 2026-10-12 while reviewing packeteer 0.18.0.dev3, which fixed #172 (an
`http` section could not carry a header name twice). Kober raised #172 for this
very case, so it was run end to end: a response with

```
Transfer-Encoding: gzip
Transfer-Encoding: chunked
```

and a chunked gzip body. packeteer sends both lines in order, `parse` writes
them as `[name, value]` pairs, and a replay of the parsed capture is byte for
byte the original. `examples/http.yaml` frames the message as chunked, as
`0.5.0` made it, and its `body` record is exactly the gzip stream, de-chunked.
**It does not inflate it.** The `encoding` select reads `Content-Encoding`
only, so a `gzip` *transfer*-coding leaves no `content` record, the body
stays compressed, and nothing in the file says why.

That is within what `0.5.0` promised: it made two `Transfer-Encoding` lines one
list for **framing**, and its CHANGELOG says a coding it does not decode leaves
the body as it arrived. It is a gap rather than a bug, and a rare one in real
traffic, since servers send `Content-Encoding`. It is not this phase's work and
not in its acceptance.

**What closing it would take**, as a change of its own:

- In `examples/http.yaml`, a transfer-coding before `chunked` (RFC 7230 §4:
  `gzip`, `x-gzip`, `deflate`) decoded after the chunks are joined and before
  any `Content-Encoding`, so a body with both is inflated twice, in that
  order. A transfer-coding it does not know (`compress`, `br`) leaves the body
  as it arrived, as an unknown content coding does. Its own `select` over
  `transfer-encoding`, since the last item is the framing and those before it
  are codings, which is what `endswith` (#50) was added to say.
- What the file says when a coding is left undecoded: a field naming it, so
  the body's record says why it is still compressed rather than staying
  silent.
- A corpus: packeteer 0.18.0's `--protocol-messages` with header pairs, as in
  the review, framed by hand (the gzip body cut into chunks), through
  `tools/pipeline.py` lossless and lossy, with the shape asserted: each
  inflated `content` byte-identical to the document compressed.

## Acceptance

1. A user can run the example from its README with packeteer, `zpfwire` and
   kober installed, and nothing else.
2. The pipeline's WireGuard corpus decodes to `truth.jsonl` exactly (Q7),
   under loss, corruption, reordering and duplication, with both directions
   and at least one rekey.
3. Each corrupted datagram is one `decrypt-failed` region with
   `reason_class: bytes`, and the next datagram decodes.
4. No key appears in any output, diagnostic or failure detail.
   `params_digest` differs when any key in `keys.json` differs.
5. Nothing under `src/kober` names WireGuard, and no upstream project gained
   WireGuard code.
6. The cipher passes its known-answer tests independently of `wg_seal.py`
   (Q4).
7. The walkthrough is the page a user with another protocol would follow.
   Read it as that user before calling it done.

## What this phase does not do

- **Decrypt the handshake in kober.** The Noise IK state runs across
  messages. If that line ever moves, it moves in its own phase, with the
  stateful-transform design the transform plan reserved.
- **Detect replays.** Same reason (Q8).
- **Ship a cipher in kober.** `CLAUDE.md`, and the transform plan's Q7.
- **Add a conditional expression.** That is considered under Q1 and is worth
  doing on its own merits, separately.
