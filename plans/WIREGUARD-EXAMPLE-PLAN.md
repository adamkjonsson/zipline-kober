# Phase plan: a WireGuard tunnel, as the worked example of bringing your own code

**State: Stages 0 to 4 done (2026-10-13).** `0.6.0.dev0`, with the
pipeline baseline taken on the unchanged `0.5.0` code in
`../kober-baselines/v0.5.0`, outside the repository. Map parameters and
`keys[receiver]` landed in both backends (*Stage 1 — done*). `fails_as` is
declared, checked, planned by both backends, and written with its
`reason_class` since `zpf` 0.5.2 released
[python-zipline#79](https://github.com/adamkjonsson/python-zipline/issues/79)
(*Stage 2 — done*). `examples/wireguard/` holds the spec, the cipher and the
transform, decoding datagrams built in the tests (*Stage 3 — done*), and
`wg_seal.py` seals packeteer's generated traffic with a real handshake, which
Wireshark opens (*Stage 4 — done*). Upstream issues filed 2026-10-11 (see
*What it waits for*). Stage 5 is next, and waits on zpfwire#35 for its design
or takes its fallback.

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
| [zpfwire#35](https://github.com/adamkjonsson/python-zipline-wire/issues/35) | Sessions from a `.zpf` of IP packets | Stage 5 as designed | Stage 5's fallback |

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
  keeps it by default; `--checksum drop` turns it into a loss. And Wireshark
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
