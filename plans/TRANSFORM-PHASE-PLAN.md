# Phase plan: transforms — decompression and decryption

**State: Stage 1 done; its three decisions made (2026-09-26).** Stage 0 landed (`0.5.0.dev0`,
a pipeline baseline). The Stage 1 spike ran on 2026-09-24 and is recorded in
*What the Stage 1 spike found*, below. Where it proved a leaning wrong, the
leaning is rewritten and says so. Where it turned a leaning into a choice
between two defensible designs, the choice is listed under *Decisions the
spike leaves open*, and *Decided, 2026-09-26* records the answers.
*Stage 1b* ([#49](https://github.com/adamkjonsson/zipline-kober/issues/49))
is done, and its results are recorded there. Next is Stage 2.

> **Written 2026-09-19** against `0.3.0`, `DESIGN.md` revision 9, `zpf` 0.5.0
> (spec 0.21), packeteer 0.16.0. The prompt was a question — *zipline is ready
> for protocols that change data; what does kober need?* — and the short
> answer is: nothing from the format, and one construct plus its plumbing
> from us.

> **Revised 2026-09-23, against `0.4.0`**, before any of it was started. The
> upstream state is unchanged (`zpf` 0.5.0, spec 0.21, packeteer 0.16.0), so
> nothing the format settles moved. What moved is kober: the verdict phase
> ([`VERDICT-PHASE-PLAN.md`](VERDICT-PHASE-PLAN.md)) shipped between this
> plan's writing and its start, and three of its changes bear on transforms.
> **Stream confirmation** (#32) declines a stream whose first message is
> `undecodable`, which a transform failure is, so a wrong key would be written
> as *not this protocol*: new **Q10**. A decline **quotes the failure detail
> into the file**, so Q4's promise about secrets and Q6's wording now reach
> the output. And the fix to a `count` that raised is a reminder that *a
> decode never raises* is one registered callable away from false: Q6 gains a
> bullet. Beside those, the plan now uses the tools 0.4.0 built
> (`tools/pipeline.py` and its `--baseline`, `tests/zpfcompare.py`), gains a
> Stage 0, corrects its version targets to `0.5.0` and its `DESIGN.md`
> revision to 12 (the header's "revision 9" was already wrong: `0.3.0` was
> revision 10), follows code that moved, and adds the terminal rule's
> exemption that the tunnel shape needs.

`kober` gains the ability to say **these bytes, after this transform, are
this** — the one thing [`concepts.md`](../docs/format/concepts.md) still lists
under *What a spec cannot say*:

> **Bytes are not transformed.** Decompression and decryption are not
> expressible; a body that is gzipped decodes as the bytes it is. That is an
> owed extension rather than a rule, and the reasoning is in `DESIGN.md` §11.5.

```
   HTTP  Content-Encoding: gzip   →  "inflate the body, then read it"   →  transform + type:
   TLS   application_data record  →  "decrypt it; someone else reads it" →  transform, no type:
   HTTP  chunked + gzip           →  "gather the chunks first"           →  concat
```

## Why this phase

Three reasons it is next, and one reason it is affordable now.

**The format is ahead of us, and has been since its 0.13.** The Zipline
specification settled every file-side question a transform raises, and did it
before this project could use any of it:

| Question | What the specification says | Where |
| --- | --- | --- |
| May a decoder emit bytes its input does not hold? | Yes: a decoder *frames, recodes, or does both*. | § *Typing a decoded record* |
| What does a recoded record cite? | The input region it was **computed from** — *correspondence, not identity*. A record of 8 bytes may span 16 000. | § *TLV option framing* |
| May two records cite the same input? | Yes; only *spanned and Undecoded* is forbidden. A nonce and tag fed every unit in a packet. | same |
| What is a failed decryption? | A bytes-class region (the vector's reason is `decrypt-failed`, not `undecodable`, as Stage 1 found); the neighbours do not join, so a Discontinuity `decrypt-failed`. | § *Worked example: a decrypted tunnel* |
| Where does a key live? | In the config `params_digest` covers — the reproducibility contract holds, but only a key-holder can act on it. | § *Decoder Descriptor* |

So kober needs **no change to the file it writes**, only to what it can say
and what it puts in a descriptor it already writes. That is the best possible
position to start from, and it will not stay this clean if the two projects
keep moving.

**The seam was drawn for this, on purpose, one phase ago.** The pointer phase
argued that *a pointer and a byte transform are the same shape* — decode a
unit against bytes that are not where the cursor is, and cite an input region
for the result — and built the redirect as a `(data, base, limit)` triple with
that in mind
([`POINTER-PHASE-PLAN.md`](POINTER-PHASE-PLAN.md), Q5). It also stated the
test for whether the seam was drawn right: *adding a gzip transform should
touch the byte-source type and the spec vocabulary, and **not**
[`decoder.py`](../src/kober/decoder.py)'s field or unit loops.*
[`_Read`](../src/kober/decoder.py#L80) says the same in its own docstring.
This phase is that test being run.

**§11.5 has already chosen the shape.** The design's long argument about
where the line between spec and program sits ends, in revision 8, with a
concrete case for the one thing it had deferred: *byte transforms cannot come
from a closed table, because nobody can ship every proprietary codec. What they
want is: the spec names a transform, a registry supplies it.* And it says why
that is not a fourth row in §3.3's function table — *a function maps a value to
a value; a transform maps bytes to bytes and feeds a sub-decode with its own
offset space.* The plan takes that as given rather than reopening it.

**What makes it affordable** is the same list as last time, one phase longer:
the differential holds the interpreter and compiler to the same records; the
fuzz suite asserts the promises no example can; the deeper pipeline reaches
the driver, and since `0.4.0` is a checked-in script
([`tools/pipeline.py`](../tools/pipeline.py)) that can diff a change against
a baseline; and `packeteer` can now put an arbitrary `raw:` body into an
impaired stream, which is how a gzip body reaches a capture at all.

## What the format leaves to us, in one sentence

The output file's offset space is the **input's**. Everything a transform
produces lives in a space the file cannot name — so whatever kober says about
the inside of an inflated body, it says in the tree, in `kober try`, in a
generated module's `__spans__`, and in its own invariants, **never** in an
`Undecoded` block. That is the one genuine cost, and Q5 is about being honest
about it rather than hiding it.

## What the Stage 1 spike found

Written 2026-09-24. The spike was interpreter-only, on a throwaway branch
(`spike_transform`, stashed rather than committed): `transform` with `from`,
`with`, `limit` and an optional `type`; `concat` as a field type; `space` on
`Node`; `gzip`, `zlib` and raw `deflate` bound from `zlib` with the limit
enforced incrementally; and a spike `http.yaml` that inflates its body.
**Not exercised**: `transforms:` declarations (Q3), `params:` and
`params_digest` (Q4), statefulness (Q8), a decompression bomb, and the
compiler. Nothing below is evidence about those.

### The corpus (Q9)

The route Q9 named does not work, and a different one does.

- **`packeteer stream --payload http` ignores `--protocol-messages` without
  saying so.** It generated its own REST traffic, and the gzip bodies were
  not in the capture. That is worth filing against packeteer: a flag
  accepted and dropped.
- **What works is a packeteer protocol spec of kober's own**: `blob`, one
  `data: bytes remaining` field, `input: datagram` over TCP. It needs a port
  packeteer's `http` does not claim (both 80 and 8080 are taken, and the error
  blames "a bug in packeteer's compiler"), and its messages are keyed by the
  protocol's field name (`{"data": hex}`), not `raw`.
- **A custom protocol's message is always one TCP segment.** `--mss` is
  HTTP-only, a 3.8 KB message went out as one segment, and `--mtu` fragments
  at the IP layer instead. So the script cuts the HTTP byte stream into
  200-byte pieces and sends each piece as a message: `--mss` done by hand,
  which is what puts a loss in the middle of a body.
- **`blob` sends from the client only.** The corpus is therefore a response
  direction on its own, which is also what makes Q10 testable: a request
  first would confirm the stream before any body was read.

The resulting corpus: 30 responses (15 gzip, 10 deflate, 5 identity; 19
length-framed, 11 chunked, some with trailers), 38 576 bytes, 193 pieces, and
a manifest with each body's SHA-256. The spike's `http.yaml` inflated **all 25
compressed bodies exactly** on the clean capture and **21, every one genuine,**
on the 5%-loss capture, conformant with full coverage at both granularities.
The builder is `spike/corpus.py` on the spike branch. Stage 5 turns it into
pipeline inputs.

### Q2 — `concat` is required, not optional

`from:` names one field, and `http.yaml` frames a body two ways: `body` when
length-framed, `chunks[*].data` when chunked. With `from:` naming one field,
inflating *whichever body this message has* cannot be written without a
transform per framing. What works is `concat` **as a field type**, so that
`body` becomes one switch with a `concat` case and a `bytes` case, and
`from: body` covers both. Q2 listed that as a nicety. It is what makes the
driving example expressible.

The switch needs a second `select` (`framing`, valued `'chunked'` or
`'length'`), because `check` refuses a switch on a boolean and the language
has no conditional expression. That is expressible today, only verbose.

**The hull said one false thing, and it is fixed by a rule.** The terminating
chunk's `data` is empty and sits *after* its `0\r\n` line, so the hull
stretched over that line. An empty member cites nothing. With that rule the
hull runs from the first data byte to the last, the interior size lines and
CRLFs are cited twice, and conformance holds on both captures. Nothing else
false was found, so **multi-range citation stays out.** One cost to note: at
field granularity a `concat` leaf is itself written as a `prim:bytes` record,
duplicating the chunk data it joins.

### Q5 — `space` does disturb the emitter, in two places

- **`_walk` needs the citation override**: every leaf under a transform
  cites the transform's source range. It is a parameter on the walk, in
  `emit.py`, not in the decoder.
- **`_reason_for` misattributes a hole to an inner node.** It picks the
  narrowest failing node containing an uncovered run, and it walks inner
  nodes too, whose offsets are in another space. A crafted spec (a message at
  offset 0 whose inner decode truncates over as many bytes as the message
  has) was written as **`truncated` over `[0, 12)`**: a false hole, for a
  message that arrived whole. `_holes` and `_reason_for` must skip nodes in
  another space. Stage 7's inner-coverage invariant would not have caught this,
  since it is about the output; the input-space fuzz invariants should gain
  transform-bearing specs whose inner decodes fail.
- An inner `emit: none` has nothing it can be written as, since a `skipped`
  region would carry inner offsets. The spike drops it.
- The differential's `compare()` checks each field's span against the tree,
  so Stage 6 has to say what an inner object's span is compared against.

Also: `check` passes the spike spec without knowing the new kinds exist, and
warns that the `document` unit is *never referenced* because it does not look
inside `transform.type`. Stage 2 is the whole checker, not a few rules.

### What happens to the source's bytes (new)

**`emit: none` on the field a transform reads crashes the run.** Its bytes
are written `skipped`, the transform's inner records cite the same bytes, and
`zpf` refuses the file at close: `ZpfError: [96, 338) is both decoded and
explicitly marked Undecoded`, raised out of `kober.stage.run`. A tunnel spec
would naturally write exactly that, since nobody wants the ciphertext written
as a record of its own. Either `check` refuses `emit: none` on a transform's
source, or the transform takes over its source's bytes (decision 1 below).

### Q6 and Q10 — the failure model is wrong in a way Q10 did not see

Two captures with a corrupted gzip body, run through the unchanged 0.4.0
driver:

| capture | what the file says | messages kept |
| --- | --- | --- |
| `first_bad`, first response corrupt | the stream declined, `not http: gzip: …` | **0 of 30** |
| `mid_bad`, fourth response corrupt, after confirmation | the rest of the connection `undecodable` | **3 of 30** |

Q10 foresaw the first row. The second is worse and was not foreseen: **in a
byte stream, any `undecodable` message ends the run** (`_decode_run`), before
or after confirmation, and the driver resumes only after the next gap. That
is right for a desync, where the extent is unknown. A transform failure is not
a desync. The framing decoded whole and the cursor sits exactly at the end of
the message, and on a lossless keep-alive connection the next gap is the end
of the connection. Q10's flag on `_Verdict` fixes only the first row.

The spike then tried **containment**: a transform failure leaves its node
`OK` with the failure as its `detail`, which is the precedent a malformed
string already sets (§3.2: *a fact about the input, not a failure of the
decoder*). Both captures then kept **30 of 30** messages, 24 of 25 bodies
inflated, and the files were conformant. **But the file says nothing about
the failed body.** It is one inner record short, with no region. The failure
is visible in the tree and in `kober try`, and nowhere in the output.

### The tunnel vector does not have the shape Q6 and acceptance 2 assume

`../zipline/vectors/tunnel/packets.jsonl`, the decrypt stage:

- one record per datagram, **citing the whole datagram**, not a ciphertext
  field inside it;
- a failed datagram is an `Undecoded` region with the **custom reason
  `decrypt-failed`**, classed `bytes`, not `undecodable`;
- and **a Discontinuity `decrypt-failed`** in the output participant, because
  the plaintext on either side does not join.

Q6 says *no seam is owed* and acceptance 2 says *no seam*, while this plan's own
opening table says the Discontinuity is there. kober writes a seam only after
a hole-class region. At field granularity (a unit sequence) a Discontinuity
would be redundant, and at message granularity kober writes the message, not
the plaintext. So what "matches `vectors/tunnel/` in shape" means has to be
decided, not assumed (decision 3).

### Wording

The declined stream's comment quoted **zlib's own text** (`Error -3 while
decompressing data: invalid code lengths set`). CPython's wording would then
be written into the file, and a second backend or another Python version
could say it differently. Q4's rule, kober's own wording, applies to the
**shipped** codecs too, not only to callers'.

### Q7 — the table, checked

Checked against each platform's documentation on 2026-09-24, and Node 18
probed directly. Go and Java are as the table says. The rest has moved:

| | deflate-raw | zlib | gzip | bzip2 | xz | br | zstd |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Python ≥ 3.11 | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 3.14+ only |
| Node | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ 10.16+ | ✅ 22.15+, experimental |
| Go | ✅ | ✅ | ✅ | decompress only | ❌ | ❌ | ❌ |
| Java | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| .NET | ✅ | ✅ 6+ | ✅ | ❌ | ❌ | ✅ | ✅ in current docs |
| Browser `DecompressionStream` | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ listed | ✅ listed |

Three consequences:

- **`deflate` is a trap.** In HTTP's `Content-Encoding` *and* in the browser
  API, `deflate` means **zlib** (RFC 1950), and raw RFC 1951 is `deflate-raw`.
  The plan defines `deflate` as RFC 1951. An author who copies the header value
  into `with:` would get the wrong codec and fail on every body. The spike's
  own spec had to map `deflate` to `zlib` by hand. Q7 is rewritten to follow
  the browser's names.
- **`br` and `zstd` are now more portable than `bzip2` and `xz`**, which
  remain Python's extras. The core tier (the three deflate containers) is
  unchanged. The extended tier's order of likely demand is `br`, `zstd`,
  then the two Python-only names.
- **This backend's bound set depends on the interpreter.** `zstd` is in the
  standard library from Python 3.14, and kober supports 3.11. A capability
  set is a property of the *runtime*, not only the backend. Acceptance 8's
  static refusal has to be computed where the code runs.

### The seam test

**It passes in the interpreter.** The spike's diff to `decoder.py` only adds
code: two branches in `_value`'s dispatch, and the new methods. `_unit`,
`_field`, `_repeat`, `_elements`, `_one` and `_constrained` are unchanged,
`_Read` gained nothing, and the second cursor is `Cursor(output, 0)` with a
fresh `_Read(origin=0)`. What the seam did *not* carry is on the emitting side
(Q5 above). The existing suite passed on the spike except three
documentation-coverage tests, which fail because the new kinds are
undocumented, and which will hold Stage 8 to its word.

### Decisions the spike leaves open

1. **What a transform failure does, and what the file says about it.** Three
   shapes, all measured or measurable:
   - *Stop* (the plan as written): the message is `undecodable`, so the rest
     of the run is lost, and before confirmation the stream is declined.
     Visible, at 27 of 30 messages' cost on `mid_bad`.
   - *Contain*: the node stays `OK` with the failure as its detail. Nothing
     is lost, and the file says nothing about the failure. No change to the
     driver or the decoder's loops. Q10 disappears.
   - *Take over the source*: a transform's outcome speaks for its source's
     bytes. On success the output records cite them and the source is not
     written as a record of its own. On failure they become an `undecodable`
     region, and the message carries on. This is the tunnel vector's shape,
     it is what makes `emit: none` on the source unnecessary, and it is the
     only one of the three where the file says a body failed without losing
     what follows. It costs a rule in the emitter and a change to what a
     source field writes. **Leaning, pending Adam: this one.**

   **Measured**, same day, with take-over paired with the rule that a
   message whose transform failed **neither confirms nor declines** the
   stream. That pairing matters: a transform is often a weakly framed
   protocol's only real identity check (an AEAD tag that verifies), so a
   failure must not confirm, and a stream where every transform fails is
   declined at its end with a comment that says so. A fifth capture,
   `all_bad`, has every body compressed and every body corrupt, which is what
   a wrong key looks like to a decoder. Messages kept, field granularity, every
   output conformant:

   | capture | stop | contain | take over |
   | --- | --- | --- | --- |
   | `clean` | 30, 25 inflated | 30, 25 inflated | 30, 25 inflated |
   | `first_bad` | **0**, declined | 30, failure not in the file | **30, 24 inflated, 1 `undecodable` region** |
   | `mid_bad` | **4**, rest of the connection lost | 30, failure not in the file | **30, 24 inflated, 1 `undecodable` region** |
   | `all_bad` | 0, declined | **30 confirmed, 0 inflated, nothing said** | 0, declined at the end |

   The region is exactly the corrupt body (`[96, 338)` in `first_bad`), and
   nothing else is marked. `all_bad` is declined with `not http: no message
   decoded whole; every transform failed, the first with gzip: not valid
   compressed data`. The comment's wording needs work, since for a wrong key
   *not http* is still false, but it is honest about what was seen. `contain`
   is ruled out by the last row: it confirms a stream in which nothing
   inflated and says nothing about it. At message granularity all three modes
   write 30 whole message records for `first_bad` and `mid_bad`. The message
   record cites the body, so no region can name its failure there. That is
   message granularity's resolution, and the docs should say so.

   What it cost the spike: in the decoder, a failure leaves the node `OK`
   carrying its detail, and the loops are still untouched. In the emitter, a
   transform's source is skipped when the transform is present, and a failed
   transform names the source's range `undecodable`. In the driver, a step
   verdict meaning *decoded whole but held*, and the new end-of-stream
   comment. On `clean`, take-over writes 25 fewer records, one per compressed
   body, since those bodies are no longer written as records of their own.

2. **The output's unread tail.** A `type` that reads less than the whole
   output leaves bytes no inner node claims. The plan is silent. The spike made
   it `undecodable`, which is strict. The alternative is an inner `skipped`,
   which the file cannot carry anyway.
3. **What acceptance 2 means by "the tunnel's shape".** Whole-datagram
   citation, a custom `decrypt-failed` reason, and a Discontinuity are each a
   different feature from what kober writes. The minimum honest target is
   *one output record per datagram, citing input the datagram holds; a
   failed datagram named `undecodable`; the next datagram decoded*.


### Decided, 2026-09-26

Adam settled all three. The rest of this plan is rewritten to agree; where a
passage argued otherwise, it says so.

1. **Take over the source**, with a failed transform **neither confirming
   nor declining** the stream. Accepted with it:
   - a. A transform's source is not written as a record of its own when the
     transform is present. The outcome speaks for those bytes: the output's
     records cite them on success, and an `undecodable` region names them on
     failure. A source whose transform is absent (its condition false) is
     written as before. `emit: none` on a source is therefore unnecessary,
     and `check` refuses it rather than let `zpf` raise at close.
   - b. Failure covers the codec, `limit`, **and the inner decode**. An
     output that does not decode as its `type` fails the whole transform,
     and inner records that did decode are dropped, since they would cite
     bytes marked `undecodable`.
   - c. No seam after the failed source. `undecodable` is bytes-class, and a
     field-granularity file is a unit sequence anyway.
   - d. At message granularity the failure is not in the file. The message
     record cites the body. This is documented as that granularity's
     resolution.
   - e. A stream that ends unconfirmed because every message that decoded had
     a transform fail is declined, keeping the `not <spec>:` prefix the
     pipeline and consumers read, worded as what was seen: `not http: every
     message that decoded had a transform fail; the first: gzip: not valid
     compressed data`.
2. **Strict.** Output a `type` does not read to its end is a transform
   failure, and so, under 1, the whole source is `undecodable`. An author
   expecting trailing bytes says so with a `remaining` field.
3. **Acceptance 2 is reworded** (below), and **the args citation rule is
   adopted**: a transform cites its source **and every field its `args`
   read**, as one range from the first to the last, the way a `computed`
   field cites what its expression read. For an AEAD whose nonce and
   associated data are the header, that is the whole datagram, which is the
   tunnel vector's citation. Only the source is taken over under 1. The
   argument fields keep their own records, and the overlap is legal. Custom
   reasons such as `decrypt-failed` and a Discontinuity after a failure stay
   out of this phase. The first would extend kober's reason vocabulary for one
   user. The second is redundant under a unit sequence, and message
   granularity does not write plaintext at all.

### Found on the way: phantom messages after a gap (not a transform issue)

The lossy capture shows **34 start lines for 30 responses**, under every mode
and under the shipped `examples/http.yaml` on 0.4.0 too. After each of its 8
gaps, the driver resumes mid-body, reads body bytes up to a chance CRLF as a
start line, truncates, and, the stream being confirmed, writes that partial
tree. That breaks `tools/pipeline.py`'s lossy bound (*no more start lines
than messages sent*). packeteer's own HTTP bodies are small, so a gap had
never landed mid-body often enough to show it. This corpus's bodies span
dozens of pieces. It is a 0.4.0 issue in resynchronising after a gap, filed
as [#49](https://github.com/adamkjonsson/zipline-kober/issues/49) and added to
the `0.5.0` milestone. Reproducing it for the issue showed the damage goes
past the phantom line: the **next real status line is read as a header
value**. It is scheduled as *Stage 1b*, since it fails Stage 5's pipeline
input until it is fixed.

## Design questions to settle first

### Q1 — Is a transform a construct in the spec, or a stage between specs?

Two architectures, and the tunnel example in the specification is built on
the second:

1. **Inline.** One spec, one stage. `body` is read, inflated, and decoded in
   place; the JSON inside an HTTP response is in the same tree as the headers
   that framed it.
2. **A stage of its own.** `http.yaml` emits the body bytes; a `gunzip` stage
   writes a file whose records are the inflated bytes, citing the compressed
   ones; a third spec reads those. Every hop gets its own file, its own
   offset space, and — the point — its own complete coverage accounting.

Neither alone is enough. Inline is required because *whether* to inflate is
decided by a header in the same message, and a downstream stage would have to
sniff for it. A stage of its own is required because TLS's next protocol is a
different spec, and because it is the only way an inner undecoded region can
be written into a file.

**Leaning: one construct with an optional `type:`, which gives both.**

```yaml
- name: body
  bytes: {size: {expr: "content_length"}}
- name: content
  transform:
    from: body                            # bytes already decoded — never the cursor
    with: gzip                            # a name; the registry binds it
    args: {}                              # expressions, typed by check
    type: {unit: json_document}           # optional: decode the output here
    limit: 16777216                       # required: max output bytes
    content_type: "mime:application/json" # when type: is absent
```

With `type:`, the output is decoded in a second offset space and every leaf
under it cites `body`'s range. Without it, the output bytes **are** the record
payload, citing `body`'s range with the given `content_type` — which is
exactly what `wireguard-decrypt` does in the specification's worked example,
and what a downstream kober stage then reads as datagrams. The second shape
falls out of the first for free; the plan should check it does rather than
assume it.

### Q2 — Where do the input bytes come from?

**Leaning: from a field already decoded, never from the position.** `from:`
names a `bytes` field earlier in the unit (or a parameter of type `bytes`).
That is the whole of why §2.1 survives untouched: like `select`, the construct
reads **nothing** where it stands — the bytes were claimed by the field that
read them — and both implementations assert the position is unchanged across
it, the way they already do for `select` (§2.1 revision 9). It is zero-width
at the cursor and cites elsewhere, which is `Computed`'s and `Pointer`'s shape,
so `Node` and `Emission` keep their single contiguous range.

A transform that read at the cursor (`transform: {bytes: {size: …}, with: gzip}`)
is shorter to write and was considered. It is refused because it makes one
construct both a reader and a transformer, and the rule this project has held
since revision 4 is that a construct does one of those.

**The chunked case is the hard one, and it needs a second key.** A chunked
body is `chunks[*].data`, scattered through a repetition with a size line and
a CRLF between every piece, and gzip wants it as one buffer. Kober has no list
type and should not get one; the shape is the one that answered §11.6 — one
construct with the binding inside it:

```yaml
  transform:
    from: {concat: chunks.data}
    with: gzip
```

`concat` yields `bytes` and is the repetition exemption reaching one more
place: a repeated field may be named there, meaning each element in turn, and
nowhere new. **What it cites is the real question.** The element ranges are
disjoint, `Node` carries one range, and the pointer phase's Q6 declined
multi-range citation as a wider change than it wanted. Leaning: **the hull**,
first element's start to last element's end. The chunk-size lines inside it
are cited twice — once by their own fields, once here — and overlap is legal;
they arguably did feed the result, since without them there is no
concatenation. The fallback, if the hull turns out to say something false in
a real capture, is the multi-range `cites` that `zpf.record()` already
accepts; the spike measures which.

`concat` without `transform` — just gathering a chunked body into one `bytes`
value — is useful on its own and comes at no extra cost. It should be a field
type in its own right, and `transform.from` accepts a field of that type.

*Stage 1:* it is **required**, not merely useful. Only as a field type can
one `body` field hold either framing, so that `from: body` covers both. The
spelling that worked is `concat: chunks.data` as a switch case. An empty
member cites nothing, which keeps the hull off the terminating chunk's size
line. The hull said nothing else false on the corpus.

### Q3 — How does `check` type `args` when the registry is process-local?

This is the objection §11.5 raised against caller-registered *functions*, and
it applies to transforms word for word: if `check` reads a transform's
parameter types off whatever the registry holds, *a spec is valid in one
process and invalid in another*, and a YAML file that another language could
consume becomes one only this runtime can check.

**Leaning: the spec declares the interface; the registry supplies the
implementation; they are checked at different times.**

```yaml
transforms:
  gzip: {}
  aes-gcm: {params: {key: bytes, nonce: bytes, aad: bytes}}
```

`check` types every `args:` entry against the declaration, statically, with
no registry loaded. Binding a declared name to a callable happens when a
`Decoder` is built (or a generated module imported), and *declared but not
registered* is a different error at a different time. The shipped transforms
need no `params:` line; an undeclared `with:` name is a `check` error the way
an unknown unit is.

The cost is a few lines of declaration for a codec kober already ships. It
buys a spec that says what it needs, which a non-Python backend can read and
bind to its own codecs — and it keeps `check` answering before any data
exists, which is the property this project has defended in every phase.

### Q4 — Where does a key live, and what does the file say about it?

A key is not in the spec — a spec is checked in — and not in an expression.
It is **run configuration**, and the specification already says where run
configuration goes: `params_digest` on the Decoder Descriptor.

**Leaning: a document-level `params:` block, supplied at run time, hashed
into `params_digest`.**

```yaml
params:
  key: {type: bytes, secret: true}
```

- `kober run spec.yaml in.zpf -o out.zpf --param key=hex:…` and
  `Decoder(spec, params={"key": …})` supply it; a missing required parameter
  refuses before the stage opens, since nothing that runs could be reproduced.
- A parameter is in expression scope under its name, exactly as a unit
  parameter is (§3.1) — so `args: {key: "key"}` is ordinary.
- **Kober writes no `params_digest` today.** [`Spec.as_decoder`](../src/kober/spec.py#L781)
  returns `(name, version)`, and a transform-free spec has nothing to put
  there. This phase starts writing one: a hash over the canonical spec
  document plus every parameter value, so the reproducibility contract holds
  — and a `secret: true` value is hashed, never echoed in `comment`, `role`
  or a diagnostic.
- **Since `0.4.0` a failure detail is written into the file.** A declined
  stream's regions carry `not <spec>: <detail>, stopped at offset <n>`, with
  the detail quoted as the decoder gave it. Under Q6 a transform's failure
  detail would be its exception's message — text a caller's cipher controls
  and kober does not. So the detail kober reports for a transform failure is
  **kober's own wording**, naming the transform and the kind of failure, never
  the callable's message passed through; a test puts a secret in a raising
  transform's message and asserts it appears nowhere in the output.
- Reading back at message granularity goes through
  [`content_registry`](../src/kober/stage.py#L665), which hands a record's
  payload to `decode_bytes`; a spec with a keyed transform needs the key at
  read time too, so the registry is built from a `Decoder`, which already
  holds it. Nothing changes in the API shape.

### Q5 — Two offset spaces: what does a node under a transform carry, and what does it cite?

[`node.py`](../src/kober/node.py) says ranges are *absolute in the stream's
offset space*. Under `type:` that stops being true for a subtree, and the
subtree's numbers are meaningful — `kober try` prints them, a generated
dataclass's `__spans__` carries them, and the differential compares them.

**Leaning: a node carries the space it is measured in, and the emitter maps
every leaf under a transform to the `from` range.**

- `Node` gains a `space` (the transform node's identity, or `None` for the
  input), set on every node decoded through the second cursor. `Node.width`
  and `walk()` are unaffected. `render()` shows it —
  `content  [12, 340) → gzip:[0, 1811)`, an inner leaf `[0, 4)@gzip`.
- **Every emission under a transform cites the `from` range**, whatever inner
  range it came from. That is the correspondence rule applied literally, and
  it is why the file needs no new vocabulary. At field granularity the `body`
  record and every inner leaf cite the same input; overlap is legal, and it is
  the *nonce and tag* case the specification describes.
  *Decided 2026-09-26:* the range is the source **plus every field the
  `args` read**, first to last, and the source is taken over rather than
  written as its own record (*Decided*, 1 and 3).
- **Inner coverage is kober's promise, not the file's.** An inner byte no leaf
  claims cannot be an `Undecoded` block — its input is spanned, and *spanned
  and Undecoded* is the one contradiction the format forbids. So the fuzz
  suite gains an invariant the file cannot carry: *every byte of a
  transform's output is cited by an inner node or named by an inner
  non-`OK` node, and never both.* The same invariant set that guards the
  input space, run over the inner one; the machinery exists.
- A generated dataclass keeps `__spans__`; `runtime.span()` on an object that
  came from a transform returns inner-space offsets, and the transformed
  field's own span on the parent is the `from` range. Whether the space needs
  to be readable from the object is Stage 6's call — leaning no, because
  nothing in the read-side API asks *which* space today, and adding an
  attribute for a question nobody has asked is the abstraction the pointer
  phase warned against.

### Q6 — What is a failure, and how is the output bounded?

**Leaning: `undecodable`, bytes-class, always — and a `limit:` that is not
optional.**

- A transform that raises (bad gzip header, authentication failure, wrong key)
  is a wrong claim about input that arrived, never input that did not. The
  node is `UNDECODABLE` with the transform's message as `detail`; no seam is
  owed. This is the pointer's rule 3 and needs no new argument.
  *Stage 1: open again.* An `undecodable` message ends its run, so this
  loses every message after it, and the tunnel vector writes a
  Discontinuity after a failed decryption. Decision 1 and decision 3 under
  *What the Stage 1 spike found* replace this bullet.
- A **short read inside the inner decode** is converted from `truncated` to
  `undecodable`, exactly as [`_pointer`](../src/kober/decoder.py#L722) converts
  it: `truncated` is hole-class and would declare a break the stream never
  had. `DESIGN.md` §11.5 now states this as a principle — `truncated` is never
  claimed for bytes that arrived — with `pointer` and, since `0.4.0`, a field
  starved under `check=False` as its two applications. This is the third.
- **Whatever a registered callable raises is converted, not only
  `TransformError`.** A caller's `aes-gcm` from `cryptography` raises
  `InvalidTag`, and the compiled step catches only `TruncatedRead`,
  `EvalError`, `Undecodable` and `ZeroDivisionError`
  ([`stage.py`](../src/kober/stage.py#L469)). `0.4.0` found and fixed one
  escape from *a decode never raises* (a `count` dividing by zero), which no
  spec in the fuzz corpus could reach; a registry that trusted its callables'
  exception types would open another. The wrapper in `ops.py`, shared by both
  backends, converts any `Exception` from the callable to `undecodable` with
  kober's own wording (Q4), and the fuzz corpus gets a transform that raises
  something foreign.
- **`limit:` is required, and exceeding it is `undecodable`.** A kilobyte of
  gzip inflates to a gigabyte; a transform with no output bound is not total,
  and totality is what §2.1's first bullet demands of every construct. The
  registry API takes the bound (`transform(data, limit=…, **args)`), the
  shipped decompressors honour it incrementally (`zlib.decompressobj().decompress(data, max_length)`
  exists for this), and `check` refuses a transform without one rather than
  defaulting it. Whether the spec author or the runtime should own the number
  was considered; the author knows the protocol's plausible sizes and the
  runtime does not.
- **Failure of `with:` binding** — declared, not registered — is raised when
  the `Decoder` is built, before any stream is opened. It is a `SpecError`
  in spirit (the spec asks for something this process cannot give), and it
  must not become a per-message `undecodable` that quietly marks a whole file.

### Q7 — Which transform names does the *language* have, and which does *this implementation* bind?

The first draft of this question asked only *what can kober ship, under the
standard-library rule?*, answered *the registry and `gzip`/`zlib`/`deflate`/
`bz2`/`lzma`*, and was wrong in a way worth recording rather than quietly
fixing — because the error is one this project has made nowhere else and
would have been expensive to find later.

**It derived the language's vocabulary from CPython's packaging.** Those are
two rules, and they must stay apart:

| Rule | What it governs | Where it comes from |
| --- | --- | --- |
| kober depends on the standard library and the zipline projects only | what this Python package may `import` | `CLAUDE.md` |
| which transform names a spec may use | the **format**, which Q3 defends as consumable by another implementation | this plan |

Deriving the second from the first produces exactly the failure Q3 refuses —
a spec valid against one backend and invalid against another — only now
discovered at *backend* time rather than at `check` time.

**The assumption does not survive contact with any other language.** Node 18's
`zlib` was probed directly; Go, Java, .NET, Rust and the browser are from
knowledge and should be re-checked in Stage 1:

| | deflate | zlib | gzip | bz2 | lzma/xz |
| --- | --- | --- | --- | --- | --- |
| Python | ✅ | ✅ | ✅ | ✅ | ✅ |
| Node | ✅ | ✅ | ✅ | ❌ | ❌ |
| Go | ✅ | ✅ | ✅ | ✅ *decompress only* | ❌ |
| Java | ✅ | ✅ | ✅ | ❌ | ❌ |
| .NET | ✅ | ✅ (6+) | ✅ | ❌ | ❌ |
| Rust | ❌ | ❌ | ❌ | ❌ | ❌ |
| C | ❌ | ❌ | ❌ | ❌ | ❌ |
| Browser `DecompressionStream` | ✅ | ✅ | ✅ | ❌ | ❌ |

`deflate`/`zlib`/`gzip` are effectively universal among languages that ship
compression at all; Rust and C ship none, which is a different problem — there
the codec is a dependency every project already has. `bz2` and `lzma` are
Python's generosity and not a norm. Go's bzip2 being decompress-only costs
nothing here, because **kober only ever decompresses** — a fact worth stating
in its own right, since it shrinks what any backend must bind.

**And the inversion is what settles it.** Python's standard library has no
**brotli**. `Content-Encoding: br` is one of the three encodings actually met
on the wire, RFC 7932 defines it, and Node and .NET have it built in. Under
the first draft's rule the spec language could never name `br` — while
carrying `lzma`, which no network protocol uses. The set was chosen by an
accident of CPython's packaging, and `examples/http.yaml`, this phase's own
driving example, is where that would have been felt.

**Leaning: a well-known name is defined by a normative reference, tiered for
portability, and bound per backend.**

1. **A name means a specification, not an implementation.** `deflate` =
   RFC 1950 (zlib), `deflate-raw` = RFC 1951, `gzip` = RFC 1952, `br` =
   RFC 7932, `zstd` = RFC 8878, plus `bzip2` and `xz`. That is what makes a
   name portable, independent of who has the codec. *Stage 1 changed this
   line*: the first draft had `deflate` = RFC 1951 and `zlib` = RFC 1950,
   which disagrees with HTTP's `Content-Encoding` and with the browser's
   `DecompressionStream`, the two vocabularies a spec author is copying
   from. The names now follow the browser's. `zlib` may be kept as a synonym
   for `deflate` if it earns its place; it is not a name a header will
   carry.
2. **Two tiers.** A **core** tier — `deflate`, `deflate-raw`, `gzip` — that any
   backend must bind to claim conformance, and an **extended** tier a backend
   may decline. A spec that stays in core is portable by construction; one
   that does not says so in its own `transforms:` block, where an author can
   see it before a backend refuses it.
3. **A backend declares a capability set, and refusal is static.**
   `kober compile --target go` refuses a spec needing a name that target
   cannot bind, before generating a line. `check` with no target stays
   target-independent: it verifies the name is well-known or declared, and
   nothing more. This is Q3's discipline applied one level up — the spec
   declares, the binder supplies, and the two are checked at different times.
4. **What this implementation ships is then a separate, short sentence.** The
   core tier plus `bzip2` and `xz`, all from the standard library, and `zstd`
   on Python 3.14 and later, where the standard library has it. `br`, and
   `zstd` before 3.14, go through the same caller registration that ciphers
   use. No new mechanism, only a different framing of the one below. Because
   the bound set moves with the interpreter, the capability set is computed
   at run time, not written down once per backend.

The registry itself is unchanged by any of this:

- `kober.transforms`: `register(name, fn)`, `lookup(name)`, and the bound set
  above. Each is `(data: bytes, *, limit: int, **args) -> bytes`, raising one
  `TransformError` that becomes `undecodable`. That is what the shipped
  bindings do. A caller's callable may raise anything, and Q6 says why the
  wrapper converts that too.
- **Decryption is always caller-registered**, and the docs say so in the first
  paragraph: the standard library has no AES, no ChaCha20 and no GCM, and
  `CLAUDE.md` forbids reaching for one. A caller registers `aes-gcm` from
  `cryptography` or wherever, in their own process, and the spec declares it
  under `transforms:`. The test suite does the same with a deliberately
  trivial cipher (XOR with the key, plus a fake tag check) — stdlib-only,
  deterministic, and enough to exercise every path a real cipher would:
  parameters from fields and from `params:`, failure on the wrong key,
  `params_digest` changing with the key.
- A generated module `import`s the registry and binds its names at import
  time, so an unregistered transform fails when the module loads, not when a
  message arrives — the compiled analogue of Q6's last bullet.

**What this costs now is one table and one flag's worth of design; what it
would have cost later is the vocabulary.** A name that ships is a name that
has to keep working, so a second backend arriving to find `lzma` in the core
set and `br` unnameable would be a break in the format rather than a fix to a
plan.

### Q8 — Stateful transforms?

TLS 1.3 derives each record's nonce from a per-connection counter; deflate
with context takeover (WebSocket `permessage-deflate`) keeps its window across
messages; HPACK keeps a dynamic table. All three carry state from one message
to the next, and kober's step is per message
([`stage.py`](../src/kober/stage.py#L442)) with nothing between two calls.

**Leaning: not in this phase, and nothing in this phase may make it harder.**
A stream-scoped instance — the driver calling a factory once per stream and
handing the instance to each step — is a natural later extension of the
registry, and the `transforms:` declaration leaves room for a `stateful: true`
flag that `check` would use to refuse a stateful transform under `concat` or
in a repetition. The plan reserves the *shape*, not the key: adding a key
nobody reads is the thing this project has learned not to do.

What this phase covers without state: `Content-Encoding: gzip` (whole-body,
stateless), a TLS record whose nonce is *in* the record or supplied as a
parameter, and any per-datagram cipher. What it does not: the three above.
The docs list them.

### Q9 — Where does the corpus come from?

Nothing in `zpfwire`'s sixteen captures carries a compressed body, and
packeteer's HTTP payload has no `--content-encoding`. Two routes, both
already available:

- **packeteer `--protocol-messages FILE`** with `raw:` sections: bodies built
  by Python's own `gzip` in a small script, framed as HTTP by hand, fed
  through `packeteer stream --packet-loss --gap-jitter`. *Stage 1: not as
  written.* `--payload http` ignores the flag, so the bytes go through a
  `blob` protocol spec of kober's own, cut into pieces by the script. See
  *What the Stage 1 spike found*. This is the only way
  to get a gzip body into an *impaired* stream, and it is the same route the
  compressed-DNS case took. Chunked + gzip is the same script with the body
  split into chunks — and since packeteer's own chunking cannot be applied to
  a raw body, the script frames the chunks itself.
- **A decryption corpus** is synthetic by construction: the test cipher of Q7
  over generated inner traffic, one datagram per record, with a deliberately
  corrupted third datagram so the `undecodable` path and the no-seam rule are
  both exercised. `../zipline/vectors/tunnel/` is the reference for what the
  output should look like block for block.

If the raw-section route turns out to be too awkward to script, a
`--content-encoding` flag belongs in packeteer as a protocol feature, not
filed as a kober workaround.

Both corpora become pinned inputs of `tools/pipeline.py`, which did not exist
when this was written. It is where a gzip body meets the driver, and a
lossless one can have its shape counted exactly by the script's independent
HTTP reader. `0.4.0` found that bounds on the counts let a real bug through
([`VERDICT-PHASE-PLAN.md`](VERDICT-PHASE-PLAN.md) §9.2).

### Q10 — Does a transform failure decline the stream? *(added against `0.4.0`)*

> *Stage 1:* this question was too narrow. The spike measured the decline
> (0 of 30 messages kept) and also found the larger loss after confirmation
> (3 of 30), which the flag below does not touch. It is folded into
> decision 1 under *What the Stage 1 spike found*. Two of that decision's
> answers make this question go away. The text is kept as it was argued.
> *Decided 2026-09-26:* take-over, and a failed transform neither confirms
> nor declines. That keeps this question's leaning for the first message
> and adds the half it missed: the message decodes whole, so the run goes on.

Since `0.4.0` a stream is **confirmed** by its first whole message, and one
that meets an `undecodable` first is **declined** (`DESIGN.md` §3.1). The
driver keeps no record for it, marks what it tried `undecodable` and the rest
`skipped`, and writes `not <spec>: <detail>` on every region. A failed field
ends its unit and makes the message `undecodable`
([`decoder.py`](../src/kober/decoder.py#L413)), so under Q6 as written:

- **A wrong or missing key declines every stream it touches**, each labelled
  `not tunnel` or `not http`. That is false. The protocol is right, and the
  key is wrong. §3.1 accepted the declining of a right-protocol stream whose
  first message fails because none of the 22 real captures had one. A
  transform makes it systematic: every stream, every time the key is wrong.
- **A corrupt body or an exceeded `limit` in the first response** loses the
  whole connection, where a desync after confirmation would have lost one
  message.
- Acceptance 2 as first written avoided the question by corrupting the
  *third* datagram.

The confirmation rule exists to stop a **guess about the protocol** from
writing a fabricated tree. A transform failure is not evidence about the
protocol. The framing that located the transformed bytes was read whole, and
they were rejected by a codec or a key. **Leaning: a failure inside a
transform does not decline, and it does not confirm.** Its message is
written as an ordinary post-confirmation failure would be: the transform node
`undecodable` and its input cited. The stream stays unconfirmed until a
message decodes whole, and it declines at its end if none ever does, which
keeps the end-of-stream rule intact. What that needs is for the step's
verdict to tell a failure inside a transform from any other. `_Verdict`
gains a flag, set by both backends from the one place in `ops.py` that
converts a transform's failure. The driver reads it. The decoder's loops do
not change, which keeps the seam test honest.

The alternative, **accept and document**, costs no code, and it writes a
false statement into every file decoded with the wrong key. It is considered,
and it loses on the one thing 0.4.0 was about: what a file says about the
bytes it was given. The spike (Stage 1) runs the corpus both ways, and the
pipeline's declined-stream count is the measure: a key that is right should
decline nothing that was confirmed before this phase.

## The insight, restated as a test

The pointer phase's claim was that the seam it built would carry a transform
without re-plumbing the read path. Concretely, after Stage 4:

- `decoder.py`'s unit and field loops are unchanged.
- `_Read` gains nothing but a way to say *this cursor is over synthesized
  bytes* — or nothing at all, if `space` on the node is enough.
- The second cursor is `Cursor(output, 0)`, which is the `(data, base, limit)`
  triple with `base = 0` and `limit = len(output)`.

If the diff says otherwise, the seam was drawn wrong and that is worth
knowing before the compiler copies the mistake.

## Stages

### Stage 0 — `0.5.0.dev0`, and the baseline

`pyproject.toml` → `0.5.0.dev0`. Run `tools/pipeline.py` on the unchanged
`0.4.0` code and keep its output as the baseline. `0.4.0` found this the most
useful decision in its plan ([`VERDICT-PHASE-PLAN.md`](VERDICT-PHASE-PLAN.md)
§9.1). Every later stage diffs against it with `--baseline`, and for a
transform-free spec that diff must stay empty through the whole phase,
**except for what Stage 1b moves**. #49 changes what 0.4.0 writes for a lossy
stream, so Stage 1b is checked against this baseline and then replaces it.

### Stage 1 — settle Q1–Q10, with a spike

Build the gzip corpus (Q9) first, because every later stage needs it and
because building it says whether packeteer's raw route is usable. Then, on a
branch that is thrown away: a `transform` field with `from:` and `type:`,
gzip only, in the interpreter only, with a `space` on `Node`, and
`examples/http.yaml` reading the inflated body as text. Measure against the
seam test above. Record, per question, what the spike found; rewrite the
leanings that were wrong.

Two things the spike should try that the plan cannot decide on paper: whether
`concat`'s hull citation says anything false on the chunked corpus (Q2), and
whether `space` on `Node` disturbs any of `emit._walk`, `_holes`, or the
differential's comparison (Q5). A third: a stream whose first gzip body is
corrupt, and one decoded with the wrong key, through the driver under both of
Q10's answers, with the declined-stream counts compared.

One thing it should *check* rather than try: Q7's table is one row verified
and seven recalled. Confirm what Go, Java, .NET, Rust and the browser
actually have before the tiering is written down, because the tier boundary
is a promise the format has to keep.

### Stage 1b — phantom messages after a gap ([#49](https://github.com/adamkjonsson/zipline-kober/issues/49))

A driver fix, independent of every transform decision, and first for two
reasons. Stage 5's lossy gzip input fails the pipeline's shape bound until it
lands. And it moves transform-free output, so doing it before any transform
code means one diff against the Stage 0 baseline shows exactly what it
moved, and nothing else can be mixed into that diff.

- **Decided 2026-09-26**, and recorded on
  [#49](https://github.com/adamkjonsson/zipline-kober/issues/49#issuecomment-5845321378).
  Measured first: all 8 gaps in the lossy gzip capture land inside a body.
  The 4 in `Content-Length` bodies are exactly the 4 real responses the
  phantoms swallowed, and the 4 in chunked bodies left junk messages. Three
  parts land here, in both backends:
  1. **Resume at a known end.** A gap that cuts a read whose length was
     already decided, with nothing after it up to the entry unit reading
     bytes, leaves the message's end known. The next run resumes there. The
     bytes from the gap to that end are `skipped`, with the comment *rest of
     a message cut by a gap*.
  2. **Where the end is not known**, the first message after a gap is held.
     If it decodes whole it is released. If not, its partial tree is
     discarded and the rest of the run is `undecodable`, with a comment
     saying no message boundary was found after the gap. Such a failure never
     declines the stream. No forward scanning.
  3. **A failed guard writes no fields**, anywhere. It was a separate defect
     against `DESIGN.md` §3.1, found on the way, and part 2 depends on it. No
     shipped spec has a guard, so no example output moves.

  The fourth part, a spec recognising its own start line, needs
  `startswith`/`endswith`: [#50](https://github.com/adamkjonsson/zipline-kober/issues/50),
  also in `0.5.0`, not in this stage. Datagram input is untouched, since a
  datagram cannot be cut by a gap.
- **Tests first**, reverted-and-watched: #49's reproduction as a stage-level
  test through both drivers, and the lossy gzip capture's shape (*no more
  start lines than responses sent*) as the property. The stage-level fuzz
  0.4.0 added gets streams with gaps landing inside messages.
- **Measure against the Stage 0 baseline.** Every output the fix moves must
  be one it means to move, checked stream by stream as 0.4.0 checked its
  declines (`VERDICT-PHASE-PLAN.md` §9.1). Then run the pipeline again into
  a **new baseline** (`../kober-baselines/0.5.0-stage1b`), which is what
  every later stage keeps.
- `CHANGELOG.md` under `Unreleased`: `Fixed`, and `Breaking:` under `Changed`
  if what a file says about a lossy stream changes the way #32's did.

**Done, 2026-09-26.** All three parts, in both backends, with every
regression test watched failing against the code it guards, including two
tests that pin down the *wrong* fixes (dropping records on any failure, and
guessing a refusal from a unit whose fields all decoded). A new stage-level
fuzz cuts gaps anywhere in framed streams and checks, against ground truth,
that no message start is cited inside a message and that every whole message
after a known cut is decoded. It was watched failing with the resume
disabled. What it found:

- **On the lossy gzip capture**, start lines went from 34 (26 real, 8
  phantom) to 32: **all 30 responses at their real offsets**, 4 `skipped` cut
  regions, 2 `undecodable` lost runs, and 2 phantoms left, both after a gap
  into a chunked body, both decoding whole. That is #50's case. The capture
  therefore still breaks the lossy bound (32 > 30) until #50 lands.
- **Against the Stage 0 baseline, 4 of 64 outputs moved**, all one stream:
  the generated HTTP traffic under `dns.yaml`, declined as before over the
  same bytes, now with the end-of-stream comment instead of the specific
  failure, because the attempt that failed came after a gap. No HTTP output
  moved: the pipeline's lossy HTTP input has only 2 gaps.
- **The pipeline's lossy HTTP input has had 2 phantom start lines since
  0.4.0** (`b''` and `b'19'`, chunk framing read as start lines), hidden by
  its count bound because the same gaps took 2 real start lines. A check that
  every start line looks like one would have caught them. It belongs with
  #50, since it fails until #50 lands.
- The guard fix moved nothing: no shipped spec has a guard.
- An end-of-stream decline after a lost attempt needed its own wording, since
  0.4.0's "every attempt ran out of input" is false when one failed some other
  way.

The new baseline is `../kober-baselines/0.5.0-stage1b`.

### Stage 2 — the constructs in the model, loader, and checker

- `Transform` and `Concat` field types in [`spec.py`](../src/kober/spec.py);
  `transforms:` and `params:` on `Spec`; `Param` reused for the latter.
- The loader accepts both keys, with source locations on faults as the
  dialect phase established.
- `check` rules: `from` names an earlier `bytes`-typed field, `concat` field
  or `bytes` parameter; `with` is a well-known name or declared under
  `transforms:`; every `args` entry is typed against the declaration and
  every declared parameter is supplied; `limit` is present and positive;
  `type` resolves; `content_type` is well-formed and only present without
  `type`; a `concat` names a repeated field's element field and nothing else.
  A transform in a repetition without progress is refused the way a repeated
  pointer is.
- **The terminal rule exempts both constructs.** `check` refuses a field after
  a `remaining` unless it reads nothing where it stands, and only `computed`,
  `select` and `pointer` are listed as such
  ([`check.py`](../src/kober/check.py#L521)). `payload: remaining` followed by
  `transform: {from: payload}` is the tunnel shape, acceptance 2's own spec,
  and would be refused. `transform` and `concat` join the exemption, and
  `starved_fields` must agree, since both backends convert from it.
- *Stage 1:* `check` must also **look inside** the new kinds: it walks a
  `transform`'s `type` for reachability, scope and typing, as it does a
  `pointer`'s. And it refuses `emit: none` on a transform's source: the
  transform takes over those bytes (*Decided*, 1a), so the setting has
  nothing to do, and a spec written before that rule would otherwise make
  the run raise `ZpfError` at close.
- **No rule here consults a binding** — that is Q7's split, and
  it is what keeps `check` answering the same way against every backend.
- `kober show` renders `content: gzip(body) → json_document`.

### Stage 3 — the well-known names, the registry, and the bound set

Two things, and Q7 says why they are two:

- **The name table** — the well-known names with their normative references
  and their tier, in the package but not tied to any binding. `check` reads
  it; a backend's capability set is declared against it. Core is `deflate`
  (RFC 1950), `deflate-raw`, `gzip`; extended is `br`, `zstd`, `bzip2`, `xz`
  (Stage 1's names and order, Q7).
- **The Python binding** — `kober.transforms` per Q7, binding the core tier
  plus `bzip2` and `xz` from the standard library, and `zstd` where the
  interpreter has it (3.14+), with the bound honoured
  incrementally and a test that a crafted bomb stops at `limit` in bounded
  memory, not after. The spike bound all three core names this way
  (`zlib.decompressobj(wbits).decompress(data, limit + 1)`, then refusing
  output past `limit`). A shipped codec's failure is worded by kober, never
  by `zlib`. `br` is a well-known name this backend does
  not bind, which is the first live test that a declined name fails cleanly
  rather than looking like a typo.

The test cipher lives in `tests/`, not in the package.

### Stage 4 — the interpreter

The second cursor over the output, `space` on every node beneath it, the
position asserted unchanged, and `decode_bytes`/`Decoder` taking `params`.
A failure of any kind (codec, `limit`, the inner decode, an unread tail)
leaves the transform node `OK` with no output and its failure as the detail,
as a malformed string is (§3.2), so the unit and field loops never see it. A
short inner read is not reported as `truncated` anywhere. The seam test is run
here and the result recorded.

### Stage 5 — emission, the stage driver, and the CLI

- `plan()` maps every emission under a transform to the transform's range
  (the source plus its `args` fields); a `type`-less transform emits its
  output as the payload with the declared `content_type`. A source whose
  transform is present is not written as a record of its own. A failed
  transform names its source's range `undecodable`. `_holes` and
  `_reason_for` skip nodes in another space.
- `params_digest` computed and written, via a `DecoderHandle`, from both
  drivers through the one place a decoder is declared.
- `kober run --param NAME=VALUE` (with `hex:` and `file:` forms for bytes);
  `kober try` likewise. `content_registry` already takes a `Decoder`, so it
  gains the parameters with no change of signature.
- A step reports a message that decoded whole with a failed transform as
  its own verdict. Both drivers carry on after it, since the message's extent
  is known, and it neither confirms nor declines. A stream that ends
  unconfirmed this way is declined with *Decided* 1e's comment.
- `_Writer` changes only in the comment it declines a stream with, which is
  the claim to check: nothing a transform does reaches the writer as anything
  but a record citing input bytes or a region naming them. Since `0.4.0` it
  holds everything before confirmation, and an inner record is held and
  released like any other.
- `tools/pipeline.py` gains the Q9 inputs, with an exact shape count on the
  lossless gzip stream and the lossy bound on the other, which holds only
  once #50 has landed as well (Stage 1b left two phantoms that only the spec
  can refuse). Its diff against the Stage 1b baseline stays empty
  for every transform-free output.

### Stage 6 — the compiler

Generated code calls the registry through [`ops.py`](../src/kober/ops.py), so
the bound, the error conversion and the citation mapping are written once and
shared. A generated module binds its transforms at import. `__spans__` carries
inner-space offsets for inner objects. The differential is extended to every
transform-bearing spec in every corpus, byte-identical files block for block
under `tests/zpfcompare.py`'s `blocks()`, the one definition both the suite
and the pipeline use. It compares region comments too, so the two backends
must word a transform failure identically, and Q4's rule makes that wording
kober's. `tests/compiled_dns.py` is regenerated and must diff empty: a spec
with no transform compiles to the same source as before.

### Stage 7 — fuzz, and the new invariants

Four invariants, each verified against a deliberately broken implementation
before it is trusted:

1. The position is unchanged across a transform — checked against a version
   that consumes a byte, as `select`'s is.
2. Inner coverage: every output byte is cited by an inner node or named by
   an inner non-`OK` node, never both — checked against a version that drops
   the inner tail.
3. `limit` holds: no transform's output exceeds it, and exceeding it is a
   failure — checked against a version with the bound removed and a bomb in
   the corpus.
4. A transform's source is spoken for exactly once: on success it is cited by
   the output's records and by no record of its own, on failure it is one
   `undecodable` region and cited by nothing. Checked against a version that
   also writes the source's own record, and one that drops the region.

Plus the existing set over the input space, unchanged, which is itself a
claim: a transform must not weaken *any* of the four promises `test_fuzz.py`
already makes. *A decode never raises* is the one most at risk (Q6), so the
corpus includes a registered transform that raises something other than
`TransformError`. `0.4.0` also added the suite's first stage-level fuzz,
over confirmation. Streams whose messages carry transforms, with some failing,
join it. It asserts *Decided* 1: a transform failure neither confirms nor
declines, and a message after one is still decoded. Only a stream in which no
message decoded whole without one is declined.

### Stage 8 — examples, documentation, and what has to be restated

- `examples/http.yaml` gains `content`, decoded by `Content-Encoding`; its
  gzip disclaimer goes.
- A short `examples/` entry or test spec showing a `type`-less transform
  feeding a second stage — the tunnel shape — so the docs can point at the
  two-stage route rather than describe it.
- [`types.md`](../docs/format/types.md) gets `transform` and `concat`;
  [`document.md`](../docs/format/document.md) gets `transforms:` and
  `params:`; [`concepts.md`](../docs/format/concepts.md) loses its last
  *cannot say* bullet and gains a paragraph on the second offset space, and
  on what the file does and does not say about it.
- **The well-known name table is reference documentation, not a note**: every
  name, its normative reference, its tier, and whether this backend binds it.
  It is what an author consults before using `br`, and what a second backend
  implements against — so it belongs beside the type reference rather than in
  a changelog entry.
- `DESIGN.md`: revision 12 (10 and 11 were taken by `0.3.0` and `0.4.0`).
  §2.1 gains a cursor over bytes that are not input; §3.1's confirmation
  section gains Q10's rule for transform failures; §3.2 gains the two
  constructs; §6 gains `params`; §11.5 records that the deferred branch was
  taken and where the line sits now, and the inner short read as the third
  application of its `truncated` principle; a new §13 entry for what the gzip
  corpus found.
- `docs/format/concepts.md` *What a spec meets in someone else's stream*
  says that a transform failure does not decline.
- `CHANGELOG.md` under `Unreleased`, then `0.5.0`: a minor bump for new
  spec keys, and `Breaking:` only if `content_registry`'s signature changes.

## What this phase does not do

- **Stateful transforms** (Q8). TLS 1.3 nonces, deflate with context
  takeover, HPACK. The registry's shape leaves room; nothing here builds it.
- **Ship a cipher.** The standard-library rule forbids it, and the plan does
  not argue with the rule.
- **A transform that reads at the cursor.** `from:` a decoded field, always.
- **Hooks.** A transform is a registered callable, which is closer to a hook
  than anything before it — but it gets bytes and returns bytes, cannot see
  the position, and is declared in the spec so `check` stays static. That is
  the line §11.5 drew, and this phase stays on its side.
- **Multi-range citation** on `Node` or `Emission`, unless the spike proves
  the hull says something false.
- **A second backend.** Q7 tiers the names so one is possible later and
  writes the capability set down; it does not build a target, and
  `--target` has exactly one value until one exists.
- **A release.** `0.5.0` is a separate step and follows the release procedure
  in `CLAUDE.md`; this plan ends at *merged under `Unreleased`*.

## Acceptance

1. `examples/http.yaml` decodes a `Content-Encoding: gzip` body — length-framed
   and chunked — into the inner content, on generated captures with loss,
   conformance- and coverage-clean at both granularities; its gzip disclaimer
   is gone.
2. A `type`-less transform produces a file a second kober stage reads, with
   one plaintext record per datagram citing only bytes that datagram holds
   (the whole datagram, when the header is the cipher's nonce and associated
   data); a corrupted datagram's ciphertext named `undecodable`; the datagram
   after it decoded; the chain conformant with full coverage. The same holds
   when the corrupted datagram is the **first**. A wrong key, where every
   datagram fails, declines the stream with *Decided* 1e's comment. The
   vector's custom `decrypt-failed` reason and its Discontinuity are out of
   scope (*Decided*, 3).
3. The differential passes over every corpus with transform-bearing specs in
   each, byte-identical files block for block under `blocks()`, including
   `params_digest` and region comments. `tests/compiled_dns.py` regenerates
   with an empty diff, and `tools/pipeline.py`'s diff against the Stage 1b
   baseline is empty for every transform-free output.
4. The four new fuzz invariants hold and were each seen to fail against the
   broken implementation they target; the four existing ones are unchanged.
5. The seam test passes: the diff to `decoder.py`'s field and unit loops is
   empty.
6. `check` refuses an undeclared transform, an untyped or missing argument, a
   missing `limit`, and a `from` that is not an earlier bytes field — before
   any data exists, with no registry loaded — and accepts a transform after a
   `remaining`.
7. **The core tier is stated as a conformance claim**: a backend binding
   `deflate`, `deflate-raw` and `gzip` can run any spec that stays inside it, and the
   docs say which names are core, which are extended, and what each one's
   normative reference is.
8. **An extended-tier name a backend declines fails statically and says so** —
   `br` against the Python binding is the case in hand — with a message that
   distinguishes *this backend does not bind that* from *no such transform*,
   and `check` without a target still passes the same spec.
9. `DESIGN.md` and the format docs say what is true of both implementations
   afterwards, and `concepts.md` no longer lists transforms as something a
   spec cannot say.
10. **#49 and #50 are fixed**: no stream in any pipeline input, lossy gzip
    included, has more start lines than messages sent or a start line that
    does not look like one, and the Stage 1b diff against the Stage 0
    baseline moved only what #49 meant to move.
11. **No secret reaches the file**: a `secret: true` value, and a secret in a
    raising transform's own message, appear in no record, region comment or
    diagnostic, including a declined stream's.
