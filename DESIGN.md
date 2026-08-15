# kober — design draft

**Status:** draft for discussion. Nothing here is implemented.

Revision 5. Revision 1 was written blind and got the layer wrong — it invented
reassembly, gaps, and provenance that `zpf` already provides. Revision 2 fixed
that against the source. Revision 3 added the results of an executable pressure
test (§10) and treated this project as what it is: **a load test of `zpf`, where
a gap upstream is a finding rather than a constraint to route around.**

Revision 4 records what that load test produced. All three findings were filed
against `python-zipline` and all three are fixed
([#55](https://github.com/adamkjonsson/python-zipline/issues/55),
[#56](https://github.com/adamkjonsson/python-zipline/issues/56),
[#57](https://github.com/adamkjonsson/python-zipline/issues/57)), and released
in `zpf` 0.2.0. **`Emit.FIELD` is no longer blocked** — with the caveat in
§4.1, which is now about the durability of the mechanism rather than its
absence. The approach worked, so it stays.

Revision 5 corrects the reasoning in §2, which justified the declarative spec
model with an argument that contradicted its own opening paragraph. The line
that matters is **who moves the cursor** (§2.1), not declarative-versus-code.
That closes §11 question 2 in favour of keeping `Computed` and reframes §3.3's
minimal expression language as a choice about cost rather than safety.

Claims below marked **[verified]** were executed against `zpf` 0.16, not
reasoned about; the script is in §10.

## 1. What `zpf` already does, and what is left for us

This is the important framing, because it shrinks the project a lot.

`.zpf` is a *payload* format. Packets are already reassembled into session
byte streams before we ever see them — that is `python-zipline-wire`'s job.
`zpf.decode_stage()` then provides the entire decode-stage scaffolding:

| Concern | Provided by `zpf` | Left to us |
| --- | --- | --- |
| TCP reassembly | `SessionReader.reassemble()` → `StreamView` | — |
| Missing bytes | `StreamView.chunks()` → `Segment \| Gap` | react to a `Gap` |
| Datagram vs byte stream | `is_stream_oriented`, `datagrams()` | support both |
| Provenance | `Span`, `cites=(off_start, off_end)` | cite accurately |
| Coverage guarantee | auto-fill on close | claim only what we decoded |
| Output scaffolding | source, decoder, participants, extents | — |
| Iteration | chained stages, file to file **[verified]** | — |
| Message timestamps | `Segment.ts` is already the *last* contributor's **[verified]** | — |

**What is actually left is one thing: turn a declarative spec into the loop
that reads segments and calls `dec.record(...)`.** That is the whole product.
Everything else in this document exists to serve it.

Three consequences, each of which killed something from revision 1:

- **No sinks, no reassembly primitives.** Cross-packet reassembly is upstream.
  Deleted.
- **Spans are byte offsets, not bits.** `cites=(off_start, off_end)` is in
  logical stream offsets. Bitfields still decode *within* a record, but a
  record citing a bitfield cites the containing bytes. Open question 1 in
  revision 1 is settled: bytes.
- **No `refine()` API.** Iteration is a chain of files
  (`raw.zpf → stage1.zpf → stage2.zpf`), and a later pass reads the earlier
  pass's `Undecoded` blocks. Revision 1's open question 2 is settled by the
  format itself.

## 2. The coverage guarantee drives the design

Every input offset must end up either cited by a record or named by an
`Undecoded` block, never both. `decode_stage(fill_undecoded=True)` makes that
true by construction, but *silence is a lie by default*: bytes we simply fail
to mention get auto-filled as `skipped`, which claims we chose to pass over
them. The format reserves `undecodable` for "tried and failed", and only an
explicit `DecodeStage.undecoded(...)` call can say it.

So the spec model needs a deliberate answer, per construct, to "what happens
when this doesn't match":

- a `Switch` with no matching case and no default → `undecoded(reason="undecodable")`
- a length field pointing past the end of the segment → `reason="truncated"`
- a field landing inside a `Gap` → `reason="gap"`
- a region the spec deliberately ignores (padding, encrypted body) → `reason="skipped"`

### 2.1 The cursor rule

Revisions 1–4 justified the declarative spec model here with: *if specs could
run code they could silently swallow input, so because they can't, coverage is
provable from the spec alone.* That argument does not survive contact with the
paragraph above it, and it is worth correcting rather than quietly dropping,
because as written it pushes later decisions the wrong way.

Coverage is not made true by the absence of code — `fill_undecoded=True` makes
it true by construction, whatever the spec looks like. Two weaker and more
specific things are true instead, and they are what the design actually rests
on:

1. **Every construct has a total, declared failure behaviour** — the four
   bullets above. That is a property of the *construct vocabulary*, not of
   whether an expression can call a function. It is what lets `check` say
   ahead of time that a spec will account for its input *honestly*:
   `undecodable` where we tried and failed, `skipped` only where we chose to
   pass over.
2. **Nothing author-supplied may move the read cursor.** This is the real
   invariant. Bytes consumed without being claimed become auto-filled
   `skipped`, and that is precisely the lie in "silence is a lie by default".

So the line that matters is not *declarative versus code*. It is **who moves
the cursor**, and it splits cleanly:

| Concern | Rule | Why |
| --- | --- | --- |
| Framing and consumption — order, sizes, repeats, switches, conditions | Declarative only | Decides which bytes belong to what; coverage analysis reasons over it |
| Value computation — what a field's bytes *mean* | Unconstrained in principle | Cannot affect coverage: the bytes are already claimed |

Drawing it here has one immediate consequence: `Computed` (§3.2) is on the safe
side by construction. It consumes nothing and cannot touch the cursor, so it
was never the thin end of a wedge — §11 question 2 is closed on that basis.

It also names the invariant the decode loop must enforce when it is built: the
cursor is the runtime's, advanced only by declarative constructs, and any
future extension point (§11.5) gets values and returns values, never the
position.

## 3. Spec model

Frozen dataclasses, `from __future__ import annotations` throughout.

```python
@dataclass(frozen=True)
class Spec:
    """A protocol specification."""

    name: str                           # becomes the zpf decoder name
    version: str                        # becomes the zpf decoder version
    entry: str                          # root unit
    units: Mapping[str, Unit]
    enums: Mapping[str, EnumDef] = field(default_factory=dict)
    input: InputShape = InputShape.EITHER
    doc: str | None = None
```

`input` is new in this revision and comes straight from the two stream shapes:

```python
class InputShape(Enum):
    STREAM = "stream"       # TCP: parse segments, messages may span records
    DATAGRAM = "datagram"   # UDP: one message per datagram, self-contained
    EITHER = "either"
```

A DNS spec is `EITHER` (it runs over both); HTTP is `STREAM`. Declaring it lets
`check` reject a spec run against the wrong transport instead of producing
garbage, and lets the runtime pick `segments()` vs `datagrams()` without
guessing.

Note **[verified]**: a *decoded* input is always packet-oriented, whatever the
original transport, because decoded records carry no `seq_start`. So a spec at
stage 2+ sees `DATAGRAM` shape even when stage 1 read TCP — which is coherent
(each decoded record is a self-contained unit) but means the runtime must
dispatch on `stream.is_stream_oriented`, never on the spec's declaration alone.

### 3.1 Units and fields

```python
@dataclass(frozen=True)
class Unit:
    """A named, reusable group of fields."""

    name: str
    fields: Sequence[Field]
    params: Sequence[Param] = ()
    confirm: Expr | None = None         # dispatch guess held up
    reject: Expr | None = None          # abandon: emit undecodable, don't fail
    doc: str | None = None


@dataclass(frozen=True)
class Field:
    name: str | None                    # None = anonymous (padding, reserved)
    type: FieldType
    condition: Expr | None = None
    repeat: Repeat | None = None
    emit: Emit | None = None            # see §4; None inherits from the unit
    doc: str | None = None
```

`confirm`/`reject` survive from revision 1 and matter more here than they did
in Spicy, because rejecting cleanly is how a wrong protocol guess becomes an
honest `undecodable` region instead of a fabricated field tree.

### 3.2 Field types

```python
FieldType = IntType | BytesType | StringType | UnitRef | Switch | Computed


@dataclass(frozen=True)
class IntType:
    bits: int                           # need not be a multiple of 8
    signed: bool = False
    endian: Endian = Endian.BIG         # network order is the sane default
    enum: str | None = None


@dataclass(frozen=True)
class BytesType:
    size: SizeSpec


@dataclass(frozen=True)
class StringType:
    size: SizeSpec
    encoding: str = "utf-8"             # decode errors recorded, never raised


@dataclass(frozen=True)
class UnitRef:
    unit: str
    args: Sequence[Expr] = ()


@dataclass(frozen=True)
class Switch:
    on: Expr
    cases: Mapping[int | str, FieldType]
    default: FieldType | None = None    # None = undecodable, per §2


@dataclass(frozen=True)
class Computed:
    expr: Expr                          # decodes nothing; cites its inputs
```

```python
SizeSpec = Fixed | FromExpr | Terminated | Remaining
Repeat = Count | Until | ToEnd
```

`Terminated(delimiter, consume, required)` and `Remaining()` both need a
truncation answer: in `STREAM` shape, a missing terminator at the end of the
available data means *truncated*, which may simply mean the message continues
in a segment we don't have. That is a normal outcome, not an error.

### 3.3 Expressions

Small, total, side-effect free: arithmetic, comparison, boolean ops, field
references, literals. No calls, no loops. Authored as strings
(`size: "header.length * 4"`), parsed to an AST at load time so `check` can
type them and scope them against the spec before any data exists.

Scoping follows Kaitai: `this`, `parent`, `root`, plus unit param names. A
reference to a not-yet-decoded field is a load-time error.

Read "no calls, no loops" as **a choice about taste and cost, not a safety
requirement.** Per §2.1, an expression cannot move the cursor whatever it
contains, so no amount of arithmetic here threatens the coverage guarantee.
The language is small because a small one is cheap to check, cheap to explain,
and portable to a non-Python reader — not because a bigger one would be
dangerous. Growing it is §11 question 5, and the parser is built from a
whitelist precisely so that growing it is a list change.

## 4. Emission granularity, and the one thing `zpf` cannot express

```python
class Emit(Enum):
    MESSAGE = "message"     # one record per top-level unit instance
    FIELD = "field"         # one record per leaf field
    NONE = "none"           # decode for control flow only; emit nothing
```

**`MESSAGE`** matches the decoding tutorial exactly: one record per protocol
message, `content_type="dec:dns-message"`, payload = the message bytes,
`cites` = its range. The field tree finds message boundaries and is then
discarded — available from the Python API, absent from the file. Simple,
conformant, cheap. **[verified]** clean conformance and coverage.

**`FIELD`** is where a spec-driven decoder earns its keep: one record per leaf,
each citing the exact bytes it came from. Two things had to be true for this to
work, and both are **[verified]**:

- **`prim:` normalization is accepted.** A big-endian `u16` at offset 0 becomes
  payload = the value re-encoded little-endian, `content_type="prim:u16"`,
  `cites=(0, 2)`. The record is *created*, so its payload need not equal its
  input bytes. Conformance clean, and `zpf.decode_prim` reads `0x1234` back as
  `4660`. Normalizing wire order into `prim:`'s little-endian is what that
  scheme is for.
- **Overlapping spans are accepted.** Three records citing `(2, 4)` — the flags
  word, plus `qr` and `opcode` inside it — pass both checks. The coverage rule
  forbids a range being *both* cited and marked `Undecoded`; it does not forbid
  two records citing the same range. So sub-byte fields work.

### 4.1 Naming decoded fields — solved, on a stopgap

A `Record` block has `payload`, `content_type`, `spans`, and `comment`. When
revision 3 was written, `comment` was the only per-record free slot and **it
could not be written**: `Record.comment` existed in the block model and read
back fine, but neither `SessionWriter.record()` nor `DecodeStage.record()`
accepted `comment=`. Field granularity produced this **[verified]**:

```
ct=prim:u16   value=4660     cites=[(0, 2)] comment=None
ct=prim:u16   value=256      cites=[(2, 4)] comment=None
ct=prim:u16   value=0        cites=[(2, 4)] comment=None
ct=prim:u16   value=0        cites=[(2, 4)] comment=None
ct=prim:u16   value=1        cites=[(4, 6)] comment=None
```

Every value correct, every span correct, and useless: two records read `0` with
nothing saying one is `qr` and the other `opcode`.

`comment=` is now accepted on both methods
([#55](https://github.com/adamkjonsson/python-zipline/issues/55)), and the same
run gives **[verified]**:

```
ct=prim:u16   value=4660     cites=[(0, 2)] comment='dns.id'
ct=prim:u16   value=256      cites=[(2, 4)] comment='dns.flags'
ct=prim:u16   value=0        cites=[(2, 4)] comment='dns.flags.qr'
ct=prim:u16   value=0        cites=[(2, 4)] comment='dns.flags.opcode'
ct=prim:u16   value=1        cites=[(4, 6)] comment='dns.qdcount'
```

Conformance and coverage stay clean, and `prim:`'s normative typing survives
intact — which is why this beats the revision 3 fallback of putting the path in
the label (`content_type="dec:dns.header.id"`). That fallback conflated *type*
with *name*: `dec:dns.header.id` and `dec:dns.header.qdcount` would be two
types that happen to both be `u16`, with nothing left in the file saying they
share one. It is dropped.

**The caveat, and it is the load-bearing one.** `zpf` documents `comment` as
free text — *nothing parses it and no consumer may depend on its shape*. So a
field path carried there is honest for a human reading the file and gives a
*program* no contract. Upstream says as much in the same change that added it,
and argues the real fix in
[#58](https://github.com/adamkjonsson/python-zipline/issues/58) (a dedicated,
checkable `label`/`field_path` on `Record`) against `zpf` 0.3.

Two consequences for us:

- **Confine the field-path formatting to one function**, so switching to a real
  `label=` is a change at a single emit site rather than a scattered one.
- **Do not build a reader that parses `comment` back into structure.** The read
  side stays `decode_bytes` on our own `Node` tree (§6) until #58 lands. A
  `comment` is for the human looking at the file.

The strategic question — whether per-field records are the right level for a
*payload* format at all — is genuinely still open, and is now #58's to settle.
Real files from this project are the evidence it wants, which is an argument
for building `Emit.FIELD` rather than deferring it.

## 5. Seams

A decoder must declare a break where two of its own adjacent output records do
not join. Framing bytes skipped between two messages still join. A `Gap`
between them does not. So the runtime rule is mechanical:

> when the region between two emitted records intersects a `Gap`, pass
> `seam=Seam(width=..., reason="stream-gap")`; otherwise omit it.

Worth stating explicitly because it is easy to forget and impossible for the
conformance checker to catch — only the producer knows.

## 6. Public API

```python
from kober import Decoder, Spec

spec = Spec.from_file("dns.yaml")       # dispatches on suffix
spec = Spec.from_json(text)             # stdlib only
spec = Spec.from_dict(mapping)

decoder = Decoder(spec, emit=Emit.FIELD)

# The main entry point: one spec, one file in, one file out.
decoder.run("raw.zpf", "decoded.zpf", produced_by="kober 0.1")

# Lower level: drive an existing stage, so callers can mix spec-driven
# decoding with hand-written logic in one stage.
with zpf.decode_stage("raw.zpf", "out.zpf", decoder=spec.as_decoder(), ...) as dec:
    for stream in dec.streams():
        decoder.decode_stream(dec, stream)

# No file at all — for tests, REPL work, and the `try` CLI verb.
tree = decoder.decode_bytes(b"\x12\x34...")     # -> Node

# The read side, generated from the same spec.
registry = decoder.content_registry()
with zpf.open("decoded.zpf", registry=registry) as f: ...
```

`Node` is our own in-memory tree (name, value, `(off_start, off_end)`,
children, status). It is deliberately *not* written to the file — it is what
`decode_bytes` returns and what `Emit.FIELD` walks to produce records. Keeping
it out of the file is what avoids inventing a parallel representation
alongside `zpf`'s.

CLI, one verb per API entry point:

```
kober run    SPEC IN.zpf -o OUT.zpf [--emit field|message]
kober check  SPEC                      # validate + type expressions
kober show   SPEC                      # human-readable field tree
kober try    SPEC --hex 0a0b           # decode one buffer, print tree
```

## 7. Example spec

This one loads and checks clean; `tests/test_loader.py` runs it, so it cannot
drift from the schema.

```yaml
name: dns
version: "1.0"
entry: message
input: either

enums:
  opcode: {0: query, 1: iquery, 2: status}

units:
  message:
    fields:
      - name: id
        type: {int: {bits: 16}}
        doc: Copied into the reply; matches responses to requests.
      - name: flags
        type: {unit: flags}
      - name: qdcount
        type: {int: {bits: 16}}
      - name: questions
        type: {unit: question}
        repeat: {count: "this.qdcount"}

  flags:
    fields:
      - name: qr
        type: {int: {bits: 1}}
      - name: opcode
        type: {int: {bits: 4, enum: opcode}}
      - {name: null, type: {int: {bits: 2}}}    # reserved

  question:
    fields:
      - name: qname
        type: {string: {size: {terminated: {delimiter: "\0"}}}}
      - name: qtype
        type: {int: {bits: 16}}
```

The `doc:` entries are the argument for YAML over JSON: annotation is the
difference between a spec someone can maintain and one they can't.

Two things this example got wrong before the loader existed, both worth naming
because they are the kind of thing a written-out schema fixes. `enum` belongs
*inside* `int`, not beside it: a `type:` is a single-key mapping naming the
kind, and a second key beside it has no meaning. And the earlier version
referenced a `question` unit it never defined, which `check` now reports as an
unknown unit — the example was illustrative rather than real, and is now real.

## 8. YAML

Optional extra (`pip install kober[yaml]`), imported lazily. Core
parses the *model*, so `from_dict` and `from_json` work stdlib-only and the
CLI is the only thing that really wants YAML. `safe_load` only. Guard against
implicit typing — `on`/`off`/`yes`/`no` become bools and `1.10` becomes a
float — with strict schema validation immediately after load.

## 9. Upstream findings — all three resolved

The pressure test produced three findings, all filed against `python-zipline`,
all fixed, and all released in `zpf` 0.2.0. Kept here because the reasoning
still constrains our design, not as an open list.

### 9.1 A per-record name for decoded fields — fixed, and still argued

Was **blocking `Emit.FIELD`**. Three options were put upstream, cheapest first:

1. **Plumb `comment=` through both `record()` methods.** No format change,
   unblocks immediately — but `comment` is documented free text, and a field
   name is load-bearing semantics.
2. **A dedicated optional `label`/`field_path` on `Record`.** A format change.
   Says what it means and is checkable; costs a field only decoders use on the
   format's hottest block.
3. **Declare message granularity the intended level and drop `Emit.FIELD`.**
   `.zpf` is a *payload* format, so per-field records may be the wrong level.

**Upstream took (1)** ([#55](https://github.com/adamkjonsson/python-zipline/issues/55)),
explicitly as a stopgap, and deferred the (2)-vs-(3) call to
[#58](https://github.com/adamkjonsson/python-zipline/issues/58) on `zpf` 0.3 —
which is the outcome revision 3 recommended. The strategic question is
therefore still live, and it is more about what `zpf` is for than about what we
need. What changed is that we can now build and measure instead of waiting, and
bring #58 evidence rather than an opinion. See §4.1 for how we hold the
mechanism at arm's length so that #58 stays a one-site change.

Worth noting for our own planning: #58 and
[#59](https://github.com/adamkjonsson/python-zipline/issues/59) (restructuring
the `record()` signatures rather than suppressing `PLR0913`) are both `zpf` 0.3
work, and every `zpf` minor is a break. Our pin is `zpf>=0.2.0,<0.3`, so
that break is ours to take deliberately, as a minor bump here.

### 9.2 Smaller findings

- **Decoded files are packet-oriented.** **[verified]** chaining works, but a
  decoded input has `is_stream_oriented=False` (decoded records carry no
  `seq_start`), so stage 2+ must iterate `datagrams()`, not `segments()`. Now
  documented upstream in the decoding tutorial and on `DecodeStage.record`
  ([#56](https://github.com/adamkjonsson/python-zipline/issues/56)); the fix
  was documentation, with no new API. **The design consequence is unchanged and
  still ours:** dispatch on `stream.is_stream_oriented`, never on the spec's
  declared `InputShape`.
- **`check_coverage(decoded, raw)` takes paths, not readers.** Passing an open
  `FileReader` leaked `AttributeError: 'FileReader' object has no attribute
  'seekable'`; it now raises a `TypeError` naming the mistake, and pointing out
  that `decode_stage` *does* accept a reader
  ([#57](https://github.com/adamkjonsson/python-zipline/issues/57)). Error
  quality only — we pass paths regardless.

## 10. The pressure test

[`pressure_test.py`](pressure_test.py) builds a transport file (a 29-byte DNS query split
across two records), runs a message-granularity stage, chains a second stage
over its output, and runs a field-granularity stage with overlapping spans,
`prim:` normalization, and a field path per record — checking conformance and
coverage at each step. It is the source of every **[verified]** claim here and
should become the seed of the test suite.

Its five questions and their answers: Q1 a decoded file works as decode-stage
input; Q2 overlapping spans are accepted; Q3 a created payload may differ from
its cited bytes; Q4 a message spanning segments takes the last segment's `ts`;
Q5 a per-field record can carry its name — via `comment=`, with §4.1's caveat.

## 11. Open questions (ours, not `zpf`'s)

1. **Which stream shape does a spec get to assume?** `InputShape` declares it,
   but a `DATAGRAM` spec run against a TCP stream is meaningful
   (length-prefixed DNS over TCP is a real case). Perhaps the spec should
   describe a framing adapter rather than just refusing. Note that stage 2+
   *always* sees datagram shape, so this is not an edge case.
2. ~~**`Computed` in v1?**~~ **Closed: kept.** The objection was that it is the
   thin end of the wedge toward specs-as-code. §2.1 draws the line at the
   cursor instead, and `Computed` consumes nothing and cannot move it, so it
   is on the safe side by construction. It adds no capability the expression
   language did not already have — it only lets a derived value be *named*,
   which is what keeps a wire encoding (lengths in 32-bit words, say) from
   leaking into every expression that needs bytes.
3. **`.ksy` importer** — deferred, cheap to add later given the layering, but
   its parsers throw where ours must degrade, so semantics won't map cleanly.
4. **When do we take the `zpf` 0.3 break?** #58 would replace `comment=` with a
   real per-record name and #59 reshapes `record()`, both on 0.3, and every
   `zpf` minor is a break with no upgrade path. Following early means churn on
   an API we have barely built; following late means shipping files whose field
   names no consumer may rely on. My inclination is to ship 0.1 on `comment=`,
   keep §4.1's single emit site, and treat 0.3 as the trigger for our own 0.2.
5. **How far does the spec go before it becomes a program?** §2.1 says value
   computation cannot break coverage, which removes the *safety* argument for
   keeping expressions minimal but settles nothing about taste. Three distinct
   things get called "specs-as-code", and they are worth keeping apart:

   - **Richer expressions** — a fixed, total set of builtins (`min`, `max`,
     `len`, checksums). Cheap: the parser already works from a whitelist.
   - **Hooks** — declarative structure, with named points where a *caller*
     registers Python callables for validation, transformation, or a custom
     size. The spec file stays data; the decoder is what gets augmented. This
     is roughly Spicy's split, and it keeps `check` meaningful over the
     declarative core.
   - **Specs are Python** — a builder DSL, as in Construct. It costs most of
     what `check` does today (forward references, expression types,
     non-terminating recursion, all caught before any data exists), and it
     locks protocol descriptions to this runtime. Zipline is a *standard* with
     other implementations in mind, and a YAML spec is an artifact another
     language can consume; that argues against this one specifically, as does
     question 3, which it would kill.

   Note that §6 already has an escape hatch: `decode_stream` lets a caller mix
   spec-driven decoding with hand-written logic in one stage. So code is
   already permitted, and the live question is only whether the seam belongs at
   the stage (where it is) or at the field (where hooks would put it).

   My read: hooks are the right extension path and should wait for a concrete
   case that needs one. Nothing built so far forecloses them — the declarative
   core is the substrate they attach to, so they are additive. Going straight
   to a builder DSL is the one move that throws work away.

## 12. Prior art

- **Kaitai Struct** — spec vocabulary, expression scoping, `switch-on`.
- **Spicy** (Zeek) — confirm/reject; its gaps and sinks are `zpf`'s job here.
- **Wireshark** — field naming and the value-string idea.
- **Construct** — Python API ergonomics, deferred field references.
