# kober — design draft

**Status:** draft for discussion. Nothing here is implemented.

Revision 3. Revision 1 was written blind and got the layer wrong — it invented
reassembly, gaps, and provenance that `zpf` already provides. Revision 2 fixed
that against the source. Revision 3 adds the results of an executable pressure
test (§10) and treats this project as what it is: **a load test of `zpf`, where
a gap upstream is a finding rather than a constraint to route around.**

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

This is why the declarative-only rule matters. If specs could run code, they
could silently swallow input and break the guarantee. Because they can't,
**we can prove coverage from the spec alone.**

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

### 4.1 The blocker: decoded fields cannot be named

A `Record` block has `payload`, `content_type`, `spans`, and `comment`. The
`comment` field is the only per-record free slot — and **it cannot be
written**. Neither `SessionWriter.record()` nor `DecodeStage.record()` accepts
`comment=`, though `Record.comment` exists in the block model and reads back
fine. `Custom` is a standalone PEN-namespaced *block*, not a record annotation,
so it cannot label a record without fragile positional correlation.

The consequence, straight from the run **[verified]**:

```
ct=prim:u16   value=4660     cites=[(0, 2)] comment=None
ct=prim:u16   value=256      cites=[(2, 4)] comment=None
ct=prim:u16   value=0        cites=[(2, 4)] comment=None
ct=prim:u16   value=0        cites=[(2, 4)] comment=None
ct=prim:u16   value=1        cites=[(4, 6)] comment=None
```

Every value is correct, every span is correct, and the output is useless: two
records read `0` and nothing says one is `qr` and the other `opcode`. **Field
granularity is unusable without a naming mechanism.** See §9 for the upstream
options.

The workaround that needs no upstream change is to put the path in the label —
`content_type="dec:dns.header.id"` — since `dec:` is "a type private to the
record's decoder, meaning whatever that decoder documents". We could generate a
`ContentRegistry` from the spec so readers decode it back. It works, but it
conflates *type* with *name*: `dec:dns.header.id` and `dec:dns.header.qdcount`
are two types that happen to both be `u16`, so nothing left in the file says
they share a type, and `prim:`'s normative typing is gone.

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
        type: {int: {bits: 4}, enum: opcode}
      - {name: null, type: {int: {bits: 2}}}    # reserved
```

The `doc:` entries are the argument for YAML over JSON: annotation is the
difference between a spec someone can maintain and one they can't.

## 8. YAML

Optional extra (`pip install kober[yaml]`), imported lazily. Core
parses the *model*, so `from_dict` and `from_json` work stdlib-only and the
CLI is the only thing that really wants YAML. `safe_load` only. Guard against
implicit typing — `on`/`off`/`yes`/`no` become bools and `1.10` becomes a
float — with strict schema validation immediately after load.

## 9. Upstream asks for `zpf`

Ordered by how much they block this project.

### 9.1 A per-record name for decoded fields — **blocking `Emit.FIELD`**

Three options, cheapest first:

1. **Plumb `comment=` through `SessionWriter.record()` and
   `DecodeStage.record()`.** The block field already exists, encodes, and reads
   back; only the writer API omits it. Smallest possible change, no format
   change, unblocks experimentation immediately. But `comment` is documented as
   a free-text note, and a field name is load-bearing semantics — a reader would
   have to *rely* on free text, which invites exactly the drift the format is
   otherwise careful to avoid.
2. **A dedicated optional `label` (or `field_path`) option on `Record`.** A
   0.17 format change. Says what it means, is checkable, and makes
   field-granularity decoding a first-class citizen. The honest cost: it adds a
   field only decoders use, on the format's hottest block.
3. **Declare message granularity the intended level and drop `Emit.FIELD`.**
   Also a legitimate answer. `.zpf` is a *payload* format — "records are whole
   application messages" — so per-field records may simply be the wrong level,
   and the field tree should live in our API and never in the file.

**This is the strategic question the pressure test surfaced,** and it is more
about what `zpf` is for than about what we need. My read: (1) as an immediate
unblock so we can build and measure, with the (2)-vs-(3) decision deferred
until we have a real decoder emitting real files and can see whether
field-level records are genuinely useful or just noise. I'd rather bring you
evidence than an opinion here.

### 9.2 Smaller findings

- **Decoded files are packet-oriented.** **[verified]** chaining works, but a
  decoded input has `is_stream_oriented=False` (decoded records carry no
  `seq_start`), so stage 2+ must iterate `datagrams()`, not `segments()`. This
  is coherent — each decoded record *is* a self-contained unit — but it is not
  stated in the decoding tutorial, and a decoder that hardcodes `segments()`
  works at stage 1 and raises at stage 2. Worth a documentation sentence at
  minimum.
- **`check_coverage(decoded, raw)` takes paths, not readers**, while most of
  the API accepts either. Passing an open `FileReader` fails with
  `AttributeError: 'FileReader' object has no attribute 'seekable'` — an
  internal leak rather than a clear `TypeError`.

## 10. The pressure test

[`pressure_test.py`](pressure_test.py) builds a transport file (a 29-byte DNS query split
across two records), runs a message-granularity stage, chains a second stage
over its output, and runs a field-granularity stage with overlapping spans and
`prim:` normalization — checking conformance and coverage at each step. It is
the source of every **[verified]** claim here and should become the seed of the
test suite.

## 11. Open questions (ours, not `zpf`'s)

1. **Which stream shape does a spec get to assume?** `InputShape` declares it,
   but a `DATAGRAM` spec run against a TCP stream is meaningful
   (length-prefixed DNS over TCP is a real case). Perhaps the spec should
   describe a framing adapter rather than just refusing. Note that stage 2+
   *always* sees datagram shape, so this is not an edge case.
2. **`Computed` in v1?** Convenient, and the thin end of the wedge toward
   specs-as-code. I'd cut it until something needs it.
3. **`.ksy` importer** — deferred, cheap to add later given the layering, but
   its parsers throw where ours must degrade, so semantics won't map cleanly.

## 12. Prior art

- **Kaitai Struct** — spec vocabulary, expression scoping, `switch-on`.
- **Spicy** (Zeek) — confirm/reject; its gaps and sinks are `zpf`'s job here.
- **Wireshark** — field naming and the value-string idea.
- **Construct** — Python API ergonomics, deferred field references.
