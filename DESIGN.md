# kober — design

**Status:** implemented and exercised against real captures, not released.
The spec model, expression language, checker, decode engine, emitter, stage
driver, all five CLI verbs, the **compiler** (§14), and the `Pointer` construct
(§3.2) exist, in both implementations. What is *not* built is marked as such:
everything in §11 that is still a question.

**Sections marked [verified] were executed, not reasoned about** — against
`zpf` by [`pressure_test.py`](pressure_test.py), and since revision 6 against
real captures too.

Revision 8. Revision 1 was written blind and got the layer wrong — it invented
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

Revision 6 records what **real captures** found, which is a different thing
from what the pressure test found: the pressure test asked whether `zpf` could
hold what this design wanted to write, and real traffic asks whether the design
can describe what is actually on a wire. Two boundaries and two upstream bugs,
all in §13, and one of the boundaries is being closed — the `Pointer`
construct of §3.2.

The pattern is worth naming, because it decided how much of this document to
trust. Every hand-built fixture in the test suite was written by whoever wrote
the code it tests, and each of the four findings was invisible to all of them:
compression pointers, text-derived framing, a repeat named twice, and a seam
rule that was too narrow. None needed a clever test. They needed input nobody
had simplified first.

Revision 7 adds the compiler (§14) — a second way to run a spec, alongside the
interpreter rather than instead of it — and **restates §2.1**, which had claimed
an impossibility that generated code ends. The cursor rule is now a property of
one program rather than of the language, and what makes that defensible is that
the two implementations are compared on every input the suite can produce. Which
also produced the revision's other content: five bugs, four of them in the
interpreter or in code both share — since joined by a sixth, in revision 9.

Revision 8 closes the two things §13 left open, or tries to. `Pointer` (§3.2)
is built, in both implementations, and §13.1 is closed: a whole DNS message
decodes with nothing left over. The expression language gained two functions
(§3.3), and §13.2 is **half** closed — which is the revision's real content,
because the diagnosis that section carried was wrong. Text arithmetic was not
what stood between HTTP and its body framing; being unable to say anything at
all about a *repeated* field was, and that is now question 6 of §11.

Two rules changed character rather than lapsing, and both are argued where they
are stated: §2 gives up "leaves tile the input", since a pointed-at region is
cited twice, and §2.1 admits a second cursor. The pattern from revision 7 held
again — the guarantee stays, the impossibility does not, and what replaces it
is a bound the runtime applies rather than a promise the spec makes.

Revision 9 closes the last of §13 and answers §11 question 6. `Select` (§3.2)
lets a spec ask a question about a **repeated** field, and `within` lets a
delimited read stop at one boundary without running past another — between them
`examples/http.yaml` chooses its framing instead of assuming it, and the
capture that had never been run decodes 2000 messages with no undecoded region
where it used to leave 405 421 of its 414 460 bytes `undecodable`.

The revision's real content is the same shape as revision 8's, one level in.
Aggregation went into the **model** rather than into the expression language,
which is the third real gap closed by making the declarative language say more
— and §11 question 5's line moves accordingly, with hooks weaker still.

Two corrections, both kept visible because a tidy document would be worth less:

- **§13.2's diagnosis was wrong a second time**, in the other direction. The
  fix looked complete because every measurement agreed with it, and every
  measurement was taken on the arm that worked. The corpus holds exactly one
  chunked message against 1151 counted ones, and a `trim` missing from §3.3's
  table made the spec read that one as unframed for the whole phase.
- **A byte count is not a criterion**, which this is the proof of: the wrong
  decode accounted for every byte, because a message that stops early leaves
  its tail to the driver and the driver's records cite it. Coverage whole,
  conformance clean, decode nonsense. What answers it is asserting the shape.

And §2.1 gains the general form of that lesson. A select that *consumed* input
passes every coverage-shaped invariant the suite has — the byte it took would
simply be covered by whatever followed — so the rule it is supposed to obey is
asserted directly and each assertion is checked against an implementation that
breaks it.

Claims below marked **[verified]** were executed, not reasoned about: against
`zpf` 0.16 by the script in §10, and against real captures as recorded in §13.

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

**What the guarantee is not: leaves do not tile the input.** Until `Pointer`
(§3.2) existed, every leaf covered a distinct range and the leaves together
covered the message exactly once, so "tiling" and "covered" were the same
statement and the emitter was built on the stronger one. A pointer breaks it —
a region decoded in place and then reached again by reference is cited twice —
and that is legal: `zpf` requires every offset to be covered **at least** once,
and says in as many words that two records MAY cite the same input region.

The retirement is worth stating rather than performing, because tiling is the
property a reader would assume and it is the one a test asserted. What survives
is exactly the guarantee: every byte cited or named, and **never both**. That
second half is untouched by pointers, since a pointed-at region is cited, and
cited is precisely what "not undecoded" means. Overlap is duplication, not
contradiction; the contradiction the format forbids is a byte that is both
spoken for and disclaimed.

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

#### What compiling changed about this — revision 7

The rule above was true *by impossibility*: there was no author-supplied code,
so nothing author-supplied could move the cursor. There is now. A compiled
decoder (§14) keeps its read position in a local variable and reads the buffer
by index, because that is worth about five times the arithmetic a cursor costs
— and it is code generated from a spec, which is as author-supplied as anything
here gets.

So the invariant changes character rather than lapsing, and the change has to be
argued rather than glossed:

- **Interpreted, it remains an impossibility.** `kober.decoder` reaches the
  bytes only through `kober.cursor.Cursor`, and a spec has no way to reach past
  it. Nothing about that path is weakened by the existence of another.
- **Compiled, it becomes a property of one program.** The generator emits the
  position arithmetic, and a spec cannot influence *how* — only how many fields
  of what widths. Every read it emits is preceded by the bounds check for that
  read, every advance is by an amount that read consumed, and every byte the
  position passes is cited by a record or named by a region. The spec decides
  what to read; the generator still decides where.

That is a weaker guarantee than an impossibility, and pretending otherwise
would be the quiet falsehood this section exists to correct. What makes it
defensible is not the argument but the check: **the two implementations are
compared on every input the test suite can generate**, and they must produce the
same values, the same byte ranges, the same records and the same undecoded
regions. A generator that emitted a position error would have to make the
interpreter make the same one, and the interpreter still cannot.

The evidence that this is not wishful is which way the disagreements have gone.
Four of the six bugs the comparison has found were in the **interpreter** or in
code both share — two places a partial decode was discarded, a `switch` case
that wrote no record, a computed value that raised out of the emitter — and two
were in the compiler. The cursor rule survives as a claim about a *pair* of
implementations that agree, which is a different and more testable thing than a
claim about one.

#### What a second cursor changed about it — revision 8

`Pointer` (§3.2) reads somewhere other than where the position stands. That is
the first construct in the language that reads at all out of order, and the
rule has to say why it is still the same rule.

**It is, and the reason is that the spec names an offset rather than a
position.** `Pointer.at` is an expression over fields already decoded; the
runtime resolves it, opens a *second* cursor over the bytes, and reads there.
The enclosing position never moves — that is asserted in both implementations,
and a repeat of pointers terminates on its own progress check precisely because
a pointer consumes nothing. A hook would have solved the same problem by
handing an author the position, which is the one thing this section reserves,
and that is why §3.2 chose a construct instead.

Three things make the second cursor safe rather than merely narrow, and each is
a bound the runtime applies, not a promise the spec makes:

1. **It can only look backwards, inside its own message.** The window is
   `[message origin, position)`. A target before the origin would reach into a
   neighbouring message sharing the run; a target at or past the position would
   make a decode depend on bytes it has not claimed — which is not theory: the
   same message given three different neighbours decoded three different ways
   before the ceiling replaced a run-wide bound.
2. **A chain's offsets strictly decrease**, because each hop lowers the ceiling
   to its own target. A cycle cannot be constructed, so nothing has to detect
   one. The hop bound that remains guards recursion depth, not looping.
3. **Failure is `undecodable`, never a hole.** A target that does not decode is
   a wrong claim about input that arrived, not input that never did. A short
   read *inside* a target is therefore converted rather than propagated, since
   `truncated` is hole-class (§5) and would declare a break that the stream
   never had.

**What the guarantee costs here is stated in §2: leaves no longer tile.** A
region decoded in place and reached again by reference is cited twice. Nothing
about *coverage* weakens — every byte is still cited or named, and never both —
and the compiled implementation agrees with the interpreter on all of it,
including which bytes a pointer cites and where a failed one stopped.

#### Where `Select` sits, and why it is the easy case — revision 9

`Select` (§3.2) is the second construct to reach values it did not read where it
stands, and unlike `Pointer` it needs no argument at all: it reads **nothing**.
The repetition is decoded before it runs, so there is no position to move and
no byte to claim. It is value computation, which the table above puts on the
unconstrained side, and it is on that side for the same reason `Computed` is.

**Totality** is the one thing worth stating rather than assuming, because a
construct with a loop in it invites the question. Every element is visited at
most once and a decoded repetition is finite, so a select terminates on any
input. It cannot be made to spin, and `default` being required means it cannot
be made to have no answer either.

Two consequences follow, and both are enforced rather than hoped for:

1. **A repetition of selects cannot terminate**, exactly as a repetition of
   pointers cannot, and for the same reason: neither advances the position. The
   runtime's progress check is what says so, in both implementations.
2. **The checker's exemption reaches two expressions and no further.** A
   repeated field may be named inside a select's `where` and `value`, where it
   means one element, and nowhere else — not in its `default`, which matched
   nothing and so has no element to mean. The language still has no list type
   and gains none: nothing anywhere can hold a list, pass one, or return one.

**The claim that a select moves nothing is asserted directly, and it has to
be.** No coverage-shaped invariant can catch a select that consumed a byte —
the byte it took would simply be covered by whatever followed, leaving coverage
whole and conformance clean. A deliberately consuming implementation was run
against the whole invariant set and passed every one of them. So both
implementations compare the position either side of a select and require it
unchanged, and each check is verified against the consuming version. This is
the general lesson of §2.1 arriving again: what makes a rule defensible is the
check, and a check has to be aimed at the rule rather than near it.

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
FieldType = (
    IntType | BytesType | StringType | UnitRef | Switch | Computed | Pointer | Select
)


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

#### `Pointer` — built

```python
@dataclass(frozen=True)
class Pointer:
    at: Expr                            # where to read, not how far to move
    type: FieldType                     # what is there
```

A back-reference: *read this type at that offset, and carry on where you
were.* Added because real DNS demanded it — an answer record's owner name is
usually two bytes meaning "the name at offset 12" (RFC 1035 §4.1.4), and
without this the answer section of nearly every real response is undecodable
(§13.1).

**It does not break §2.1's cursor rule, and that is why it was chosen over a
hook.** The spec *names* an offset; the runtime does the seeking, with a
second cursor, so the reading position never moves and coverage stays
provable. A hook would solve the same problem by handing an author the
position, which is the one thing §2.1 reserves.

Three things it needed that nothing else in the model does, and how each was
answered. **[verified]** against all eight messages of `dns_example.pcapng`,
and against the pathologies no capture holds.

- **An offset space.** DNS pointers are message-relative; the cursor holds
  run-relative positions. The expression means the *message's* space and the
  runtime translates — and that space exists nowhere else, since a run holds
  many messages: it is fixed once per message, where the entry unit starts.
  There is deliberately no way for a spec to mean another one, so there is
  nothing to mean by accident.
- **A bound**, which turned out to be the *second* line of defence. A target
  must lie at or after the message origin and strictly before the position,
  and each hop lowers that ceiling to its own target — so a chain's offsets
  strictly decrease and a cycle cannot be constructed at all. The hop bound
  that remains is a guard against recursion depth, since a large message
  admits a legal chain long enough to exhaust a stack.
- **A note on coverage**, now §2's: leaves no longer tile the input. A region
  reached through a pointer is cited a second time, which the format permits
  in as many words. What is untouched is the guarantee itself — cited or
  named, never both.

Out-of-range, cyclic, forward and garbage targets all produce `undecodable`
regions and none of them raise. A short read *inside* a target is converted to
`undecodable` rather than propagated as `truncated`, because `truncated` is
hole-class (§5) and would claim the stream had a gap it did not have.

#### `Select` — asking a question about a repetition, revision 9

```python
@dataclass(frozen=True)
class Select:
    source: str      # a repeated field, declared earlier in this unit
    where: Expr      # a predicate over one element
    value: Expr      # the projection of the first element it holds for
    default: Expr    # what to say when nothing matched — required
```

The construct §11 question 6 asked for, and the one that lets a message frame
its own body. Before it, `headers` was a repetition and the checker refused
every reference to one, so nothing could ask whether *any* header said
`chunked` — and `examples/http.yaml` had to assume a framing and call every
other body `truncated` (§13.2).

**Aggregation went into the model rather than into the grammar**, which is the
choice §11.5 keeps making and the reason to state it again. The obvious answer
was an expression form — `any(headers, …)`, `first(headers, …)` — and it costs
more than it looks:

- **A select needs no new expression type.** Its result is a scalar whose type
  is its projection's, so `check` types it with machinery that already existed
  and a later field references it like any other value. `first(headers, …)`
  returning an *element* has nowhere to go: `ExprType` has four members and
  none of them is "an instance of a unit".
- **The binding stays inside one construct.** `where` and `value` see the
  element and `default` does not, which `check` knows structurally. An
  expression form would put a binding into the general grammar — a lambda in
  everything but name, in a language whose case for being small is that it is
  cheap to check and portable to a non-Python reader.
- **Totality is structural.** `default` is a required key, so "nothing matched"
  has an answer the author wrote. There is no partial function to argue about
  and no case a backend must invent a value for.

**A keyed repeat was considered and refused** — `repeat: {key: "lower(name)"}`,
then `headers["content-length"]`. It reads beautifully for headers and badly
for everything else, it introduces a map type *and* an indexing syntax, and it
has no answer for duplicate keys, which HTTP has (`Set-Cookie`).

The element binds under **the repetition's own name**, which is not merely
consistent with `until` but is `until`'s mechanism: the checker already had
`element_of`, and the decode loop already wrote the element under that name
before evaluating a repeat clause. Neither half needed a concept it lacked.

It cites **the element it selected**, not the whole repetition — this value came
from *that* header, and citing every element would be the weaker claim. A
default matched nothing, so it cites nothing: zero width, on the path
`Computed` already exercised.

An expression in `where` or `value` that cannot be evaluated makes the field
`undecodable`, on the same path an unevaluable size takes. It is deliberately
**not** treated as "no match", which would report the author's default as
though it had been read off the wire.

`Terminated(delimiter, consume, required, within)` and `Remaining()` both need
a truncation answer: in `STREAM` shape, a missing terminator at the end of the
available data means *truncated*, which may simply mean the message continues
in a segment we don't have. That is a normal outcome, not an error.

**`within` bounds the search**, and it is what lets one line split into two
fields. Reading a header's name as "up to the next colon" without a bound runs
into the *next* header, or past the end of the headers entirely, on any line
that has no colon in it. The rule is **whichever comes first**: a delimiter
beginning after the bound reads as though it were absent, and `required` still
decides what that means. The bound is a limit on the search and never a second
terminator — letting the value run to it would be reading under a delimiter
that was never found, which is the class of quiet guess §2 exists to refuse.

The blank line ending a header block falls out of that with no special case: it
has no colon before its CRLF, so an optional bounded terminator takes nothing
and both halves come back empty.

### 3.3 Expressions

Small, total, side-effect free: arithmetic, comparison, boolean ops, field
references, literals, and **calls to a closed table of three functions**. No
loops, and nothing an author can add to. Authored as strings
(`size: "header.length * 4"`), parsed to an AST at load time so `check` can
type them and scope them against the spec before any data exists.

Scoping follows Kaitai: `this`, `parent`, `root`, plus unit param names. A
reference to a not-yet-decoded field is a load-time error.

Read the smallness as **a choice about taste and cost, not a safety
requirement.** Per §2.1, an expression cannot move the cursor whatever it
contains, so no amount of arithmetic here threatens the coverage guarantee.
The language is small because a small one is cheap to check, cheap to explain,
and portable to a non-Python reader — not because a bigger one would be
dangerous. Growing it is §11 question 5, and the parser is built from a
whitelist precisely so that growing it is a list change.

**Real HTTP is the first thing that needed it grown** (§13.2), and it is what
these functions are for. HTTP frames its body from a header **value**:
`Content-Length` is a decimal string, a chunk size is a hexadecimal one, and
whether chunked framing applies depends on matching a header value whose case
varies and which carries whatever whitespace followed the colon. Those needs
are the table:

| Call | Result |
| --- | --- |
| `to_int(s)`, `to_int(s, base)` | int |
| `lower(s)` | str |
| `trim(s)` | str |

`to_int` is deliberately stricter than a typical library conversion: leading
and trailing whitespace is allowed, because an HTTP field value carries
optional whitespace by rule, but a digit separator or a radix prefix is not.
Reading `1_0` as ten would turn a malformed wire length into a plausible one.
Text that is not a number makes the field `undecodable` on the path a size
expression that cannot be evaluated already takes — **partial at the value
level, total at the decode level**.

**`trim` is the third row, and it was added late for a reason worth keeping.**
Revision 8 argued that `to_int`'s whitespace allowance was what "saves the
language a fourth function". That was true only of *conversion*. The moment a
field value is **compared** — `== 'chunked'` — nothing strips the space the
sender was entitled to put there, and the comparison quietly answers false.
This project shipped exactly that bug: `examples/http.yaml` read every real
chunked response as unframed while accounting for every byte, and it survived
five stages of measurement because the corpus holds one chunked message against
1151 counted ones. The table is closed, not finished, and the thing that reopens
it is a use the previous entry did not have in view.

**What admitting calls did not open.** The whitelist never bought "no
functions"; it bought no author-supplied code and no unbounded work, and a
closed table of total functions costs neither. A *transform* — decompression,
decryption — is not a candidate for the table: a function here maps a value to
a value, where a transform maps bytes to bytes and feeds a sub-decode with its
own offset space. Routing one through this language would also cost `check`
its static answer, since a spec's validity would come to depend on what a
caller had registered. That extension point is question 5's *hooks* branch, and
the shape it wants is the spec **naming** a transform while a registry supplies
it — the spec file staying data, which is also what keeps a non-Python backend
possible.

This is the "richer expressions" branch of question 5, taken.

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

> when a **hole-class** undecoded region lies between two emitted records,
> pass a `Seam`; otherwise omit it.

**"Hole-class", not "`Gap`" — an earlier draft of this rule said `Gap` and was
too narrow.** `zpf` sorts undecoded reasons into two recoverability classes
(`zpf.blocks.UNDECODED_REASONS`): `gap` and `truncated` are **`hole`**, meaning
the bytes never existed, while `undecodable` and `skipped` are **`bytes`**,
meaning they existed and simply were not decoded. Content either side of a
`bytes`-class region still runs on, so it owes nothing. Content either side of a
hole does not, whichever hole it was — and a truncated message is a hole just as
a lost segment is. Reading the class from `zpf`'s own table rather than
restating it here is what keeps the two from drifting.

Found by fuzzing, not by reading: gap-only seams passed every hand-built test
and every clean capture, and failed on the first adversarial corpus.

Worth stating explicitly because it is easy to forget and impossible for the
conformance checker to catch — only the producer knows.

**The width is left absent, correcting an earlier draft of this section**,
which wrote `Seam(width=..., ...)`. `zpf` defines `Seam.width` as the break's
extent in *this stream's* offset space — the **output's** — and says absent
means unknowable. We know how many input bytes the hole swallowed; we do not
know how many decoded units they would have become. Reporting the input count
in a field defined as an output measurement would be misleading rather than
merely imprecise, so it is omitted, which still says the two do not join.

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
with zpf.open("decoded.zpf", content=registry) as f:
    tree = f.content(record)        # a Node, for a dec: message record
```

Two corrections to that last block, found by writing it: the keyword is
`content=`, not `registry=`, and a `dec:` label resolves through
`FileReader.content(record)` rather than `Record.content()` — its token is
namespaced by the producing decoder's *name*, which only the file knows. Field
records need none of this: they are `prim:`, which `zpf` decodes natively, and
that was the argument for normalizing into it (§4.1).

`Node` is our own in-memory tree (name, value, `(off_start, off_end)`,
children, status). It is deliberately *not* written to the file — it is what
`decode_bytes` returns and what `Emit.FIELD` walks to produce records. Keeping
it out of the file is what avoids inventing a parallel representation
alongside `zpf`'s.

The compiler's half of the same surface, added in revision 7 (§14):

```python
from kober import Plan, render_spec, run_compiled

source = render_spec(spec, emit=Emit.FIELD)     # a module, as text
Path("dns.py").write_text(source)

import dns                                       # no kober loader, checker or
message = dns.decode(payload)                    # spec model at decode time
message.questions[0].qname.labels[0].text        # -> 'example'
span(message, "qdcount")                         # -> (4, 6)

run_compiled(dns, "raw.zpf", "decoded.zpf", produced_by="kober 0.1", produced_at=0)
```

A generated module imports :mod:`kober.runtime` and nothing else from here, so
a decoder built from a spec ships without the machinery that built it.

CLI, one verb per API entry point:

```
kober run     SPEC IN.zpf -o OUT.zpf [--emit field|message]
kober check   SPEC                      # validate + type expressions
kober show    SPEC                      # human-readable field tree
kober try     SPEC --hex 0a0b           # decode one buffer, print tree
kober compile SPEC -o dns.py            # write a decoder for it, as Python
```

## 7. Example spec

A cut-down illustration of the schema. The **shipped** specs are
[`examples/dns.yaml`](examples/dns.yaml) and
[`examples/http.yaml`](examples/http.yaml), which decode real captures and are
exercised by `tests/test_examples.py`; this one stays here because it is short
enough to read in one go.

It loads and checks clean too — `tests/test_loader.py` runs it, so it cannot
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

## 9. Upstream findings from the pressure test — all three resolved

The pressure test produced three findings, all filed against `python-zipline`,
all fixed, and all released in `zpf` 0.2.0. Kept here because the reasoning
still constrains our design, not as an open list.

Real captures later produced two more, both **open**, in §13.4 — this section
is the pressure test's three, not the project's total.

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

   **Two concrete cases have since arrived, and neither wants hooks** (§13).
   Real DNS needed a back-reference, answered by the `Pointer` construct of
   §3.2 — a declarative addition that leaves §2.1 intact, where a hook would
   have handed an author the cursor. Real HTTP needed arithmetic on text,
   which wants three total string builtins (§3.3) — the *richer expressions*
   branch, the cheapest of the three.

   So the case for hooks is weaker than when this question was written, not
   stronger. Both real gaps were closable by making the declarative language
   say more, rather than by letting code in beside it, which is evidence that
   the language was under-built rather than that the approach was wrong.
   Hooks stay deferred, and now have a reason rather than only a lack of one.

   **The branch was taken, and here is where the line sits now — revision 8.**
   *Richer expressions* is no longer a proposal: the language has `to_int` and
   `lower`, in a closed table an author cannot add to (§3.3). Two things that
   move the line are worth separating from two that do not.

   On the near side, and taken: a **fixed table of total functions**. What the
   parser's whitelist bought was never "no functions" — it was no
   author-supplied code and no unbounded work — and a closed table costs
   neither. `check` still types every expression before any data exists, which
   is the property that would have been lost by letting a caller register one:
   a spec would be valid in one process and invalid in another.

   On the near side, and taken since — revision 9: **speaking about a
   repetition** (§11.6), which §13.2 turned out to need. It landed as a *field
   type* rather than as an expression form, which moves the line in a direction
   worth being precise about: the declarative model grew, and the expression
   language did not. `check` still types every expression before any data
   exists; a select is one more construct with a total, declared failure
   behaviour, which is exactly what §2.1's first bullet asks of the vocabulary.

   That this was the third real gap closed by *making the declarative language
   say more* — after `Pointer` and after the builtins — is the strongest
   evidence the question has accumulated. Three concrete needs arrived from
   real captures and none of them wanted a hook. The language was under-built;
   the approach was not wrong.

   The one qualification is honest and small: the closed table did have to grow
   again, and late (`trim`, §3.3). That is not a hook and not a wedge — an
   author still cannot add to it, `check` still answers statically — but it is
   a reminder that "closed" describes who may extend the table, not that the
   table is finished.

   On the far side, and still deferred: **hooks**. Their concrete case has
   arrived after all, and it is not the one this question expected. Byte
   transforms — decompression, decryption — cannot come from a closed table,
   because nobody can ship every proprietary codec. What they want is the shape
   this question already described for hooks: *the spec names a transform, a
   registry supplies it*, kober shipping the well-known set and a caller
   registering its own. The spec file stays data, which is what keeps `check`
   static and a non-Python backend possible.

   The distinction that matters, and the reason a transform is not a third row
   in §3.3's table: **a function maps a value to a value; a transform maps
   bytes to bytes and feeds a sub-decode with its own offset space.** They are
   different layers, and merging them would cost `check` its static answer for
   the sake of a syntax.

   Still on the far side and still refused: **specs are Python**. Nothing here
   moved it.

6. ~~**How does a spec say anything about a repeated field?**~~ **Closed:
   `Select` (§3.2).** It could not, and that is what stopped HTTP choosing its
   own framing (§13.2). `headers` is a repeat, the checker refuses references
   to repeated fields because there is no list type, and so no expression could
   ask whether *any* element said something.

   Three shapes suggested themselves and none was obviously right: a total
   quantifier (`any(headers, lower(this.line) == 'transfer-encoding: chunked')`),
   a count, or naming an element by a key. All three widen the expression
   language in a way the two builtins did not — they need a binding form, and
   `check` has to type it — so this is a phase rather than a table entry.

   It also has to stay total: whatever is added must terminate on any input and
   must not reach the cursor, or §2.1 has a new hole in it.

   **The answer was none of the three, and the reason is the interesting part.**
   All three are shapes for the *expression language*, and the construct went
   into the **model** instead: a field type naming a repetition, a predicate, a
   projection and a required default. That is what avoids the binding form the
   question worried about — the binding lives inside one construct, where
   `check` knows structurally where it applies — and it is why no new
   `ExprType` member was needed. A select yields a scalar; the language it is
   written in did not grow a list type and gains none.

   `any` falls out of it (`value: "true"`, `default: "false"`) and got no
   shorthand, because the finished spec never asks for one: HTTP wants to know
   what a header *says*, not whether it is there.

   Both totality conditions hold and are enforced rather than promised — see
   §2.1's revision 9, which also says why the second one needed its own
   assertion instead of the invariant set that could not see it.

## 12. Prior art

- **Kaitai Struct** — spec vocabulary, expression scoping, `switch-on`.
- **Spicy** (Zeek) — confirm/reject; its gaps and sinks are `zpf`'s job here.
- **Wireshark** — field naming and the value-string idea.
- **Construct** — Python API ergonomics, deferred field references.

## 13. What real captures found

Captures converted with `zpfwire`, from its own `tests/captures/`. The plan is
[`plans/REAL-CAPTURE-PHASE-PLAN.md`](plans/REAL-CAPTURE-PHASE-PLAN.md); this is
the part that constrains the design.

Both boundaries below are about **what the language can say**, and neither is
about coverage. That distinction is the useful one: the guarantee §2 rests on
survived contact with real traffic unchanged, while the vocabulary did not.

**Both are closed as of revision 9**, by four constructs between them —
`Pointer`, a table of three functions, `Select`, and a bounded terminator — and
every one of those is the declarative language saying more rather than code
being let in beside it. What did not survive unchanged is a habit of
measurement, and §13.2 records why.

### 13.1 DNS name compression — closed

`dns_example.pcapng`, first response, last bytes of the answer record:

```
0030  00 01 c0 0c 00 01 00 01 00 00 00 9f 00 04 22 95
            ^^^^^  the name at offset 0x0c
```

Two bytes meaning *the name already at offset 12*. A name is a union of labels
or a pointer, which `Switch` expresses; the pointed-at bytes may be cited
twice, which is legal. What could not be said was **read there and return** —
answered by `Pointer` (§3.2).

`examples/dns.yaml` now decodes a **whole message** — the answer, authority and
additional sections included, following a pointer into a name decoded earlier.
**[verified]** over all eight messages of the capture, with *no undecoded
regions at all*, conformance and coverage clean at both granularities, and the
compiled decoder resolving the same pointer through its typed API.

Record data stays opaque bytes, which is a choice rather than a boundary: what
is inside RDATA depends on the record type, and a switch over the type registry
would be most of that file for none of the point.

### 13.2 HTTP body framing — closed, and the diagnosis was wrong twice

`http_example.pcapng` carries `Transfer-Encoding: chunked` *and* a gzip body,
so both of HTTP's framing mechanisms appear in one exchange.

**What this section used to say was that both need arithmetic on a header
value** — a decimal string, a hexadecimal string, and a case-insensitive match
— and that the language had none. The language has that arithmetic now (§3.3),
and the boundary did not close. The diagnosis was incomplete in two ways, and
the second is larger than anything it named.

- **A header value cannot be extracted.** `to_int` reads a whole string field,
  and a header is one line: `"Content-Length: 1234"` is not a number. Reaching
  the value needs a substring, and a `":"`-terminated read cannot be bounded to
  the line it is in.
- **Nothing can ask a question about the *set* of headers.** `headers` is a
  repeated field and the checker refuses references to those, because the
  language has no list type — so a body's framing cannot depend on whether
  *any* header said `chunked`. Even with a substring builtin, choosing between
  the two framings would still be unsayable.

Both of those are now closed, by `Select` and by `within` (§3.2), and
`examples/http.yaml` chooses its framing rather than assuming it. The paragraph
above stays because a diagnosis that was wrong for four revisions is worth more
than a tidy section — and it was wrong a second time, in the other direction,
which is the part below.

**What closing it is worth, measured.** The capture this section was written
against was never the hard one. Two that had never been run are:

| | Before | After |
| --- | --- | --- |
| `http_stream_1.pcap` — 2000 messages, 40 runs | 309 records, **405 421 of 414 460 bytes `undecodable`** | 30 761 records, **no undecoded region at all** |
| `http.pcap` — the 18 364-byte response | 294 bytes of headers, then **18 070 bytes `truncated`** | the whole body, read by its declared length |

**[verified]** at both granularities, interpreted and compiled agreeing in every
record, span and reason, and — the criterion that matters — every one of the
2000 messages framed at the same boundary an independent RFC 7230 reader gives
it, with 853 / 1147 framing counts matching exactly.

The old failure is worth naming precisely, because it is the one this project
cares most about: a body that was not chunk-formatted had no size line, so the
read for one came back `truncated` — hole-class (§5), declaring a gap in a
stream that had none. Two fifths of real messages have no framing header at
all, so that was not an edge case.

#### The second wrong diagnosis, and what it says about measuring

The corrected diagnosis above named two things, and it named them right. What
it got wrong was believing the fix was complete when the numbers agreed.

`trim` (§3.3) was missing, so `lower(value) == 'chunked'` was false on every
real chunked message — the value carries the whitespace RFC 7230 permits, and
`to_int` strips that internally only for a *conversion*. The spec read chunked
responses as unframed for five stages of this phase while every measurement
agreed with it.

Three things kept it hidden, and each is a lesson about evidence rather than
about HTTP:

- **The corpus cannot exercise the arm.** Across all sixteen captures and
  everything the traffic generator produces there is exactly **one** chunked
  message, against 1151 with a `Content-Length`. The arm with 1151 examples ran
  constantly; the arm with one was checked by a count.
- **A byte count is not a criterion.** The chunked response decoded 834 of its
  2756 bytes; the driver then read the body as further HTTP messages, and those
  cited every remaining byte. Zero undecoded regions, conformance clean,
  coverage whole, decode nonsense.
- **The prediction existed and was filed under the wrong option.** The phase's
  own plan wrote *"the moment a header value is compared rather than converted,
  the fourth function is back"* — as an argument against a design that was not
  chosen. It was true of the one that was.

What answers all three is asserting the **shape**: one message consuming its
whole extent, its body in the parts it should have. That is what the tests do
now, and it is the general form of §2's complaint about silence.

### 13.3 Gaps at scale — the design held

`packet_loss.pcap`: 7 segments, **6 real gaps**, 71 KB, decoded line by line
into 2386 records. Six `gap` regions, six `stream-gap` seams with widths
absent, seven `truncated` regions where a hole cut a line in half, no message
spanning a hole, conformance clean. §5's rule and §2's vocabulary both work at
a scale no fixture reached. **[verified]**

### 13.4 Two upstream bugs

- **[#62](https://github.com/adamkjonsson/python-zipline/issues/62)** — which
  timestamp a message inside a multi-message run should carry. `zpf`'s own
  documentation states the rule two ways ("the last input record *its payload*
  came from" and "the run's `Segment.ts`") and they diverge exactly when a run
  holds more than one message, which is kober's normal case.
- **[#63](https://github.com/adamkjonsson/python-zipline/issues/63)** —
  `check_coverage` measures a real TCP stream as 2³²−1 bytes. A zero-length SYN
  record sits one below the `isn + 1` origin, so its offset underflows, and
  `stream_extent` takes the maximum. `chunks()` skips empty records and
  `record_ranges` does not. It makes `check_coverage` report false violations
  on any capture including its handshake — the tool a decode stage proves
  itself with.

### 13.5 Two of our own, and why no test could have caught them

Both were fixed in place; both were invisible to every hand-built fixture,
which is the argument for this phase existing.

- **A repetition was named twice in field paths** — `dns.questions.questions[0]`
  — because a repeat's container and its elements share a spec field. No
  fixture had nested repeats. Real DNS has questions holding labels.
- **The seam rule was too narrow.** It fired on `Gap` only, where `zpf` requires
  a break after any *hole*-class region, `truncated` included. This produced
  **nonconformant files** whenever a partial message sat between two whole
  ones. It passed every hand-built test and every clean capture, and failed on
  the first adversarial corpus — 340 fuzzed DNS records from `packeteer fuzz`.
  §5 is corrected.

That last one also produced the phase's one reassuring result: across those 340
adversarial datagrams the decoder **raised nothing**, which is the promise
`kober.decoder` makes and the first time anything tried to break it.

## 14. The compiler — a second way to run a spec

Revision 7. `kober compile` turns a spec into a Python module with a typed API.
The interpreter stays: it is what `try` should always use, it is where
exploratory work belongs, and it is the reference implementation the generated
code is checked against. Neither replaces the other, and the reason to have both
is stronger than either.

### 14.1 Why, and what the measurements said

The proposal began as "make it faster" and the measurements changed what it was
about. Interpreting `examples/dns.yaml` costs 91 µs a message, of which the
largest single entry is `Node.__init__` — forty nodes per message, built so that
a *generic* walker can rediscover at decode time what a compiler already knows:
a field's path, its `prim:` token, its granularity, whether it is anonymous.

So a generated decoder that still built a `Node` tree would recover about a
quarter of the gap. **The typed API and the speed are the same win**, not two
that arrive together: the typed objects are what replaces the tree, and the tree
is where the time goes. A generic tree is a decoder's internal representation
leaking into its public API, and the cost is that flaw measured in microseconds.

Measured on the same query, at field granularity with every record written:
**6.2 µs against the interpreter's 126.6**, or 20.6×. At message granularity,
3.3 against 90.6. The full analysis is
[`plans/CODEGEN-ANALYSIS.md`](plans/CODEGEN-ANALYSIS.md); what was actually
built and what it cost is [`plans/COMPILER-PHASE-PLAN.md`](plans/COMPILER-PHASE-PLAN.md).

### 14.2 The shape

```
  Spec ──→ Plan ──→ backend ──→ source text ──→ a module that imports
        (kober.ops)  (kober.pygen)               kober.runtime and nothing else
```

The middle layer is **language-neutral**, and the rule that decides what belongs
there is: it describes *what the format means*, a backend decides *how a
language says it*. A field has a byte range and a value of some kind — meaning.
Whether that range is a dunder, a parallel array or an accessor, and whether a
name grows a trailing underscore to dodge a keyword, is a target's business. So
a plan carries the spec's own names, unmapped: Rust reserves different words and
mangles different characters, and a plan holding Python identifiers would hand a
second backend a mapping made for the wrong language.

It is **not** an intermediate representation and should not become one. It is
the ordered description a backend walks, with the spec's indirections resolved
and nothing invented — plus the analyses any backend would want and none should
repeat: which repetitions provably make progress, which counts cannot be
negative, which units can reach themselves, and which outer values each unit
actually needs.

Emitting Rust or C++ later means a second backend, not a second interpreter.
That is the whole reason for the seam, and it cost one module to leave open.

### 14.3 What a generated module is

One `slots` dataclass per unit, with the annotations a consumer completes
against: `int`, `str`, a class per unit, `list[…]` for a repeat, `| None` for a
`condition`. Byte ranges live **beside** the values in one flat `__spans__`
tuple per object — the object's own extent, then a pair per attribute — read
back by `kober.runtime.span`. A wrapper per field would reintroduce exactly the
allocation this exists to remove.

Enums are **mappings, not `IntEnum` subclasses**. A value with no label is
normal on the wire — DNS opcode 3 has none — and a decoder may not raise, so a
labelled field stays an `int` and the labels are a lookup beside it.

Emission is **direct**: the decoder calls a sink as it reads, with the field
path, the content type, the `prim:` token and the payload encoding all baked in
as literals. The sink's two calls are `Emission` and `Unclaimed` written as
method signatures, so `plan()` gained a second producer rather than being
replaced — and the two can be compared record for record, which is the whole
argument for keeping both.

**Granularity is a compile-time choice**, because it is a difference in the
code and not in a flag: at `message` a decoder builds no field paths at all,
and at `field` the path is threaded through every unit function.

### 14.4 Names, and refusing rather than renaming

Spec names are author-chosen and need not be valid Python. A unit becomes a
`CamelCase` class, a field keeps its spec name, a Python keyword gets a trailing
underscore, and **anything else is a `CompileError`** — a decoder whose field
quietly changed name is worse than one that would not compile. Two names landing
on one identifier is the same refusal, and every problem is reported at once.

An anonymous field gets no attribute at all. It is read, cited, and spelled `_`
in a path, but a field with no name is not something a caller can ask for, and
inventing one would be the silent mangling the rule exists to refuse.

The Python backend reserves every identifier beginning with an underscore, and
nothing else — so `size`, `data` and `path` remain usable field names, which
matters because they are ordinary names for a protocol field.

### 14.5 The security posture, which is new

Generating Python from a data file is a boundary this project did not have
before. Names, enum labels and `doc:` strings all flow toward source text, and
"a spec cannot run code" is partly a security property.

The rule is that **nothing author-supplied is ever interpolated into source**.
Identifiers are validated against a whitelist and everything else becomes an
escaped literal or an escaped docstring; `render` then parses its own output
before returning it, so a generator bug is a refusal rather than a broken
module. It is tested as a property: a spec whose enum label is a
docstring-closing `__import__` attempt still imports, still holds the label as
data, and touches nothing.

### 14.6 What it cost, and what it found

One narrowing, and it belongs to the Python backend rather than to the language:
a unit whose fields do not add up to a whole number of bytes is refused, because
the generated code tracks a byte offset and cannot express a unit that starts or
ends part-way through one. Such a spec is nearly always a fault already — the
interpreter carries on mid-byte and then raises out of the decode at the next
`bytes` field.

And six bugs, four of them in the interpreter or in code both implementations
share:

- a nested unit that failed part-way was **discarded whole**, so the emitter
  named bytes `truncated` that had been read and understood;
- a repetition lost **every** element when any of them failed, for the same
  reason one level down;
- a `switch` with both a unit case and an integer case wrote no record for the
  integer;
- a computed value too wide for `prim:` raised `ValueError` out of the emitter;
- and two in the compiler: a signed sub-byte field called a helper that was
  never emitted, and — revision 9 — a `select` whose *extent* was the empty
  range where it stood rather than the element it chose, which the interpreter
  had right. A decoded element carries no offsets, so the backend has to keep
  them as the repetition goes past; the differential is the only thing that
  asks.

None had a failing test. They were found by writing a second implementation and
insisting the two agree, which is what §2.1's restatement now rests on.
