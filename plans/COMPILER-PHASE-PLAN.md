# Phase plan: the compiler

**State: live.** Written after the documentation phase landed, against
`DESIGN.md` revision 6, and on the evidence in
[`CODEGEN-ANALYSIS.md`](CODEGEN-ANALYSIS.md).

`kober` gains a second way to run a spec. The interpreter stays; a **compiler**
is added that turns a spec into a Python module with a typed API.

```
                      ┌─→  Decoder(spec)              interpret, now
   spec.yaml ─→ Spec ─┤
                      └─→  kober compile ─→ dns.py    compile, this phase
```

## Why both, rather than one

Not a migration. The two answer different questions and each makes the other
better.

The interpreter is what `kober try` should always use — no build step, change
the YAML and rerun — and it is the natural home for exploratory work. The
compiler is for a decoder someone deploys: typed, fast, and shippable without
this project installed.

And keeping both buys the strongest test available here. **Differential
testing** — the two must agree on every input — costs one test module and turns
the interpreter into a reference implementation. That property only exists if
both do.

## What the measurements say the target is

From the analysis, on `examples/dns.yaml` against a real query:

| | µs/message | throughput |
| --- | --- | --- |
| Interpreter, builds a `Node` tree | 97.0 | 0.30 MB/s |
| Straight-line, still building `Node`s | 7.4 *(6 nodes)* | 3.9 MB/s |
| Straight-line, typed objects, no tree | **1.7** | **16.8 MB/s** |

**The win is in not building a generic tree, not in compiling the spec.** A
generated decoder that still produced `Node`s would recover about a quarter of
the gap. So the typed API and the speed are one thing, and the phase either
gets both or neither.

## The insight this phase is built on

Most of what a `Node` carries exists so that a *generic* walker can rediscover
at runtime what the compiler already knows.

A field's path, its `prim:` token, its emission granularity, its enum, whether
it is anonymous — all of that is fixed when the spec is compiled. Generated code
does not need to carry `spec_field` and `resolved_type` so an emitter can look
them up; it can **bake them in as constants** and carry only what varies per
message: values and offsets.

That is what makes direct emission cheap rather than expensive, and it is the
reason the hard question below has a good answer.

## Design questions to settle first

All four are **settled by the stage 1 spike**, which is
[`tests/compiled_dns.py`](../tests/compiled_dns.py) and its tests. Each
settlement below is what that module does, and every one of them is checked
against the interpreter record for record.

### Q1 — How do generated decoders emit records? — **settled: direct emission, one pass**

The crux, and the one that decides whether this phase delivers 56× or 4×.

- **(a) Direct emission.** The generated decoder calls a sink —
  `sink.record(payload, content_type, start, end, comment)` — with path,
  content type and granularity baked in as literals. No tree.
- **(b) Carry the bookkeeping.** Generated objects hold offsets and statuses,
  and `plan()` walks them as it walks a tree today.

**Settled: (a)**, because the constants are known at compile time and (b) gives
back most of what the phase is for. `plan()` stays pure and keeps its tests; it
gains a second producer rather than being replaced.

The sink's two calls are deliberately `Emission` and `Unclaimed` as method
signatures. That is what makes the differential test a comparison rather than a
translation, and it is the whole reason the spike could be checked against the
interpreter on its first day.

Three things the spike settled that were not obvious from the sketch:

**Direct emission makes the coverage bookkeeping simpler, not harder.** The
emitter subtracts intervals after the fact because it is handed a finished
tree and has to work out what nothing claimed. A generated decoder emits in
decode order, so the boundary between "cited" and "not decoded" is just where
the cursor stopped — one expression, no interval arithmetic.

**A failure needs no per-field handler.** The interpreter catches
`TruncatedRead` per field because it has a node to mark. Generated code has
nothing to mark, and any failure abandons the message anyway, so one handler at
the entry point is the whole of it.

**Granularity is a compile-time choice, not a runtime one.** At `emit: message`
a decoder builds no field paths at all, and at `emit: field` the path plumbing
is threaded through every unit function. That is a difference in the code, not
in a flag, so `kober compile` chooses it and the module is compiled for it.
`decode_message` in the spike is the entry point the same spec produces under
`emit: message`; nothing else about the module changes.

**One bug found, and it is a design one.** At message granularity a truncated
message must mark its *whole* extent undecoded, not just the tail past where
the decode stopped — because nothing cited the bytes that did decode. At field
granularity those same bytes are cited one by one and the region starts
further along. Both are now asserted.

### Q2 — Where do byte ranges live in the typed API? — **settled: `__spans__`, flat**

A consumer wants `msg.questions[0].qtype` to be an `int`, not a wrapper. But
provenance is this project's whole point, and a caller must be able to ask
*which bytes* a field came from.

- **(a) A sidecar** — `spans(msg)` returns a mapping from path to range.
- **(b) A dunder** on each object: `msg.__spans__["qtype"]`.
- **(c) Every field is a wrapper** carrying value and range.

**Settled: (b)**, with one correction from the spike: a **flat tuple of ints**,
not a mapping. A dict per object per message is the allocation this phase
exists to remove, and the name → position map is known at compile time, so it
is a class attribute and the instance carries `(start, end)` pairs only.
`span(obj, "qtype")` reads it back; `span(obj)` with no name is the object's
own extent, which is what a caller needs when there is no parent to ask.

Two consequences worth recording:

- A repeated field's pair is the **repetition's** extent. Elements of a
  repeated *unit* carry their own, but a repeated **scalar** would have
  nowhere to put per-element ranges — the parallel array stops being parallel.
  The records still carry them at field granularity. Stage 2 decides whether
  that is enough.
- An absent conditional field cites a zero-width range at the position it was
  skipped, and its value is `None`. Absent and empty stay distinguishable.

### Q3 — What does generated code depend on? — **settled: a small `kober.runtime`, but not the cursor**

- **(a) A small `kober.runtime`** — the cursor and the sink protocol.
  Generated modules import it; consumers install `kober` but need no YAML.
- **(b) Fully standalone**, inlining everything.

**Settled: (a).** It is also the shape a future non-Python backend wants —
a runtime library plus generated code is how every such compiler is built. (b)
can be an option later if a genuinely dependency-free artifact is wanted.

What belongs in it is narrower than the sketch assumed. The spike needs the
`Sink` and `Spanned` protocols, `span()`, and the entry-point accounting that
is identical for every spec. It does **not** want `Cursor` on the fast path —
see Q5, which is the finding that matters most in this phase.

Two smaller notes for stage 6. The runtime's read API must not require the spec
model: `Cursor.read_int(endian=Endian.LITTLE)` takes a `kober.spec` enum today,
and generated code importing the spec model to read a little-endian integer
would be exactly the dependency this answer is trying to avoid. And nothing in
the generated module may import `kober.node`: `NodeStatus`'s values are the
`reason=` strings, so the runtime owns that vocabulary or the strings are baked
in as literals.

### Q4 — How is the API named? — **settled**

Spec names are author-chosen and need not be valid Python identifiers, and
units and fields can collide with each other and with keywords. Needs a
documented mapping, and a **hard failure on any collision** rather than silent
mangling — a decoder whose field silently changed name is worse than one that
would not compile.

The rules the spike is written to, for the **Python backend** to implement in
stage 2:

- A unit becomes a class in `CamelCase`; a field becomes an attribute with its
  spec name unchanged. `msg.qdcount` is what the spec called it.
- A Python keyword or soft keyword gets a trailing underscore. Builtins do
  not: `msg.id` is right, and shadowing `id` inside a generated function harms
  nothing.
- **An anonymous field gets no attribute.** It is still read, still cited, and
  still spelled `_` in a path — but a field with no name is not something a
  caller can ask for, and inventing one would be the silent mangling this rule
  exists to refuse.
- **The backend reserves every identifier beginning with an underscore**, for
  locals, fallback helpers, and the span bookkeeping. A field whose mapped name
  would land in that namespace, or collide with another field, its class, or a
  module-level name the backend emits, is a hard failure with both names in the
  message.
- Enums stay **mappings**, not `IntEnum` subclasses. A value with no label is
  normal on the wire — DNS opcode 3 has none — and `Opcode(3)` raising is not
  something a decoder may do. The field stays an `int` and the labels are a
  lookup, which is also what keeps the interpreter and the compiler agreeing on
  values.

Names, labels, and `doc:` strings reach the source text as **docstrings and
literals only**. Nothing author-supplied is ever interpolated into an
identifier without going through the rules above.

### Q5 — How does generated code read bytes? — **settled: directly, at offsets the compiler worked out**

Not one of the questions this plan set out with, and the one the spike changed
its mind about. On the same 29-byte query, all three producing byte-identical
typed objects and spans:

| | µs/message | throughput |
| --- | --- | --- |
| Interpreter, tree then `plan()` | 94.4 | 0.31 MB/s |
| Compiled, reading through `Cursor` | 14.0 | 2.1 MB/s |
| Compiled, reading the buffer directly | 2.1 | **13.7 MB/s** |

The middle row is the spike as committed. **Going through `Cursor` costs 6.6×
and gives back most of the phase.** The profile says why and it is not
surprising: 218 Python calls per message, nearly all of them `tell`, `span`,
`_require` and `read_int`, against about ten for the direct version. Bounds
checks are not the cost — adding the ones exact truncation needs to the direct
version measures 2.12 µs against 2.15 without them.

So acceptance criterion 4 is reachable, but not by reusing the cursor, and
stage 4 has to be designed for that from the start. What makes it delicate is
**not** speed, it is the truncation boundary:

- The interpreter stops at the *first field* that does not fit and cites
  everything before it. One merged bounds check over a fixed 12-byte header
  would report a different boundary for a 5-byte buffer, and the differential
  test would fail — correctly.
- Bit fields are worse. With one byte of a two-byte flags word available, five
  of its eight fields decode. Reading the word as a unit cannot reproduce that.

The shape that resolves both, for stage 4 to confirm: a **fast path with a
guard**, where a statically-sized run of fields is preceded by one bounds check
and read straight-line with no per-field checks, and a failing guard falls back
to the careful per-field path — which is what the cursor already is. The guard
precedes any emission for that run, so the fallback re-decodes without
duplicating a record. Truncation is rare; correctness on it is not optional.

This is also the concrete form of what `DESIGN.md` §2.1 has to be restated as.
Generated code holding a byte offset in a local *is* author-adjacent code
moving the read position, and the argument has to be that the generator only
emits patterns that claim what they read.

#### What the rewrite found, and what it measured

**The stage 1 estimate attributed the win to the wrong thing.** "Direct reads
instead of the cursor" is worth 2×, not 6.6×. Four measurements on the same
query, all producing byte-identical values, ranges and records:

| | µs/message |
| --- | --- |
| Through `Cursor`, as stage 4 emitted it | 13.8 |
| Direct reads, position tracked in bits | 6.9 |
| Direct reads, **byte offsets and baked deltas** | 2.9 |
| The analysis's ceiling, no checks or ranges | 1.7 |

The lever is not how a byte is fetched, it is **knowing where it is**. A cursor
has to be told the position and asked for it back, and code that tracks bits has
to shift and round at every field; a compiler already knows the offset of every
field from the one before it, so a read is an index and a byte range is an
addition. So the answer to Q5 is not "read directly" but *"read at offsets
resolved when the spec was compiled"*, and reading directly is what that allows.

**Exact truncation came free, and needs no fallback.** The plan expected a fast
path guarded by a merged bounds check with a careful slow path behind it. Not
needed: a per-field check against a baked offset measures the same as no check
at all (2.87 against 2.9), so every field keeps its own and the boundary is
exactly the interpreter's. The two-path design would have doubled the generated
code for nothing.

**The cost is one refusal.** The byte model cannot express a unit that starts or
ends part-way through a byte, so the backend refuses one with a message saying
which unit and how far into a byte it got. Such a spec is nearly always a fault
anyway — the interpreter carries on mid-byte and then raises `ValueError` out of
the decode at the next `bytes` field — but it is a real narrowing, and it is the
Python backend's alone rather than the language's.

**Measured after the rewrite**, on the same query:

| | µs/message | throughput | against the interpreter |
| --- | --- | --- | --- |
| Field granularity, records and all | 6.2 | 4.7 MB/s | 20.6× |
| Message granularity | 3.3 | 8.8 MB/s | 27.6× |
| Typed objects, nothing emitted | 3.8 | 7.6 MB/s | — |

Acceptance criterion 4 asked for reach of 16.8 MB/s, which was measured with no
bounds checks, no byte ranges and no field paths. What is left between 3.3 µs
and that 1.7 is exactly those three, and each is something the phase promised
rather than overhead: a decode that cannot run past its input, provenance for
every field, and a path on every record.

## Room for other targets later

Rust or C++ is a stated intention, not a hypothetical. That does not change
what is built now, but it changes one seam — cheaply, if it goes in from the
start.

Split the generator in two:

```
  Spec ──→ plan of operations ──→ backend ──→ source text
           (language-neutral)      (Python)
```

The middle is an ordered list of what to do — read 16 bits big-endian here,
repeat this until that, mark this region truncated — with offsets and constants
resolved. It is *not* a full IR and should not become one; it is the list the
Python backend walks, kept free of Python-specific decisions so a second
backend has somewhere to attach.

**The cost of doing this now is small; the cost of retrofitting it is a
rewrite.** But it stays a seam rather than an abstraction: one backend exists,
and the plan does not pretend otherwise.

**Confirmed**: this means the compiler *emitting* Rust or C++, not
re-implementing the interpreter in them. So the seam is a real requirement
rather than a hedge, and two of the questions above narrow because of it.

**Q4's naming rules belong to the backend, not the neutral plan.** Rust wants
`snake_case` fields and has its own reserved words; C++ has different ones
again. If the plan of operations carried Python identifiers, a second backend
would inherit a mapping made for the wrong language. The neutral layer should
carry the **spec's own names**, and each backend maps them — including the
hard failure on collision, since what collides differs by target.

**Q2's span representation is likewise a backend concern.** `__spans__` is a
Python answer. What the neutral layer owes is *that* a field has a byte range
and what it is; how a target exposes it — a dunder, a parallel array, a
`spans()` accessor — is the backend's call.

The pattern generalises: the neutral layer describes **what the format means**,
and a backend decides **how that language says it**. Anything that reads like a
Python decision is a sign it is in the wrong layer.

## Stages

### Stage 1 — settle Q1–Q4, with a spike — **done**

Not prose. Hand-write the module the compiler should produce for
`examples/dns.yaml`, by hand, exactly as intended — typed classes, direct
emission, spans — and run it against the real capture end to end, checking
conformance and coverage.

That fixes the target before any generator exists, and it is the cheapest way
to find out that an answer to Q1 or Q2 does not work. The hand-written module
becomes the first test fixture: the generator's output should converge on it.

Landed as [`tests/compiled_dns.py`](../tests/compiled_dns.py) and
[`tests/test_compiled_dns.py`](../tests/test_compiled_dns.py). It decodes real
DNS traffic into typed objects, emits records and regions directly, and is
checked two ways: **against the interpreter**, emission for emission and region
for region over four inputs at both granularities, and **against `zpf`**,
through a real decode stage past `ConformanceChecker` and `check_coverage`.

It settled Q1–Q4 above, found one design bug (message-granularity truncation),
and produced the measurement that opened Q5 — the only answer here that came
out differently from the leaning it started with.

The read path in the committed module is the **cursor** one, which Q5 says is
not the target. It is what makes the module comparable to the interpreter today
and it is the fallback the fast path needs anyway; none of the Q1–Q4
settlements depend on it, because the direct-read version was measured
producing byte-identical objects and spans.

### Stage 2 — the typed model — **done**

Spec → dataclasses, one per unit, with `slots`, annotations, optional fields
for `condition`, lists for `repeat`, and the span representation from Q2. Plus
the identifier and collision rules from Q4 — which live in the **Python
backend**, not the neutral layer, per the confirmation above.

Self-contained and testable without decoding anything.

Landed as `kober/ops.py` — the neutral plan, and the seam a second backend
attaches to — and `kober/pygen.py`, the Python backend, with `tests/test_ops.py`
and `tests/test_pygen.py`. The spike's `enums` and `the typed model` blocks are
**now generated text**, compared character for character, which is what makes
"the generator's output converges on the fixture" a test rather than an
intention.

What it settled beyond the sketch:

**Q4 was missing a rule.** A field becomes a *local* in a decode function as
well as an attribute, so the backend has to reserve the names those functions
take as parameters — `cur`, `sink`, `path` — not only the underscore namespace.
Checked now, though it cannot bite until stage 4.

**A name that is not an identifier is refused, not mangled.** `content-length`
does not compile; the message says to rename it. Mapping `-` to `_` is exactly
the silent rename Q4 exists to refuse, and the collision rule could not save it
either — `a-b` and `a_b` would both arrive at `a_b`.

**The neutral layer needed one thing from the checker, not a copy of it.** A
`computed:` field's type is the only type a spec does not state, and inferring
it needs the scoping rules. `check.scope_at` exposes the scope the checker
already builds, so there is one implementation of what a name means rather than
two that drift.

**Q2's repeated-scalar limitation resolves the boring way.** `__spans__` carries
the repetition's extent; per-element ranges of a repeated *scalar* live in the
records and nowhere else. A parallel array cannot hold a variable number of
pairs without stopping being parallel, and the alternative — a wrapper per
element — is the allocation the phase exists to remove.

**Prose and code want different widths.** Generated modules pass `ruff` with
this project's own config, which is the acceptance criterion, but 100-column
docstrings read badly; the backend wraps prose at 79 and code at 100.

One thing stage 3 inherits: `expr.unparse` is fully parenthesized on purpose,
for error messages where being unambiguous beats being pretty. In a docstring it
renders `((ancount + nscount) + arcount) > 0`, and in *generated code* it would
be worse. Stage 3 owes a precedence-aware Python renderer, and the docstrings
should use it once it exists.

### Stage 3 — expressions to source — **done**

The AST already exists and `unparse` is close. New work is scope binding —
`this`/`parent`/`root` and unit parameters resolving to locals or attributes —
and the two semantics that differ from Python: `/` is floor division, and
`and`/`or` must short-circuit exactly as the interpreter does, since a spec
relies on it to guard a division.

Landed as `pygen.render_expr` and `pygen.Binding`, with `ops.walk_path` for the
neutral half of resolving a path. The headline test is **differential at the
expression level**: 27 expressions × 6 value sets, each evaluated by the
interpreter over its own AST and by Python over the rendered source, and they
must agree or fail together. Breaking `/` → `//` fails 13 of them; breaking the
associativity rule fails 6. That is the cheapest strong check available here,
and it exists because rendering can look right while meaning something else.

**`parent` and `root` are parameters, not a frame chain.** The parent's fields
are locals in a function that has not finished running, so there is nothing to
ask for them — but the compiler knows *which* of them an expression names, so it
passes exactly those. That is the insight of this phase applied again: the
interpreter carries a frame chain so a generic lookup can find anything, and a
compiler needs only what is actually referenced. Stage 4 threads them, under the
`_parent_` and `_root_` prefixes this stage reserves.

**Two guards survive compilation and one does not.** The shift bound has to: `1
<< n` with `n` off the wire allocates until the process dies, so a count that
cannot be seen to be in range becomes a call to `expr.shift_left`. Division by
zero survives as `ZeroDivisionError`, which stage 4's entry point turns into an
`undecodable` region — the same outcome by a shorter road. What does not survive
is the interpreter's `_as_int`/`_as_bool`, because the checker proved the types
already.

**The `unparse` wart is fixed rather than worked around**, and it turned out to
be worth more than tidiness: `PRECEDENCE` now lives in `expr.py` as the one
statement of how expressions group, and both renderers read it, so the spec's
spelling and Python's cannot disagree about grouping. Docstrings use `unparse`
rather than the Python rendering on purpose — `//` and `_parent_x` are this
backend's business and would be noise to whoever reads the generated doc.

**One bug found, in the language rather than the compiler.** `true` and `false`
are documented literals that parsed as *references* to fields with those names,
because borrowing `ast.parse` makes a bare name a name. So `condition: "true"`
failed with a message about an undecoded field, and `unparse` emitted `true` for
a boolean — text that meant something else when read back. Fixed, which is also
what makes "what `unparse` writes parses back to the same tree" a total
property rather than one with an exception.

A limitation worth recording: a field named like a Python keyword **cannot be
referenced from a spec expression at all**, since Python's parser refuses
`header.class` before this project's whitelist sees it. The compiler maps it to
`class_`, so it is reachable from generated code and from a consumer — just not
from the spec that declared it.

### Stage 4 — the decoder body — **done, reading through the cursor**

The bulk. Every field type, size, and repeat; `condition`, `confirm`, `reject`;
truncation and the bounded loops. The invariants of `docs/dev/architecture.md`
have to hold in emitted code, and the generator is now the single place that
guarantees them.

**Q5 is this stage's first decision**, not a later optimisation: whether a
field is read directly or through the cursor decides how truncation is
detected, and that is the semantics of every one of the constructs above.

Two checks the spike showed a generator can compile away rather than emit: a
repeat count read from an unsigned field is never negative, and a repetition
whose element always reads at least one bit cannot fail to make progress. Both
are runtime guards in the interpreter because it cannot see the spec's types
when it needs them.

Landed as `pygen.render_decoder` / `render_entry`, the operations and analyses
`ops.py` grew to support them, and `kober/runtime.py` — which stage 6 was
supposed to introduce, but a decoder that reads needs something to read
through, and absorbing the one spec-shaped import (`Endian`) is exactly what a
runtime is for.

**The headline is `tests/test_compiled.py`**: a generated decoder and the
interpreter must agree, field for field, on every value and every byte range —
or fail at the same offset for the same reason. Every construct has a case, and
the sweep is worth more than any of them: **every prefix** of a real DNS query
and a real HTTP request is decoded both ways, which walks truncation across
every field boundary and through the middle of a bitfield word. Recursion is in
it too, at 40 and 200 levels, because refusing the same input matters as much as
refusing it.

Four checks compile away rather than being emitted — the two above, plus a codec
name validated once at compile time, and a depth bound threaded only through
specs that can recurse. Where any of them can fire, it is emitted; `nonnegative`
answers conservatively, since a wrong "provable" is a crash and a wrong
"unprovable" is one comparison.

**Q5 is answered in the order the answer can be trusted, not the order the plan
assumed.** The generated decoder reads through `Cursor`, which measures 13.4 µs
a message against the interpreter's 91.5 — 6.9× — and against 2.1 for direct
reads. The note in Q5 said this could not be a later optimisation because
truncation semantics depend on it. That was right about the risk and wrong about
the remedy: what makes the read strategy safe to change is a test that pins the
semantics, and the prefix sweep is that test. Swapping the reads now means
changing code the differential suite already holds in place, rather than trying
to get two things right at once.

So the direct-read pass is a separate, measured step, and if it does not land,
acceptance criterion 4 is met by its own escape clause with the number above and
the reason beside it.

One thing found while measuring, which **stage 5 has to answer before it emits
anything**. When a nested unit fails part-way, the interpreter *discards* the
partial unit: `_unit_ref` re-raises, so the failed unit's node — and every field
it decoded — never reaches the tree, and `plan()` marks those bytes `truncated`
instead of citing them. A generated decoder emitting as it goes has already
emitted them. On a 3-byte DNS query the interpreter writes one record and marks
`[2, 3)`; direct emission would write six records and mark nothing. Both are
honest about coverage and they are not the same file, so stage 5 either buffers a
unit's records until it completes — reintroducing bookkeeping this phase removed
— or argues that citing what was actually read is better and takes the
difference to the interpreter instead.

### Stage 5 — emission — **done**

Wire Q1's answer through: constants baked in, sink calls emitted, coverage
regions reported. When this lands, a generated module decodes a real capture
into a conformant `.zpf`.

It does. `tests/test_compiled.py` writes a two-datagram capture through a real
decode stage at both granularities and puts it past `ConformanceChecker` and
`check_coverage` — **acceptance criterion 1**, with a generated module rather
than a hand-written one. And the differential now covers records: every prefix
of a real DNS query, at every granularity, must produce the same emissions and
the same regions as `plan()`.

**Granularity is a compile-time choice**, which the plan suspected and this
stage confirms as a difference in the *code*: at `message` a decoder builds no
field paths and takes no sink, at `field` the path is threaded through every
unit function. A unit reached at two granularities is refused rather than
compiled twice — the interpreter resolves that per node, and a compiler would
have to emit the function twice, which is worth building when a real spec asks.

**`tests/compiled_dns.py` is now the generator's output, byte for byte**, header
and docstrings included. The spike is fully converged: what began as the module
the compiler *should* produce is what it *does* produce, and one test compares
the whole file. Generated code stays in the repository on purpose — it is source
this project ships, so a diff in it should be reviewable like any other.

**The blocking question answered itself in the interpreter's favour being
wrong.** Stage 4 found that a nested unit failing part-way was discarded whole,
so `plan()` named bytes `truncated` that had been read and understood. Emitting
as you go cannot reproduce that without buffering — the bookkeeping this phase
exists to remove — so the alternative was to take the difference to the
interpreter, and it did not survive contact: those bytes *were* read. Fixed
there. Then the prefix sweep found the same bug one level down, where a
repetition lost **every** element because they were accumulated in a list a
raise unwound past. Fixed the same way.

Both were latent before the compiler existed and neither had a failing test.
That is the differential test earning the phase's cost on its own: two bugs in
the reference implementation, found by writing a second one and insisting they
agree.

Measured at field granularity: 16.6 µs a message against the interpreter's
126.6, so **7.6×**, of which emission is about 2.5 µs. Q5's direct-read pass is
still the outstanding one.

### Stage 6 — `kober compile`, and the runtime — **done**

The CLI verb, and `kober.runtime` factored out of what generated code needs.

The runtime arrived early — stage 4 needed something for generated code to read
through — so what was left here was the verb and the thing nobody had listed: a
**driver**, without which a generated module is only usable by hand-written
glue. `kober compile examples/dns.yaml -o dns.py` now produces a module, and
`kober.run_compiled` runs it over a capture.

**One driver, two producers.** The seam rules — a gap is a message boundary, a
seam is owed after a hole, a run's tail belongs to whoever owns the run — are
true of a decode however the decode was written, and they are the subtlest code
in this project; the gap-seam bug of the real-capture phase passed every
hand-built test. So `stage.py` was refactored rather than duplicated: a
`_Writer` sink, a step-based loop, and two steps. The interpreter's path writes
through that sink as well, which is Q1's argument arriving where it was always
going — `plan()` gained a second producer, and the two meet the same writer.

That makes the differential stronger than "the same records": the two write
**byte-identical files**, block for block, over a capture holding a whole
message, a truncated one, and one with bytes after it. Acceptance criterion 2,
at the level a user would notice.

One thing straightened out on the way: `decode_from` now accounts for its own
extent at message and none granularity, where before the entry point did it.
A driver decoding several messages from one run cannot account for a message it
did not write, and the module always can.

### Stage 7 — testing — **done**

The headline is **differential**: for every example spec and every fuzz corpus,
the interpreter and the generated module must produce the same values, the same
ranges, and the same records. That is a stronger statement than either
implementation's own tests, and it is the reason to keep both.

Also: generated modules must pass `ruff` (they are source we ship), and the
existing fuzz properties must hold over generated decoders — which means the
suite generates, then fuzzes.

All of it, and one addition the plan did not ask for that turned out to matter
more than the rest: **a corpus of specs chosen to be hard to compile.** The
shipped examples exercise a fraction of the language, and every one of the
compiler's decisions about *where a field is* stays right on `dns.yaml` while
being wrong elsewhere. Seven specs now cover bitfields that do not divide a
byte, a word straddling two, a switch whose branches differ in width, repeats by
count and to the end, every size a spec can write, and a computed value.

**Three bugs, in under a minute of running it.** A signed sub-byte field called
a helper the generator never emitted. A `switch` with both a unit case and an
integer case wrote no record for the integer, because one object alternative
made the whole field a container. And a computed value too wide for `prim:`
raised `ValueError` out of the emitter — **in both implementations**, since
`1 << n` with `n` off the wire is an ordinary expression and an enormous number.
The first is the compiler's; the other two were shared or the interpreter's, and
neither had a failing test.

That is now four bugs the differential has found in the reference
implementation, against one in the compiler. Which is the argument for keeping
both, arriving from the direction nobody expected: the compiler's value here has
been as much in what it revealed about the interpreter as in what it produces.

The fuzzing reaches the driver as well, which the in-suite fuzzing never could
before: a fuzzed capture of datagrams, and a fuzzed byte stream with a hole in
it, driven through both implementations and compared block for block. That is
the shape the seam rules exist for.

### Stage 8 — documentation

`docs/format/` gains nothing; the spec language does not change. `docs/dev/`
gains a compiler page, `docs/api/` the new modules, and `DESIGN.md` gains a
section — including the restatement below.

## What has to be restated, not just extended

**§2.1's cursor rule changes character.** Today nothing author-supplied moves
the read cursor *because there is no author-supplied code*. Generated code
moves it directly, so the invariant becomes a property of the generator rather
than an impossibility. That is still a good position, and it must be argued
rather than assumed — the current wording would be quietly false.

**Generating Python from a data file is a new security posture.** Names,
labels, and `doc:` strings flow toward source text. The generator must never
interpolate them: identifiers validated against a whitelist, everything else
emitted as constants or escaped literals. "A spec cannot run code" is partly a
security property today, and this is exactly where it would be lost by
carelessness.

## What this phase does not do

- **Retire the interpreter.** It is the reference implementation, the `try`
  path, and half of the differential test.
- **Change the spec language.** No new constructs. `Pointer` (`DESIGN.md`
  §3.2) is still owed and is a separate piece of work — it should land in the
  interpreter first, so the compiler has something to be checked against.
- **Add a non-Python backend.** Only the seam.
- **Optimise the interpreter.** Dropping `frozen` from `Node` is worth 1.5×
  for one line, and it costs immutability that was deliberate. A separate
  decision on its own merits; 1.5× and 56× are not alternatives.

## Acceptance

1. `kober compile examples/dns.yaml -o dns.py` produces a module that decodes
   the real DNS capture into a conformant `.zpf`, clean under
   `ConformanceChecker` and `check_coverage`.
2. The differential test passes over both example specs and the fuzz corpora:
   same values, same ranges, same records as the interpreter.
3. Generated modules pass `ruff` and are readable — someone can open one and
   see what their protocol decodes to.
4. The measured throughput is within reach of the analysis's 16.8 MB/s ceiling.
   If it is not, the reason is understood and written down.
5. `DESIGN.md` §2.1 says what is actually true of both implementations.
