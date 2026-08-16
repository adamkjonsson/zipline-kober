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

### Q5 — How does generated code read bytes? — **not settled; the measurement says it must not be `Cursor`**

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

### Stage 2 — the typed model

Spec → dataclasses, one per unit, with `slots`, annotations, optional fields
for `condition`, lists for `repeat`, and the span representation from Q2. Plus
the identifier and collision rules from Q4 — which live in the **Python
backend**, not the neutral layer, per the confirmation above.

Self-contained and testable without decoding anything.

### Stage 3 — expressions to source

The AST already exists and `unparse` is close. New work is scope binding —
`this`/`parent`/`root` and unit parameters resolving to locals or attributes —
and the two semantics that differ from Python: `/` is floor division, and
`and`/`or` must short-circuit exactly as the interpreter does, since a spec
relies on it to guard a division.

### Stage 4 — the decoder body

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

### Stage 5 — emission

Wire Q1's answer through: constants baked in, sink calls emitted, coverage
regions reported. When this lands, a generated module decodes a real capture
into a conformant `.zpf`.

### Stage 6 — `kober compile`, and the runtime

The CLI verb, and `kober.runtime` factored out of what generated code needs.

### Stage 7 — testing

The headline is **differential**: for every example spec and every fuzz corpus,
the interpreter and the generated module must produce the same values, the same
ranges, and the same records. That is a stronger statement than either
implementation's own tests, and it is the reason to keep both.

Also: generated modules must pass `ruff` (they are source we ship), and the
existing fuzz properties must hold over generated decoders — which means the
suite generates, then fuzzes.

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
