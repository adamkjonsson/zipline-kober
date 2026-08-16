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

### Q1 — How do generated decoders emit records?

The crux, and the one that decides whether this phase delivers 56× or 4×.

- **(a) Direct emission.** The generated decoder calls a sink —
  `sink.record(payload, content_type, start, end, comment)` — with path,
  content type and granularity baked in as literals. No tree.
- **(b) Carry the bookkeeping.** Generated objects hold offsets and statuses,
  and `plan()` walks them as it walks a tree today.

**Leaning: (a)**, because the constants are known at compile time and (b) gives
back most of what the phase is for. `plan()` stays pure and keeps its tests; it
gains a second producer rather than being replaced.

Open sub-question: whether decoding and emitting are one pass with an optional
sink, or two entry points. Suggest one pass — `decode(data, sink=None)` — since
a second pass would rebuild what the first knew.

### Q2 — Where do byte ranges live in the typed API?

A consumer wants `msg.questions[0].qtype` to be an `int`, not a wrapper. But
provenance is this project's whole point, and a caller must be able to ask
*which bytes* a field came from.

- **(a) A sidecar** — `spans(msg)` returns a mapping from path to range.
- **(b) A dunder** on each object: `msg.__spans__["qtype"]`.
- **(c) Every field is a wrapper** carrying value and range.

**Leaning: (b)**, one `__spans__` tuple per object, parallel to its fields.
(c) reintroduces the allocation the phase exists to remove. (a) is clean but
needs a second traversal to build.

### Q3 — What does generated code depend on?

- **(a) A small `kober.runtime`** — the cursor and the sink protocol.
  Generated modules import it; consumers install `kober` but need no YAML.
- **(b) Fully standalone**, inlining everything.

**Leaning: (a).** It is also the shape a future non-Python backend wants —
a runtime library plus generated code is how every such compiler is built. (b)
can be an option later if a genuinely dependency-free artifact is wanted.

### Q4 — How is the API named?

Spec names are author-chosen and need not be valid Python identifiers, and
units and fields can collide with each other and with keywords. Needs a
documented mapping, and a **hard failure on any collision** rather than silent
mangling — a decoder whose field silently changed name is worse than one that
would not compile.

## Room for other targets later

The stated possibility is Rust or C++ eventually. That does not change what is
built now, but it changes one seam, cheaply, if it is put in from the start.

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

```{note}
Read as "a backend emitting Rust or C++". If what was meant is
re-implementing the *interpreter* in another language, none of this plan is
affected — that would be a separate project consuming the same spec format.
```

## Stages

### Stage 1 — settle Q1–Q4, with a spike

Not prose. Hand-write the module the compiler should produce for
`examples/dns.yaml`, by hand, exactly as intended — typed classes, direct
emission, spans — and run it against the real capture end to end, checking
conformance and coverage.

That fixes the target before any generator exists, and it is the cheapest way
to find out that an answer to Q1 or Q2 does not work. The hand-written module
becomes the first test fixture: the generator's output should converge on it.

### Stage 2 — the typed model

Spec → dataclasses, one per unit, with `slots`, annotations, optional fields
for `condition`, lists for `repeat`, and the `__spans__` shape from Q2. Plus
the identifier and collision rules from Q4.

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
