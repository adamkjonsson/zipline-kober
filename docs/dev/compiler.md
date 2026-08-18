# The compiler

`kober` runs a spec two ways. {class}`kober.decoder.Decoder` **interprets** one,
walking the model over a cursor and building a {class}`kober.node.Node` tree.
`kober compile` turns one into a Python module with a typed API, which decodes
without this project's loader, checker or spec model — only
{mod}`kober.runtime`.

Neither replaces the other, and the reason is not diplomacy. The interpreter is
what `try` should use, needs no build step, and is where exploratory work
belongs. It is also the **reference implementation**: the two are compared on
every input the suite can generate, and that comparison has found more bugs than
any other test here. See [Testing](testing.md#two-implementations-and-the-test-that-compares-them).

## The shape, and the seam in the middle

```
  Spec ──→ Plan ──────────→ backend ──→ source text
           kober.ops        kober.pygen
           language-neutral  Python-specific
```

**The rule that decides which side a decision belongs on:** `ops` describes
*what the format means*; a backend decides *how a language says it*. A field has
a byte range and a value of some kind — meaning. Whether the range is exposed as
a dunder, a parallel array or an accessor, and whether a name grows a trailing
underscore to dodge a keyword, is a target's business.

So a {class}`kober.ops.Plan` carries **the spec's own names, unmapped**. Rust
reserves different words than Python and mangles different characters; a plan
holding Python identifiers would hand a second backend a mapping made for the
wrong language. Anything in `ops.py` that reads like a Python decision is in the
wrong file.

It is deliberately **not an intermediate representation**. It is the ordered
description a backend walks, with the spec's indirections resolved and nothing
invented, plus the analyses any backend wants and none should repeat:

| Analysis | What a backend does with it |
| --- | --- |
| {attr}`kober.ops.FieldPlan.consumes` | Drops the runtime check that a repetition is making progress |
| {func}`kober.ops.nonnegative` | Drops the check that a count or size came off the wire negative |
| {attr}`kober.ops.ObjectPlan.recursive` | Threads a depth bound only through units that can reach themselves |
| {attr}`kober.ops.ObjectPlan.needs_parent` / `needs_root` | Passes exactly the outer values a unit names, instead of a frame chain |

Emitting Rust or C++ later means a second backend, not a second interpreter.
That is what the seam is for, and it cost one module to leave open.

## What the backend decides

Everything Python-specific is in {mod}`kober.pygen`, and it is three kinds of
decision.

**Names.** A unit becomes a `CamelCase` class, a field keeps its spec name, a
Python keyword gets a trailing underscore, and **anything else is refused** with
a {class}`kober.errors.CompileError`. A decoder whose field quietly changed name
is worse than one that would not compile. The backend reserves every identifier
beginning with an underscore and nothing else, which is why `size`, `data` and
`path` are still usable field names.

**Byte ranges.** One flat `__spans__` tuple per object — its own extent, then a
pair per attribute — read back by {func}`kober.runtime.span`. A wrapper per
field would reintroduce the allocation the compiler exists to remove.

**Where a field is.** The one that pays for itself: the generator tracks each
field's offset from the last position only the running decode could know, so a
read is an index, a bounds check is a comparison against a number, and a byte
range is an addition. Tracking the position in bits instead measures 6.9 µs a
message against 2.9; going through the cursor measures 13.8.

## Invariants a change here must not break

### Generated code is compared, not trusted

The compiler's correctness argument is not "read it and see". It is
`tests/test_compiled.py`: the same bytes decoded both ways must produce the same
values, byte ranges, records and regions — or fail at the same offset with the
same reason — over every example, an awkward-spec corpus, and every mutation of
both. **A change that cannot be checked that way needs a very good reason.**

### Nothing author-supplied is interpolated into source

Names, enum labels and `doc:` strings all flow toward source text, and "a spec
cannot run code" is partly a security property. Identifiers are validated
against a whitelist; everything else becomes an escaped literal or an escaped
docstring. {func}`kober.pygen.render` parses its own output before returning it,
so a generator bug is a refusal rather than a broken module.

### Generated modules are source this project ships

They pass `ruff` with this repository's own configuration, and
`tests/compiled_dns.py` is the compiler's output for `examples/dns.yaml`,
checked in and compared character for character. A diff in generated code is
reviewable like any other, which is the point of keeping it.

### A generated module imports `kober.runtime` and nothing else

No spec model, no `Node`, no YAML, no checker. That is what makes a decoder
shippable, and it is why {func}`kober.runtime.read_int_le` exists at all — the
one spec-shaped import happens there, once.

### Both halves write through the same driver

`stage.py` has one loop, one sink, and two steps. Gaps, seams and run tails are
true of a decode however the decode was written, and the seam rules are the
subtlest code here — they had a bug that passed every hand-built test. One
implementation of them is one place for them to be wrong.

## What the Python backend refuses

Two things, both deliberate, both with a message naming the spec's own words:

- **A name it will not rename** — not an identifier, colliding with another, or
  inside the underscore namespace.
- **A unit whose fields do not add up to a whole number of bytes**, since the
  generated code tracks a byte offset and cannot express a unit that starts or
  ends part-way through one. Such a spec is nearly always a fault already: the
  interpreter carries on mid-byte and then raises out of the decode at the next
  `bytes` field.

Both are narrower than what the interpreter accepts. That is the honest cost of
compiling, and it is stated rather than worked around.
