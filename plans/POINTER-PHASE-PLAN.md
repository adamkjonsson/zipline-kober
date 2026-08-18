# Phase plan: the language

**State: not started.** Written after the compiler phase landed
([`COMPILER-PHASE-PLAN.md`](COMPILER-PHASE-PLAN.md)), against `DESIGN.md`
revision 7 and `zpf` 0.2.x.

`kober` gains the two things real captures asked for and the spec language
could not say: the **`Pointer`** construct (`DESIGN.md` §3.2) and a small,
closed set of **string builtins** (§3.3). Both close a boundary named in §13.

```
   §13.1  DNS  c0 0c  →  "the name at offset 12"      →  Pointer
   §13.2  HTTP "1a2b" →  "that is a hex chunk length" →  string builtins
```

## Why this phase

Everything else is now built twice — model, checker, interpreter, compiler,
docs, differential and fuzz testing. What is not built is the ability to *say
enough about a real protocol*. Both shipped example specs document their own
incompleteness in their own `doc:` strings:

- [`examples/dns.yaml`](../examples/dns.yaml) decodes the header and question
  section and marks the answer section `skipped` — "a back-reference this
  language cannot follow".
- [`examples/http.yaml`](../examples/http.yaml) decodes the start line and
  every header and claims the body as opaque `remaining` bytes — correct for
  one message per direction, wrong for two.

That is the product's stated promise — decode a protocol from a spec — unmet
on the only two protocols it ships. Nothing else on the list is worth doing
first, and two things on it are actively worth *not* doing first: a second
backend would emit fast code for a language that still cannot read a DNS
answer, and a `.ksy` importer would import constructs we cannot express.

**The prior authority is explicit.** The compiler phase listed `Pointer` under
*What this phase does not do*: "still owed and is a separate piece of work — it
should land in the interpreter first, so the compiler has something to be
checked against." And §11.5 already concluded that both real gaps wanted the
declarative language to say *more*, rather than wanting hooks — "evidence that
the language was under-built rather than that the approach was wrong". This
phase is that conclusion being acted on.

**The safety net landed first, which is why this is affordable now.** The
differential makes the interpreter a reference implementation, `packeteer` and
`zpfwire` supply adversarial and real corpora, and [`ops.py`](../src/kober/ops.py)
gives the compiler a neutral layer to hang a new operation on. `Pointer`
changes citation semantics; doing that before anything could audit it would
have been the wrong order.

## The insight this phase is built on

**A pointer and a byte transform are the same shape.** Both mean: *decode a
unit against bytes that are not where the cursor is, and cite an input region
for the result.*

| | Where the bytes come from | Offset space | What it cites |
| --- | --- | --- | --- |
| `Pointer` | the same buffer, another offset | the input's | the region it read, honestly |
| A transform (gzip, decryption) | a **different** buffer, synthesized | its own | the region it was computed from |

They differ in one variable — whether the byte source is the input or a
derived buffer — and share everything else: a secondary read position, a
depth or size bound, and a mapping from "where I read" back to "what I cite".

This matters because compression and encryption are a stated future goal, and
the Zipline standard already permits them: 0.13 settled that a decoder MAY emit
bytes that do not appear in its input, and that **`spans` asserts
correspondence, not identity**
([the Zipline payload format](https://github.com/adamkjonsson/zipline/blob/main/docs/zipline-payload-format.md),
§ *Typing a decoded record*). So no format change is owed for that phase either;
what is owed is the same seam this phase needs.

**Therefore this is a requirement of this phase, not an aspiration for the
next one:** the redirect is built as *decode a unit against a byte source that
carries its own offset space and its own citation mapping*, with `Pointer`
supplying the one implementation where source and input coincide. The cost of
that framing now is small — it is mostly where a boundary is drawn in
[`decoder.py`](../src/kober/decoder.py) and what [`Cursor`](../src/kober/cursor.py)
is handed. The cost of retrofitting it is re-plumbing the read path. It is the
same argument the compiler phase made for the backend seam, and that one paid.

**It stays a seam, not an abstraction.** One redirect exists. The plan does not
invent a transform vocabulary, a codec registry, or a key-passing API, and it
should not read as though it half-did.

## What the two gaps actually need

### DNS name compression

```
0030  00 01 c0 0c 00 01 00 01 00 00 00 9f 00 04 22 95
            ^^^^^  the name at offset 0x0c
```

A name is *a union of labels or a pointer*, which `Switch` already expresses.
The top two bits set mean the remaining 14 are an offset. What cannot be said
is **read there and return**. Three things it needs that nothing in the model
has today, all three already named in §3.2:

- **An offset space.** DNS pointers are message-relative; the cursor holds
  run-relative positions with an absolute `base`.
- **A bound.** Pointer chains are legal and can loop. A decoder that follows a
  cycle forever is the failure §2 exists to prevent, reached from a new
  direction.
- **A coverage note.** A region reached *only* through a pointer is cited
  without having been walked.

### HTTP body framing

`Content-Length: 1234` and a chunk header `1a2b` are both **arithmetic on a
header value**: a decimal string, a hexadecimal string, and a case-insensitive
match on a header name. The language has none — and, more than that, it has no
*calls at all*: [`expr.py`](../src/kober/expr.py) refuses `ast.Call` by
whitelist, which is what makes "no calls, no loops" true by construction rather
than by rule. Adding three functions is therefore not a small edit to a parser;
it is the first widening of that whitelist, and it needs the same argument the
whitelist itself got.

## Design questions to settle first

Q1 is settled. Q2–Q5 carry leanings rather than answers, and Stage 1 settles
them with a spike, as the compiler phase's Q1–Q5 were settled — a written
answer with code behind it, not a preference.

### Q1 — What offset space does `Pointer.at` mean, and who translates? — **settled: message-relative, and out of range is `undecodable`**

`Pointer.at` is an expression yielding an offset. DNS means *from the start of
the message*; the cursor reports absolute stream offsets. Something must
translate.

**The space is message-relative, always, and is not declared on the
construct.** The draft leaned toward a declared space defaulting to
message-relative, on the grounds that a spec silently meaning stream-absolute
would work on a run's first message and misread every later one. That argument
dissolves once the space is fixed: with one space there is nothing for a spec
to mean by accident, and the failure mode the declaration guarded against
cannot arise. Offering the choice would be speculative generality of exactly
the kind this plan refuses elsewhere — and if a second space ever earns its
place, an optional key is an additive change, while a key shipped now is one
the format is stuck with.

**An out-of-range offset is `undecodable`, not a hole.** It is a wrong claim
about the input rather than a piece of input we never received, and §2 reserves
`undecodable` for *tried and failed*, which is exactly what this is.

Two things follow that the spike must still pin down, because "the message" is
the underspecified word here and it is where the bug will live:

- **What the origin actually is, in `STREAM` shape.** A run is not a message:
  `_decode_run` in [`stage.py`](../src/kober/stage.py) loops, decoding as many
  messages as fit one contiguous run, over a single `Cursor` carrying the
  *run's* `base`. So message-relative is a third space that exists nowhere in
  the code today — neither the run's base nor the stream's origin — and the
  phase has to carry the current message's start into the decode. That is a
  small addition, and it is the whole of what Q1's settlement costs.
- **What "out of range" is measured against.** The message's start is known;
  its end is not, until the decode finishes. So the reachable range is bounded
  below by the message origin and above by what the run actually holds. Whether
  a *forward* pointer into not-yet-decoded bytes is legal is a separate call:
  RFC 1035 requires DNS pointers to point backwards, but that is a protocol's
  rule and not obviously the language's. Leaning: allow forward, bound by the
  available data, and let a protocol that wants stricter say so in prose — but
  the spike should confirm nothing in emission or seams depends on the reads
  being ordered.

A pointer must not reach outside the current message into a neighbour that
shares its run. That falls out of the origin being the message rather than the
run, and it matters: citing a previous message's bytes from this one's record
would put the emitter in a position §5's seam rule has no answer for.

### Q2 — How is the chain bound expressed, and what happens when it blows?

`MAX_DEPTH = 64` in [`decoder.py`](../src/kober/decoder.py) already
bounds unit nesting and raises `_Stop` into an `undecodable` region.

**Leaning: a separate module-level bound, not a reuse of `MAX_DEPTH`,** and a
bound on *pointer hops*, not on bytes read. Two reasons to keep them apart: a
deep unit tree and a long pointer chain are different pathologies with
different natural limits, and a shared constant would make one protocol's
tuning silently change the other's failure threshold. A blown bound is
`undecodable` with a detail naming the chain, which is what §2 asks for.

Settle whether a *cycle* is detected directly (a visited set) or only caught by
the bound. Leaning: only by the bound — a visited set costs an allocation per
pointer read on the hot path to detect a case the bound already handles, and
the compiler would have to reproduce it exactly for the differential to pass.

### Q3 — What does a pointed-at region cite, and what happens to tiling?

Overlapping citations are legal and **[verified]**. But two properties in the
code assume more than the format requires:

- `test_every_byte_is_covered_by_a_leaf` in
  [`test_decoder.py`](../tests/test_decoder.py) asserts *leaves tile the input* — every byte covered by exactly the leaves, once.
- [`test_fuzz.py`](../tests/test_fuzz.py) asserts *no byte is both cited and
  marked undecoded*.

The second must survive untouched — it is the coverage guarantee, and a
pointer does not threaten it, because a pointed-at region is cited, and cited
is exactly what "not undecoded" means. The first must go, and **that retirement
has to be argued in the design rather than performed in a diff**: it was a real
property, the emitter was built on it, and it is being given up deliberately.

**Leaning: a pointer read cites the bytes it actually read, at the offset it
read them,** so the pointed-at region ends up cited twice — once by whatever
decoded it in place, once by the reference. That is the honest statement and it
is what the format's overlap allowance exists for.

Settle what [`emit.py`](../src/kober/emit.py)'s hole-finding does when
emissions overlap: `_holes` subtracts spoken-for intervals from the tree's
extent, and overlap is new input to that. It is very likely already correct via
`_union`; "very likely" is not the standard, so it gets a test that fails
without the check.

### Q4 — Do string builtins mean calls in the expression language?

The whitelist refuses `ast.Call`. Three options:

1. **Admit `ast.Call` with a closed function table.** `to_int(s)`,
   `to_int(s, 16)`, `lower(s)`. Familiar, and the parser change is small.
2. **Admit no calls; use operators or type-directed coercion.** Cheaper to
   argue, much worse to read, and it does not extend.
3. **Method syntax** (`s.to_int()`), which needs `ast.Attribute` on values —
   and `Ref` already owns dotted paths, so this collides with field access.

**Leaning: (1), with the table closed, total, and typed** — every function
total (no exceptions, a defined answer for malformed input), and its result
type inferred by [`check.py`](../src/kober/check.py) like any other expression.
The whitelist's promise was never "no functions"; it was *no author-supplied
code and no unbounded work*, and a closed table of total functions keeps both.
Say that in §3.3 rather than letting the change look like erosion.

Settle what a malformed input yields — `to_int("abc")`. Leaning: a defined
sentinel-free answer is impossible without an option type, so the function is
**partial at the value level and total at the decode level**: the field it
sizes becomes `undecodable`, the decoder does not raise, and `check` cannot
know in advance. That is the same shape as a length field pointing past the end
of a segment, which the model already handles.

### Q5 — How far does the read seam generalize now?

The insight above says the redirect is built to carry a future transform. The
risk is building an abstraction for one caller.

**Leaning: generalize exactly two things and no more** — (a) the byte source a
sub-decode reads from is a parameter rather than the enclosing run, and (b) the
citation a sub-decode reports is computed by the source rather than being its
own offsets. `Pointer` supplies a source where (b) is the identity function.
Everything else — codecs, keys, `params_digest`, a derived offset space that
does not correspond to input bytes one-to-one — stays out, and the seam is
documented as *what it does not yet do*.

The test that this was drawn right is stated now, so it can be checked later:
adding a gzip transform should touch the byte-source type and the spec
vocabulary, and **not** `decoder.py`'s field or unit loops.

## Stages

### Stage 1 — settle Q2–Q5, with a spike

Hand-write, against the real `dns_example.pcapng` response, what a compressed
name decode should produce: which nodes, which offsets, which citations, at
both granularities. Then answer Q2–Q5 in this document, each with the evidence
that decided it, along with the two details Q1's settlement left open — what
the message origin is in `STREAM` shape, and what an out-of-range offset is
measured against. No production code.

Deliverable: this file's Q sections marked **settled**, and a scratch script
that produced the numbers.

### Stage 2 — `Pointer` in the model, loader, and checker

- [`spec.py`](../src/kober/spec.py): `Pointer` as a frozen dataclass, added to
  `FieldType`, validating what one object can see by itself.
- [`loader.py`](../src/kober/loader.py): the tagged-mapping schema
  (`{pointer: {at: "...", type: {...}}}`), strict keys, path-carrying errors.
- [`check.py`](../src/kober/check.py): `at` types as `int`; the pointed-at
  `type` is checked like any other field type; the forward-reference rule
  applies to `at` as it does to a size. Settle and test what `parent`/`root`
  mean *inside* a pointed-at unit — the scoping is the enclosing site's, since
  the pointer does not create a new parent.
- Recursion: a unit reachable only through a pointer is still reachable, so
  `_check_reachability` must count it, and `_recursive`/`_check_left_recursion`
  must not treat a pointer read as consuming input — it does not.

That last bullet is the one most likely to be got wrong quietly: a pointer
target that recurses into itself is exactly the cycle Q2 bounds, and the
checker's existing non-termination analysis will reason about it wrongly unless
told that a pointer consumes nothing at the cursor.

### Stage 3 — `Pointer` in the interpreter

The byte-source seam from Q5, then `Pointer` on it. A second `Cursor` over the
same run at the resolved offset; the enclosing cursor never moves. Bound from
Q2. Out-of-range, blown bound, and a target that itself fails all produce
`undecodable` regions with details, and **nothing raises** — the promise
[`decoder.py`](../src/kober/decoder.py) makes and that the fuzz suite asserts.

### Stage 4 — coverage, and the invariants restated

- Retire the tiling assertion `test_every_byte_is_covered_by_a_leaf` in
  [`test_decoder.py`](../tests/test_decoder.py), replacing it with the weaker true property (every byte covered *at least*
  once by leaves) and a comment pointing at the design section that explains
  why it weakened.
- Add the pointer case to [`test_fuzz.py`](../tests/test_fuzz.py): cited and
  undecoded stay disjoint under pointers, including cyclic and out-of-range
  ones. **Check the new fuzz invariant against a deliberately broken
  implementation** — per `CLAUDE.md`, a regression test that passes either way
  is worthless, and this project has written several.
- Confirm `emit.py`'s hole-finding under overlap, with a test that fails
  without the fix if there is one.
- Confirm the §5 seam rule is untouched: a pointer produces no hole-class
  region, so it owes no seam. State it, because "obviously fine" is how the
  seam rule was wrong the first time.

### Stage 5 — string builtins

Q4's table, in [`expr.py`](../src/kober/expr.py) (parse, infer, `unparse`) and
[`check.py`](../src/kober/check.py) (argument count and types, result type).
Three functions, no more, each total at the decode level. `unparse` must
round-trip. The parser change is the security-relevant one: the function table
is closed and matched by name, and an unknown name is refused by the same
mechanism that refuses `ast.Call` today.

### Stage 6 — both, in the compiler

- [`ops.py`](../src/kober/ops.py): a pointer read in the neutral plan, carrying
  the spec's own names and no Python decisions — the layer rule from its
  module docstring applies and is easy to break here, because "read at an
  offset" invites baking in a Python slice.
- [`pygen.py`](../src/kober/pygen.py): the backend, and the generated module's
  handling of the bound. Generated code stays `ruff`-clean under this
  project's own config, and [`tests/compiled_dns.py`](../tests/compiled_dns.py)
  is regenerated and reviewed as a diff.
- String builtins compile to inline expressions, not helper calls, unless the
  measurement says otherwise.

The differential is the acceptance test for this stage. It found five bugs in
the last phase, four of them in the *older* implementation; expect the same
distribution and treat an interpreter bug found here as the stage working.

### Stage 7 — the examples finished

`examples/dns.yaml` decodes the answer, authority, and additional sections,
and its `skipped` disclaimer is **deleted**. `examples/http.yaml` frames the
body by `Content-Length` and by `Transfer-Encoding: chunked`, and its
disclaimer is deleted. Both stay conformance- and coverage-clean over all four
real DNS pairs and the real HTTP exchange, at both granularities.

Deleting those two `doc:` paragraphs is the phase's real acceptance criterion.
Everything above exists to earn it.

A gzip body is still not decoded, and `examples/http.yaml` says so — the one
disclaimer that survives, now naming a missing *transform* rather than a
missing *language*.

### Stage 8 — documentation, and what has to be restated

Covered below; it is a stage because it is work, not a formality.

## What has to be restated, not just extended

**§2.1's cursor rule, for the second time.** The compiler phase already changed
its character once — from "nothing author-supplied can move the cursor" to a
property of the generator. A pointer adds a *second* cursor, and the rule has
to say why that is still the same guarantee: the spec names an offset, the
runtime does the seeking, and the reading position never moves. That is the
argument §3.2 already makes for choosing `Pointer` over a hook, and it now has
to be true of running code rather than of a design sketch.

**§13.1 stops being "a boundary, being closed" and becomes closed.** §13.2
likewise. Those two sections are the record of what real traffic found; leaving
them in the present tense after the fix is how a design document starts lying.

**§3.3's "no calls" becomes "no calls but these three".** With the reason: the
whitelist bought *no author-supplied code and no unbounded work*, and a closed
table of total functions costs neither. Written as a narrowing of the rule's
scope, not as an exception to it.

**§11.5's line moves, and should be re-drawn explicitly.** The question was how
far the spec goes before it becomes a program. This phase takes the *richer
expressions* branch it named as cheapest. Hooks stay deferred; the section
should say that the branch was taken and what is now on each side of the line,
rather than leaving a reader to infer it from a changelog.

**The tiling property, per Q3.** Where it was assumed, what replaced it, and
why the coverage guarantee is untouched by the change.

**A note that the transform seam exists and is unused.** One paragraph, in the
architecture doc rather than the design: what a byte source is, what `Pointer`
supplies, and what a future transform would supply instead. Written so the next
phase inherits a decision rather than re-deriving one.

## What this phase does not do

- **Transforms.** No compression, no decryption, no codec vocabulary, no key
  passing. The seam only.
- **Hooks.** §11.5's middle branch stays deferred, and this phase is evidence
  for that deferral rather than against it.
- **A `.ksy` importer, or a second backend.** Both wait until kober handles
  standard protocols well, which is what this phase is for.
- **A release.** 0.1.0 is the phase after, and it is entangled with §11.4 —
  when to take the `zpf` 0.3 break.
- **New size or repeat constructs.** `Pointer` is one field type and three
  functions. A phase that also "tidies" the model is two phases pretending to
  be one.

## Acceptance

1. `examples/dns.yaml` decodes every section of all four real query/response
   pairs from `dns_example.pcapng`, including compressed names, conformance-
   and coverage-clean at both granularities — and its `skipped` disclaimer is
   gone.
2. `examples/http.yaml` frames bodies by `Content-Length` and by chunked
   encoding, correct for **all four** messages in `http_example.pcapng` rather
   than for two, with only the gzip disclaimer left.
3. The differential passes over both examples, the awkward-spec corpus, and the
   fuzz corpora, still writing byte-identical files block for block — with
   pointer-bearing specs in every corpus.
4. Fuzzing over pointer-bearing specs raises nothing, never cites and marks the
   same byte, and terminates on cyclic chains. The new invariants are checked
   against a broken implementation, not merely observed to pass.
5. `DESIGN.md` says what is true of both implementations after the change:
   §2.1 with two cursors, §3.3 with three functions, §13.1 and §13.2 closed,
   and §11.5's line re-drawn where this phase left it.
