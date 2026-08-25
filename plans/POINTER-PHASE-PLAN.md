# Phase plan: the language

**State: stage 1 done, stages 2–8 not started.** Written after the compiler
phase landed
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

**All six are settled**, each by Stage 1's spike rather than by argument — a
written answer with code behind it, as the compiler phase's Q1–Q5 were settled.
Q6 was raised by reading the capture rather than by writing this plan, and Q1's
second half was **overturned** by running the code, which is what the stage was
for.

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

- **What the origin actually is, in `STREAM` shape** — *settled: it lives in
  `decode_one`.* A run is not a message: `_decode_run` in
  [`stage.py`](../src/kober/stage.py) loops, decoding as many messages as fit
  one contiguous run, over a single `Cursor` carrying the *run's* `base`. So
  message-relative is a third space that exists nowhere in the code today, and
  the origin is fixed per **message**, where the entry unit starts —
  `cursor.byte_offset()` on entry to `decode_one`, not `base`, and not
  anything `decode_bytes` knows.
- **What "out of range" is measured against** — *settled: the message's
  high-water mark, and the leaning it replaces was wrong.* The draft leaned
  toward allowing forward pointers, bounded by the available data. The spike
  killed that: bounding at the run makes a message's decode depend on the bytes
  that happen to **follow** it. The same message, given three different
  neighbours, decoded three ways — `ok` and `truncated`, a target extent of
  `[0,1)` or `[0,20)`, 14 or 18 bytes consumed.

  A pointer may therefore target only bytes the message has **already
  decoded**: at or after the origin, strictly before the cursor. Every real
  pointer in the corpus is backwards, so nothing is lost, and a decode becomes
  self-contained — which it demonstrably was not before.

A pointer must not reach outside the current message into a neighbour that
shares its run. That falls out of the origin being the message rather than the
run, and it matters: citing a previous message's bytes from this one's record
would put the emitter in a position §5's seam rule has no answer for.

### Q2 — How is the chain bound expressed, and what happens when it blows? — **settled: the bound is a backstop, not the defence**

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

**Settled, and better than the leaning: no cycle can be constructed.** Each hop
inherits a ceiling equal to the previous hop's *target*, so a chain's offsets
strictly decrease. A self-pointer and a two-node cycle are both refused at the
second hop, by the range rule, before the bound is consulted. No visited set,
and no allocation.

A legal backward chain still resolves: a hand-built message whose answer name
points at a question name that is itself a pointer decodes to `'com'` through
two hops, whole message consumed, status `ok`.

**The hop bound stays, with its job restated.** It no longer guards against
cycles, because there are none; it guards against *depth*. A 64 KB message
admits a legal chain tens of thousands of hops long, and that is a stack
overflow rather than a loop. It stays a separate constant from `MAX_DEPTH`, per
the leaning above.

### Q3 — What does a pointed-at region cite, and what happens to tiling? — **settled as leaned, and the emitter needed no fix**

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

**Settled as leaned: a pointer read cites the bytes it actually read, at the
offset it read them,** so the pointed-at region ends up cited twice — once by
whatever decoded it in place, once by the reference.

The overlap is **partial**, as the corpus predicted. In the 157-byte response,
`dns.answers[0].rdata` cites `0x3b-0x61` while eight leaves under
`dns.authority[0].name…target…` cite sub-ranges inside it, starting at `0x48`.

**`emit.py` needed no fix.** Across all four responses at both granularities:
cited ∩ undecoded is empty, no byte is uncovered, and `_holes` handles partial
overlap correctly through `_union`. The prediction that it was "very likely
already correct" held, and it was checked rather than assumed.

Field granularity emits the pointed-at name **twice**, under two paths —
`dns.questions[0].qname…` and `dns.answers[0].name.labels[0].rest.target…` —
with identical payloads and ranges. That is the intended, honest outcome.
Message granularity is unaffected: one record, overlap invisible.

Tiling retires as expected. The weaker true property — every byte covered *at
least* once — holds everywhere.

### Q4 — Do string builtins mean calls in the expression language? — **settled: option (1), and it costs nothing at decode time**

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

Settled what a malformed input yields — `to_int("abc")`. The function is
**partial at the value level and total at the decode level**: the field it
sizes becomes `undecodable`, the decoder does not raise, and `check` cannot
know in advance.

**That needs no new mechanism.** `_one` in
[`decoder.py`](../src/kober/decoder.py) already catches `EvalError` and returns
an `undecodable` node, which is exactly how a bad size expression behaves
today. The builtin inherits the existing path rather than adding one.

The parser change is likewise contained: the refusal is one message at one
site — *"a function call is not allowed in an expression"* — so admitting a
closed table replaces a blanket refusal with a lookup, in one place.

Real numbers to write against, from `http_example.pcapng`: the response is
`Transfer-Encoding: chunked` with `Content-Encoding: gzip`, and its first chunk
header is `776` — hexadecimal, 1910 bytes. Both builtins are needed for one
message.

**What admitting calls does *not* open, and this is worth stating because the
next phase will test it.** Transforms — decompression, decryption — will need
an extension point that a closed table cannot give them, since kober cannot
ship every proprietary codec. That extension point is **not** this one. A
builtin maps a value to a value; a transform maps bytes to bytes and feeds a
sub-decode with its own offset space, and merging the two into "calls" is a
category error.

The concrete cost of routing transforms through the expression language is that
`check` stops being static: a user-registered function makes a spec valid in
one process and invalid in another, depending on what was registered, and
`kober check spec.yaml` could no longer answer on its own. A transform escapes
that because its type is always bytes → bytes, so a spec can **name** a codec
the checker does not have and still be checkable — an unknown codec becomes an
undecodable region at decode time, as an unmatched `Switch` case already does.

So the shape for later is the one §11.5 already named: **the spec names a
transform; a registry supplies it**, kober shipping the well-known set and a
caller registering their own through the Python API. The spec file stays data,
which is also what keeps a non-Python backend possible — a spec naming a Python
callable cannot be compiled by one, and a spec naming `gzip` can.

### Q5 — How far does the read seam generalize now? — **settled: the seam is a `(data, base, limit)` triple**

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

**Settled, and smaller than expected: the seam is a `(data, base, limit)`
triple.** The spike needed no byte-source abstraction at all — a second
`Cursor` over `data[:limit - base]` was the whole of it, and the slice *is* the
byte source in embryo. A transform supplies a different `data` and a `base`
that no longer indexes the input; `Pointer` supplies the enclosing run's own
bytes with a ceiling. Those are the two parameters, and nothing else varied.

So the seam to build in Stage 3 is: **a sub-decode takes the bytes it reads,
the offset those bytes start at, and the offset it may not read past.** Naming
it a type is Stage 3's call; the spike says the type has three fields and no
behaviour.

### Q6 — Can one field cite two disjoint ranges? — **settled: the question dissolves**

Raised by reading the capture, and folded into Q3 in the first draft, which was
wrong: it is structural rather than a matter of policy, and it decides whether
this phase touches the emitter's data model.

A pointer field inherently cites **two** ranges — the two bytes at the cursor
that encode the reference, and the target region elsewhere. `zpf` is content:
`record(cites=...)` takes "a pair, a ready `Span`, or a **sequence** of
either". [`node.py`](../src/kober/node.py) and [`emit.py`](../src/kober/emit.py)
are not: `Node` and `Emission` each carry one `off_start`/`off_end` pair, and
`Node.width` is defined as their difference.

**Leaning: decomposition, not multi-range.** The pointer node covers its own
two bytes; the decoded target hangs beneath it as a child covering the target
region. Every node stays contiguous, `Node` is untouched, and the two ranges
exist as two nodes. What it costs is **tree containment** — a child would sit
outside its parent's hull for the first time, and `_walk` in `emit.py` may lean
on containment without saying so.

If containment turns out to be load-bearing, the fallback is a multi-range
citation on `Node` and `Emission`, which is a wider change than this phase
wants and would be felt by the compiler's plan layer too.

**Settled: neither. The question dissolves, and it dissolves for a reason worth
keeping.** `Pointer.at` is an *expression*, so a pointer reads **nothing** at
the cursor — the reference bytes are read by ordinary fields, whose citations
already cover them. In the DNS spec the two bytes are `label.length` and
`ptr.lo`; the `Pointer` field is zero-width where it stands and cites exactly
one contiguous range, the target.

The two-range case never arises, so `Node` and `Emission` are untouched and the
compiler's plan layer inherits nothing. The shape is `Computed`'s — zero width
at the cursor, cites elsewhere — which the model already carries.

Containment *does* break, as predicted: a `target` node at `0x0c-0x2e` sits
under an ancestor spanning `0x32-0x42`, and the tree stops being monotonic in
offset. `emit._walk` turned out not to care. That was the risk, and it did not
bite.

## Stages

### Stage 1 — settle Q2–Q6, with a spike — **done**

Hand-write, against the real `dns_example.pcapng` responses, what a compressed
name decode should produce: which nodes, which offsets, which citations, at
both granularities. Then answer Q2–Q6 in this document, each with the evidence
that decided it, along with the two details Q1's settlement left open — what
the message origin is in `STREAM` shape, and what an out-of-range offset is
measured against. **No production code**: the prototype is scratch, and being
free to get it wrong is the point.

#### What the corpus actually holds

Established before planning the stage, by converting the capture and
enumerating every pointer site in the four responses:

| Response | qd/an/ns/ar | Sites | Targets |
| --- | --- | --- | --- |
| 146 B | 1/0/1/0 | 1 | `0x32` → `0x0c` |
| 66 B | 1/1/0/0 | 1 | `0x32` → `0x0c` |
| 157 B | 1/1/1/0 | 3 | `0x2f`→`0x0c`, `0x61`→`0x48`, `0x87`→`0x71` |
| 113 B | 1/2/0/0 | 2 | `0x2f`→`0x0c`, `0x61`→`0x3b` |

Three things follow, and each changed the stage:

- **Not every target is the question name.** `0x48` and `0x71` point *into the
  middle of an earlier record's RDATA* — the tail of a CNAME's name, and the
  tail of an SOA's MNAME — and `0x3b` points at an earlier RDATA's first byte.
  So Q3's overlap is **partial**, not whole-region, which is the harder case
  for `_holes` and `_union` and is not what the first draft assumed.
- **The corpus contains no chain.** All seven targets begin with a label,
  never with another pointer. Q2's bound cannot be exercised by real traffic,
  so the stage has to *build* its adversarial inputs rather than find them.
- **Q6 exists**, per above.

#### Steps

0. **The fixture.** The four responses as inline byte literals.
   [`test_examples.py`](../tests/test_examples.py) sets the rule: the suite
   "deliberately does not depend on" the sibling checkout, so real bytes are
   inlined rather than read from `../python-zipline-wire`.
1. **Hand-write the expected decode** — the 66-byte response first, then the
   157-byte one, which has all three interesting targets. Nodes, offsets,
   citations, both granularities. Tables, not code.
2. **A throwaway prototype**: a minimal `Pointer` in a scratch copy of the
   decoder, enough to produce trees for all four responses.
3. **Settle Q6, then Q3.** Try decomposition first; find out whether `_walk`
   leans on containment. Then run partial overlap through `emit.plan` and
   confirm cited ∩ undecoded stays empty.
4. **A real decode stage**, past `ConformanceChecker` and `check_coverage`.
   Coverage is a promise about a file, and a tree is not a file.
5. **Build the adversarial inputs Q2 needs**: a two-hop chain, a self-pointer,
   a two-node cycle, a forward pointer, an out-of-range offset, and — for
   `STREAM` shape — a pointer aimed at a neighbouring message in the same run,
   which tests the boundary Q1's settlement created and which nothing in the
   corpus produces.
6. **Q4, separately.** String builtins share nothing with the pointer work: a
   parse/infer/unparse sketch over the three functions, with the
   malformed-input answer decided against the real HTTP exchange rather than
   in the abstract.
7. **Write the settlements** into this document, each with its evidence.

Deliverable: this file's Q sections marked **settled**, and a scratch script
that produced the numbers.

#### What the spike found beyond the six questions

The emitter turned out to be right under partial overlap, so the stage's
"expect a bug" prediction did not pay off there. It paid off twice elsewhere.

**A truncation inside a pointer target must not stay `truncated`.** Following a
pointer into nonsense makes the target read run off the end, and the natural
result is a `truncated` node. But `truncated` is **hole**-class (§5), so it
declares a `stream-gap` seam and says those bytes never existed — a lie about
the input, when what actually happened is that the spec aimed somewhere silly
at input that arrived intact. A short read *inside a pointer read* is therefore
converted to `undecodable`, which is `bytes`-class and owes no seam. With that,
every pathology in the corpus — self-pointer, cycle, forward, out of range,
garbage target — lands on `undecodable`, nothing raises, and everything
terminates.

**Conformance cannot catch an origin bug, so the test for it must compare
values.** Running the whole corpus with the origin deliberately set to the
run's base instead of the message's produced a file that is conformance-clean
*and* coverage-clean — while message 1's answer name silently resolved to
message 0's question name. A wrong pointer still cites *some* region in range,
so the coverage guarantee is satisfied by a decode that is simply wrong. Stage
4 must therefore assert on decoded **values** across a multi-message run; a
conformance check would pass either way, which by `CLAUDE.md`'s rule makes it
worthless as a regression test for this.

#### What the spike did not settle

`examples/dns.yaml`'s final shape. The spike's spec is built in Python because
the loader has no `pointer:` key yet, and it models a name as a `label` repeat
switching on the top two bits — which works, but Stage 7 should decide whether
that is the spec an author would want to read.

### Stage 2 — `Pointer` in the model, loader, and checker — **done**

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

**What it actually needed was smaller than the sketch, in one place and larger
in another.**

`_leading_chain` needed nothing. It already refuses to walk anything that is
not a plain `UnitRef`, so a leading `Pointer` field stops the walk on its own —
and that is the *right* answer rather than a lucky one, because Q2's
strictly-decreasing rule means a unit pointing at itself does terminate. A test
records that, so the behaviour is deliberate rather than incidental.

Reachability and parenting both fell out of one change: `_walk_types` now
descends into a pointer's target. `_index_parents` and `_check_reachability`
share that walk, so a unit reached only through a pointer is both reachable and
parented at the pointing site — which is what settles `parent`'s meaning inside
a pointed-at unit without a second rule. Reverting that branch fails four
tests; reverting the `at` type check fails two.

**One thing the sketch missed.** Adding a field type the checker accepts made
`kober compile` crash with a bare `TypeError` on a spec `kober check` had just
passed. `ops.py` now raises `CompileError` naming the limitation, which is what
that exception exists for — the spec is valid and runs under the interpreter,
and only the compilation is impossible. Stage 6 removes it.

### Stage 3 — `Pointer` in the interpreter — **done**

The byte-source seam from Q5, then `Pointer` on it. A second `Cursor` over the
same run at the resolved offset; the enclosing cursor never moves. Bound from
Q2. Out-of-range, blown bound, and a target that itself fails all produce
`undecodable` regions with details, and **nothing raises** — the promise
[`decoder.py`](../src/kober/decoder.py) makes and that the fuzz suite asserts.

**The seam landed as `Cursor.view(off_start, off_end)`**, plus `seek_to` for
absolute positioning. Q5 called the seam a `(data, base, limit)` triple and
that is exactly a view: its own bytes, its own base so spans stay absolute, its
own end so a sub-decode cannot see what it was not given. A transform supplies
different bytes to the same call.

`_Read(origin, limit, depth, hops)` replaces the bare `depth` parameter
threaded through the decode. Folding them together keeps the parameter count
where it was and puts the four limits a redirect needs in one place.

**Two things the spike had not exposed.**

The window is `[origin, ceiling)`, **not** `[target, ceiling)`. Slicing from
the target is the obvious reading of "the bytes it may see", and it makes the
decoder *raise*: a further hop has to reach back past the current one, and a
cursor rebased at the target no longer covers those bytes. The legal two-hop
chain caught it. Bounding at both ends is also what stops a pointer reading
into a neighbouring message that shares the run.

**A self-pointer is not the cycle worth testing.** Two of the first tests
written here passed with the inherited limit removed, because a target that
reads nothing before hopping is refused by the range rule alone. The real
cycle reads *forward* and then points back at itself, and only the inherited
ceiling refuses it — structurally, without the hop bound ever being consulted.
That is now the test, and it fails when the limit is removed.

### Stage 4 — coverage, and the invariants restated — **done**

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

**The emitter was right, and the seam rule holds — but only because of stage
3's conversion.** `_holes` handles a citation nested wholly inside another,
which is the real-DNS case of an owner name pointing into an earlier record's
rdata. No fix was needed, and there is now a test that would have caught one,
with a companion asserting the overlap is really there so it cannot quietly
stop proving anything. The seam test fails the moment a pointer target's short
read is left as `truncated`: that is hole-class, and it would put a false
`stream-gap` between two real records.

**Two fuzz invariants had to be sharpened before they had teeth.** The first
attempt asserted that trailing bytes never change a decode, which is simply
false — a message that ran out of input is entitled to decode further when
given more. Conditioning on the extent was wrong too, because a read that runs
out leaves the position *before* the last byte. The discriminator that works is
the status: `truncated` means "the input ended", and only those cases are
exempt. A `assert compared` guard keeps the exemption from swallowing the whole
corpus.

Both mutations are checked. A run-wide ceiling fails two fuzz tests; a run-base
origin fails the message-boundary one. The containment property — no node
reaches past the message it belongs to — turned out to be the more robust of
the two ways of saying it, and is worth keeping alongside.

### Stage 5 — string builtins — **done**

Q4's table, in [`expr.py`](../src/kober/expr.py) (parse, infer, `unparse`) and
[`check.py`](../src/kober/check.py) (argument count and types, result type).
Three functions, no more, each total at the decode level. `unparse` must
round-trip. The parser change is the security-relevant one: the function table
is closed and matched by name, and an unknown name is refused by the same
mechanism that refuses `ast.Call` today.

**Three signatures, two names.** `to_int(s)`, `to_int(s, base)`, `lower(s)` —
the three capabilities §13.2 asked for, spelled as two rows in `BUILTINS`.
Arity is settled at parse time, where a float literal already is; argument
types at inference, with the rest of typing.

**`to_int` had a decision the plan had not seen.** Python's `int` accepts
`1_000` and, in base 16, a `0x` prefix. Inheriting that would read a malformed
wire length as a plausible number, which is the failure this project exists to
avoid, so the conversion validates its own digits. Whitespace *is* stripped,
because an HTTP field value carries optional whitespace by rule and allowing it
is what saves the language a fourth function.

**Nothing new was needed for failure.** A malformed value raises `EvalError`,
which `_one` already turns into an `undecodable` node — the same path a size
expression that cannot be evaluated has always taken. Q4 predicted this and it
held exactly.

Two documents said something now false and were corrected here rather than in
stage 8: `docs/format/expressions.md`, whose whole "no string arithmetic"
section was the *reason* for this work, and `DESIGN.md` §3.3's "no calls".
A normative document that lies in the interim is worse than one polished late.
`test_docs.py` gained a check that every `BUILTINS` row is documented, matching
what it already does for loader keys.

### Stage 6 — both, in the compiler — **done**

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

**The distribution was different this time: four bugs, all four in the
compiler**, and three of them in code that predates the constructs that exposed
them. A field path carried the backend's identifier rather than the spec's, so
a field named `class` was `class_` in every record the compiled decoder wrote.
A unit reachable only through a pointer was dropped from the plan, and the
module then called a decode function it had not generated — the checker had
been taught to walk a pointer's target in stage 2, and the compiler's own
reachability walk had not. A generated decoder let `EvalError` escape, because
the backend's list of expressions that can fail did not know about `to_int`.
And a `switch` mixing a nested unit with a scalar generated nested `if`s that
`ruff` refuses, so such a module failed the project's own lint.

**The seam held.** `at` on `ValueType` is the whole of the neutral change: a
pointer adds no kind of its own, so the plan describes the target and stamps
*where* on it. No Python decision leaked in — the offset arithmetic, the
save-and-restore of the read position, and the hop bound are all the backend's.

**Threading is a whole-plan decision, like `recursive`.** A module whose plan
has no pointer is generated exactly as before, down to the byte, which is what
keeps `tests/compiled_dns.py` a stable fixture and costs pointer-free specs
nothing. Where there is one, every decode function takes the message origin,
the chain's ceiling and the hop count.

**One deviation from the plan, and not for the reason it anticipated.** The
plan asked for builtins inline rather than as helper calls unless a measurement
said otherwise. `to_int` compiles to a call on `kober.runtime.to_int`, which
*is* the function the interpreter evaluates — the reason is correctness rather
than speed. The conversion is deliberately stricter than Python's, and two
copies of that rule would be two things to keep in step. `lower` is inline.

Measured on the real 66-byte response: **6.5 µs against the interpreter's 203,
31× at 10 MB/s.**

### Stage 7 — the examples finished — **done for DNS, partly for HTTP**

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

**DNS is done, and it is what the phase was for.** All eight messages in
`dns_example.pcapng` decode with **no undecoded regions at all**, conformance-
and coverage-clean at both granularities, and the compiled module resolves a
pointer through its typed API. The `skipped` disclaimer is gone.

**HTTP is half done, and the plan's premise for the other half was wrong.**

The chunked half works: `to_int` on the size line frames the real body into its
two chunks exactly, and both messages in the capture decode with nothing left
over. (Two, not four — the count in the acceptance criterion was mine and it
was wrong; the capture holds one message per direction.)

**`Content-Length` framing is not reachable, and not for the reason §13.2
gave.** That section diagnosed the gap as arithmetic on a header *value*, and
this phase built the arithmetic. Two things it did not name:

- **A header value cannot be extracted.** `to_int` reads a whole string field,
  and a header is one line — `"Content-Length: 1234"` is not a number. Getting
  at the value needs a substring, which the language does not have, and a
  `":"`-terminated read cannot be bounded to the line.
- **Worse, and the real blocker: nothing can ask a question about the set of
  headers.** `headers` is a repeated field, and the checker refuses references
  to those because there is no list type — so a body's framing cannot depend on
  whether *any* header said `chunked`. Even with a substring builtin, the
  choice between the two framings would still be unsayable.

So the shipped spec **assumes** chunked framing and says so. The cost is
stated in its `doc:` and asserted in a test: a body that is not chunk-formatted
comes back `truncated`, which is hole-class and claims a gap the stream did not
have. That is the least comfortable thing this phase ships, and it is written
down rather than discovered later.

**What §13.2 actually needs is a way to speak about a repetition** — an
`any`/`count` over elements, or a way to name one by a key. That is a
language question of a different size from three builtins, and it belongs to
its own phase rather than to the end of this one.

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
