# Phase plan: the decoder

**State: done.** All five stages landed on `decoder_work`; all five design
questions settled, two of them not as this plan predicted (Q2 and Q5 — see
each). Written after the spec-model phase landed
([`SPEC-MODEL-PHASE.md`](SPEC-MODEL-PHASE.md)) and against `DESIGN.md`
revision 5, `zpf` 0.2.0.

This is the phase [`DESIGN.md`](../DESIGN.md) §1 calls the whole product:

> **What is actually left is one thing: turn a declarative spec into the loop
> that reads segments and calls `dec.record(...)`.**

Everything before it built the spec side. Nothing yet reads a byte.

---

## What exists to build on

| Piece | Where | What it gives this phase |
| --- | --- | --- |
| Spec model | `kober.spec` | The tree to walk. Frozen, normalized, well formed. |
| Expression AST | `kober.expr` | Parsed, scoped, and **typed** — so evaluation never has to ask what an operand is. |
| Checker | `kober.check` | A clean `check()` means references resolve, ordering holds, and types agree. The decoder may assume all of it. |
| Loaders | `kober.loader` | YAML/JSON → `Spec`. |
| `zpf` 0.2.0 | released | `decode_stage`, `record(comment=)`, `undecoded`, `Seam`, coverage and conformance checking. |
| `pressure_test.py` | root | Every zpf behaviour this phase depends on, already **[verified]**. |

**The checker's guarantees are load-bearing here.** The decoder should not
re-validate what `check` proved; it should assume a checked spec and fail loudly
if that assumption is broken. Whether `Decoder.__init__` runs `check` itself is
an open question below.

---

## The invariants this phase must enforce

These are not new decisions. They are the parts of the design that had nothing
to enforce them until now, gathered so they can be tested rather than
remembered.

1. **The cursor rule** (§2.1). The read cursor belongs to the runtime and is
   advanced only by declarative constructs. Nothing author-supplied moves it.
   This is what makes coverage honest; it is also what makes a future hook API
   (§11.5) safe, since a hook would take values and return values, never a
   position.
2. **Silence is a lie** (§2). Every byte the spec declines must be named with
   the *right* reason: `undecodable` for a switch with no case and no default,
   `truncated` for a length past the end, `gap` for a field inside a `Gap`,
   `skipped` only where the spec deliberately passes over. Letting auto-fill
   write `skipped` on our behalf is the failure mode, not the safety net.
3. **Cite accurately, and only what we decoded** (§1). A sub-byte field cites
   the bytes containing it. Overlapping citations are legal — **[verified]** —
   so a flags word and the bits inside it may all cite the same range.
4. **One emit site for field paths** (§4.1). The path that goes into `comment=`
   is formatted in exactly one function, so upstream
   [#58](https://github.com/adamkjonsson/python-zipline/issues/58) is a one-line
   change when it lands. Nothing parses `comment` back.
5. **Dispatch on the stream, not the spec** (§9.2). `InputShape` is a
   declaration to check against; `stream.is_stream_oriented` is what decides
   `segments()` versus `datagrams()`. A decoded input is always packet-oriented
   whatever the transport underneath it was.
6. **Seams** (§5). Where the region between two emitted records intersects a
   `Gap`, pass `seam=Seam(width=..., reason="stream-gap")`. Otherwise omit it.
   Only the producer knows; the conformance checker cannot catch a missing one.

---

## Stages

Sized to land one commit each, as the spec-model phase did.

### Stage 1 — expression evaluation

`kober.expr.evaluate(expr, env) -> int | str | bytes | bool`, mirroring
`infer_type` node for node, against an environment protocol resolving a
reference path to a *value* the way `Scope` resolves it to a type.

- Types are already proven, so evaluation does not type-check. It may assert.
- `/` is integer division (`//` on ints), per §3.3.
- **Division by zero is the one non-total case** and cannot be checked away
  statically. It is a decode-time condition: the field it sizes becomes
  `undecodable`, not an exception out of the decoder.

*Testable with no zpf and no bytes.*

### Stage 2 — the cursor and the `Node` tree

The decode engine proper: bytes in, tree out, nothing about files.

- A cursor over a byte buffer with **bit-level** position, since `IntType.bits`
  need not be a multiple of 8. It exposes the containing byte range for a
  sub-byte read, which is what stage 3 cites.
- `Node`: name, value, `(off_start, off_end)`, children, status. **Not written
  to any file** (§6) — it is what `decode_bytes` returns and what stage 3 walks.
- A `NodeStatus` vocabulary that maps onto §2's reasons: `OK`, `TRUNCATED`,
  `UNDECODABLE`, `GAP`, `SKIPPED`. Getting this vocabulary right here is what
  makes stage 3 mechanical.
- Every field type: `IntType` (signed, endian, sub-byte), `BytesType`,
  `StringType` (decode errors *recorded on the node, never raised* — §3.2),
  `UnitRef` with arguments bound to params, `Switch`, `Computed`.
- Every size: `Fixed`, `FromExpr`, `Terminated`, `Remaining`.
- Every repeat: `Count`, `Until`, `ToEnd`.
- `condition`, and unit-level `confirm` / `reject` — a rejected unit is
  abandoned and its extent marked, never raised (§3.1).
- `Decoder.decode_bytes(data) -> Node` (§6), the REPL and test entry point.

*Testable with no zpf. This is the largest stage and may split in two.*

### Stage 3 — emission: `Node` → records

Walk the tree and call `dec.record(...)` / `dec.undecoded(...)`.

- `Emit.MESSAGE`: one record per top-level unit instance,
  `content_type="dec:<spec>-message"`, payload = the message bytes, cites its
  range. **[verified]** conformant.
- `Emit.FIELD`: one record per leaf, payload = the value normalized into
  `prim:`'s little-endian, `content_type="prim:uN"`, cites the wire bytes, and
  the field path in `comment=`. **[verified]** conformant, coverage clean, and
  the two identical-valued flag records come back distinguishable.
- `Emit.NONE`: decode for control flow, emit nothing.
- Granularity resolves **field → unit → decoder** (`Field.emit`, `Unit.emit`,
  `Decoder(emit=)`).
- The single `_field_path(...)` function of invariant 4.
- Coverage: walk the tree's non-`OK` nodes into `undecoded()` calls with the
  matching reason. **Every byte accounted for before the stage closes.**

### Stage 4 — the stage driver

- `Decoder.decode_stream(dec, stream)` (§6), so a caller can mix spec-driven
  decoding with hand-written logic in one stage.
- `Decoder.run(inp, out, produced_by=...)` — one spec, one file in, one file
  out.
- Shape dispatch per invariant 5, and an `InputShape` mismatch reported rather
  than decoded into garbage.
- `Gap` handling and the seam rule (invariant 6).
- `Decoder.content_registry()` (§6), generated from the same spec.

### Stage 5 — the CLI

- `kober run SPEC IN.zpf -o OUT.zpf [--emit field|message]`
- `kober try SPEC --hex 0a0b` — decode one buffer, print the tree, no file
- Both are already designed in §6 and deliberately unregistered today, so this
  stage is mostly wiring plus the tree printer, which `kober show` half exists
  as already.

---

## Design questions this phase has to settle

Flagged here rather than guessed at in code. Each changes what gets built. **All
five are now settled**, and each records what it was settled as and why — two
of them not as this plan predicted.

### Q1 — What does the decoder read: `reassembled()`, `segments()`, or `chunks()`? — **settled: `chunks()`**

The pressure test used `segments()` for message granularity and
`reassembled()` for fields, which was fine for a probe and was never a
decision. Confirmed as `chunks()`.

The three are not equally safe, and the reason is not the obvious one — an
earlier draft of this plan had it backwards, so the actual behaviour, read off
`zpf.reassembly`:

| Iterator | On a gap | Consequence |
| --- | --- | --- |
| `reassembled()` | **Raises `ZpfError`** — "a convenience for the common gap-free case" | Safe but brittle: one missing packet and we decode *nothing*, rather than decoding what we do have |
| `segments()` | **Skips the hole silently** | The real hazard. Two consecutive runs arrive with nothing saying whether they abut or straddle a hole |
| `chunks()` | Yields it as a `Gap` | The only iterator that shows where the holes are |

So `reassembled()` never produces wrong offsets — it refuses. `segments()` is
the one that loses information, and it loses exactly the information invariants
2 and 6 need: without seeing the `Gap` we cannot mark the region
`reason="gap"`, and we cannot know when two adjacent output records need
`seam=Seam(reason="stream-gap")` between them.

**What follows:**

- Decode over `chunks()`, treating a `Gap` as a **hard message boundary** — a
  message may not span one, because the bytes either side were never observed
  to be adjacent.
- Reassemble contiguous runs of `Segment` between gaps and decode within a run.
- The offset → ts map of Q2 falls out of the same walk, since each `Segment`
  carries its own `ts`.
- The cost is bookkeeping, not correctness: a run-relative cursor whose offsets
  must be translated back to stream offsets for every `cites=`.

**Scope.** This governs the **stream-oriented** branch only. `chunks()`,
`segments()`, and `reassembled()` all raise on a packet-oriented stream;
`datagrams()` is that path, and each datagram is self-contained, so the gap
question does not arise there. Which branch runs is invariant 5's dispatch on
`stream.is_stream_oriented` — never on the spec's declared `InputShape`.

### Q2 — Which timestamp does a record get? — **settled: the run's, and no map is possible**

**[verified]** (Q4): `Segment.ts` is already the *last* contributing packet's
time, which is the specification's rule for a reassembled payload. But a
message spanning two segments has two candidate `ts` values, and the rule wants
the completion time — the ts of the segment containing the message's **last**
byte.

This assumed a run could span several segments and need an offset → ts map.
**It cannot.** Read off `zpf.reassembly.chunks`: contiguous records are
*coalesced into one Segment*, whose `ts` is already `max` over its
contributors. A run **is** a segment, there is no multi-segment run, and no map
is constructible.

So: one `ts` per run, taken from `Segment.ts`. That is also what
`DecodeStage.record` documents — *"the completion time of the last input
record the payload came from (a run's Segment.ts)"* — so the API sanctions it
directly.

**One imprecision falls out of that, and it is worth naming rather than
hiding.** Where a run holds several messages, every one of them gets the run's
timestamp — the *last* contributing record's — even a message that finished
inside the first packet. Per-message times are not recoverable from `chunks()`,
which collapses them by design; recovering them would mean going around the
reassembly API to the raw records. `zpf`'s own docstring says to use the run's
value, so this is the sanctioned reading and not a defect, but a decoder
emitting one record per message *does* have a finer notion of "when" than the
format's reassembly layer offers it. Worth a question upstream if per-message
timing ever matters to a consumer.

### Q3 — Where does message framing come from in `STREAM` shape? — **settled as sketched**

In `DATAGRAM` shape a message is a datagram and this question does not arise.
In `STREAM` shape the decoder decodes the entry unit repeatedly until the run
is exhausted, and the entry unit's own extent is the frame. Two consequences:

- A trailing partial message is **`truncated`**, not an error — it may simply
  continue in a segment we do not have (§3.2). Normal outcome.
- A `Terminated` size with no terminator before the end of the run is the same
  condition and must not be reported as `undecodable`.

Built as sketched, with one thing the sketch missed: **at message granularity a
failed tree must not be emitted as a record at all.** A half-decoded message is
not a message, and writing one would claim we decoded something we did not —
its bytes are named with the failure's reason instead. Field granularity keeps
the asymmetry on purpose: the fields decoded *before* the trouble really were
decoded, so their records stand, and only the failed region is marked.

Shape dispatch settled as: refuse only a `DATAGRAM` spec meeting a
stream-oriented input, which is the mismatch that would fabricate a field tree
over unframed bytes. A `STREAM` spec over datagrams is allowed, since each
datagram is one self-contained message — and every chained stage needs that,
because a decoded input is always packet-oriented.

### Q4 — Does `Decoder.__init__` run `check()`? — **settled: yes, by default**

Running it is friendlier and makes the decoder's assumptions true by
construction. Not running it keeps `Decoder` cheap and leaves validation an
explicit step.

**Leaning:** check by default, with `Decoder(spec, check=False)` for a caller
who already did it — and refuse to construct on an ERROR finding, since every
guarantee in stage 2 rests on one.

### Q5 — How is a sub-byte field's payload normalized? — **settled: widen**

The question was sized wrong here. `prim:`'s vocabulary is **closed** —
`zpf.content.PRIM_WIDTHS` is `u8/i8/u16/i16/u32/i32/u64/i64`, plus `bytes` —
so it is not only sub-byte widths that have no token. A `u24` or a `u12` has
none either, and the spec model allows any width from 1 to 64.

**Settled: widen to the smallest token that holds the declared width.** A `u4`
is written `prim:u8`, a `u24` is written `prim:u32`. The alternative, dropping
to `dec:` for unrepresentable widths, would lose normative typing for exactly
the fields §4.1 fought to name — a reader without our registry would get opaque
bytes instead of a number.

Widening is honest because the payload is *created*, not copied: a `u4` holding
5 really is the integer 5, and any reader gets 5. What is lost is the field's
exact width, which the format has nowhere to record anyway — and `cites`
already rounds a sub-byte field out to its containing byte for the same reason,
so width was never recoverable from the file.

Strings get `mime:text/plain; charset=utf-8` rather than a `prim:` token, since
that scheme has no text member. Bytes get `prim:bytes`.

**No new pressure-test question was added, against this plan's own suggestion.**
The empirical parts — that overlapping spans are accepted, that a created
payload may differ from its cited bytes, that `prim:` normalization reads back
— were already **[verified]**, and what remained was a judgement about honesty
that no probe can settle. `tests/test_emit_conformance.py` does the equivalent
work with more force: it writes real files at both granularities and puts them
past `ConformanceChecker` and `check_coverage`.

---

## What this phase does *not* do

- **Hooks or a richer expression language** (§11.5). Deferred until a concrete
  case needs one; the declarative core is the substrate they would attach to.
- **The `.ksy` importer** (§11.3).
- **Following `zpf` 0.3** (§11.4). #58 would replace `comment=` with a real
  per-record name and #59 reshapes `record()`; both are 0.3, both are breaks,
  and invariant 4 is what keeps the cost to one site.
- **A framing adapter for `DATAGRAM`-shaped specs over TCP** (§11.1). Length-
  prefixed DNS over TCP is real, and out of scope here.

---

## Acceptance

The phase is done when:

1. `examples/dns.yaml` — a real spec, checked clean — decodes the pressure
   test's 29-byte DNS query end to end, at both `MESSAGE` and `FIELD`
   granularity.
2. `zpf.ConformanceChecker` and `zpf.check_coverage` are clean on both outputs,
   asserted in the test suite rather than eyeballed.
3. Every byte of the input is cited or named, with `undecodable` and
   `truncated` appearing where they should and `skipped` appearing **only**
   where the spec says so.
4. A chained second stage reads the first stage's output — **[verified]**
   possible, not yet done from a spec.
5. `kober run` and `kober try` work, and `pressure_test.py` still passes.
6. Ruff clean, no `noqa`, and the suite green.

And one thing that is not a test: this phase is what finally produces **real
files from a real decoder**, which is the evidence upstream #58 asked for when
it deferred the question of whether per-field records are the right level for a
payload format at all. Bringing that back is part of the deliverable.
