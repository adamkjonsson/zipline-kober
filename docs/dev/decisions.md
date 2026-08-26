# Where decisions live

Most of this project's reasoning is written down, but it is spread across four
places with different jobs. This page is the index, because a contributor
currently has to already know `plans/` exists to find any of it.

## `DESIGN.md` — the design, and why it is that shape

The normative document. It carries the spec model, the decode semantics, the
public API, and the arguments behind them. **Claims marked [verified] were
executed, not reasoned about.**

It is revised rather than patched, and each revision says what changed and why.
The ones worth knowing about are the ones that **corrected** the document
rather than extending it, and there are more of those than is comfortable —
which is the point of keeping them:

- **Revision 5** rewrote §2's central argument. It had justified the
  declarative spec model with "if specs could run code they could swallow
  input, so coverage is provable" — which contradicts its own opening
  paragraph, since `fill_undecoded=True` makes coverage true by construction
  regardless. The line that matters is §2.1's: **who moves the cursor.**
- **Revision 6** records what real captures found, in §13, and dropped a status
  line claiming nothing was implemented that had been false for two phases.
- **Revision 7** adds the compiler (§14) and **restates §2.1**, which had
  claimed an impossibility that generated code ends: a compiled decoder keeps
  its read position in a local, so the cursor rule becomes a property of one
  program rather than of the language. The restatement is the argument for why
  that is still defensible, and it rests on the comparison rather than on
  assertion.
- **Revision 8** adds `Pointer` and the first expression functions, and
  corrects §13.2's diagnosis, which had been wrong for four revisions: text
  arithmetic was never what stopped HTTP framing its body. §2.1 admits a
  *second* cursor, and §2 gives up "leaves tile the input" — a pointed-at
  region is cited twice.
- **Revision 9** adds `Select`, closes §13.2 and answers §11 question 6. It
  corrects §13.2 **again**, in the other direction: the revision-8 diagnosis
  was right and was believed *complete* too early, because every measurement
  agreed with it and every measurement ran the framing arm that worked. Both
  wrong readings are kept side by side, which is the most useful thing in that
  section.

Sections most worth reading before changing code: §2.1 (the cursor rule), §4.1
(field naming and its stopgap), §5 (seams), §9.2, §13 and §14.

## `plans/` — how each phase was run, and what it found

One document per phase, [indexed here](https://github.com/adamkjonsson/zipline-kober/tree/main/plans).
They are **historical, not normative**: where a plan disagrees with the code,
the code is right.

Their value is the design questions. Each plan states the questions the phase
must settle *before* the work starts, and records how each was settled and why
— including the ones settled differently from the plan's own prediction, which
is the part that would otherwise vanish. Two examples:

- The decoder phase predicted that timestamps would need an offset-to-time map.
  Reading `zpf.reassembly` showed a run *is* a segment, so no such map is
  constructible.
- It also sized the `prim:` problem as sub-byte only. The vocabulary is closed
  at 8/16/32/64, so `u24` has no token either.
- The compiler phase predicted that reading directly instead of through the
  cursor was worth 6.6×. It is worth 2×; the other 3× is in *baked offsets*, and
  the plan records both the wrong estimate and the four measurements that
  replaced it. It also predicted a fast path with a careful fallback for exact
  truncation, which turned out to be unnecessary — a per-field bounds check
  against a known offset costs nothing measurable.
- The repetition phase stated four facts about its own corpus and got all four
  wrong, including "no run holds more than one message" — every run of the
  capture it was about holds fifty. Every design leaning in that plan survived;
  what did not survive was the measurement. The plan is corrected in place with
  the numbers and the method that produced them, because the pattern is the
  useful part: **the wrong things were the facts, not the judgements.**

## Upstream issues — what is blocked on the format

`kober` is a load test of `zpf`, and a gap upstream is treated as a finding
rather than something to route around. Six have been filed against the format:

| Issue | What | State |
| --- | --- | --- |
| [#55](https://github.com/adamkjonsson/python-zipline/issues/55) | No `comment=` on `record()`, which blocked field granularity | Fixed in 0.2.0 |
| [#56](https://github.com/adamkjonsson/python-zipline/issues/56) | Decoded inputs are packet-oriented and nothing said so | Fixed in 0.2.0 |
| [#57](https://github.com/adamkjonsson/python-zipline/issues/57) | `check_coverage` leaked an `AttributeError` for a `FileReader` | Fixed in 0.2.0 |
| [#58](https://github.com/adamkjonsson/python-zipline/issues/58) | Whether the format wants per-field records at all, and how to name them | Open — evidence supplied |
| [#62](https://github.com/adamkjonsson/python-zipline/issues/62) | Which timestamp a message inside a multi-message run carries | Open |
| [#63](https://github.com/adamkjonsson/python-zipline/issues/63) | `check_coverage` measures a real TCP stream as 2³²−1 bytes | Open |

#58 is the one that shapes this codebase: it may replace `comment=` with a real
per-record label, which is why the field path is formatted in exactly one
place.

The same rule applies to the **test tooling**, which is upstream in the same
sense: a gap in what an adversary can generate is a gap in what this project
can be sure of. Three are filed against
[`packeteer`](https://github.com/adamkjonsson/packeteer):

| Issue | What | Why it matters here |
| --- | --- | --- |
| [#81](https://github.com/adamkjonsson/packeteer/issues/81) | `encode_http_message` adds `Content-Length` beside `Transfer-Encoding`, counting the *encoded* body | A chunked message cannot be hand-built through it, and the result is the RFC 7230 §3.3.3 ambiguity |
| [#82](https://github.com/adamkjonsson/packeteer/issues/82) | `--payload http` cannot generate a chunked response | The framing arm the real captures also cannot reach — see `docs/dev/testing.md` |
| [#83](https://github.com/adamkjonsson/packeteer/issues/83) | TCP anomalies are ignored with `--payload http` | Impaired *HTTP* streams have to come from fuzzing a real capture instead |

#82 is the one with a bug behind it rather than an inconvenience: the chunked
path had one message of real traffic in reach, and a decoder that read every
chunked response wrong shipped for a whole phase behind that.

## Commit messages

Longer than usual here, and deliberately. Where a change corrected an earlier
decision, or where the tests found something the implementation had wrong, the
commit says so — including the several cases where a first attempt at a
regression test passed either way and was worthless until corrected. `git log`
is the record of what was tried and rejected, which neither the code nor
`DESIGN.md` states.

## What is *not* written down

The open questions, deliberately. `DESIGN.md` §11 carries six, of which **three
are still open** — they are questions rather than decisions, and writing a
decision down before it is one is how a document starts lying:

1. Which stream shape a spec may assume, and whether a framing adapter belongs
   in the model.
2. *(Closed — `Computed` stays.)*
3. Whether to import `.ksy`.
4. When to follow `zpf` 0.3, which will break.
5. How far the spec language goes before it becomes a program. The one that has
   moved most: `Pointer`, a closed table of three functions, and `Select` have
   all landed on the near side, each closing a real gap by making the
   *declarative* language say more. Hooks stay on the far side, and now have a
   concrete case waiting for them — byte transforms, which no closed table can
   hold.
6. *(Closed — `Select` answers it.)*

## What is owed, and is not a question

Two things are decided in outline and simply not built, which is a different
state from either of the above and worth not confusing with them:

- **Byte transforms** — decompression and decryption. The shape is settled in
  §11.5: the spec *names* a transform and a registry supplies it, so the spec
  file stays data and `check` stays static. `examples/http.yaml` has a
  `Content-Encoding: gzip` body it deliberately leaves opaque, and
  `http_gzip.pcap` is the fixture kept for it.
- **`Transfer-Encoding: gzip, chunked`**, which is legal HTTP and which
  `examples/http.yaml` does not recognise, because saying "ends with chunked"
  needs a function the language does not have. It reads as *unframed* rather
  than mis-framed, which is the safe direction, and the spec says so where a
  reader meets it.
