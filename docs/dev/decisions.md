# Where decisions live

Most of this project's reasoning is written down, but it is spread across four
places with different jobs. This page is the index, because a contributor
currently has to already know `plans/` exists to find any of it.

## `DESIGN.md` — the design, and why it is that shape

The normative document. It carries the spec model, the decode semantics, the
public API, and the arguments behind them. **Claims marked [verified] were
executed, not reasoned about.**

It is revised rather than patched, and each revision says what changed and why.
Two are worth knowing about, because both corrected the document rather than
extending it:

- **Revision 5** rewrote §2's central argument. It had justified the
  declarative spec model with "if specs could run code they could swallow
  input, so coverage is provable" — which contradicts its own opening
  paragraph, since `fill_undecoded=True` makes coverage true by construction
  regardless. The line that matters is §2.1's: **who moves the cursor.**
- **Revision 6** records what real captures found, in §13, and dropped a status
  line claiming nothing was implemented that had been false for two phases.

Sections most worth reading before changing code: §2.1 (the cursor rule), §4.1
(field naming and its stopgap), §5 (seams), §9.2 and §13.

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

## Upstream issues — what is blocked on the format

`kober` is a load test of `zpf`, and a gap upstream is treated as a finding
rather than something to route around. Five have been filed:

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

## Commit messages

Longer than usual here, and deliberately. Where a change corrected an earlier
decision, or where the tests found something the implementation had wrong, the
commit says so — including the several cases where a first attempt at a
regression test passed either way and was worthless until corrected. `git log`
is the record of what was tried and rejected, which neither the code nor
`DESIGN.md` states.

## What is *not* written down

The open questions, deliberately. `DESIGN.md` §11 carries four, and they are
questions rather than decisions:

1. Which stream shape a spec may assume, and whether a framing adapter belongs
   in the model.
2. *(Closed — `Computed` stays.)*
3. Whether to import `.ksy`.
4. When to follow `zpf` 0.3, which will break.
5. How far the spec language goes before it becomes a program — where the
   `Pointer` construct and the missing string builtins both land.
