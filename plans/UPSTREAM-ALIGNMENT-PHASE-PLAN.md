# The upstream-alignment phase — `0.3.0`

**State: done.** All eight issues landed on `plan_0_3_0` and shipped in
`v0.3.0` (2026-09-19), in the order §2 argues for. A final section recording
what the plan got right and wrong is owed, as the `0.2.0` plan's §9 was; the
rest is left as written on 2026-09-19.

> **Written 2026-09-19** against `0.2.0` and the seven issues on
> the [`0.3.0` milestone](https://github.com/adamkjonsson/zipline-kober/milestone/2),
> whose statement is *alignment with zipline 0.21, python-zipline 0.5.0 and
> packeteer 0.16.0* — plus #31, added to the milestone the same day on this
> plan's argument (§3.4). It decides an order, settles the decisions the
> issues leave open where they interact, and records what the milestone does
> not contain.

> The upstream state this was checked against: `../python-zipline` at `v0.5.0`
> (spec `0.21`), `../packeteer` at `v0.16.0`, `../python-zipline-wire` at
> `v0.3.0`, `../zipline` at `v0.21`. The suite is 1526 passing against the
> `0.5.0` checkout — see §2 step 0 for why that is already true.

---

## 1. What this release is

The last milestone changed the surface an author writes. This one changes
nothing an author writes — with one exception, §4 `#39` — and instead moves
the two projects kober sits between under it: the library it writes files
with, and the tool whose dialect it shares. Two strands and a bug that
belongs to the second:

| Strand | Issues | What it changes |
| --- | --- | --- |
| **`zpf` 0.5.0 / spec 0.21** | [#34](https://github.com/adamkjonsson/zipline-kober/issues/34), [#35](https://github.com/adamkjonsson/zipline-kober/issues/35), [#36](https://github.com/adamkjonsson/zipline-kober/issues/36); [#33](https://github.com/adamkjonsson/zipline-kober/issues/33) is the notice they answer | The pin moves two minors; field-granularity output declares itself a unit sequence; a generated module records its granularity so the compiled driver can say the same. |
| **packeteer 0.16.0** | [#37](https://github.com/adamkjonsson/zipline-kober/issues/37), [#38](https://github.com/adamkjonsson/zipline-kober/issues/38) | The vendored specs and the drift test catch up four releases; the reference stops warning readers off a transfer that works. |
| **The terminal-unit bug** | [#31](https://github.com/adamkjonsson/zipline-kober/issues/31), [#39](https://github.com/adamkjonsson/zipline-kober/issues/39) — one check, see §3.4 | `check` refuses a `remaining` that is not last, and a unit that reads to the end of the message when it is referenced from anywhere but the end. packeteer's rule, from its 0.13.0. |

Two of the seven are purely mechanical (#34) or purely prose (#38). The
substance is #35 + #36, which are one change to what a kober file *asserts*,
and #39, which is one new rule in `check`. **Nothing here changes a decode**:
the records, spans, payloads and undecoded regions a stage writes are
byte-identical before and after, and the only file-level difference is one
byte in each field-granularity participant descriptor. That is the test for
most of it (§5).

`#33` is the upstream notice from `python-zipline`; it needs no code of its own
and closes with #34 and #35. Its two loose ends — a `pressure_test.py` Q6 and a
row for zipline#106 in the decisions table — are carried by #35.

---

## 2. Order, and why

```
0.  version → 0.3.0.dev0; refresh the editable zpf install
1.  #34  the pin                     ← mechanical; everything else assumes 0.5.0's API
2.  #35  adjacency for the interpreter  ┐ one derivation, written once,
3.  #36  EMIT + adjacency for the compiler ┘ used by both drivers
4.  #39 (+#31)  the terminal-unit check  ← independent of zpf; can interleave anywhere
5.  #37  re-copy packeteer's specs, flip the drift test
6.  #38  the reference's transfer section
7.  fuzz pipeline on 0.5.0 (README, Fuzzing); release
```

**#34 first because it is the gate.** It costs nothing in code — the whole
suite passes on `0.5.0` unchanged — and until it lands the pin in
`pyproject.toml` contradicts the code the venv runs. Step 0 is a real step:
`.venv/bin/pip show zpf` reports `0.3.0` while `../python-zipline` is checked
out at `v0.5.0`. The editable install's *metadata* is frozen at install time;
the *code* is whatever the checkout is. So the suite already exercises 0.5.0
and `zpf.decode_stage` already takes `adjacency=`, but the moment the pin
becomes `>=0.5.0` pip's resolver will read the stale `0.3.0` metadata and
refuse `pip install -e .`. Run `.venv/bin/pip install -e ../python-zipline`
before changing the pin, and `.venv/bin/pip install -e .` after. The sibling
venvs (`../python-zipline-wire/.venv` reports `0.4.0.dev0` for the same
reason) need the same refresh before the pipeline in step 7 is trusted.

**#35 before #36, and the derivation in one function.** Both issues end in
the same keyword on `zpf.decode_stage`, and #36 says outright that it does
"what `run` does". Write a single `stage._adjacency(emit: Emit) ->
zpf.Adjacency | None` when doing #35, and #36 becomes: teach the generator
to export the granularity, have `run_compiled` read it back into that same
function. Two derivations would be two places for the interpreter and the
compiler to disagree about the participant line — which is exactly the
disagreement #36 exists to prevent.

**#39 is independent** of the `zpf` strand — it touches `check.py` and
nothing that imports `zpf` — so if the upstream strand stalls on anything,
this one can be done meanwhile. It is placed after because the `zpf` strand
is the one that currently *blocks a user*: kober on `zpf 0.3` cannot read
what `zpfwire 0.3.0` writes.

**#37 before #38** because #38's new section is a set of claims about what
packeteer 0.16.0 accepts and declines, and #37's flipped test is the evidence
for the half of those claims that runs the other way. Write the test, then
the prose it supports.

---

## 3. Decisions the issues leave open

### 3.1 What decides the adjacency: the root granularity, and only that

#35 proposes `UNITS` when `Emit.FIELD` is "in force at the entry unit" and
`None` otherwise, and asks for the value to be derived, not passed. The
question is what "in force" means when a spec mixes overrides — a root at
`field` with a unit marked `emit: message`, or the reverse.

`emit.plan()` answers it, and the answer is that the root is decisive.
`plan()` resolves the granularity once, at the tree's root
([`emit.py:172`](../src/kober/emit.py)), and branches on it: `MESSAGE` writes
one whole-message record or nothing; `FIELD` walks the tree, and only the
walk honours per-unit and per-field overrides; `NONE` marks the message
skipped and writes no record at all. So a field record can exist in the
output **iff the root resolves to `FIELD`**, and a root at `MESSAGE` or
`NONE` never produces one no matter what the units below it say. The rule is
exact, not a heuristic:

```python
def _adjacency(emit: Emit) -> zpf.Adjacency | None:
    return zpf.Adjacency.UNITS if emit is Emit.FIELD else None
```

where `emit` is `resolve_emit()` applied to the entry — the entry unit's own
`emit` if set, else the decoder's. That is decidable from `Decoder` + `Spec`
with no decoding, as #35 says, and it is the same function the compiler bakes
its granularity from, so `EMIT` in a generated module is the same value.

`None`, not `CONTIGUOUS`, for the other two: #35 verified that `None` carries
the *input's* adjacency forward and an explicit `CONTIGUOUS` overrides it.
The carry-forward is the right thing for a stage chained over a `units` file
(`DESIGN.md` §9.2) and is the one behaviour a test must pin, because it is
the one a future reader will "simplify" away.

### 3.2 A module without `EMIT` is refused, not defaulted

#36 asks for this and the reason is worth restating so it survives review: a
stale module writing `contiguous` over sub-byte fields is the exact silent
wrong statement the adjacency field exists to prevent. `run_compiled` raises
`CompileError`-class (whatever `stage.py` already uses for a malformed
module; if nothing, a `TypeError` naming the constant) with a message that
says `EMIT`, says the module predates it, and says `kober compile`. It does
not fall back to sniffing `MESSAGE_CONTENT_TYPE` / `TEXT_CONTENT_TYPE`, which
is the recoverability #36 rejects — a field module with no text exports
neither.

`EMIT` is the `Emit` value's *string* (`"message"`, `"field"`, `"none"`),
because a generated module imports `kober.runtime` only and must not grow a
dependency on `kober.spec` for one constant. `run_compiled` turns it back
into `Emit(module.EMIT)` and hands it to §3.1's function.

This is **Breaking** for the compiled path and goes in the changelog as such:
every module compiled by `0.2.0` must be regenerated. `tests/compiled_dns.py`
is one, kept as reviewable source, and is regenerated in the same change.

### 3.3 `DESIGN.md` §14.3 stays true; `--help` gets one clause

§14.3 says granularity "is a compile-time choice, not a flag the module
carries", restated in `kober compile --help`
([`cli.py:149-151`](../src/kober/cli.py)). The decision that sentence records
is that a module does not *switch* granularity at runtime — at `message` it
builds no field paths at all. `EMIT` switches nothing; it records which way
the module was built, as `NAME` and `VERSION` record which spec. The
wording is adjusted so it cannot be read as forbidding the constant:
"a compile-time choice — the module records it in `EMIT` but cannot change
it; at message granularity it builds no field paths at all."

### 3.4 #31 is in the milestone, because #39 cannot be done without it

#39 asks for "one check for `Remaining` and `Fill` together, walking unit
references transitively, so #31 and this are one fix rather than two that
could disagree." #31 was not on the milestone when the seven were filed.
Doing #39 alone would mean writing the transitive walk, the "terminal unit"
notion and the refusal message for `fill` and then leaving `remaining` — the
*simpler* case of the same rule, with no check at all today — unhandled
beside it. That is the asymmetry #31 complains about, preserved on purpose.
So #31 was added to the milestone (2026-09-19) and the spec-level check
covers both keys in one pass.

The shape, stated once so the two do not drift:

- A field is **terminal** if its size is `Remaining` or `Fill` (through
  `_walk_types`, so a `switch` arm counts), or it references a unit that is
  terminal. A unit is terminal if any of its fields is. Compute the unit set
  by fixpoint over `spec.units`, with the `seen` guard `_trailing_bits`
  already uses for recursion.
- A `Remaining`-sized field with any field after it in its unit is an error
  naming both. A `Fill`-sized field's trailing fields are its trailer and
  are allowed — that is what `fill` is for — and `_check_fills` keeps
  refusing a trailer it cannot size.
- A field that references a terminal unit from anywhere but the last
  position of its own unit is an error, in packeteer's words, since they
  name everything the author needs at the line they need it on:
  *`'body' is unit 'inner', which reads to the end of the message through
  'data', but 'trailer' is decoded after it and would have no bytes left`*.
  The message names the innermost reaching field, found during the walk.
- A `Remaining` under a `repeat` is an error outright, as a repeating `fill`
  already is.
- Errors, not warnings: no input decodes such a spec, so there is nothing
  for an author to weigh. `input: stream` changes nothing about the rule.

**Decode-time verdict is left alone in this release.** #31's second point —
that `truncated` is a hole-class misdiagnosis for a spec fault — is real, but
once `check` refuses the spec it is reachable only through
`Decoder(spec, check=False)`. Changing what the decoder reports for a spec
the checker rejects is a separate decision and is not what either issue's
"what to do" section asks for. Say so in the changelog entry.

### 3.5 What is *not* decided per spec: containment

#33 offers "`UNITS` iff the spec's field tree has containment" as the truer
statement for a flat spec. #35 declines it, and this plan agrees: the walk
order is not a continuity claim even when the leaves happen to abut, and a
predicate over `emit` overrides, sub-byte runs, `computed` and `pointer` is a
fragile thing to maintain for a distinction no consumer can use. `UNITS`
asserts less and is never wrong. Recorded here so it is not reopened.

### 3.6 Keep `_Writer._seam` under `units`

The spec says the Discontinuity block stays permitted in a unit sequence,
both drivers share `_Writer`, and a branch to suppress it under `UNITS`
would be a second code path through the one place seams are decided. Keep
it. The tests in `test_stage.py` and `test_emit_conformance.py` keep
asserting that the checker accepts `Seam` + `units` together, which is the
only thing that could go wrong.

### 3.7 `requires-python` stays `>=3.11`

`python-zipline` went to `>=3.10` in 0.4.0. #34 found no 3.11-only construct
here, so following is possible; it is also unasked-for, untested (the venv
is 3.14), and not part of alignment. Leave it.

---

## 4. The work, issue by issue

### Step 0 — `0.3.0.dev0`

`pyproject.toml` version → `0.3.0.dev0`. Refresh the editable `zpf` install
(§2). Confirm `.venv/bin/pip show zpf` says `0.5.0` and the suite still
passes — it should, unchanged, which is #34's finding reproduced locally.

### #34 — the pin

Files: [`pyproject.toml`](../pyproject.toml) (`dependencies`, the comment
above it, `[project.urls] Specification` → `blob/v0.21/`),
[`README.md`](../README.md) *Development* (three `0.3.0`s), 
[`docs/dev/contributing.md`](../docs/dev/contributing.md) (same paragraph),
[`DESIGN.md`](../DESIGN.md) §9.1 (~line 968, the pin stated as current fact).
Leave `docs/dev/architecture.md:185` and `src/kober/emit.py:9` — they say
`role` was *added* in 0.3.0, which stays true.

The new comment gives the new reason: the floor is `0.5.0` because
`adjacency=` on `decode_stage` landed there; the ceiling is the `0.x`
one-minor rule, as before.

Changelog: `Changed`, **Breaking:** required `zpf` moves from `0.3` to `0.5`;
a caller on `zpf 0.3` must upgrade; any kept `.zpf` is regenerated, not
transcoded, since `0.5.0` refuses `0.3.0`'s files at the gate. Note that
`0.4.0` and `0.5.0` change nothing else kober touches, so a reader knows the
jump is the version gate and one new field.

### #35 — the interpreter declares `units`

Files: [`src/kober/stage.py`](../src/kober/stage.py) — add `_adjacency()`
(§3.1), pass it from `run()`; the module and `_Writer` docstrings say why
field granularity is a unit sequence (the three shapes: sub-byte, computed,
pointer) and why message granularity passes `None` rather than `CONTIGUOUS`.
[`src/kober/decoder.py`](../src/kober/decoder.py) `Decoder.run` docstring:
what the output declares. No signature changes anywhere.

Tests, each reverted-and-watched-to-fail per `CLAUDE.md`:

- field-granularity `run()` over a transport input → participant
  `adjacency is UNITS`; message-granularity → `CONTIGUOUS`.
- message-granularity `run()` over a `units` input → `units` (the
  carry-forward; fails if `None` becomes `CONTIGUOUS`).
- the consumer idiom: `for unit in view.units(): if isinstance(unit,
  zpf.Break)` yields `declared=False` between every pair of field records
  and `declared=True` after a hole.
- `test_emit_conformance.py`, `test_stage.py`: `Seam` + `units` accepted.

`pressure_test.py`: Q6 — *can a per-field file say its records do not join,
and does a stage chained over it keep saying so?* — with the answer, since
that script is the record of what this project needs from `zpf` and this is
now on the list.

Docs: `DESIGN.md` §5 *Seams* gains the wholesale form beside the per-seam
rule and says why field granularity takes it;
[`docs/dev/decisions.md`](../docs/dev/decisions.md) *Upstream issues* gets a
row for zipline#106 — the only format-level issue kober's files raised, and
the table currently lists `python-zipline` ones only.

Changelog: `Changed` — field-granularity output declares `adjacency=units`.
Not breaking for a reader; a test elsewhere comparing projected JSONL sees
`"adjacency":"units"` on those lines.

### #36 — the module says what it is

Files: [`src/kober/pygen.py`](../src/kober/pygen.py)
`_granularity_constants` — emit `EMIT = "<value>"` after `VERSION`, for all
three granularities, with the comment #36 drafts.
[`src/kober/stage.py`](../src/kober/stage.py) `run_compiled` — read `EMIT`,
refuse its absence (§3.2), pass `_adjacency(Emit(module.EMIT))`; the
docstring's list of what a module must provide grows by one.
[`src/kober/cli.py`](../src/kober/cli.py) `--emit` help and `DESIGN.md` §14.3
(§3.3). Regenerate [`tests/compiled_dns.py`](../tests/compiled_dns.py).

The differential. #35 and #36 both say `tests/fuzzing.py`, but that file is
the mutation library; the comparison that runs a spec both ways through a
real stage is
[`tests/test_compiled.py::blocks()`](../tests/test_compiled.py), and it
collects `Record` and `Undecoded` blocks only — a participant line is
invisible to it. Add the `Participant` block's `adjacency` to what `blocks()`
returns, so `test_the_same_records_are_written_for_dns` / `_http` and
`test_every_prefix_writes_the_same_records` fail if the two derivations ever
disagree. That is one edit to one helper and it covers every existing
differential case at both granularities.

Also: a generated-module test that a `field` module with no text field
exports `EMIT` (the case that had nothing before), the `ruff` pass over
generated source, and a test that `run_compiled` refuses a module lacking
`EMIT` with a message naming it.

Changelog: `Added` — generated modules export `EMIT`. `Changed`,
**Breaking:** `run_compiled` requires it; regenerate with `kober compile`.

### #39 and #31 — the terminal-unit check

Files: [`src/kober/check.py`](../src/kober/check.py) — one new pass beside
`_check_fills` implementing §3.4, sharing `_walk_types` / `_size_of` and the
recursion guard. Nothing in `loader.py`, `decoder.py` or `pygen.py` changes.

Tests, each reverted-and-watched: `remaining` not last in its unit; `fill`
in a unit referenced before a trailer (#39's spec); both of those two levels
deep; `remaining` under a repeat; a `switch` with a `remaining` arm followed
by a field; and the case that must keep passing — a unit with a `fill`
referenced from the last position, which is the ordinary and correct use,
and is what `examples/` already do. Run `kober check` over `examples/*.yaml`
and `tests/packeteer/*.yaml` as part of the test to prove nothing shipped is
refused.

Changelog: `Fixed`, one entry for both issues, noting that the decode-time
verdict for a spec run with `check=False` is unchanged.

### #37 — the vendored specs

Copy `sensor.yaml` and `rpc.yaml` from `../packeteer/examples/protocols/` at
`v0.16.0`; bump the version in
[`tests/packeteer/README.md`](../tests/packeteer/README.md).
[`tests/test_packeteer.py`](../tests/test_packeteer.py): the `Foreign`
`where`/line assertions for `sensor.yaml` move with the short-form rewrite.
Replace `test_the_other_spec_is_still_blocked_by_the_dispatch_key` with: it
loads; `check` reports exactly the four foreign keys plus the no-default
`switch` warning and no errors; it **decodes** a switch-dispatched message,
since the construct that was blocked is the one to exercise.

[`plans/PACKETEER-ALIGNMENT.md`](PACKETEER-ALIGNMENT.md): add a state
paragraph at the top recording that every item is discharged — §3.1–3.3 in
kober 0.2.0, §5.1–5.3 in packeteer 0.13.0 — the way the 0.2.0 plan was
closed in `3dbe654`. Update the README table's description to match.

No changelog entry of its own (test-only); the pin bump rides on #38's
`Documentation` entry.

### #38 — the reference

[`docs/format/document.md`](../docs/format/document.md) *What still does not
transfer* → replaced with what actually does not, checked against packeteer
0.16.0 and, for the constructs kober-side, against #37's test:

- **Declined by packeteer, reported as not supported yet:** `pointer`,
  `select`, `computed`, delimiter framing in either spelling, `until` /
  `to_end` repeats, unit `params` / `args`, `confirm` / `reject`, `emit`,
  recursive units, `input: stream`. On `examples/dns.yaml` four named errors;
  `examples/http.yaml` refused outright.
- **Accepted differently:** sub-byte runs (packeteer requires whole bytes;
  kober cites the containing byte, `PACKETEER-ALIGNMENT.md` §4); `fill`
  before a `switch` (kober accepts when every arm agrees on a width;
  packeteer refuses).
- **A different default:** `input` omitted means `datagram` there and
  `either` here.

Verify each "declined" claim against the live packeteer before writing it —
the section being replaced was true when written too. `docs/format/index.md:12`
still describes the page; leave it. Changelog: `Documentation`, carrying the
note that the vendored copies and the test now track packeteer 0.16.0.

---

## 5. Definition of done

- `ruff check` clean; `.venv/bin/pytest` green; `sphinx-build -W` clean.
- **The decode is unchanged.** For every spec in `examples/` and every
  differential case, the sequence of `Record` and `Undecoded` blocks a
  `0.3.0` stage writes is identical to `0.2.0`'s; the only file-level
  difference is the participant descriptor's adjacency byte at field
  granularity. `blocks()` extended per #36 is what proves the two drivers
  agree; a before/after diff of projected JSONL on `dns_example` is what
  proves nothing else moved.
- `kober check` accepts every spec in `examples/` and `tests/packeteer/`
  after #39 — the new refusal must not catch the correct use of `fill`.
- `tests/compiled_dns.py` regenerated and reviewed as source.
- Every regression test was reverted-and-watched.
- `CHANGELOG.md` `Unreleased` carries: `Added` (EMIT), `Changed` (pin —
  breaking; `units`; `run_compiled` requires EMIT — breaking), `Fixed`
  (#31/#39), `Documentation` (#38, with #37's note).
- `plans/PACKETEER-ALIGNMENT.md` and `plans/README.md` record their state.

---

## 6. Releasing

1. Refresh the sibling venvs' editable `zpf` (§2) and run the deeper fuzz
   pipeline from the README's *Fuzzing* section against `0.5.0`: `packeteer`
   0.16.0 → `zpfwire` 0.3.0 → kober → `zpf` conformance, at both
   granularities, plus `packeteer stream --payload http` chunked and
   `--payload dns` with a compressed `raw:` response. `CLAUDE.md` requires
   this before a release and it is the only thing that reaches the stage
   driver, which #35/#36 touch.
2. `CHANGELOG.md`: `Unreleased` → `[0.3.0] - <date>`, fresh `Unreleased`,
   link definitions.
3. `pyproject.toml`: drop `.devN`.
4. Tag `v0.3.0`.
5. Close #31, #33–#39 and the milestone — at release, not at merge.

---

## 7. What the milestone deliberately leaves out

- **#32** (a disagreeing constant should decline the stream, not end one
  message). A decode-semantics change with its own argument; not alignment,
  and not in the milestone. Left where it is.
- **The decode-time verdict for a non-final `remaining`/`fill`** (§3.4).
- **A per-spec containment predicate** for `contiguous` on flat specs (§3.5).
- **Suppressing `Seam` under `units`** (§3.6).
- **`requires-python >= 3.10`** (§3.7).
- **The `unit-sequence-nested` shape** — a container emitted whole *and* its
  children. #35 notes kober does not produce it (`_walk` never emits a
  container) and that the case for `units` does not depend on it. Nothing
  here asks for it.
