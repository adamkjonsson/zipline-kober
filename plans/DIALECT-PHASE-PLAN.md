# The dialect phase — `0.2.0`

> **Plan.** Written 2026-09-09 against `0.1.0` and the seven issues on the
> [`0.2.0` milestone](https://github.com/adamkjonsson/zipline-kober/milestone/1),
> whose statement is *focus on the syntax of spec files: add some
> simplifications to improve usability, and improve alignment with the
> corresponding syntax of packeteer.* It decides an order, resolves the
> decisions the issues left open where they interact, and records the one item
> the milestone does not contain.
>
> The arguments behind it are in [`FORMAT-ERGONOMICS.md`](FORMAT-ERGONOMICS.md)
> and [`PACKETEER-ALIGNMENT.md`](PACKETEER-ALIGNMENT.md). This does not repeat
> them; it schedules them.

---

## 1. What this release is

Nothing in this milestone changes what kober decodes. Every one of the seven
issues is about the surface an author writes and the messages they get back
when they write it wrong. That is worth saying at the top, because it is what
makes the release both cheap to verify and easy to get wrong: **the test for
almost everything here is that the `Spec` does not change.**

Three strands, plus a sweep:

| Strand | Issues | What it changes |
| --- | --- | --- |
| **Shorthands** | [#22](https://github.com/adamkjonsson/zipline-kober/issues/22), [#23](https://github.com/adamkjonsson/zipline-kober/issues/23), [#24](https://github.com/adamkjonsson/zipline-kober/issues/24) | The loader accepts shorter spellings of what it already accepts. Model untouched. |
| **Diagnostics** | [#25](https://github.com/adamkjonsson/zipline-kober/issues/25) | A fault says which file and line, not only which construct. |
| **Alignment** | [#26](https://github.com/adamkjonsson/zipline-kober/issues/26), [#27](https://github.com/adamkjonsson/zipline-kober/issues/27) | One packeteer key implemented; four recognised and declined out loud. |
| **The sweep** | [#21](https://github.com/adamkjonsson/zipline-kober/issues/21) | The reference is rewritten in the dialect the examples use. |

[#26](https://github.com/adamkjonsson/zipline-kober/issues/26) is the only one
that touches a decode, and the only one that reaches
[`decoder.py`](../src/kober/decoder.py) and
[`pygen.py`](../src/kober/pygen.py). Everything else stops at
[`loader.py`](../src/kober/loader.py),
[`check.py`](../src/kober/check.py) and the docs.

---

## 2. Order, and why

```
0.  version → 0.2.0.dev0
1.  #25  source locations           ← widest signature change; do it before the others add call sites
2.  #23  lifted repeat kind          ┐
3.  #24  short parameter form        ├ one rule, stated once
4.  #22  inherited endian            ┘
5.  #26  const on a field
6.  #27  foreign keys recognised     ← needs #26 decided, wants #25 for lines
7.  #21  the documentation sweep     ← absorbs every spelling the six above created
8.  release
```

**#25 goes first because it is the only one that rewrites call sites it does
not own.** Roughly 180 mentions of `where` across
[`loader.py`](../src/kober/loader.py), about 85 of them deriving a child path
with an f-string, all become a location. Every issue after it *adds* sites:
#23 adds a lifted-repeat path, #24 a second parameter spelling, #22 a defaulted
integer constructor, #26 a `const` read, #27 a foreign-key table. Adding them
against the new signature is free; adding them first means threading locations
through them afterwards, which is the same rework paid five times.

The secondary reason is [#27](https://github.com/adamkjonsson/zipline-kober/issues/27):
its whole output is warnings about keys in someone else's file, and a warning
about a foreign key is markedly more useful with the line on it.

**The risk of putting it first is that it is the largest single diff**, and if
it stalls, everything stalls. It does not have to: nothing in #22/#23/#24
depends on it *semantically*. If #25 turns out to be worse than it looks, drop
it to position 6 and pay the rework — that is a real cost, not a blocker.

**#21 goes last** even though it is the cheapest and the one
[`FORMAT-ERGONOMICS.md`](FORMAT-ERGONOMICS.md) §2 says should happen regardless.
Every issue before it changes what the short dialect *is* — #23 changes how a
repeat is written, #24 how a parameter is written, #22 what an integer field
may omit, #26 adds a key — and all of them land on the same three pages. Doing
the sweep first means writing `docs/format/concepts.md` twice. It also needs
the `show` and `try` transcripts re-run, and those are only worth running
against the final format.

The exception, stated so it is not mistaken for slippage: **each code issue
still adds its own row to the reference tables as it lands.**
[`tests/test_docs.py`](../tests/test_docs.py) reads the loader's key sets and
fails when one is undocumented, so a key cannot wait for the sweep even if the
prose can.

---

## 3. Three decisions the issues leave open

These are the parts that only appear when the seven are read together. Each
changes what gets built.

### 3.1 A location must not enter equality — and that is not a detail

Three issues rest on the same test: a spec written short builds the
**identical** `Spec` as one written long. #22, #23 and #24 each name it, and it
is what makes them shorthands rather than features.

Two texts that differ in spelling also differ in line layout. So if #25 puts a
line number anywhere that `Spec`'s frozen dataclasses compare on, **it breaks
the test that defines the other three.** The two halves of this release
collide in exactly one place, and this is it.

**Decision: locations never participate in comparison.** Whatever carries them
onto the model is `dataclasses.field(compare=False, repr=False)`. The equality
tests keep working unchanged, and they keep meaning what they say.

### 3.2 The checker cannot see lines unless something hands them over

[#25](https://github.com/adamkjonsson/zipline-kober/issues/25) says
`Finding.where` becomes a location. It does not say how `check` learns one, and
the answer is not obvious: [`check.py`](../src/kober/check.py) runs on a built
`Spec` and derives every `where` from model names —
`f"{self.spec.name}.{unit.name}.{label}"` — with the source document long gone.
The loader knows the lines. The checker does not, and there is no path between
them today.

Three ways to build one:

| | Cost |
| --- | --- |
| A `loc` attribute on `Field`, `Unit`, `Spec` | Every model object grows a field no consumer reads; `from_dict` must default it; §3.1's `compare=False` on each |
| A side table keyed by `id()` | Rejected for the reason packeteer's own docstring gives, quoted in #25: it leaks or it lies |
| **One dotted-path → `Location` map, on the `Spec`, non-comparing** | One field, one place, and the key is the string `check` already builds |

**Decision: the map.** `check` already computes the dotted path for every
finding it emits; a lookup on that path is the whole integration, and a miss
degrades to exactly today's message. It also gives JSON and `from_dict` the
right behaviour for free — an empty map, no lines, unchanged output — which #25
requires and which the standard-library-only path depends on.

### 3.3 Thread one context, not two parameters

[#25](https://github.com/adamkjonsson/zipline-kober/issues/25) threads a
location through `_field_type`, `_int_type`, `_switch` and `_pointer`.
[#22](https://github.com/adamkjonsson/zipline-kober/issues/22) threads a
default endian through *the same four functions*, and calls that plumbing "the
one argument against doing this".

Doing them as two parameters means changing those signatures twice and carrying
two threaded arguments forever. **Decision: #25 introduces a small internal
context object — location plus lexical defaults — and #22 adds a field to it.**
The second issue then costs a resolution rule and a constructor, which is what
it should have cost. The context is private to the loader; nothing in the model
or the public API learns about it.

Note the site that is easy to miss: `_field_type`'s `bits:` branch
([`loader.py:562`](../src/kober/loader.py)) builds an `IntType` **directly**,
without going through `_int_type`. It is the shorthand #22 exists to make
usable, so it is the one branch that must not be forgotten.

---

## 4. The work, issue by issue

Each entry states what is not obvious from the issue. The issues carry the
argument and the full landing list; this carries the additions.

### Step 0 — `0.2.0.dev0`

[`pyproject.toml`](../pyproject.toml) says `0.1.0` with no suffix, which is the
post-release state. Per `CLAUDE.md`, development of the next release carries
`.devN`. First commit on the branch, before anything else, so every build from
here identifies itself honestly.

### #25 — source locations

The bulk of the release. `Location(path, line, source)` with `child(step)` and
`at_line(n)`; a `SafeLoader` subclass recording `node.start_mark.line + 1` into
a `dict` subclass with a `line` slot.

- **Breaking, and it must be called out.** `Finding.where`
  ([`check.py:96`](../src/kober/check.py)) and `ExprError.where`
  ([`errors.py:69`](../src/kober/errors.py)) are both public and both change
  type. #25's open question leans to changing rather than adding a sibling, and
  below `1.0` that is allowed in a minor. Take the change; two ways to ask one
  question is the worse outcome.
- `Finding.__str__` renders `file:line: path: message` when it has them and
  `path: message` when it does not, so `cli.py` needs nothing.
- **The JSON and `from_dict` paths are not a degraded mode to tolerate — they
  are the standard-library-only path this project promises.** Test them as
  first-class: no line, message otherwise identical.

### #23 and #24 — the lifting rule

These are one change wearing two hats, and they should land as two commits on
one branch with a shared docstring.

#23 lifts `count` / `until` / `to_end` into the field; #24 lets a parameter be
`{high: int}`. Both are instances of the rule #16 established, and #23 asks for
it to be stated once rather than accumulating as special cases:

> a tagged construct's kind may lift into its parent where the key sets do not
> overlap

Write that sentence into the [`loader.py`](../src/kober/loader.py) module
docstring. It is now true of three constructs, and the next one should be able
to cite a rule rather than a precedent.

`_reject_unknown` for a field widens to `_FIELD_KEYS | _TYPE_KEYS |
_REPEAT_KINDS`. #23 is right that the error must then name *which set* a key
was expected in — three sets in one message with no structure is worse than the
two-set message it replaces.

#24's own open question — whether it is worth doing alone — is answered by this
plan: it is not, and it rides here.

### #22 — inherited endian

`endian` on the document and on the unit, resolved lexically into each
`IntType`. Given §3.3, the work is the resolution chain and the tests.

- `signed` does **not** inherit. #22's open question argues it and the argument
  holds: a protocol is little-endian; it is not *signed*.
- Verify `show`'s `" little-endian"` label against a spec where the default
  does the work. With inheritance in force that label is the only place the
  resolved answer is visible, which is the mitigation #22 offers for the cost
  it admits.

### #26 — `const`

The only issue that reaches a decode, and therefore the only one with real
risk.

- **A disagreeing constant makes the region `undecodable` and never raises.**
  That is the whole adaptation from packeteer, where it raises.
  [`tests/test_fuzz.py`](../tests/test_fuzz.py) already asserts that a decode
  never raises, which is precisely the invariant this construct is most likely
  to break — so the fuzz corpus must include a spec carrying a `const` before
  this is believed. Per `CLAUDE.md`, a new invariant of that kind gets a fuzz
  test, not just an example.
- The interpreter and the compiled decoder must agree, which is
  [`tests/test_compiled.py`](../tests/test_compiled.py)'s job:
  [`decoder.py`](../src/kober/decoder.py) records the verdict,
  [`pygen.py`](../src/kober/pygen.py) raises `Undecodable`, and the entry point
  turns it back into a region.
- `Field` gains `const` **appended after `doc`**, with a default. Every field
  after `type` already has one, so appending keeps positional construction
  working and the addition stays additive.
- `check` verifies the three faults #26 lists: the field's type holds a value,
  the constant's type matches, an integer constant fits its `bits`.
- DNS has no magic number, so this gets a test fixture rather than a forced
  example — and there is a better source than a fixture. packeteer `0.12.0`
  can generate traffic for a protocol given as a `packeteer protocol` spec, and
  `const` is packeteer's own key. **A generated protocol with a magic number,
  impaired and decoded here, tests the construct against the project it came
  from** rather than against our reading of it. That is the second kind of test
  `CLAUDE.md` says finds the bugs the first kind cannot.

### #27 — foreign keys

Recognise `over`, `ports`, `derive`, `sensitive`; decline them by name as
warnings. `const` leaves this list because #26 implements it — which is why #26
lands first.

- #27's open question is where the keys live, and it leans to a side list on
  the `Spec` rather than attributes on `Field`. **Take that**, and note it is
  the same shape §3.2 chose for locations: diagnostics the loader collects and
  the checker reads, kept off the model objects that decoding uses.
- **The fixtures are copies.** `sensor.yaml` and `rpc.yaml` get copied into
  `tests/`; the suite must not depend on `../packeteer` being checked out.
  Record which packeteer version they came from, in the fixture or beside it,
  or the test silently measures against a moving target.
- This closes [`PACKETEER-ALIGNMENT.md`](PACKETEER-ALIGNMENT.md) §5.3 from one
  side only. The other side — kober's shorthands loading in packeteer, and the
  `dispatch:` / `on:` disagreement in §5.1 — is packeteer's to schedule, and
  neither is a condition of this release.

### #21 — the sweep

Invert the presentation across `docs/format/concepts.md`, `document.md` and
`types.md`: the short form is the language, the long form is the escape hatch.

- The `show` and `try` transcripts in `concepts.md` are **re-run, not
  hand-edited**. The whole value of that section is that it is real output.
- Its open question — whether `document.md`'s tables should show the long form
  at all — is worth answering **yes, briefly**: one column, deferring the
  detail to `types.md`. Showing one form in a table and the other on the page
  it links to is how this happened, but a table with no long form leaves an
  author who meets `type: {int: …}` in an older spec with nowhere to look.
- By this point the sweep also has to carry #22's `endian` rows, #23's lifted
  repeat keys, #24's parameter form and #26's `const` section. That is the
  point of doing it last.

---

## 5. The examples, and a free proof

[`examples/dns.yaml`](../examples/dns.yaml) and
[`examples/http.yaml`](../examples/http.yaml) convert to the lifted repeat form
(#23), and `dns.yaml`'s one `params:` to the short form (#24), for the reason
#16 gave: an example that does not use the short form argues the short form is
not wanted.

**That conversion comes with a proof, and it is stronger than the equality
tests.** [`tests/test_pygen.py:87`](../tests/test_pygen.py) regenerates a module
from `examples/dns.yaml` and compares it against
[`tests/compiled_dns.py`](../tests/compiled_dns.py) *character for character*.
If the converted example produces a byte-identical module, then nothing
downstream of the loader saw the change — which is the claim #22, #23 and #24
each make about themselves, checked end to end through the compiler rather than
asserted about a dataclass.

So: **convert the examples, and expect zero diff in `compiled_dns.py`.** A diff
there is a bug in the shorthand, not a fixture to update.

---

## 6. What the milestone deliberately leaves out

[`FORMAT-ERGONOMICS.md`](FORMAT-ERGONOMICS.md) §3.2 — *a size is the only place
an expression is not a bare string* — has no issue and is not on the milestone.
It is the one item from that assessment that was not filed, and **it stays out
of `0.2.0` by decision, not by oversight.** Recorded here so the next release
finds a choice rather than a gap.

```yaml
bytes: {size: {expr: "rdlength"}}   # today
bytes: "rdlength"                   # proposed
```

The assessment calls it "the largest per-occurrence saving available", says it
removes two levels of nesting rather than characters alone, and counts four
occurrences across both shipped examples — where #24, which *is* on the
milestone, has one.

It is the one item here that carries a decision the others do not: **it
consumes the string slot**, so `size: remaining` and `size: fill` as bare words
become impossible afterwards. The assessment argues the expression is worth
more, and the occurrence counts back it — but that is a choice about the
format's future rather than a mechanical addition, and it is not one to make
alongside six changes that each promise the model does not move.

Everything else in this release can be checked by an equality test. This one
cannot: it would be the first thing in `0.2.0` to close a door. Keeping it out
keeps the release a single, verifiable claim — *shorter to write, better
diagnostics, same decode* — and leaves the string slot free for whoever argues
the case properly.

Left for a later release, on its own merits.

---

## 7. Definition of done

- [ ] `pyproject.toml` at `0.2.0.dev0` from the first commit, `0.2.0` at the last.
- [ ] Seven issues implemented; each has a `CHANGELOG.md` entry under
      `Unreleased` **in the change that introduces it**, not batched at the end.
- [ ] `Documentation` for #21; `Added` for #22, #23, #24, #26, #27; `Added`
      plus a `Breaking:` note under `Changed` for #25.
- [ ] `DESIGN.md` updated where the model and the public API changed: §3.1/§3.2
      for `const`, §6 for `Location`, `Finding` and the foreign-key records.
- [ ] Both spellings of every shorthand build an equal `Spec`, and
      `compiled_dns.py` is byte-identical after the examples convert.
- [ ] `tests/test_fuzz.py` carries a `const`-bearing spec, and the "a decode
      never raises" invariant still holds.
- [ ] A regression test for each fix is checked against the bug it claims to
      catch: revert, watch it fail, restore.
- [ ] packeteer's two examples load, producing exactly the expected warnings.
- [ ] `.venv/bin/pytest` clean; `ruff check` clean on every touched file;
      `.venv/bin/sphinx-build -W docs docs/_build/html` clean.
- [ ] The deeper fuzzing pipeline in the README run before the release — this
      release touches the loader, not the stage driver, so it is the release
      gate rather than a per-change one.

## 8. Releasing

Per `CLAUDE.md`, in order: rename `Unreleased` to `## [0.2.0] - YYYY-MM-DD` and
add a fresh empty one above it; drop `.dev0`; update the link definitions at the
bottom of `CHANGELOG.md`; tag `v0.2.0`; **then** close the seven issues and the
milestone. Issues close at release, not at merge — work sits on `main` under
`Unreleased` until it is in a release, and closing earlier claims a delivery
that has not happened.
