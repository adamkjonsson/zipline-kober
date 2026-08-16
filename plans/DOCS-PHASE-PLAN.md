# Phase plan: documentation

**State: done** (bar the deferred user docs). Written after the real-capture phase landed
([`REAL-CAPTURE-PHASE-PLAN.md`](REAL-CAPTURE-PHASE-PLAN.md)), against
`DESIGN.md` revision 6.

Follows `python-zipline`'s documentation style, which is the house convention:
Sphinx with MyST markdown, `furo`, `autodoc` + `napoleon`, `nitpicky = True`,
and a `docs/{dev,user,api}/` split.

## The ordering, and why

Developer documentation first, the spec format second, user documentation
deferred until the API settles. Two things worth stating about that.

**Scaffolding is step 0 and is not overhead.** There is no `docs/` directory.
`CLAUDE.md` has documented `sphinx-build docs docs/_build/html` as a standard
task since the scaffold, and it has never worked, which is its own small
argument for this phase.

**The spec format is the only thing with *zero* coverage today.** `DESIGN.md`
§3 documents the Python *model* — `IntType`, `SizeSpec`, `Repeat` — not the
YAML surface an author actually writes (`{int: {bits: 16}}`). That mapping
exists only in `loader.py`'s docstrings and two example files. It is second in
this plan rather than first because the developer docs capture a layering that
is fresh right now, and because a contributor needs the invariants before
touching anything — but it is closer to first than its position suggests.

**`docs/api/` is folded in early**, against the "users can wait" line, because
it is not user documentation in the tutorial sense. It is `autodoc` over
docstrings already written carefully in Google style, so it costs little and
serves a contributor more than a user. It will also do real work under
`nitpicky`: every cross-reference in our docstrings that does not resolve
becomes a build failure, and there are certainly some.

## What is being documented

Eleven modules, and the shape is a **pipeline with one purity boundary**
rather than a stack:

```
   loader.py ─→ spec.py ─→ check.py         the spec: data, validated
                   │
                   ▼
   cursor.py ─→ decoder.py ─→ node.py       the engine: bytes → tree
                   │
                   ▼
                emit.py                     pure: tree → what to write
                   │
                   ▼
                stage.py ───────────────→   the only module that imports zpf
                   │
                   ▼
                 cli.py
```

That boundary is the architectural fact most worth writing down: `decoder.py`
and `emit.py` touch no `zpf`, which is why both are testable without a file and
why `emit.plan()` is pure. `stage.py` exists so every assumption this project
makes about the format is auditable in one place.

## Stages

### Stage 1 — scaffolding — **done**

`docs/conf.py`, `docs/Makefile`, `docs/index.md`. Sphinx + MyST + furo +
autodoc + napoleon, `nitpicky = True` with a documented `nitpick_ignore` for
the categories that genuinely cannot resolve (standard-library names without
intersphinx, `tuple[X, ...]` annotations Sphinx splits on the comma). The build
command in `CLAUDE.md` must work when this stage ends.

### Stage 2 — `docs/dev/` — **done**

The priority. Four pages, mirroring `python-zipline`'s:

- **`architecture.md`** — the pipeline above, a module-map table, data flow,
  and the **design invariants**: the cursor rule (§2.1), the coverage
  vocabulary (§2), failure never escaping a decode, the single field-path emit
  site (§4.1), and shape dispatch coming from the stream rather than the spec
  (§9.2). A change breaking one of those is almost certainly wrong, and that
  should be written where a contributor will read it rather than inferred from
  `DESIGN.md`.
- **`testing.md`** — the test map, and the practice `CLAUDE.md` now records:
  fuzz tests are standard, a regression test is checked against the bug it
  claims to catch, and real captures and adversarial input are what verify the
  *design* rather than the code. The deeper `packeteer` → `zpfwire` → `kober`
  pipeline belongs here in full; the README carries only the short version.
- **`contributing.md`** — the venv, ruff, the changelog rule, the `noqa` rule,
  and the fact that `zpf` comes from a sibling checkout until it reaches PyPI.
- **`decisions.md`** — a short index pointing at where reasoning already
  lives: `DESIGN.md` for the design and its revisions, `plans/` for phase
  history, upstream issues for what is blocked on the format. Contributors
  currently have to know that `plans/` exists to find any of it.

### Stage 3 — `docs/api/` — **done**, pulled forward

The developer guide cross-references API symbols and these pages define them,
so stage 2 could not build without it. Two config decisions were needed beyond
`automodule`: `napoleon_use_ivar`, without which every frozen dataclass field is
documented twice, and ignoring the union aliases, which are module-level
assignments with no object for a reference to land on.

Original note:

One page per module, `automodule` with members. Expected to surface docstring
cross-references that do not resolve; fixing those is part of the stage.

### Stage 4 — `docs/format/` — **done**

The YAML/JSON spec-format reference, which is the product's real surface.

- **`index.md`** — the document shape: `name`/`version`/`entry`/`units`, and
  the single-key tagged-mapping convention that types, sizes, and repeats all
  follow.
- **`types.md`** — every field type, size, and repeat form, with what each
  does when it does not match, since §2 makes that half of every construct's
  meaning.
- **`expressions.md`** — the language: scoping (`this`/`parent`/`root`),
  the ordering rule, integer division, no truthiness, and what it deliberately
  cannot do (no string arithmetic — §13.2).
- **Traps**, which need saying because both have already bitten: `on:` is a
  YAML boolean and the loader repairs it; a `doc:` containing a comma inside a
  flow mapping silently becomes two keys.

### Stage 5 — deferred

`docs/user/` — tutorial, CLI guide, concepts. Waits for the API to settle,
per the request.

## Practice carried over

`python-zipline` runs its documentation's example scripts in the suite
(`test_tutorial_examples.py`) so they cannot rot. Anything executable in these
pages gets the same treatment — `tests/test_examples.py` already does it for
`examples/`, and the pattern extends.

## Acceptance

1. `.venv/bin/sphinx-build -W docs docs/_build/html` is clean — warnings as
   errors, so a broken cross-reference fails rather than rendering as text.
2. `docs/dev/` answers, without reading the source: what each module does,
   what may not be broken, how to run the tests, and where past reasoning
   lives.
3. `docs/format/` documents every key the loader accepts, and every trap it
   guards against.
4. Any code in the docs is executed by the suite.
5. `CLAUDE.md`'s documented docs build works.
