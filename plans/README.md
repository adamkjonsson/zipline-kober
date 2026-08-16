# Plans

Working documents: the phase plans that carried this project from a design to a
working decoder. They are kept because they record *why* a thing was built the
way it was — an argument that neither the code nor the commit log states in
full — and what was known at the time the decision was made.

**They are historical, not normative.** A plan describes what was intended when
it was written. Where a plan disagrees with the code, the code is right; where
it disagrees with [`DESIGN.md`](../DESIGN.md), `CLAUDE.md`, or
[`CHANGELOG.md`](../CHANGELOG.md), those are right. Nothing here is maintained
after the work it describes has landed — a finished plan is a record, not a
to-do list, and is marked as such rather than edited into agreement.

The live records stay in the project root:

- [`DESIGN.md`](../DESIGN.md) — the design itself, and the only normative
  statement of the model, the decode semantics, and the public API. Plans cite
  it by section; it does not cite them.
- [`CHANGELOG.md`](../CHANGELOG.md) — what actually shipped.
- [`pressure_test.py`](../pressure_test.py) — the executable probe of `zpf`
  behaviour this project depends on, and the source of every **[verified]**
  claim in the design.

## Phases

| Document | What it is | State |
| --- | --- | --- |
| [`SPEC-MODEL-PHASE.md`](SPEC-MODEL-PHASE.md) | The spec model, expression language, loaders, checker, and the `check`/`show` CLI verbs. | **Done** — landed on `spec_model_and_more`. |
| [`DECODER-PHASE-PLAN.md`](DECODER-PHASE-PLAN.md) | The decoder: expression evaluation, the `Node` tree, emission, the stage driver, and the `run`/`try` CLI verbs. | **Done** — landed on `decoder_work`. |
| [`REAL-CAPTURE-PHASE-PLAN.md`](REAL-CAPTURE-PHASE-PLAN.md) | Real captures through `zpfwire`: DNS, HTTP, and packet loss, to test the design rather than the code. | **Done** — landed on `real_captures`. |
| [`DOCS-PHASE-PLAN.md`](DOCS-PHASE-PLAN.md) | The documentation tree, following `python-zipline`'s style: developer docs first, then the spec-format reference. | **Live** — the current phase. |
