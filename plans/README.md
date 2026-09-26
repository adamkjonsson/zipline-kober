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

## Analyses

| Document | What it is |
| --- | --- |
| [`CODEGEN-ANALYSIS.md`](CODEGEN-ANALYSIS.md) | Measured comparison of interpreting a spec against compiling it, and a sizing of the work. The evidence behind the compiler phase. |
| [`SIMPLIFICATION-IMPACT.md`](SIMPLIFICATION-IMPACT.md) | What the spec repository's `0.18` simplification analysis would do to this project, proposal by proposal, and which `zpf` port to take next. |
| [`FORMAT-ERGONOMICS.md`](FORMAT-ERGONOMICS.md) | Why writing a spec still costs too much typing after `0.1.0`'s shorthands: the dialect the docs teach, the four constructs that carry the remaining verbosity, what each is worth, and whether YAML is the culprit. |
| [`PACKETEER-ALIGNMENT.md`](PACKETEER-ALIGNMENT.md) | What kober should take from packeteer's dialect of the same format, what it should decline, and the finding that neither project loaded the other's examples. Discharged on both sides by kober 0.2.0 and packeteer 0.13.0; the header records how. |

## Phases

| Document | What it is | State |
| --- | --- | --- |
| [`SPEC-MODEL-PHASE.md`](SPEC-MODEL-PHASE.md) | The spec model, expression language, loaders, checker, and the `check`/`show` CLI verbs. | **Done** — landed on `spec_model_and_more`. |
| [`DECODER-PHASE-PLAN.md`](DECODER-PHASE-PLAN.md) | The decoder: expression evaluation, the `Node` tree, emission, the stage driver, and the `run`/`try` CLI verbs. | **Done** — landed on `decoder_work`. |
| [`REAL-CAPTURE-PHASE-PLAN.md`](REAL-CAPTURE-PHASE-PLAN.md) | Real captures through `zpfwire`: DNS, HTTP, and packet loss, to test the design rather than the code. | **Done** — landed on `real_captures`. |
| [`DOCS-PHASE-PLAN.md`](DOCS-PHASE-PLAN.md) | The documentation tree, following `python-zipline`'s style: developer docs first, then the spec-format reference. | **Done** — landed on `docs_phase`. |
| [`COMPILER-PHASE-PLAN.md`](COMPILER-PHASE-PLAN.md) | A compiler alongside the interpreter: a spec becomes a Python module with a typed API. | **Done** — landed on `compiler_phase`. |
| [`POINTER-PHASE-PLAN.md`](POINTER-PHASE-PLAN.md) | The two things real captures asked for and the language could not say: the `Pointer` construct, and the expression language's first functions. | **Done** — landed on `pointer_phase`. |
| [`REPETITION-PHASE-PLAN.md`](REPETITION-PHASE-PLAN.md) | A way for a spec to ask a question about a repeated field, so HTTP can choose its own body framing instead of assuming one. | **Done** — landed on `repetition_language_phase`. |
| [`DIALECT-PHASE-PLAN.md`](DIALECT-PHASE-PLAN.md) | The `0.2.0` milestone: the remaining shorthands, source locations on faults, and the packeteer keys kober should recognise rather than refuse. | **Done** — landed on `implement_v0.2.0`, shipped in `v0.2.0`. §9 records what the plan got wrong. |
| [`UPSTREAM-ALIGNMENT-PHASE-PLAN.md`](UPSTREAM-ALIGNMENT-PHASE-PLAN.md) | The `0.3.0` milestone: `zpf` 0.5.0 / spec 0.21 (`adjacency=units` for field-granularity output, from both drivers), packeteer 0.16.0 (vendored specs, the reference's transfer section), and the terminal-unit rule for `fill` and `remaining`. | **Done** — landed on `plan_0_3_0`, shipped in `v0.3.0`. §8 records what the plan got wrong. |
| [`VERDICT-PHASE-PLAN.md`](VERDICT-PHASE-PLAN.md) | The `0.4.0` milestone: stream confirmation (a stream that fails before its first whole message, or never has one, is declined rather than retried), the entry unit's `emit` honoured by both backends, `undecodable` rather than `truncated` for a field starved under `check=False`, and the deeper pipeline as a checked-in script. | **Done** — landed on `plan_0_4_0`, shipped in `v0.4.0`. §9 records what the plan got wrong. |
| [`TRANSFORM-PHASE-PLAN.md`](TRANSFORM-PHASE-PLAN.md) | Byte transforms — decompression and decryption: a `transform` construct over already-decoded bytes with an optional in-place sub-decode, `concat` for chunked input, a declared-in-spec / registry-supplied split that keeps `check` static, and `params_digest` for keys. | **In progress** — Stage 0 and the Stage 1 spike done; Stages 1b (#49, phantom messages after a gap) and 1c (#50, `startswith`/`endswith`) done; the spike's three decisions made; Stage 2 (the constructs, loaded and checked) done; Stage 3 next. |
