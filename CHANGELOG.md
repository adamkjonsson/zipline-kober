# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## Versioning

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While below `1.0`, breaking changes are allowed in a minor bump (`0.7` → `0.8`)
and are always called out.

The version is declared once, in `pyproject.toml`;
`kober.__version__` reads it back from the installed distribution
metadata. During development of the next release it carries a `.devN` suffix,
which the release commit drops.

The `zpf` version this depends on is a separate number. Because that library is
in `0.x`, where every minor is a break with no upgrade path promised, this
project pins a single `zpf` minor at a time; moving to a new one is always a
minor bump here too.

## [Unreleased] — 0.1.0, in development

Nothing is released yet: `pyproject.toml` declares `0.1.0.dev0` and no version
has been tagged. The section becomes `## [0.1.0] - <date>` when it ships.

Depends on `zpf` `0.2.x`, which implements Zipline Payload Format **v0.16**.
`zpf` `0.2.0` is released and tagged; until it reaches PyPI it has to be
installed from a checkout (see the README).

### Added

- `pyproject.toml`, packaging `kober` with a `kober` console script and an
  optional `yaml` extra for spec authoring.
- `DESIGN.md` — draft design: the spec model, decode semantics, emission
  granularity, and the public API, with the parts verified against `zpf` marked
  as such.
- `pressure_test.py` — an executable probe of `zpf` behaviour a spec-driven
  decoder depends on: stage chaining, overlapping spans, `prim:` payload
  normalization, message timestamps, and per-field record naming. Intended to
  seed the test suite.

- `kober.errors` — the exception hierarchy: `KoberError`, `SpecError`, and
  `ExprError`, which carries the offending expression text and its location.
  The split is by *when* a fault is detectable, and there is deliberately no
  decode-time tier: a decoder that cannot read its input records an undecoded
  region rather than raising, because an exception would leave the input
  outside the coverage guarantee (`DESIGN.md` §2).

- `kober.expr` — the expression language of `DESIGN.md` §3.3: a frozen AST,
  a parser, type inference against a `Scope` protocol, and `unparse`.
  Parsing borrows `ast.parse` in `eval` mode and accepts a whitelist of node
  types, so "no calls, no loops" holds by construction rather than by rule.
  Two departures from Python, both because the language has no float type:
  `/` is integer division (as is `//`), and a float literal is a parse error.
  `and`/`or` require boolean operands — there is no truthiness — and chained
  comparisons are refused with a message saying to use `and`.

- `kober.spec` — the spec model of `DESIGN.md` §3 as frozen dataclasses:
  `Spec`, `Unit`, `Field`, `Param`, `EnumDef`; the field types `IntType`,
  `BytesType`, `StringType`, `UnitRef`, `Switch`, `Computed`; the sizes
  `Fixed`, `FromExpr`, `Terminated`, `Remaining`; the repeats `Count`,
  `Until`, `ToEnd`; and the enumerations `InputShape`, `Endian`, `Emit`.
  Construction validates only what one object can see by itself — an integer
  width in 1..64, a non-negative size, a non-blank name, no duplicate field
  names — so a constructed `Spec` is *well formed*, not *valid*; everything
  needing the whole spec in view belongs to the checker. Sequences normalize
  to tuples and mappings to read-only views, so a loaded model cannot be
  mutated behind its owner's back.

  Two additions to what §3 spells out. `Unit` gains an `emit` field, because
  `Field.emit` is documented as inheriting "from the unit" and the unit had
  nowhere to hold it; granularity now resolves field → unit → decoder.
  `Param.type` is an `ExprType`, which §3 left unspecified — parameters are
  referenced from expressions, so that is the vocabulary they need.

- `kober.check` — whole-spec validation: `check(spec)` returns a tuple of
  `Finding`, each with a `Severity`, a dotted location, and a message. It
  **collects rather than raises**, so an author fixes a spec once instead of
  one fault per run, and an empty result means the spec is valid.

  It resolves and types every expression against Kaitai-style scoping (`this`,
  `parent`, `root`, bare names, unit parameters) and enforces that a field may
  reference only fields declared *before* it. `parent` resolves against every
  site that references the unit and must resolve at all of them, using each
  site's field position, so a child cannot rely on a parent field that is not
  decoded yet. `root` deliberately has no ordering rule, since how much of the
  entry unit has been decoded at arbitrary depth is not statically knowable.

  Also reported: an `entry` that names no unit or takes parameters, unknown
  unit and enum references, unit-argument count and type mismatches, duplicate
  parameter names, switch keys that disagree with the type dispatched on, a
  switch on something other than int or str, references to repeated fields
  (there is no list type) and to switch fields (no single type), and recursion
  that cannot consume input and so cannot terminate. Warnings cover units
  nothing reaches, units with no fields, and a switch with no default — which
  is legal, and makes an unmatched value an undecodable region.

  Two scoping rules worth naming: an `until` expression sees the field it
  repeats, meaning *the element just decoded* rather than the list, and that
  exemption is narrow — any other repeated field is still refused. Anonymous
  fields are unreferenceable by construction, which is what makes them safe
  for padding and reserved bits.

- `kober.loader` — `from_dict`, `from_json`, `from_yaml`, and `from_file`
  (dispatching on `.json`/`.yaml`/`.yml`), surfaced as `Spec.from_dict`,
  `Spec.from_json`, `Spec.from_yaml`, and `Spec.from_file` per `DESIGN.md` §6.
  The core parses the model, so everything but YAML is stdlib-only; YAML stays
  the optional `yaml` extra, imported lazily, `safe_load` only, and its absence
  reports the install command.

  The schema is strict: an unknown key is an error, because a misspelled
  `conditon:` that loads and does nothing is a decoder that silently does the
  wrong thing. Errors carry a path (`spec.units.message.fields[0].type`).
  YAML's implicit typing is guarded by name — `version: 1.10` and an unquoted
  `yes` are refused with a message saying to quote it, rather than becoming a
  float and a boolean.

  A type is a single-key tagged mapping (`{int: {bits: 16}}`), as are sizes and
  repeats, with two shorthands: a bare integer size means `fixed`, and a bare
  string means a unit reference with no arguments. Enum members and switch
  cases are the one place keys are not strings — JSON can only spell `1` as
  `"1"` while YAML gives an integer, and both mean the same case.

- `kober.cli` — the `kober` console script, with two verbs. `kober check SPEC`
  validates and types a spec, printing errors to stderr and warnings to stdout,
  and `--strict` makes warnings fail too. `kober show SPEC` prints the field
  tree, expanding nested units in place and guarding against recursion. Exit
  codes are `0` success, `1` the spec is unusable, `2` a bad command line.

  `run` and `try` from `DESIGN.md` §6 are deliberately **not** registered: they
  need the decoder, and a verb that exists and refuses is a worse answer than
  one that is honestly absent. `--help` says when they are coming.

- `kober` — the package now re-exports the public API: `Spec` and the rest of
  the model, `check`, `Finding`, `Severity`, `ExprType`, the loaders, and the
  exception hierarchy.

### Changed

- The `zpf` requirement is now `>=0.2.0,<0.3`, up from `>=0.2.0.dev0,<0.3`.
  The `.dev0` floor existed only so an unreleased local checkout could satisfy
  it, and `zpf` `0.2.0` is now released and tagged. Tightening it is also a
  correctness fix: `comment=` on both `record()` methods landed *in* `0.2.0`,
  so a dev build predating that change satisfied the old floor while lacking
  the API this project is built on. Not a breaking change for anyone — no
  release of this project has shipped.

### Documentation

- `README.md` — replaced the "nothing is implemented yet" banner with what
  actually works today, and added worked `check` and `show` output plus the
  API equivalent.

- `DESIGN.md` revision 5 — corrected the reasoning in §2. It justified the
  declarative spec model with "if specs could run code they could swallow
  input, so because they can't, coverage is provable from the spec alone",
  which contradicts its own opening paragraph: `fill_undecoded=True` makes
  coverage true by construction whatever the spec looks like. New §2.1 states
  the two things that are actually true — every construct has a *total,
  declared failure behaviour*, and **nothing author-supplied may move the read
  cursor** — and draws the line at the cursor rather than at
  declarative-versus-code. Framing and consumption stay declarative because
  coverage analysis reasons over them; value computation cannot affect coverage
  at all, because the bytes are already claimed.

  Consequences recorded with it: §11 question 2 is **closed, keeping
  `Computed`**, which consumes nothing and so was never the thin end of a
  wedge; §3.3's minimal expression language is reframed as a choice about cost
  and portability rather than a safety requirement; and a new §11 question 5
  separates the three things called "specs-as-code" (richer expressions, hooks,
  a builder DSL), noting that §6's `decode_stream` already permits mixing code
  with spec-driven decoding, so the open question is the seam's granularity
  rather than whether code is allowed. The module docstrings of `kober.spec`,
  `kober.check`, and `kober.expr` are corrected to match.

- Upstream findings from the pressure test filed against `python-zipline`, all
  three now fixed and released in `zpf` 0.2.0:
  [#55](https://github.com/adamkjonsson/python-zipline/issues/55) (no
  `comment=` on `record()`, which blocked per-field decoded records),
  [#56](https://github.com/adamkjonsson/python-zipline/issues/56) (decoded
  inputs are packet-oriented, undocumented), and
  [#57](https://github.com/adamkjonsson/python-zipline/issues/57)
  (`check_coverage` raises an internal `AttributeError` for a `FileReader`).

- `DESIGN.md` revision 4 — `Emit.FIELD` is unblocked: a per-field record now
  carries its field path in `comment=`, keeping `prim:`'s normative typing,
  which retires the `dec:dns.header.id` fallback revision 3 proposed. The
  mechanism is a stopgap by upstream's own description — `comment` is free text
  no consumer may depend on — so the field-path formatting stays confined to
  one emit site against
  [#58](https://github.com/adamkjonsson/python-zipline/issues/58), and nothing
  parses `comment` back. Whether to follow `zpf` 0.3 (#58, #59) is recorded as
  an open question rather than settled.

[Unreleased]: https://github.com/adamkjonsson/zipline-kober/commits/main/
