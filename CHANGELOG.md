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

- `kober.cli` — the `kober` console script, with all four verbs of
  `DESIGN.md` §6. `check SPEC` validates and types a spec, printing errors to
  stderr and warnings to stdout, with `--strict` to fail on warnings too.
  `show SPEC` prints the field tree, expanding nested units in place and
  guarding against recursion. `run SPEC IN.zpf -o OUT.zpf [--emit
  field|message] [--produced-by WHO]` decodes a file into a decode stage and
  reports what landed in it, counted by reading the output back rather than by
  trusting the writer. `try SPEC --hex 0a0b` decodes one buffer and prints the
  tree, with no file involved.

  Exit codes are `0` success, `1` the work could not be done, `2` a bad command
  line. The distinction that decides them: a spec that will not load or check
  is a failure, but input that will not fully decode is **not** — an
  undecodable or truncated region is a conformant result, so `run` reports it
  and exits `0`. `try` is the deliberate exception, since answering whether a
  spec reads some bytes is the point of it.

- `kober` — the package now re-exports the public API: `Spec` and the rest of
  the model, `check`, `Finding`, `Severity`, `ExprType`, the loaders, and the
  exception hierarchy.

- `kober.expr.evaluate(expr, env)` and the `Environment` protocol — the value
  side of the expression language, mirroring `infer_type` and `Scope`. It
  assumes the expression type-checked, since `check` proves that before any
  data exists, but still guards operands so a wrong type is refused rather
  than improvised (Python would make `"ab" * 3` a string; here it is an
  error).

  `and` and `or` short-circuit, which is load-bearing rather than an
  optimization: the language has no conditional expression, so
  `n != 0 and total / n > 5` is the only way to guard a division and it works
  only if the right side goes unevaluated. `/` and `//` are one operator and
  both floor — for the non-negative values that come off a wire, floor and
  truncation agree; they differ only on a negative operand, and this is the
  documented answer there.

- `kober.EvalError` — an expression could not produce a value *for this
  input*. Deliberately not a `SpecError`: a spec that divides by a length
  field is correct, and a packet carrying zero in it is what makes the
  expression unanswerable. The decode engine will catch it and mark the region
  `undecodable`; letting one escape a decode is a bug. Its cases are what a
  total, side-effect-free language still cannot rule out statically —
  division or modulo by zero, and a shift count that is negative or absurd.
  `1 << n` with `n` off the wire is a memory-exhaustion vector, so shift
  counts above `kober.expr.MAX_SHIFT` (1024) are refused rather than computed.

- `kober.node` — the in-memory decode tree: `Node` (name, value, byte range,
  status, children, and a link back to its spec field) and `NodeStatus`, whose
  members are exactly `DESIGN.md` §2's vocabulary with values that *are* the
  `reason=` strings `zpf` expects, so the emitter needs no mapping table.
  Deliberately not written to any file (§6) — it is what `decode_bytes`
  returns and what the emitter walks, and then it goes away.

- `kober.cursor` — a bit-level read cursor. It **owns the read position**,
  which is §2.1's invariant in code: every advance goes through a method, so
  bytes can only be consumed by being claimed. Positions are tracked in bits
  since integer widths need not be multiples of eight; citations are bytes,
  and `Cursor.span()` rounds a bit range *outward* to the containing bytes per
  §1 — which is what makes a flags word and the bits inside it legitimately
  overlap. Offsets are absolute: a cursor carries its run's `base`, which is
  the run-relative-to-stream translation the `chunks()` settlement requires.

  Bits are read most significant first; `Endian` applies only to whole-byte
  reads from an aligned position, because byte order is not a property a
  four-bit field has. Reading whole bytes from a half-consumed byte is
  **refused** rather than auto-aligned, since silently dropping the remaining
  bits is exactly the unclaimed-input failure §2 exists to prevent, and
  `align()` reports how many bits it skipped so the caller must account for
  them.

- `kober.Decoder` — the decode engine: `Decoder(spec).decode_bytes(data)`
  walks the spec over a cursor and returns a `Node` tree. Every field type,
  size, and repeat form; `condition`, unit parameters, `this`/`parent`/`root`
  references resolved against the tree being built; and `confirm`/`reject`,
  where a guess that did not hold becomes an honest `undecodable` region
  rather than a fabricated field tree.

  **Failure never raises out of a decode.** `TruncatedRead` and `EvalError`
  are caught and become a node status, because a decoder that raises leaves
  its input unaccounted for. Where a decode stops it says so: the root's
  `off_end` is how far it got, and the difference from the input's length is
  the tail the stage driver will account for. Two loops that crafted input
  could otherwise turn into hangs are bounded — a repetition whose element
  consumes nothing is refused as unable to terminate, and unit nesting past
  `MAX_DEPTH` (64) is abandoned rather than exhausting the interpreter stack.

  `Decoder` validates its spec by default and refuses to build on an error,
  since every guarantee the engine relies on is one `check` proves;
  `Decoder(spec, check=False)` skips it.

- `kober.emit` — turning a decode tree into records. `plan(spec, tree, data)`
  is **pure**: it returns the `Emission`s to write and the `Unclaimed` regions
  to mark, so every decision about *what* to write is testable without opening
  a file. `Emit.MESSAGE` produces one `dec:<spec>-message` record per
  instance; `Emit.FIELD` one record per leaf, normalized into `prim:`'s
  little-endian with the field path in `comment=`; `Emit.NONE` claims nothing
  and says `skipped` out loud rather than leaving it to auto-fill.

  Granularity resolves field → unit → enclosing → decoder, so a field naming
  its own granularity still wins over the unit holding it. `field_path` is the
  **single site** that formats a path, which is what makes upstream
  [#58](https://github.com/adamkjonsson/python-zipline/issues/58) a one-line
  change; nothing reads a `comment` back.

  Widths outside `prim:`'s closed vocabulary (`u8`…`u64`, `i8`…`i64`) widen to
  the smallest token that holds them — a `u4` is written `prim:u8`, a `u24` as
  `prim:u32` — because the payload is created rather than copied, so any
  reader gets the right number without our registry. Text uses
  `mime:text/plain; charset=utf-8`, since `prim:` has no text member. A
  `Computed` field cites the fields its expression read, per `DESIGN.md` §3.2,
  rather than the empty range it consumed.

  Conformance is asserted rather than assumed: `tests/test_emit_conformance.py`
  writes real `.zpf` files at both granularities and puts them past
  `ConformanceChecker` and `check_coverage`, including a truncated input.

- `kober.stage`, and the `Decoder.run` / `Decoder.decode_stream` /
  `Decoder.content_registry` methods of `DESIGN.md` §6. `run` decodes one file
  into another; `decode_stream` drives one stream of an already-open stage, so
  a caller can mix spec-driven decoding with hand-written logic. All `zpf`
  contact lives in this one module, so what kober needs from the format is
  auditable in one place.

  The input is read as `chunks()`, and a `Gap` is a **hard message boundary**:
  bytes either side were never observed adjacent, so no message spans one,
  the hole is marked `reason="gap"`, and the records either side declare a
  `Seam(reason="stream-gap")`. The seam's width is left **absent** — `zpf`
  defines it in the *output's* offset space, and how many decoded units a hole
  cost is not recoverable from how many bytes it swallowed.

  Shape comes from the stream, never the spec. A `DATAGRAM` spec meeting a
  byte stream is refused, being the mismatch that would fabricate a field tree
  over unframed bytes; a `STREAM` spec over datagrams is allowed, since each
  datagram is one self-contained message and every chained stage needs that.

  `content_registry()` registers the spec against its own `dec:<name>-message`
  records, so reading a decoded file hands back a `Node` tree. Field records
  need no registry — they are `prim:`, which `zpf` decodes natively.

- `kober.TruncatedRead` — a read ran past the end of the available bytes. The
  sibling of `EvalError` and the same kind of signal rather than a fault: in
  `STREAM` shape the message may simply continue in a segment we do not hold
  (§3.2), so the decode engine turns it into a `truncated` region. Like
  `EvalError`, letting one escape a decode is a bug.

- `kober.ops` — the language-neutral half of the compiler. `Plan.from_spec`
  reduces a spec to `ObjectPlan`/`FieldPlan`/`ValueType`: which units exist,
  what each field can hold, whether it repeats, and when it is present at all.
  It carries **the spec's own names**, unmapped, and no target's decisions:
  identifiers, keywords, and how a byte range is exposed all belong to a
  backend, because what collides and what reads well differ by language. A
  future Rust or C++ backend attaches here. Deliberately not an intermediate
  representation.

  Units unreachable from `entry` are left out — dead code in any target — and
  a `switch` becomes the list of types it can decode as, since that is what a
  target has to be able to hold. A `computed:` field's kind is the one thing a
  spec does not state, so it is inferred through `check.scope_at`.

- `kober.pygen` — the Python backend: a plan rendered as source. This stage
  renders the **typed model** — one `slots` dataclass per unit, with the
  annotations a consumer completes against, `list[...]` for a repeat, `| None`
  for a `condition`, and the `__spans__` tuple that carries byte ranges — plus
  a spec's `enums:` as module constants.

  Enums are **mappings, not `IntEnum` subclasses**: a value with no label is
  normal on the wire (DNS opcode 3 has none) and a decoder may not raise, so a
  labelled field stays an `int` and the labels are a lookup beside it.

  Names follow one rule with no exceptions: a unit becomes a `CamelCase`
  class, a field keeps its spec name, a Python keyword gets a trailing
  underscore, and **anything else is refused rather than renamed**. Names
  colliding, names that are not identifiers, and names inside the namespace the
  backend reserves for itself all raise `CompileError`, all of them reported at
  once. An anonymous field gets no attribute at all: it is read and cited, but
  a field with no name is not something a caller can ask for.

  Author-supplied text — names, labels, `doc:` strings — never reaches source
  by interpolation. Identifiers are validated against a whitelist and
  everything else becomes an escaped literal or an escaped docstring, and
  `render` parses its own output before returning it. "A spec cannot run code"
  is partly a security property, and this is where it would be lost.

- `kober.CompileError` — a valid spec cannot be expressed in the language being
  generated. Deliberately not a `SpecError`: the spec may be perfectly valid
  and run under the interpreter, and what collides differs by target, so this
  is a fact about a compilation rather than about the spec.

- `kober.check.require_valid` and `kober.check.scope_at`. The first refuses a
  spec with errors, listing all of them — what `Decoder.__init__` did inline,
  now shared with the compiler, which relies on the same guarantees. The second
  returns the scope an expression at one field's position resolves against, so
  the compiler asks the checker what a name means instead of implementing
  scoping a second time and drifting from it.

### Changed

- The `zpf` requirement is now `>=0.2.0,<0.3`, up from `>=0.2.0.dev0,<0.3`.
  The `.dev0` floor existed only so an unreleased local checkout could satisfy
  it, and `zpf` `0.2.0` is now released and tagged. Tightening it is also a
  correctness fix: `comment=` on both `record()` methods landed *in* `0.2.0`,
  so a dev build predating that change satisfied the old floor while lacking
  the API this project is built on. Not a breaking change for anyone — no
  release of this project has shipped.

### Fixed

- A seam is now declared after **any** hole-class undecoded region, not only
  after a `Gap`. `zpf` sorts reasons into two recoverability classes and puts
  both `gap` and `truncated` in `hole` — bytes that never existed — so a
  truncated message followed by another record needs a `Discontinuity` between
  them just as a lost segment does. Writing gap-only seams produced
  nonconformant files whenever a partial message sat between two whole ones.
  The class is now read from `zpf.blocks.UNDECODED_REASONS` rather than
  restated, so it cannot drift from what the conformance checker enforces.
  Found by fuzzing real DNS: it passed every hand-built test and every clean
  capture first.

- Field paths no longer name a repetition twice. A repeat's container and its
  elements share a spec field, so both contributed a path segment and real
  nested repeats came out as `dns.questions.questions[0].qname.labels.labels[0]`
  instead of `dns.questions[0].qname.labels[0]`. `Node.is_repetition` now
  distinguishes the container, which nothing else did. Found on the first real
  capture; no hand-built fixture had nested repeats.

- A `switch` written in YAML with an unquoted `on:` key now loads. `on` is a
  YAML 1.1 boolean, so `on: kind` parses as `{True: "kind"}` — and `on` is the
  schema's own dispatch key, which put the trap on one of the most common
  constructs there is. The loader reads that boolean back as the key it was
  written as, narrowly: only in a `switch`, only for `True`, and only when a
  real `on` is not also present (both at once is an error). JSON has no such
  coercion and is untouched. Found by the decode engine's own tests, which is
  the first code to write a `switch` in YAML.

- At message granularity, a tree that truncated or went undecodable is no
  longer written as a record. A half-decoded message is not a message, and
  emitting one claimed we had decoded something we had not; its bytes are
  named with the failure's reason instead. Field granularity keeps the
  asymmetry deliberately — fields decoded *before* the trouble really were
  decoded, so their records stand.

- `examples/http.yaml` — an HTTP/1.1 spec that decodes the real request and
  response from `python-zipline-wire`'s `http_example.pcapng`: start line and
  every header, using `Terminated` on `\r\n` and `until` on the blank line that
  ends them. The body is claimed as opaque `remaining` bytes rather than
  framed, and says why: `Content-Length` is a decimal string and a chunk size
  is a hexadecimal one, and the expression language has no string-to-integer
  conversion, substring, or case folding. Correct for a capture holding one
  message per direction, wrong the moment a connection carries two.

- `examples/dns.yaml` — a real DNS spec, checked clean, that decodes the
  `dns_example.pcapng` capture from `python-zipline-wire`: header, flags as
  nine bitfields, and the question section with names as repeated
  length-prefixed labels. The answer, authority, and additional sections are
  deliberately left `skipped` and say why — their owner names are usually
  compression pointers, which the spec language cannot follow. The phase plan
  asked for a committed example and had only test fixtures.

### Documentation

- `docs/format/` — the spec-format reference, which is the product's real
  surface and previously had no documentation anywhere: `DESIGN.md` describes
  the Python model, not the YAML an author types. `document.md` covers the top
  level, units, fields, enums, and emission granularity; `types.md` every field
  type, size, and repeat, each with **what happens when it does not match**,
  since that answer is half of what a construct means; `expressions.md` the
  language, its scoping and ordering rules, and what it deliberately cannot do.

  Both YAML traps that have caught this project are written down: `on` is a
  boolean and is the switch dispatch key, and a comma inside a flow mapping
  splits `doc:` into a second key.

- `tests/test_docs.py` — the format reference is checked against the loader's
  own key sets, so adding a schema key without documenting it fails the suite
  rather than the reader. It found five undocumented keys on its first run.

- `docs/dev/` — the developer guide. `architecture.md` gives the module map,
  how a decode flows through it, and the **six design invariants** a change
  must not break, each with what actually goes wrong when it is: the cursor
  rule, failure never escaping a decode, every byte cited or named, the single
  field-path site, shape coming from the stream, and the spec not running code.
  `testing.md` gives the test map and the practice — fuzzing is standard, a
  regression test is checked against its bug, and the deeper `packeteer` →
  `zpfwire` → `kober` pipeline is the only thing exercising the stage driver.
  `contributing.md` covers environment, style, changelog, and git.
  `decisions.md` indexes where reasoning lives, which was previously findable
  only by knowing `plans/` exists.

- `docs/api/` — one autodoc page per module, ordered by the pipeline rather
  than alphabetically. Pulled forward from its planned position because the
  developer guide cross-references API symbols and those pages are what define
  them.

- `docs/` — the documentation tree, following `python-zipline`'s style: Sphinx
  with MyST markdown, `furo`, `autodoc` + `napoleon`, and a `dev`/`format`/`api`
  split. Warnings are errors (`nitpicky = True` plus `-W`), so a cross-reference
  that does not resolve fails the build instead of quietly rendering as plain
  text. `CLAUDE.md` has documented a docs build since the scaffold and it has
  never worked; it does now, and both it and the README now name the `-W` form.

  Deliberately *not* copied from `python-zipline`: its `missing-reference` hook
  bridging `zpf.Foo` onto `zpf.module.Foo`. kober's docstrings already cite the
  defining module, so the hook would be machinery with nothing to do. Two
  ambiguous references were fixed instead — `kober.check` is both a module and
  a function, and `kober.Spec.from_dict` named the re-export rather than the
  definition.

- `tests/test_fuzz.py` — fuzz tests now run with the suite, asserting the
  promises that cannot be tested by example: a decode never raises, a decode
  never claims more than it was given, no byte is ever both cited and marked
  undecoded, and every reason is one `zpf` classifies. Mutations are seeded, so
  a failure reproduces from the bytes it prints, and an escaping exception is
  re-raised with a note rather than swallowed, so the traceback survives.

  It depends on nothing outside the standard library: by the time bytes reach
  the decoder the transport layers are gone, so the mutations that reach it are
  payload-level ones — truncate, extend, flip, boundary, replace. Verified
  against the real bug it exists for, by reverting the emitter fix and watching
  all four parametrisations fail.

  The technique came from `packeteer`, whose `fuzz` verb found a conformance
  bug the entire hand-built suite had missed. The **deeper pipeline** —
  `packeteer fuzz` → `zpfwire convert` → `kober run` — is documented in the
  README, because it is the only thing that reaches the *stage driver*, which
  needs real stream structure rather than one adversarial buffer.

- `CLAUDE.md` gains a Testing section recording all of that as standing
  practice: fuzz tests are standard rather than optional, a regression test
  must be checked against the bug it claims to catch, and the two sibling
  projects that supply real and adversarial input are named with what each is
  for.

- `DESIGN.md` revision 6 — records what real captures found, in a new §13, and
  drops the "nothing here is implemented" status line that had been false since
  the spec-model phase. The status now says what is built and points at what is
  not. §3.2 gains the `Pointer` construct (decided, not yet built) with the
  three things it needs that nothing else in the model does: an offset space, a
  bound against looping chains, and a note that a region reached only through a
  pointer retires the "leaves tile the input" property. §3.3 records that real
  HTTP is the first thing to need the expression language grown, and names the
  three total builtins that would close it. §11 question 5 is updated with the
  consequence: both real gaps were closable by making the *declarative*
  language say more, so the case for hooks is weaker than when the question was
  written, not stronger.

- Two further findings filed upstream from running kober over real captures:
  [#62](https://github.com/adamkjonsson/python-zipline/issues/62) (which
  timestamp a message inside a multi-message run should carry — the rule and
  the recommended implementation disagree) and
  [#63](https://github.com/adamkjonsson/python-zipline/issues/63)
  (`check_coverage` measures a real TCP stream as 2³²−1 bytes, because a
  zero-length SYN record underflows `record_ranges`; `chunks()` skips such
  records and `record_ranges` does not).

- `README.md` — replaced the "nothing is implemented yet" banner with what
  actually works today, and added worked `check`, `show`, `run`, and `try`
  output plus the API equivalent. The banner now says the project is early and
  exercised on small hand-built captures rather than in anger, which is the
  honest state.

- `plans/` — working documents recording why things were built the way they
  were, following the same convention as `python-zipline`: historical rather
  than normative, with `DESIGN.md` and this changelog staying the live records
  in the project root. Holds `SPEC-MODEL-PHASE.md` (a record of the completed
  spec-model phase and the decisions the next one inherits) and
  `DECODER-PHASE-PLAN.md` (the live plan for the decoder — five stages, the six
  invariants it must enforce, five design questions it has to settle, and its
  acceptance criteria).

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
