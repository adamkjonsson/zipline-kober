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

- `kober.spec.Select` and the `select:` spec key — ask a question about a
  **repeated** field, and get one scalar back. Four required keys: `from`
  names the repetition, `where` is a predicate over one element, `value`
  projects the first element it holds for, and `default` is what to say when
  nothing matched.

  ```yaml
  - name: content_length
    type:
      select:
        from: headers
        where: "lower(headers.name) == 'content-length'"
        value: "to_int(headers.value)"
        default: "-1"
  ```

  This is what lets a message frame its own body. Choosing between
  `Content-Length` and chunked encoding means asking whether *any* header said
  so, and until now nothing could: `headers` is repeated, and the expression
  language has no list type (`DESIGN.md` §11 question 6).

  **Aggregation went into the model rather than the grammar**, the same choice
  §11.5 made for `pointer:`. An `any(headers, …)` form would need a binding
  construct in the general grammar — a lambda in all but name — and a
  `first(headers, …)` would have to return an *element*, which `ExprType` has
  no member for. A select yields a scalar whose type is its projection's, so a
  later field references it like any other value, and `check` types it with
  machinery that already existed. Because `default` is required, "nothing
  matched" always has an answer the author wrote.

  Inside `where` and `value` the repeated field's own name means the element
  being tested, which is the binding `until` already uses and spelled the same
  way. `default` does not get that binding. **The language still has no list
  type and gains none:** nothing can hold a list, pass one, or return one.

  At field granularity a select cites **the element it selected** — this value
  came from *that* header, not from all of them. A default cites no bytes.

  It reads no input and moves no read position, so it stays on the
  unconstrained side of §2.1 exactly as `computed:` does. That claim is
  asserted directly, cursor either side, rather than inferred from coverage
  staying whole: a select that *did* consume would leave coverage whole anyway,
  the byte it took being covered by whatever followed.

  An expression in `where` or `value` that cannot be evaluated makes the field
  `undecodable`, exactly as an unevaluable size does. It is **not** treated as
  "no match", which would report the author's default as though it had been
  read off the wire.

  Both implementations have it. The compiler renders a select as a small nested
  function — a walk over a list yielding one value is what a function is for,
  and in one it can simply `return`, so "the first match" is a return inside the
  loop and "nothing matched" is the line after it. It is nested rather than
  module-level so that it closes over what it reads, which is the only way to be
  sure a generated helper was handed everything it needs.

  `kober.pygen` refuses one shape the interpreter accepts: a `switch` with a
  select in only *some* cases. A select's extent is the element it chose and an
  ordinary read's is where it stands, and one pair of span locals cannot hold
  both, written down as they are before the branch is chosen.

- `trim(s)` in the expression language — text without leading or trailing
  whitespace, and the language's third function.

  Not decoration, and its absence was a real bug in this project's own HTTP
  example. RFC 7230 §3.2.3 permits optional whitespace after a header's colon,
  so a value reads as `" chunked"`. `to_int` strips it internally, which is why
  a `Content-Length` needs nothing — but a string **comparison** has nothing to
  strip it, so `lower(value) == 'chunked'` answered false on every real chunked
  message. `to_int`'s whitespace allowance is a convenience for conversion, not
  a substitute for this.

- `within:` on a `terminated` size — a second byte sequence the search must
  not run past, so one line can split into two fields:

  ```yaml
  - {name: name,  type: {string: {size: {terminated: {delimiter: ":", within: "\r\n", required: false}}}}}
  - {name: value, type: {string: {size: {terminated: {delimiter: "\r\n"}}}}}
  ```

  An HTTP header then *has* a name and a value in the spec, rather than having
  them computed back out of the line by expressions afterwards — and the split
  reaches the output, so a consumer gets the name and the value as two
  separately cited records. Reading a name as "up to the next colon" without a
  bound would run into the next header, or past the end of the headers
  entirely, on any line that has no colon in it.

  The rule is **whichever comes first**: a delimiter beginning after the bound
  reads as though it were not there. `required` still decides what that means,
  with one difference worth knowing — an *optional* bounded terminator that
  finds nothing reads **nothing**, where an unbounded one reads the rest of the
  run. The bound limits the search and is never a second terminator; reading up
  to it would be reading under a delimiter that was never found.

  The blank line ending a header block needs no special case: it has no colon
  before its CRLF, so the terminator takes nothing and the name comes back
  empty.

  `kober.cursor.Cursor.find` takes the bound as a second argument, and the
  checker's "a non-required terminator on a string makes truncation invisible"
  warning no longer fires when `within` is set — the bound *is* the guarantee
  that warning exists to notice the absence of. Both implementations have it.

- `kober.spec.Pointer` and the `pointer:` spec key — a back-reference:
  *read this type at that offset, and carry on where you were*
  (`DESIGN.md` §3.2). Real DNS needs it; without it the answer section of
  nearly every response is undecodable.

  `at` is an integer expression giving an offset **from the start of the
  message**, which is the only space it can mean — a run holds many messages,
  and a stream-absolute reading would work on a run's first message and
  silently misread every later one. Because `at` is an expression, a pointer
  reads nothing where it stands: the bytes encoding the reference are read by
  ordinary fields, so a pointer cites one contiguous range and never two.

  A pointer may target only bytes the message has already decoded. Anything
  else — past the end, forward, or a target that does not decode — makes the
  region `undecodable` and never raises. That rule is also what bounds chains:
  each hop must land strictly earlier than the last, so a cycle cannot be
  constructed.

  The model, the loader schema, the checker, the interpreter, **and the
  compiler**. A generated decoder follows a pointer at 10 MB/s against the real
  DNS response — 31× the interpreter — and a spec with no pointer is generated
  exactly as before, because the message origin and the chain's ceiling are
  threaded only into a plan that has one.

  The backend refuses three shapes rather than approximating them: a `switch`
  under a pointer, a `switch` with a pointer in only some cases, and a repeated
  pointer. Each decodes under the interpreter, and each refusal names the shape
  — which beats generating something subtly different from what the
  interpreter does, the one divergence the differential could never catch.

- **Two functions in the expression language**, `to_int` and `lower`, and the
  `Call` node and closed `BUILTINS` table behind them. `to_int(s)` and
  `to_int(s, base)` read text as an integer; `lower(s)` lower-cases it for a
  case-insensitive comparison. They are what real HTTP framing needs and
  nothing more: a `Content-Length` is a decimal string, a chunk size a
  hexadecimal one, and whether chunked framing applies depends on a header
  value whose case varies (`DESIGN.md` §13.2).

  `to_int` is stricter than a typical conversion — surrounding whitespace is
  allowed, a digit separator or radix prefix is not — because reading `1_0` as
  ten turns a malformed wire length into a plausible one. Text that is not a
  number makes the field `undecodable` rather than raising, on the path a size
  expression that cannot be evaluated already takes.

  **The table is closed and matched by name.** An unknown function is a
  load-time error naming what does exist, so "a spec cannot run code" still
  holds now that calls parse at all.

  Generated code calls `kober.runtime.to_int`, which **is** the function the
  interpreter evaluates. One implementation of a conversion that is
  deliberately stricter than Python's means the two cannot drift.

- `kober.cursor.Cursor.view` and `Cursor.seek_to` — the seam a redirect reads
  through. `view(off_start, off_end)` hands out a second position over the same
  run, with its own base so spans stay absolute and its own end so a sub-decode
  cannot see a byte the caller did not give it. It does not move the cursor it
  came from, which is what keeps §2.1 true of a construct that reads elsewhere.
  `seek_to` is `seek`'s byte-offset counterpart, in the stream's own space.

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

- `kober.pygen.render_expr`, and `kober.pygen.Binding`, which is where scope
  binding lives — the new work in compiling an expression. A field of the unit
  being decoded is a local; so is a parameter; a dotted path is attribute
  access; and `parent.x` / `root.x` are **parameters the caller passes**, since
  the parent's fields are locals in a function that has not finished running.
  The compiler knows which of them an expression names, so it can pass exactly
  those and skip the frame chain the interpreter needs at decode time. Inside an
  `until` clause the repeated field's own name means the element just decoded,
  which is what that clause is for.

  Three semantics survive compilation rather than being hoped about. `/` is
  integer division in a spec, so it becomes `//`. `and` and `or` short-circuit,
  which Python's do identically — and a spec relies on it to guard a division,
  so it is tested rather than assumed. A shift count this backend cannot see to
  be in range becomes a call to a bounded helper, because `1 << n` with `n` off
  the wire allocates until the process dies.

  What does *not* survive is the interpreter's type checking: `_as_int` and
  `_as_bool` exist because it learns types at decode time, and the checker has
  already proved them. Division by zero survives as `ZeroDivisionError`, for a
  generated decoder's entry point to turn into an `undecodable` region.

- `kober.ops.ParamPlan` and `ObjectPlan.params` — a unit's parameters. Not
  fields: they decode nothing and appear in no decoded instance, but they are in
  scope for its expressions and a target has to name them somewhere.
  `ObjectPlan.field` and `ObjectPlan.param` look either up by the name the spec
  gives it.

- `kober.ops.walk_path` and `kober.ops.Step` — resolving a reference path to the
  fields it traverses, so a backend knows which unit each name belongs to and
  can map it the way that language maps names. The scope word is the caller's to
  strip, because which unit a path starts in is the only part of scoping a
  target has an opinion about.

- `kober.shift_left` and `kober.shift_right` — the language's shift bound, as
  functions **generated code can call**. A compiler can see that `x << 3` is in
  range and emit the operator, but not that `x << n` is; the bound has to live
  somewhere a generated module reaches, and it has to be this one or the two
  implementations would disagree about which inputs are decodable.

- `kober.runtime` — what a generated decoder imports, and the only thing it
  imports from this project. No spec model, no `Node`, no YAML, no checker: a
  consumer installs `kober` and gets a decoder that reads bytes, and the
  machinery that turned a specification into it stays behind. Mostly
  re-exports, deliberately — a generated decoder and the interpreter read
  through the same cursor, raise the same signals, and bound a shift the same
  way, which is what makes the two comparable. `read_int_le` is the one wrapper
  that earns its keep: `Cursor.read_int` takes a `kober.spec.Endian`, and this
  is where that import happens so generated code never needs it. `span` and
  `Spanned` moved here from the stage 1 spike.

- `kober.Undecodable` — a generated decoder read its input and could not make
  sense of it: a `switch` with no case, a negative size or count, a `confirm`
  that did not hold, a repetition that consumed nothing, nesting past
  `MAX_DEPTH`. The interpreter needs no equivalent because it records the
  verdict on a `Node`; generated code has no tree to record it on, so it says so
  by raising, and the entry point turns it into an `undecodable` region.

- `kober.pygen.render_decoder` and `kober.pygen.render_entry` — the decode
  functions, one per unit, and the two entry points. `decode(data)` returns the
  typed object or `None`; `decode_from(cur)` takes the cursor and lets the
  failure through, which is what a driver decoding several messages from one run
  needs in order to say where it stopped and why.

  Every field type, size and repeat, `condition`, `confirm`, `reject`, the
  bounded loops, and the two scope words. `parent.x` and `root.x` are
  **parameters the caller passes**: the compiler knows which outer values an
  expression names, so it passes exactly those and needs no frame chain at
  decode time. `root` inside the entry unit is that unit's own local, and a
  `root` reference to a field the entry unit has not decoded yet is refused at
  compile time — the one ordering rule the checker deliberately leaves alone,
  because only a compiler knows the position an expression is compiled at.

  Four runtime checks are **compiled away where they cannot fire**: a repeat
  count or size from an unsigned field is never negative, a repetition whose
  element always reads cannot spin, a codec name validated once cannot fail to
  exist, and a depth bound is threaded only through specs that can actually
  recurse. Where any of them can fire, the check is emitted.

- `kober.ops` grew the operations a decoder needs, which is what makes the
  neutral layer worth having for more than the object model: sizes, repeats,
  switch `branches`, `confirm`/`reject`, and the *analyses* a backend uses to
  drop a check — `FieldPlan.consumes`, `ObjectPlan.consumes`,
  `ObjectPlan.recursive`, and `nonnegative`. Those are facts about the format
  rather than about Python, so any backend gets them. `needs_parent` and
  `needs_root` say which outer values a unit depends on, `needs_root` including
  what the units below it need, since those values are threaded through.

- Emission, which is what the compiler phase has been pointing at since its
  first question: `kober.pygen.render_decoder` and `render_entry` take an
  `emit`, and a generated decoder **writes records as it reads**, with the
  field path, the content type, the `prim:` token and the payload encoding all
  baked in as literals. No tree is built and nothing generic is walked
  afterwards.

  **Granularity is a compile-time choice**, because it is a difference in the
  code and not in a flag: at `message` a decoder builds no field paths and
  carries no sink at all, at `field` the path is threaded through every unit
  function, and at `none` the message's own bytes are named rather than
  reported. `kober.pygen.granularity` resolves it once per unit, where the
  interpreter resolves it per node while walking a finished tree. A unit reached
  at two different granularities is refused rather than compiled twice.

  Four things a compiler knows and an interpreter has to work out: a field's
  `prim:` token from its declared width, its payload encoding from its type, the
  bytes a `computed:` field cites — the fields its expression read — and which
  leaves are `emit: none` and so name their bytes `skipped`. The one payload
  that cannot be baked is a `computed:` integer, which nothing declares a width
  for; that goes through `kober.runtime.prim_int` and is sized by its value, as
  the interpreter sizes it.

- `kober.runtime.Sink` — the sink protocol, moved in from the stage 1 spike.
  Its two calls are `Emission` and `Unclaimed` written as method signatures, so
  a generated decoder is a second producer for the contract the interpreter's
  emitter already has. `kober.runtime.cited` and `prim_int` are the two answers
  that cannot be settled until a message arrives.

- `kober.cursor.Cursor.slice` — the bytes of an absolute range, without moving
  the position. A whole-message record's payload *is* the input, so whoever
  emits it needs the bytes back; reading is what moves the cursor, and this does
  not read.

- `kober.ops.FieldPlan.emit` and `ObjectPlan.emit` — the spec's own `emit:`
  settings, carried so a backend can resolve granularity without the spec.

- `kober compile SPEC -o OUT.py [--emit field|message|none]` — the CLI verb, and
  the last of `DESIGN.md` §6's list plus one. It checks the spec first and
  writes nothing if that fails, which is what "errors move to build time" means
  in practice, and prints the findings `kober check` would print. With no `-o`
  it writes the module to standard output.

- `kober.stage.run_compiled` and `decode_stream_compiled` — the driver for a
  generated module, so one is runnable over a `.zpf` file without hand-written
  glue. **The same driver as the interpreter's**: gaps are message boundaries,
  a seam is owed after a hole, a run's tail is accounted for, and only the step
  in the middle differs. Everything the driver does is true of a decode however
  the decode was written, and one implementation of the seam rules is one place
  for them to be wrong.

  The interpreter's own path now writes through that sink too, which is the
  shape Q1 argued for: `plan` gained a second producer rather than being
  replaced, and here the two producers meet the same writer. A generated module
  and the interpreter produce **byte-identical decoded files** for the same
  input, which is what `tests/test_compiled.py` asserts.

- Generated decoders **read the buffer at offsets the compiler resolved**,
  rather than through a cursor. A read is an index, a bounds check is a
  comparison against a number known when the spec was compiled, and a byte range
  is an addition — because the compiler tracks where every field sits relative to
  the last position only the running decode could know.

  Measured on a real DNS query: **6.2 µs a message at field granularity against
  16.6**, and 3.3 µs at message granularity against 13.8. Against the
  interpreter that is 20.6× and 27.6×.

  The win is in knowing the offsets, not in the reads: tracking the position in
  bits and computing each range measures 6.9 µs, against 2.9 for the same reads
  at baked offsets. And exact truncation came free — a per-field bounds check
  against a known offset costs nothing measurable, so every field keeps its own
  and a decode stops exactly where the interpreter stops.

  One narrowing, and it belongs to the Python backend rather than the language:
  a unit whose fields do not add up to a whole number of bytes is refused, with
  a message saying which unit and how far into a byte it reached. The
  interpreter carries on mid-byte and then raises out of the decode at the next
  `bytes` field, so such a spec is nearly always a fault already.

- `kober.errors.Stopped` — the base of `TruncatedRead` and `Undecodable`,
  carrying **where** a decode stopped. Generated code keeps its position in a
  local, so nothing else can be asked afterwards; the entry point reads it off
  the exception and hands it back to the cursor.

- `kober.cursor.Cursor.data` — the run a cursor reads. Generated code reads the
  buffer itself, which is the difference between a method call per field and an
  index, so it has to be able to ask for it.

- The differential is now **fuzzed**. Every mutation of every example, and of a
  corpus of specs chosen to be hard to compile, is decoded both ways and the two
  must agree — same values, same byte ranges, same records, same regions, and
  where a decode fails, the same offset with the same reason. Both
  implementations are fuzzed from the same mutators, in `tests/fuzzing.py`,
  because results over inputs that differ cannot be compared.

  A generated decoder is held to the interpreter's promises too: it never
  raises, never claims a byte it was not given, never both cites and names one,
  and accounts for every byte of every input. And a fuzzed capture — datagrams,
  and a byte stream with a hole in it — is driven through both and must produce
  the same file, block for block.

### Changed

- **Breaking: `examples/http.yaml` frames its body by asking its headers**, and
  its assumption disclaimer is gone. It chooses between chunked encoding, a
  `Content-Length`, and no body at all, and a `header` unit now has a `name`
  and a `value` rather than a single `line` — so a consumer reading its output
  gets each header's two halves as separately cited records. Anything reading
  `header.line` reads `header.name` and `header.value` instead.

  What it stops doing is the point: a body that was not chunk-formatted used to
  come back `truncated`, a **hole**-class reason declaring a gap in a stream
  that had none. It now decodes 2000 real messages from
  `http_stream_1.pcap` — 1147 counted, 853 with no framing header, fifty
  pipelined per run — with no undecoded region at all, and reads the 18 070-byte
  response in `http.pcap` that used to be a hole.

- **Breaking: `examples/dns.yaml` decodes a whole message.** The answer,
  authority, and additional sections are decoded rather than marked `skipped`,
  following compression pointers into names decoded earlier. All eight messages
  in the real capture now decode with **no undecoded regions at all**, clean
  through `ConformanceChecker` and `check_coverage` at both granularities.

  Callers reading its output must expect the new shape: `message.answers`,
  `message.authority` and `message.additional` replace the single
  `resource_records` field, and a label's second field is `rest` — a switch
  holding either text or the second half of a pointer — where it was `text`.
  Record data stays opaque bytes, which is a choice rather than a limitation.

- **Breaking: `examples/http.yaml` frames a chunked body into its chunks**,
  using `to_int` on the hexadecimal size line. Both messages in the real
  capture decode with no undecoded regions.

  It **assumes** chunked framing rather than choosing it, and says so in its
  own `doc:`. Choosing would mean asking whether any header said `chunked`, and
  no expression can ask anything about a *repeated* field — there is no list
  type. A body that is not chunk-formatted therefore comes back `truncated`,
  which is hole-class and claims a gap the stream did not have. Callers reading
  its output get `message.body` as a list of chunks where it was opaque bytes.

- The `zpf` requirement is now `>=0.2.0,<0.3`, up from `>=0.2.0.dev0,<0.3`.
  The `.dev0` floor existed only so an unreleased local checkout could satisfy
  it, and `zpf` `0.2.0` is now released and tagged. Tightening it is also a
  correctness fix: `comment=` on both `record()` methods landed *in* `0.2.0`,
  so a dev build predating that change satisfied the old floor while lacking
  the API this project is built on. Not a breaking change for anyone — no
  release of this project has shipped.

- `kober.expr.unparse` now emits **only the parentheses the grouping needs**.
  It used to parenthesize everything, on the grounds that being unambiguous
  beat being pretty; minimal grouping is unambiguous too — it is read off the
  new `kober.expr.PRECEDENCE` table — and `((ancount + nscount) + arcount) > 0`
  is harder to check against what you wrote than `ancount + nscount + arcount >
  0`. Visible in `kober show`, in checker messages, and in the docstrings the
  compiler generates. What comes out parses back to the same tree, which is now
  a test rather than a hope.

- `prim_token`, `normalize_int`, `PRIM_WIDTHS` and `TEXT_CONTENT_TYPE` moved
  from `kober.emit` to `kober.runtime`. Still re-exported from `kober`, and
  `kober.emit` still uses them, so nothing changes for a caller. The reason is
  that a *generated* decoder normalizes its payloads the same way and may not
  import `kober.emit` — it would pull in the tree and the spec model — and two
  answers to "what is a `u4` written as" would be one too many.

- The Python backend no longer reserves the plain names `cur`, `sink` and
  `path`. Everything a generated function introduces now begins with an
  underscore, which the backend reserved anyway, so `size`, `data` and `path`
  are usable field names again — and they are ordinary names for a protocol
  field.

### Fixed

- **`examples/http.yaml` read every real chunked response as unframed**, and
  accounted for every byte while doing it. The header value it compared against
  `'chunked'` carries the whitespace RFC 7230 permits, so the comparison was
  false, no body was read, and the driver decoded the chunk data as further
  HTTP messages — which cited it. Coverage stayed whole and the decode was
  nonsense, which is why a record count could not have caught this and the
  tests now assert the message's *shape*: one message, the whole response, its
  body in chunks. Fixed by `trim`, above.

- **A record for a computed integer was written on one line however long it
  got.** Every other `sink.record` call the compiler emits is wrapped to the
  line length; the one for a value whose width is not declared was not, so a
  field with a long enough name generated a module that failed this project's
  own lint. Found by compiling a spec with a field called `content_length`.

- **A `computed` field of a nested unit could not be referenced from outside
  it.** Typing the reference re-checked that computed's own expression against
  the *referrer's* visible names — which, once the path had crossed into
  another unit, belonged to the wrong unit entirely, so every field of the
  inner one was reported as "declared later":

  ```
  error: probe.outer.probe: computed: 'raw' is declared later in unit 'leaf'
  ```

  The ordering rule is about where the *reference* stands, and it is applied
  where the reference is written; a computed's own ordering is checked at its
  own declaration site. Nothing is loosened by not asking twice. Found while
  writing the `select:` example, where `until: "chunks.length == 0"` is the
  natural way to end a chunked body and was refused.

- **A field path in a compiled decoder carried the backend's identifier, not
  the spec's.** A field named `class` is a Python keyword, so the attribute
  holding it is `class_` — and that spelling reached the record's field path,
  where the interpreter wrote `class`. A path is what a consumer reads out of
  the file and the two implementations have to agree on it. Found by the
  differential, in code that predates the construct that exposed it.

- **A unit reachable only through a pointer was dropped from a compiled
  module**, which then called a decode function it had not generated. The
  checker had been taught to walk a pointer's target; the compiler's own
  reachability walk had not.

- **A generated decoder could raise `EvalError`** where the interpreter
  recorded an undecodable region: the backend wraps an expression that can fail
  so the failure can say *where* it happened, and it did not know that reading
  text as a number is a fourth way to fail. A decode that raises leaves its
  input unaccounted for, which is the promise the module makes.

- **A generated `switch` mixing a nested unit with a scalar produced nested
  `if` statements** that `ruff` refuses, so such a module failed the project's
  own lint. Where exactly one branch writes a record, the two tests now fold
  into one.

- **A computed value too wide for `prim:` raised out of the emitter.** `prim:`
  stops at 64 bits and a computed value does not: `1 << n` with `n` off the wire
  is an ordinary expression and an enormous number, and labelling one raised
  `ValueError` through `plan()` and through a generated decoder alike. There is
  nothing honest to write for it, so nothing is written — `kober.runtime.prim_int`
  returns `None` and both sides skip the record. Coverage is untouched: a
  computed field consumes nothing, and the bytes it would have cited belong to
  the fields it read, which have records of their own.

- A `switch` with both a unit case and a value case wrote **no record** for the
  value cases. The field was treated as a container because one of its
  alternatives was, and a container's leaves do the writing — but an integer
  case has no leaves, only itself. Now only a field whose every alternative is a
  unit is a container.

- A signed field narrower than a byte crashed a generated decoder with a
  `NameError`: the two's-complement helper was called and never emitted.

  All three were found by fuzzing the compiler's corpus of awkward specs, none
  had a failing test, and the first two were in code the interpreter shares.

- **Two places the interpreter threw away what it had decoded.** A nested unit
  that failed part-way was discarded whole by `_unit_ref`, and a repetition
  whose element failed lost *every* element, because they were accumulated in a
  list that a raise unwound past. In both cases the bytes had been read and
  understood, and the emitter then named them `truncated` — true of the byte
  that ran out and false of the ones before it. Now a partial nested unit is
  returned, like a scalar field that failed always was, and elements reach the
  caller as they are decoded.

  On a three-byte DNS query the emitter used to write one record and mark
  `[2, 3)`; it now writes six and marks nothing, which is what those bytes
  deserve. Found by the compiler's differential test, which is what it is for: a
  generated decoder emits as it reads, so it had already reported those fields,
  and the disagreement was the interpreter's.

- `true` and `false` now parse as **boolean literals**, which is what
  `docs/format/expressions.md` has always said they are. Borrowing `ast.parse`
  made them plain names, so a spec writing `condition: "true"` got a reference
  to a field of that name and an error about it not being decoded — and
  `unparse` rendered a `BoolLiteral` as `true`, text that meant something else
  when read back. Python's own `True` and `False` are still accepted. A spec
  with a field actually named `true` or `false` can no longer reference it.

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

- **`DESIGN.md` revision 9.** §13.2 is **closed** — its wrong diagnosis kept
  visible, and a second wrong one recorded beside it — and §11 question 6 is
  answered by `Select`. §3.2 gains the construct and the bounded terminator,
  §3.3 gains `trim` and the reason a closed table reopened, and §2.1 gains the
  totality argument along with the general lesson behind it: a select that
  consumed input passes every coverage-shaped invariant, so the rule it obeys
  is asserted directly and each assertion is checked against an implementation
  that breaks it.

  §11 question 5's line moves once more. This was the third real gap closed by
  making the declarative language say more rather than letting code in beside
  it, and aggregation landed in the *model* rather than the expression
  language — so the declarative vocabulary grew and the expression language did
  not. Hooks stay deferred and are weaker still.

- **The `README` says what a spec can express**, which it never did: eight
  field types with each one's answer for what happens when it does not match,
  the three ways a field repeats, and why constructs get added rather than
  hooks. `tests/test_docs.py` now guards that table the way it already guarded
  the format reference — against the table rows rather than the whole file,
  since the prose underneath names the same constructs and a first attempt
  passed a deliberately broken table.

- **Corrected in the reference docs:** the format index quoted a schema error
  whose wording and type list had both drifted (`pointer` and `select` were
  missing from it), `docs/dev/testing.md` said fourteen captures in one place
  and sixteen in another, and the `README`'s pointer at `packeteer stream
  --packet-loss` now says that HTTP is the one payload where those options are
  ignored.

- **`docs/dev/decisions.md` is current again.** Its `DESIGN.md` revision list
  stopped at 7 and now runs to 9; the §11 tally said four questions and there
  are six, of which three are open; and it gains a section for what is *owed*
  rather than open — byte transforms, and the `Transfer-Encoding: gzip,
  chunked` form `examples/http.yaml` deliberately does not recognise. The
  upstream-issues rule now covers the test tooling too, with the three
  `packeteer` issues this phase filed.

- **`docs/dev/testing.md` gains two rules this phase paid for.** *A seed is
  only worth the code it reaches* — the HTTP fuzz seed had no framing header,
  so every variant took the third path and neither framing arm was ever
  entered. And *a byte count is not a criterion* — a message that stops early
  leaves its tail to the driver, which decodes it as further messages and cites
  it, so coverage stays whole while the decode is nonsense. Both are written
  from the bug they let through.

- **The `packeteer` notes say what it will not do**: its TCP anomalies are
  silently ignored with `--payload http`, and it cannot generate chunked HTTP —
  which matters because the sixteen real captures hold exactly one chunked
  message against 1151 counted ones.

- `DESIGN.md` **revision 8**: `Pointer` as built rather than decided (§3.2),
  §2.1 restated for a second cursor, §13.1 closed, §13.2 corrected, §11
  question 5's line re-drawn, and a new question 6.

  §13.2 is the one worth reading. It had been the record of what real HTTP
  needed and it was wrong: it named arithmetic on a header value, this release
  built that arithmetic, and the boundary did not close. What actually blocks
  HTTP is being unable to say anything about a *repeated* field, which is now
  question 6 rather than a surprise waiting in a test.

  §2.1's restatement is the second in two releases. Compiling made the cursor
  rule a property of one program; a pointer adds a position that reads
  elsewhere. It holds because the spec names an *offset* and the runtime does
  the seeking, under bounds the runtime applies: backwards only, inside the
  message, with each hop landing strictly earlier than the last.

- `docs/dev/architecture.md` describes the **redirect seam** — what
  `Cursor.view` is, that `Pointer` is its only caller, and what a byte
  transform would supply instead. Written so the next phase inherits a decision
  rather than re-deriving one, with the test that it was drawn in the right
  place stated in advance.

- `DESIGN.md` §3.3 no longer says the language has no calls, because it now
  has two. The restatement is a narrowing of the rule's scope rather than an
  exception to it: what the whitelist bought was no author-supplied code and no
  unbounded work, and a closed table of total functions costs neither. It also
  records what the table is *not* for — a byte transform maps bytes to bytes
  and feeds a sub-decode, and routing one through expressions would cost
  `check` its static answer.

- `DESIGN.md` §2 now says what the coverage guarantee is **not**: leaves do not
  tile the input. Until `Pointer`, every leaf covered a distinct range and
  "tiling" and "covered" were the same statement, so the emitter was built on
  the stronger one and a test asserted it. A region decoded in place and then
  reached again by reference is cited twice, which `zpf` permits in as many
  words. What survives is the guarantee itself — every byte cited or named, and
  never both — which pointers leave untouched, since a pointed-at region is
  cited, and cited is what "not undecoded" means.

- `DESIGN.md` **revision 7**: the compiler as §14, and a restatement of §2.1.
  The cursor rule was true by impossibility — there was no author-supplied code,
  so nothing author-supplied could move the position. Generated code ends that,
  so the rule becomes a property of one program: the generator emits a bounds
  check before every read, advances by what the read consumed, and cites or
  names every byte the position passes. That is weaker than an impossibility and
  saying so is the point; what makes it defensible is that the two
  implementations are compared on every input the suite can generate.

- `docs/dev/compiler.md` — how the compiler is put together, the seam a second
  backend attaches to, and the invariants a change to it must not break. Plus
  what the Python backend *refuses* and why, since both refusals are narrower
  than what the interpreter accepts and that is the honest cost of compiling.

- `docs/api/` covers `kober.ops`, `kober.pygen` and `kober.runtime`;
  `docs/dev/architecture.md` gains the compiler's half of the module map and
  restates the read-position invariant; `docs/dev/testing.md` explains the
  differential and why an awkward-spec corpus exists; `docs/index.md` and the
  README show what `compile` produces. `docs/format/` is unchanged — the spec
  language did not change.

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
