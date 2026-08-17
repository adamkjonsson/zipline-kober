# Architecture

`kober` is a **pipeline with one purity boundary**, not a stack of layers. A
specification is loaded and validated, an engine walks it over bytes to build a
tree, an emitter decides what that tree should be written as, and a driver
writes it through `zpf`.

```
  loader.py ──→ spec.py ──→ check.py          the spec: data, then validated
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
  cursor.py ──→ decoder.py    ops.py ──→ pygen.py    interpret, or compile
                   │             (neutral)  (Python)
                   ▼                     │
                node.py                  ▼
                   │              a generated module
                   ▼                     │
                emit.py ◀────────────────┘   both produce records
                   │
                   ▼
                stage.py ─────────────────→   the only module that imports zpf
                   │
                   ▼
                 cli.py

  runtime.py                                  what generated code imports
  errors.py                                   used by all of it
```

**There are two ways to run a spec and one way to write the result.** The
interpreter walks the spec over a cursor and builds a tree; the compiler turns
the spec into a module that reads bytes directly. Both write through the same
sink, the same driver, and the same `zpf` file — which is what lets a test
insist they produce the same output, and is why the interpreter is kept as the
reference implementation rather than retired.

**The boundary is the fact worth knowing first.** `decoder.py` and `emit.py`
import no `zpf` at all, which is why both are testable without opening a file
and why {func}`kober.emit.plan` is a pure function — a tree in, a list of
records out. `stage.py` exists so that every assumption this project makes
about the format lives in one auditable place. A change that reaches for `zpf`
outside `stage.py` is almost certainly in the wrong module.

## Module map

| Module | Responsibility |
| ------ | -------------- |
| `errors.py` | The exception hierarchy, split by *when* a fault is detectable. `SpecError`/`ExprError` are raised while a spec is being built; `EvalError` and `TruncatedRead` are decode-time signals that must never escape a decode. |
| `expr.py` | The expression language: a frozen AST, a parser built on `ast.parse` in `eval` mode, type inference against a `Scope`, and evaluation against an `Environment`. Type and value sides mirror each other node for node. |
| `spec.py` | The model — `Spec`, `Unit`, `Field`, the field types, sizes, and repeats — as frozen dataclasses. Validates only what one object can see by itself. |
| `loader.py` | YAML/JSON documents to that model, with a strict schema: an unknown key is an error, and YAML's implicit typing is guarded by name. |
| `check.py` | Whole-spec validation: scoping, ordering, expression types, reachability, non-terminating recursion. Collects findings rather than raising. |
| `cursor.py` | A bit-level read cursor. Owns the read position, translates run-relative reads into absolute citations, and rounds a sub-byte field out to its containing bytes. |
| `node.py` | The in-memory decode tree, and `NodeStatus` — whose values *are* `zpf`'s `reason=` strings. Deliberately never written to a file. |
| `decoder.py` | The decode engine: walks a spec over a cursor and returns a tree. Catches every decode-time signal and turns it into a node status. |
| `emit.py` | Pure. Decides what records to write and what regions to mark, given a tree. Holds the single site that formats a field path. |
| `stage.py` | The `zpf`-facing driver: reads `chunks()`, handles gaps and seams, writes records, and runs a whole file through `Decoder.run`. |
| `ops.py` | The compiler's language-neutral half: a `Plan` describing what a spec means, with the analyses a backend uses to drop a runtime check. Carries the spec's own names. |
| `pygen.py` | The Python backend: a plan rendered as source. Names, spans, expressions, decode functions, emission — everything Python-specific about compiling. |
| `runtime.py` | What a *generated* module imports, and all it imports. Mostly re-exports, so both implementations read, fail, and normalize payloads the same way. |
| `cli.py` | The `kober` console script: `check`, `show`, `run`, `try`, `compile`. |

Everything is re-exported at the package top level, so `import kober` reaches
all of it and no consumer imports a submodule.

## How a decode flows

**Load.** {meth}`kober.spec.Spec.from_file` dispatches on the suffix and builds
the model. Loading enforces the schema; it does not enforce anything needing
the whole spec in view. A constructed `Spec` is therefore *well formed*, not
*valid*.

**Check.** {func}`kober.check.check` resolves every reference and types every
expression. {class}`kober.decoder.Decoder` runs it by default and refuses to
build on an error, because every guarantee the engine relies on is one the
checker proves.

**Decode.** The driver iterates the input's `chunks()`, treating each `Gap` as
a hard message boundary. Within a contiguous run it builds a
{class}`kober.cursor.Cursor` and calls the engine repeatedly until the run is
exhausted. The engine walks the spec, reading through the cursor and building
{class}`kober.node.Node` objects.

**Emit.** {func}`kober.emit.plan` walks the tree and returns two lists:
`Emission` (records to write) and `Unclaimed` (regions to mark, with a reason).
It does no I/O.

**Write.** The driver writes them, attaching a seam where a hole-class region
lies between two records, and accounts for whatever the tree did not reach.

## Design invariants

These shape the whole codebase. A change that breaks one is almost certainly
wrong, and each has tests that exist specifically to catch it.

### The read cursor belongs to the runtime

Nothing author-supplied moves it. A spec describes *what* to read and the
runtime decides *where* — which is what makes coverage provable, because bytes
can only be consumed by being claimed. See `DESIGN.md` §2.1.

The practical rules: every advance goes through a {class}`kober.cursor.Cursor`
method; `Cursor.read_bytes` refuses a half-consumed byte rather than aligning
past bits nobody accounted for; and the planned `Pointer` construct will name
an offset for the runtime to read at rather than being handed the position.

### Failure never escapes a decode

{class}`kober.errors.TruncatedRead` and {class}`kober.errors.EvalError` are
caught by the engine and become a node status. A decoder that raises leaves its
input unaccounted for, and coverage is a promise about *output*. Two loops that
crafted input could otherwise turn into hangs are bounded: a repetition whose
element consumes nothing, and unit nesting past
{data}`kober.decoder.MAX_DEPTH`.

`tests/test_fuzz.py` asserts this over adversarial input, because it is a claim
about all input rather than some.

### Every byte is cited or named, never both

The coverage guarantee. A region the decoder did not read says so with one of
four reasons — `undecodable`, `truncated`, `gap`, `skipped` — and
{class}`kober.node.NodeStatus`'s values are those strings, so the emitter needs
no translation table.

Two consequences that are easy to get wrong, and both have been:

- A unit that failed part-way still **cited** what it decoded first, so marking
  its whole range would claim bytes twice. Uncovered runs are computed by
  interval subtraction.
- A seam is owed after any **hole**-class region, not only after a `Gap`.
  `zpf` classifies `gap` and `truncated` as holes; `undecodable` and `skipped`
  as bytes that existed. The class is read from `zpf.blocks.UNDECODED_REASONS`
  rather than restated here.

### The field path is formatted in exactly one place

{func}`kober.emit.field_path`. The path currently rides in `comment=`, which
`zpf` documents as free text no consumer may depend on, and upstream
[#58](https://github.com/adamkjonsson/python-zipline/issues/58) may replace it
with a real per-record label. One function is what makes that a one-line
change. For the same reason nothing reads a `comment` back: the read side is
the tree, not the file.

### Shape comes from the stream, never the spec

A decoded input is always packet-oriented, whatever transport it started on, so
`InputShape` cannot decide which iterator to use — `stream.is_stream_oriented`
does. The declaration is checked against the stream only to refuse the mismatch
that would fabricate a field tree over unframed bytes. See `DESIGN.md` §9.2.

### The spec cannot run code

Not because code is unsafe — see the cursor rule for what actually matters —
but because a small, total language is cheap to check, cheap to explain, and
portable to a non-Python reader. The parser accepts a whitelist of AST node
types, so "no calls, no loops" holds by construction rather than by a rule
someone has to remember.
