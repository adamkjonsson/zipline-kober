# Phase record: the spec model

**State: done.** Landed on `spec_model_and_more` in five commits, against
`DESIGN.md` revisions 4–5.

Written *after* the fact. This phase ran from a spoken choice between options
rather than a written plan, so this is a record of what was built and why —
kept because the next phase inherits the decisions, not because the plan
itself was ever a document.

## What it built

| Module | What |
| --- | --- |
| `kober.errors` | `KoberError`, `SpecError`, `ExprError`. Split by *when* a fault is detectable. |
| `kober.expr` | The expression language of §3.3: frozen AST, parser, type inference against a `Scope` protocol, `unparse`. |
| `kober.spec` | §3's model as frozen dataclasses. |
| `kober.check` | Whole-spec validation: scoping, ordering, expression types, reachability, recursion. |
| `kober.loader` | `from_dict` / `from_json` / `from_yaml` / `from_file`, surfaced as `Spec.from_*`. |
| `kober.cli` | `kober check` and `kober show`. |

183 tests, ruff clean, no `noqa`.

## Decisions worth carrying forward

**Parsing borrows Python's parser.** `ast.parse` in `eval` mode, translated
through a whitelist of node types. Precedence and associativity come free, and
"no calls, no loops" holds *structurally* — a construct is refused because it
is absent from the whitelist, not because a rule says so. The whitelist is also
the thing to extend if §11.5 ever grows the language.

**Validation is split by what an object can see.** The model checks local
invariants (integer width in range, non-blank names, no duplicate fields);
`check` does everything needing the whole spec. So constructing a `Spec` means
*well formed*, never *valid*, and the docstrings say so.

**`check` collects, it does not raise.** A validator that stops at the first
fault makes an author fix a spec one line per run. Raising is reserved for
faults that stop a spec being *built*.

**Strict loading.** An unknown key is an error, because a misspelled
`conditon:` that loads and does nothing is a decoder silently doing the wrong
thing. YAML's implicit typing is guarded by name — `version: 1.10` and an
unquoted `yes` are refused with a message saying to quote it.

## What the work found

**DESIGN.md §7's example was not real.** Making it loadable exposed two faults:
`enum` sat beside `int` where the schema needs it nested, and the example
referenced a `question` unit it never defined. Both fixed; the example is now
executed by `tests/test_loader.py` so it cannot drift again.

**DESIGN.md §2's central argument was wrong**, and this phase is what surfaced
it — the question "should `Computed` exist?" turned out to be drawn on the
wrong axis. §2 justified the declarative model with *"if specs could run code
they could swallow input, so coverage is provable from the spec alone"*, which
contradicts its own opening paragraph: `fill_undecoded=True` makes coverage
true by construction regardless. Revision 5 replaces it with the **cursor
rule** (§2.1), closes §11 question 2 keeping `Computed`, and reframes §3.3's
minimal expression language as a choice about cost rather than safety.

That correction is the most consequential thing this phase produced, and it is
an invariant the decoder must now enforce rather than a paragraph.

## Where it deviated from the written design

- **`Unit.emit` added.** §3.1 documents `Field.emit` as inheriting "from the
  unit", but the `Unit` listing had nowhere to hold it. Granularity now
  resolves field → unit → decoder.
- **`Param.type` is an `ExprType`.** §3.1 listed `Param` without saying what
  was in it; parameters are referenced from expressions, so that is the
  vocabulary they need.
- **`run` and `try` not registered** in the CLI. They need the decoder, and a
  verb that exists only to refuse is worse than one honestly absent.

## Left open

- `DESIGN.md` still opens with *"Status: draft for discussion. Nothing here is
  implemented."* The second half is now false.
- §11 questions 1, 3, 4, and 5 remain open. Question 2 is closed.
