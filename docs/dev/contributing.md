# Contributing

## Environment

Python 3.11+, and a checkout of
[`python-zipline`](https://github.com/adamkjonsson/python-zipline) beside this
one. One virtualenv covers everything — tests, docs, wheel builds:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ../python-zipline    # see below
.venv/bin/pip install -e . -r requirements.txt
```

**Why `zpf` comes from a checkout.** This project requires `zpf>=0.2.0,<0.3` —
it is built on `zpf.decode_stage` and on `comment=`, both `0.2.0` work — and at
the time of writing PyPI publishes only `0.1.0`. Once `0.2.0` reaches PyPI the
checkout becomes a convenience rather than a requirement.

The pin covers a single `zpf` minor deliberately: that library is in `0.x`,
where every minor is a break with no upgrade path promised, so a range spanning
two would be a promise neither project can keep.

```{note}
An editable install captures version metadata at install time. If `zpf`'s
version changes in the sibling checkout, reinstall it — otherwise
`zpf.__version__` reports the old number and a pin can appear satisfied when it
is not.
```

## The four commands

```bash
.venv/bin/pytest                                  # tests
ruff check .                                      # lint
.venv/bin/sphinx-build -W docs docs/_build/html   # docs, warnings as errors
.venv/bin/python -m build                         # wheel + sdist
```

## Code style

**Type hints everywhere** — parameters, returns, and class attributes — with
`from __future__ import annotations` at the top of every module.

**Zero ruff warnings.** A file you touched must produce none. Never silence one
by editing `ruff.toml`. A `# noqa` is a last resort and **needs asking first**;
in practice there is usually a way not to need it. When the fuzz tests needed
to catch every exception, re-raising with `exc.add_note(...)` satisfied the
blind-except rule *and* kept the traceback, which was better than the
suppression would have been.

Docstrings are Google style with ruff-enforced formatting. Sections (`Args`,
`Returns`, `Raises`, `Attributes`, `Example`) need a blank line before the
closing `"""`.

Cross-references in docstrings should name the **defining module** —
`` :class:`~kober.spec.Spec` ``, not `` kober.Spec `` — because that is where
`autodoc` documents each symbol, and the docs build treats an unresolved
reference as an error.

## Adding a construct to the language

A new field type, size kind, or repeat kind touches **eight modules**, and the
list is here because it has been got wrong twice — a `pointer` and then a
`select` both reached `kober show` unrenderable, from the same missing branch,
two phases apart.

Work down it. Each row names the exact place, because "somewhere in `check.py`"
is what the two misses had in common.

| Module | What has to learn about it |
| --- | --- |
| `spec.py` | The frozen dataclass, and **the `FieldType` union** — easy to add the first and forget the second. |
| `loader.py` | `_TYPE_KINDS`, a builder, and the branch in `_field_type` that dispatches to it. |
| `check.py` | A branch in `_Checker._check_type` to validate it, and one in `_Scope._type_of` so a *later field can reference it*. The second is the one that gets missed: without it the construct works and nothing may name its value. |
| `decoder.py` | A branch in `Decoder._value`. The chain ends by naming what it does not implement, so a missing branch is an `undecodable` region rather than a traceback — do not restore a silent fall-through. |
| `emit.py` | Only if the value is **not read from the bytes it cites**: what it cites (`_leaf`) and, for an integer with no declared width, `UNDECLARED_WIDTH`. |
| `ops.py` | A branch in `_value`, and then **four walks**, each of which has bitten someone: `_kind_exprs` (its expressions — miss it and `parent`/`root` threading silently breaks), `_referenced` (units it can reach), `_kind_consumes` (whether it advances the position), `_types` (flattening a switch). |
| `pygen.py` | Rendering in `_Function.read`, citation in `_Function.record`, and the annotation helpers. Or an explicit refusal — a `CompileError` naming the shape is a fine answer and better than generating something subtly different. |
| `cli.py` | A branch in `_render_type`. **This is the one that has been missed twice.** |

And outside the source:

- **`docs/format/types.md`** — `tests/test_docs.py` fails if a new kind is not
  documented, so this one enforces itself.
- **`CHANGELOG.md`**, under `Unreleased`.
- **`DESIGN.md`** if the construct answers an open question or moves a line in
  §2.1 or §11 — a construct that reads out of order or asks about a repetition
  does.
- **`tests/fuzzing.py`** if no shipped example exercises it. A seed that never
  enters the new branch proves nothing, and
  [Testing](testing.md) has the two rules that cost this project a bug each.

### How you find out you missed one

Not by reading the list — by the checks that fail:

- **The differential** catches a compiler that disagrees with the interpreter,
  which is most of what a missed `ops.py` walk produces.
- **`test_docs.py`** catches the reference.
- **`test_cli.py`** now runs every verb over every shipped example, which is
  what neither `pointer` nor `select` had.

So the useful move after adding a construct is to put it in a **shipped
example**, or in a spec the suite renders and decodes. Both misses above were
constructs that existed only in tests written alongside them.

## Changelog

Every user-visible change gets an entry under `## [Unreleased]` **in the same
change that introduces it**: new or changed public API, CLI flags, spec keys,
defaults, bug fixes, and docs. Purely internal refactors and test-only changes
do not.

Sections appear in this order, omitting empty ones: `Added`, `Changed`,
`Deprecated`, `Removed`, `Fixed`, `Security`, `Documentation`. Anything
breaking goes under `Changed` or `Removed` with a leading **`Breaking:`** and a
note on what callers must do instead.

## Git

**Never commit or push without being asked.** That includes `git commit`,
`git push`, and destructive commands like `reset --hard` or `checkout .`.

Work happens on a branch per phase, and `plans/` carries a plan for the phase
before the work starts. That is not ceremony: the plans are where design
questions get settled explicitly rather than in code, and several were settled
differently from how the plan predicted — which only shows up because the plan
was written down first.

## Before a release

- `pressure_test.py` green.
- The deeper fuzzing pipeline in [Testing](testing.md) run against a real
  capture — it is the only thing that exercises `stage.py`.
- The docs build clean under `-W`.
