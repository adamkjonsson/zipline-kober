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
