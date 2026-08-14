# zipline-kober — Claude guidance

## The product

This is a Python module that fits a niche in the Zipline universe. Zipline is a standard
for storing decoded network data, that supports an iterative process for decoding.
The Zipline standard is defined in https://github.com/adamkjonsson/zipline. There
is a Python implementation of this standard called python-zipline
(https://github.com/adamkjonsson/python-zipline). The module name is `zpf`. Also
related is a project called python-zipline-wire (https://github.com/adamkjonsson/python-zipline-wire),
which translates pcap-files into zipline files. 

The niche of this product is to create a Python module that can perform decoding for a given protocol
from a specification.

The product should be a CLI backed by a Python API. The API should be easy to use and feel logical.
It must be possible to everything the CLI can do from the API.

The code should only use the standard library and the libraries mentioned above.

## Code style

- **Type hints everywhere.** All function parameters, return types, and class attributes must be annotated. Use `from __future__ import annotations` at the top of every module.
- **Zero ruff warnings.** After any change, the file you touched must produce no warnings from `ruff check`. The project config is in `ruff.toml`. Never make a warning
go away by changing values in the config file. Using a # noqa: comment to suppress
warnings can only be used as a last resort, and **always ask before making such a change**.

## Git

- **Never commit or push without explicit instruction.** Do not run `git commit`, `git push`, or any destructive git command (`reset --hard`, `checkout .`, etc.) unless I have asked for it in the current message.

## Versioning and changelog

- The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
  While below 1.0, **breaking changes are allowed in a minor bump** (0.7 → 0.8);
  they must still be called out.
- `CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
  **Every user-visible change gets an entry under `## [Unreleased]` in the same
  change that introduces it** — new/changed public API, CLI flags, packet-spec
  keys, defaults, bug fixes, and docs. Purely internal refactors and test-only
  changes do not.
- Change types, in this order, omitting any that are empty: `Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed`, `Security`, `Documentation` (the last is a
  project-specific extra for docs-only work).
- Anything that breaks backwards compatibility goes under `Changed` (or
  `Removed`) with a leading **`Breaking:`** and a note on what callers must do
  instead.
- `pyproject.toml` carries the version. During development of the next release
  it is a `.devN` suffix; the release commit drops the
  suffix.
- Releasing, in order:
  1. Rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh
     empty `Unreleased` above it.
  2. Drop the `.devN` suffix from the version in `pyproject.toml`.
  3. Update the link definitions at the bottom of `CHANGELOG.md`.
  4. Tag `vX.Y.Z` (full three-part version — the older `v0.7` style is not
     used going forward).
  5. Close the release's GitHub issues and its milestone.
- **Issues close at release, not at merge.** Work can sit merged on `main`
  under `Unreleased` for a while — often while a downstream project reviews a
  `.devN` build — and closing an issue then would claim a fix is delivered
  when it is not yet in any release.

## Project layout

## Virtual environment

All development tasks (tests, docs, wheel builds) use a single venv created from `requirements.txt`:

```bash
python -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

- **Run tests:** `.venv/bin/pytest`
- **Build docs:** `.venv/bin/sphinx-build docs docs/_build/html`
- **Build wheel:** `.venv/bin/python -m build`

## Conventions

- Use `.venv/bin/pytest` to run tests and `ruff` (on PATH) to lint.
- Docstrings follow Google style with ruff-enforced formatting (see `ruff.toml`). Sections (Args, Returns, Raises, Attributes, Example) need a blank line before the closing `"""`.
