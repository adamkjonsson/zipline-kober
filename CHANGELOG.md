# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## Versioning

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While below `1.0`, breaking changes are allowed in a minor bump (`0.7` → `0.8`)
and are always called out.

The version is declared once, in `pyproject.toml`;
`zipline_decoder.__version__` reads it back from the installed distribution
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

### Added

- `pyproject.toml`, packaging `zipline_decoder` with a `zipline-decode` console
  script and an optional `yaml` extra for spec authoring.
- `DESIGN.md` — draft design: the spec model, decode semantics, emission
  granularity, and the public API, with the parts verified against `zpf` marked
  as such.
- `pressure_test.py` — an executable probe of `zpf` behaviour a spec-driven
  decoder depends on: stage chaining, overlapping spans, `prim:` payload
  normalization, and message timestamps. Intended to seed the test suite.

### Documentation

- Upstream findings from the pressure test filed against `python-zipline`:
  [#55](https://github.com/adamkjonsson/python-zipline/issues/55) (no
  `comment=` on `record()`, which blocks per-field decoded records),
  [#56](https://github.com/adamkjonsson/python-zipline/issues/56) (decoded
  inputs are packet-oriented, undocumented), and
  [#57](https://github.com/adamkjonsson/python-zipline/issues/57)
  (`check_coverage` raises an internal `AttributeError` for a `FileReader`).

[Unreleased]: https://github.com/adamkjonsson/zipline_decoder/commits/main/
