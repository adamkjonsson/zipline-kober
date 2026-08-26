# Spec format

The YAML (or JSON) document a specification is written in. This is `kober`'s
real surface: `DESIGN.md` describes the Python *model* the loader builds, while
these pages describe what an author actually types.

- [The document](document.md) — the top level, units, fields, enums, emission
  granularity, and two YAML traps that have already caught this project.
- [Types, sizes, and repeats](types.md) — every field type and what each does
  when it does not match, since that answer is half of what a construct means.
- [Expressions](expressions.md) — the small total language, its scoping rules,
  and what it deliberately cannot do.

The schema is **strict**: an unknown key is an error rather than something
ignored, because a misspelled key that loads and does nothing is a decoder
silently doing the wrong thing. Errors carry a path:

```
spec.units.message.fields[0].type: unknown kind 'enum'; expected one of: bytes, computed, int, pointer, select, string, switch, unit
```

Two complete specs ship with the project and are exercised by the test suite,
so they cannot drift:
[`examples/dns.yaml`](https://github.com/adamkjonsson/zipline-kober/blob/main/examples/dns.yaml)
and
[`examples/http.yaml`](https://github.com/adamkjonsson/zipline-kober/blob/main/examples/http.yaml).

```{toctree}
:hidden:

document
types
expressions
```
