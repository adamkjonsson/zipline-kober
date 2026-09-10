# Spec format

The YAML (or JSON) document a specification is written in. This is `kober`'s
real surface: `DESIGN.md` describes the Python *model* the loader builds, while
these pages describe what an author actually types.

- [What a spec describes](concepts.md) — start here. What a unit *is*, what
  becomes of one in the decoded tree, in a generated decoder and in the output
  file, and what a spec deliberately cannot say.
- [The document](document.md) — the top level, units, fields, enums, emission
  granularity, two YAML traps that have already caught this project, and the
  relationship to packeteer's dialect of this format.
- [Types, sizes, and repeats](types.md) — every field type and what each does
  when it does not match, since that answer is half of what a construct means.
- [Expressions](expressions.md) — the small total language, its scoping rules,
  and what it deliberately cannot do.

**A field says what it decodes on the field itself**, which is the dialect
these pages teach and the one the shipped examples are written in:

```yaml
- {name: qdcount, bits: 16}
- {name: questions, unit: question, count: qdcount}
```

Underneath is a uniform convention — a tagged mapping naming the kind —
reachable as `type: {int: {bits: 16}}` and needed where a body carries a second
key. Both build the identical spec; see
[the three rules](types.md#the-three-rules).

The schema is **strict**: an unknown key is an error rather than something
ignored, because a misspelled key that loads and does nothing is a decoder
silently doing the wrong thing. Errors carry the file, the line, and the path:

```
dns.yaml:27: spec.units.message.fields[0].type: unknown kind 'enum'; expected one of: bytes, computed, int, pointer, select, string, switch, unit
```

A spec read from JSON, or built as a mapping in memory, has no line to report —
`json` gives no positions — so those carry the path alone.

Two complete specs ship with the project and are exercised by the test suite,
so they cannot drift:
[`examples/dns.yaml`](https://github.com/adamkjonsson/zipline-kober/blob/main/examples/dns.yaml)
and
[`examples/http.yaml`](https://github.com/adamkjonsson/zipline-kober/blob/main/examples/http.yaml).

```{toctree}
:hidden:

concepts
document
types
expressions
```
