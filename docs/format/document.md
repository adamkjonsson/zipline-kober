# The document

A specification is a YAML or JSON document. YAML is the authoring format —
comments are the reason, since a protocol field wants an RFC citation beside it
and JSON cannot carry one — but the model is what the decoder consumes, so
`Spec.from_dict` and `Spec.from_json` work with the standard library alone and
YAML stays an optional extra.

{meth}`kober.spec.Spec.from_file` dispatches on the suffix: `.yaml`, `.yml`, or
`.json`.

## Top level

```yaml
name: dns
version: "1.0"
entry: message
input: either
doc: DNS messages, header and question section.

enums:
  opcode: {0: query, 1: iquery}

units:
  message:
    fields: [...]
```

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | **yes** | Becomes the `zpf` decoder's name, and the root of every field path. |
| `version` | **yes** | Becomes the decoder's version. A string — quote it. |
| `entry` | **yes** | The unit a message starts at. |
| `units` | **yes** | Every unit, by name. |
| `enums` | no | Named values for integer fields. |
| `input` | no | `stream`, `datagram`, or `either` (the default). |
| `endian` | no | Byte order for every integer below, unless it says otherwise. |
| `doc` | no | Free text. |

Anything else is an error. That is deliberate: a misspelled key that loads and
does nothing is a decoder silently doing the wrong thing.

### `endian`

Byte order resolves **field → unit → document → `big`**, and network order is
the default because the protocols this was written for are on a wire.

```yaml
name: some_container
version: "1.0"
entry: header
endian: little          # every integer below, unless it says otherwise

units:
  header:
    fields:
      - {name: magic, bits: 32}
      - {name: version, bits: 16}
      - {name: crc, int: {bits: 32, endian: big}}   # the exception, stated
```

It exists because of what the alternative costs: a field needing `endian` must
write `int: {bits: 32, endian: little}`, so **a little-endian spec could not use
`bits:` on any integer field at all**. That is most formats not on a wire — a
filesystem structure, a USB descriptor, a capture container.

Resolution happens **when the spec loads**, so the byte order is folded into
each field and nothing downstream can tell which spelling was used. It is a
shorthand, not a feature.

The cost is that a field's meaning depends on a distant line: `bits: 32` no
longer says how it is read. `kober show` prints the resolved answer, so the
question has a one-command answer that does not involve scrolling:

```console
$ kober show container.yaml
header
├── magic: u32 little-endian
├── version: u16 little-endian
└── crc: u32
```

Note what does **not** inherit: `signed`. Signedness is a property of what an
individual field means, where byte order is a property of the format as a
whole. A protocol is little-endian; it is not *signed*.

`endian` beside `bits:` at field level is an unknown-key error, as it was
before — the key is on the document and the unit, and an individual integer
still says it inside `int: {…}`.

### `input`

A declaration about what the spec was written against, not an instruction. The
runtime dispatches on the stream itself, because a *decoded* input is always
packet-oriented whatever transport it started on — so a chained stage sees
datagrams even when the first stage read TCP.

It is checked in one direction only: a `datagram` spec run over a byte stream
is **refused**, because it has no framing to find message boundaries with and
would produce a confident tree over the wrong bytes. A `stream` spec over
datagrams is allowed — each datagram is one self-contained message.

## Units

```yaml
units:
  message:
    doc: One DNS message.
    fields:
      - {name: id, type: {int: {bits: 16}}}
    params: [{size: int}]
    confirm: "id != 0"
    reject: "id == 0"
    emit: field
```

| Key | Required | Meaning |
| --- | --- | --- |
| `fields` | **yes** | The fields, in decode order. May be empty. |
| `params` | no | Values the referencing site must supply. |
| `confirm` | no | Boolean. The unit is abandoned unless this holds. |
| `reject` | no | Boolean. The unit is abandoned if this holds. |
| `emit` | no | Default granularity inside this unit. |
| `endian` | no | Byte order for this unit's integers, overriding the document's. |
| `doc` | no | Free text. |

`confirm` and `reject` are how a wrong protocol guess becomes an honest
`undecodable` region rather than a fabricated field tree. Both are evaluated
once the unit's fields are decoded, so both see all of them.

Each `params` entry is a **single-key mapping of name to type**, like every
other tagged construct in the schema, and a parameter's type is one of `int`,
`bool`, `str`, `bytes`:

```yaml
params: [{name: size, type: int}]   # long
params: [{size: int}]               # the same thing
```

An entry naming `name` or `type` is read as the long form, so `{name: size}` is
a long form missing its type rather than a parameter called `name`. A parameter
actually called `name` or `type` is written out in full, which is what the long
form is for.

**`params` is a list and not a mapping**, deliberately: arguments bind
positionally, so the order is load-bearing, and YAML does not promise the order
of a mapping's keys. Every other mapping in this schema — `units`, `enums`, a
switch's `cases` — may be reordered without changing meaning, and there is no
precedent here to lean on.

## Fields

```yaml
- name: qdcount
  type: {int: {bits: 16}}
  condition: "flags.qr == 0"
  repeat: {count: "n"}
  emit: none
  doc: Number of entries in the question section.
```

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | **yes** | The field's name, or `null` for an anonymous region. |
| `type` | **yes** | What to decode. See [Types](types.md). |
| `condition` | no | Boolean. The field is decoded only if it holds. |
| `repeat` | no | Decode it repeatedly. |
| `const` | no | A value the decoded field must equal. See [`const`](types.md#const). |
| `emit` | no | Granularity for this field. |
| `doc` | no | Free text. |

Two of those are usually written **without their wrapper**, because a tagged
construct's kind may lift into the field where the key sets do not overlap:

| Instead of | Write | Which set |
| --- | --- | --- |
| `type: {int: {bits: 8}}` | `bits: 8`, `int: …`, `unit: …`, `bytes: …`, `string: …`, `switch: …`, `computed: …`, `pointer: …`, `select: …` | a type kind |
| `repeat: {count: "n"}` | `count: n`, `until: …`, `to_end: true` | a repeat kind |

```yaml
- {name: questions, unit: question, count: qdcount}
```

Both spellings build the identical spec. See
[Shorthands](types.md#shorthands) for the rule and what it refuses.

`name` is required even when it is `null`, so that an anonymous field is a
choice rather than an omission. Anonymous fields are decoded and cited like any
other but cannot be referenced from an expression, which is what makes them
safe for padding and reserved bits.

A field whose `condition` is false is **absent**, not empty: it consumes
nothing and produces no node.

## Emission granularity

`emit` is `message`, `field`, or `none`, and resolves **field → unit →
enclosing unit → decoder**. A field naming its own granularity therefore wins
over the unit holding it.

- `message` — one record per top-level unit instance, payload the message
  bytes.
- `field` — one record per leaf, each citing the exact bytes it came from.
- `none` — decode for control flow and write nothing. The bytes are marked
  `skipped`, which says the spec deliberately passed over them.

Two chains, resolved differently, and the difference is the point:

| | Chain | Resolved |
| --- | --- | --- |
| [`endian`](#endian) | field → unit → document → `big` | when the spec **loads** |
| `emit` | field → unit → enclosing unit → decoder | while it **decodes** |

`emit`'s hop through the *enclosing* unit is dynamic: granularity depends on
where a unit was referenced from, so the same unit can emit differently at two
sites. Byte order cannot — a unit's integers are read the same way wherever it
is referenced from — so it is folded in at load time and leaves no trace.

## Enums

Two forms. The short one is a mapping of value to label:

```yaml
enums:
  opcode: {0: query, 1: iquery, 2: status}
```

The long one puts them under `members` and adds `doc`:

```yaml
enums:
  opcode:
    doc: RFC 1035 §4.1.1.
    members: {0: query, 1: iquery}
```

Member keys are integers. JSON can only spell one as `"0"`, and YAML gives a
real `0`; both mean the same member.

An enum labels a value — it does not constrain it. A field whose enum has no
entry for the decoded value still decodes; the value simply has no name.

## A YAML trap

It has already caught this project, and a second one was designed out rather
than guarded against.

**The switch dispatch key was renamed because of one.** YAML 1.1 reads bare
`on`, `off`, `yes`, and `no` as booleans, and `on` used to be the switch
dispatch key — so `on: kind` parsed as `{True: "kind"}` and the loader carried
a repair to read the boolean back as the word it was written as. The key is
`dispatch` since 0.1.0, which YAML has no opinion about, and the repair is
gone. A spec still written with `on:` is refused with a message naming the
rename, in either spelling — the bare word and the quoted `"on"`.

**A comma inside a flow mapping splits the value.** This one cannot be designed
out, because it is about values rather than keys:

```yaml
- {name: qr, type: {int: {bits: 1}}, doc: 0 query, 1 response}
```

parses `doc: 0 query` and then `1 response` as a second key, and fails with an
unknown-key error. Quote any `doc:` containing a comma, or use the block form.

The same class of trap catches `version: 1.10`, which YAML reads as the number
`1.1`. Scalars are checked by type and refused with a message saying to quote
them.

## packeteer's dialect

[packeteer](https://github.com/adamkjonsson/packeteer) generates and inspects
traffic for the same kind of protocol, and describes one with a dialect of this
format. Its reference calls that dialect a **superset of kober's**. The two
projects are meant to read each other's specs, and
[`tests/test_packeteer.py`](https://github.com/adamkjonsson/zipline-kober/blob/main/tests/test_packeteer.py)
is what keeps that from being a sentence nobody checks: it loads packeteer's own
shipped specs and asserts what happens to each.

### Four keys, recognised and declined

packeteer has keys kober has no use for, and they are **not** treated as typos:

| Key | Where | Why it has no meaning here |
| --- | --- | --- |
| `over` | top level | kober is handed a spec rather than choosing one by transport |
| `ports` | top level | kober is handed a spec rather than choosing one by port |
| `derive` | field | kober decodes and does not encode, so there is nothing to compute |
| `sensitive` | field | kober writes decoded records and has no redaction step |

Each is a `check` **warning** naming the key and the reason:

```console
$ kober check sensor.yaml
warning: sensor.yaml:1: sensor: 'over' is a packeteer key and has no meaning here; kober is handed a spec rather than choosing one by transport
warning: sensor.yaml:1: sensor: 'ports' is a packeteer key and has no meaning here; kober is handed a spec rather than choosing one by port
warning: sensor.yaml:18: sensor.reading.count: 'derive' is a packeteer key and has no meaning here; kober decodes and does not encode, so there is nothing to compute
warning: sensor.yaml:24: sensor.sample.length: 'derive' is a packeteer key and has no meaning here; kober decodes and does not encode, so there is nothing to compute
warning: sensor.yaml:25: sensor.sample.value: 'sensitive' is a packeteer key and has no meaning here; kober writes decoded records and has no redaction step
sensor 1.0: 0 error(s), 5 warning(s)
```

A key on the document is reported at the document, so the two top-level ones
say line 1 rather than the line each is written on: a mapping knows where it
began and not where each of its keys is. The field-level ones are exact,
because a field *is* a mapping.

A warning rather than an error because **ignoring any of them changes no
decode** — the spec describes the same messages either way, which is the whole
basis of the superset claim. `--strict` turns them into failures for a project
that wants them refused outright.

This does not weaken strictness. An unknown key is still an error, and the
reason for that rule is unchanged: a misspelled `conditon:` must not load and
quietly do nothing. What changed is that these four stopped being *unknown* —
known, declined, and reported is strictly more informative than either
accepting them silently or rejecting them as typos.

They are kept on the spec as {class}`kober.spec.Foreign` records rather than as
attributes on {class}`kober.spec.Field`, so a diagnostic costs no downstream
consumer a field it never reads.

`const` was packeteer's key too, and is [kober's now](types.md#const) — which
is why it is not in the table above.

### What still does not transfer

**The switch dispatch key.** kober renamed `on` to `dispatch` at 0.1.0 and
deleted the boolean repair, because YAML 1.1 reads an unquoted `on:` as `true`;
packeteer still requires `on`. That is one construct with two spellings rather
than a key one side lacks, so no amount of recognising keys helps, and it is
packeteer's to move.

**kober's shorthands, going the other way.** `bits:`, the lifted kind keys and
the bare scalars are not implemented there, so a spec from this repository
fails on the first field. That is the other project's side of the same
transfer.
