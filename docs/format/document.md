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
| `doc` | no | Free text. |

Anything else is an error. That is deliberate: a misspelled key that loads and
does nothing is a decoder silently doing the wrong thing.

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
    params: [{name: size, type: int}]
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
| `doc` | no | Free text. |

`confirm` and `reject` are how a wrong protocol guess becomes an honest
`undecodable` region rather than a fabricated field tree. Both are evaluated
once the unit's fields are decoded, so both see all of them.

A parameter's `type` is one of `int`, `bool`, `str`, `bytes`.

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
| `emit` | no | Granularity for this field. |
| `doc` | no | Free text. |

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

## Two YAML traps

Both have already caught this project, and the schema guards against one of
them.

**`on` is a boolean.** YAML 1.1 reads bare `on`, `off`, `yes`, and `no` as
booleans, and `on` is the switch dispatch key — so `on: kind` parses as
`{True: "kind"}`. The loader reads that boolean back as the key it was written
as, narrowly: only inside a `switch`, only for `True`, and only when a real
`on` is not also present. Quoting it (`"on": kind`) works too.

**A comma inside a flow mapping splits the value.** This:

```yaml
- {name: qr, type: {int: {bits: 1}}, doc: 0 query, 1 response}
```

parses `doc: 0 query` and then `1 response` as a second key, and fails with an
unknown-key error. Quote any `doc:` containing a comma, or use the block form.

The same class of trap catches `version: 1.10`, which YAML reads as the number
`1.1`. Scalars are checked by type and refused with a message saying to quote
them.
