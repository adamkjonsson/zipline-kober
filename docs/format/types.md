# Types, sizes, and repeats

Types, sizes, and repeats all follow one convention: **a single-key mapping
naming the kind**.

```yaml
type: {int: {bits: 16}}
size: {expr: "header.length"}
repeat: {count: "qdcount"}
```

Two keys in one of these mappings is an error, not a merge — which is why
`{int: {bits: 4}, enum: opcode}` does not work and `{int: {bits: 4, enum:
opcode}}` does.

Every construct also answers **what happens when it does not match**, and that
answer is half its meaning. A decode that fails says which of four things
happened — `undecodable`, `truncated`, `gap`, `skipped` — and the difference
between them is the difference between "we tried and could not" and "we chose
not to".

## Field types

### `int`

```yaml
type: {int: {bits: 16, signed: false, endian: big, enum: opcode}}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `bits` | **required** | Width, 1 to 64. Need not be a multiple of 8. |
| `signed` | `false` | Two's complement. |
| `endian` | `big` | `big` or `little`. Network order is the default. |
| `enum` | none | Name of an enum labelling the value. |

Bits are read **most significant first**, both within a byte and across a byte
boundary from an unaligned position. `endian` applies only to a whole-byte read
from an aligned position — byte order is not a property a four-bit field has.

A sub-byte field cites the byte **containing** it, since `zpf` spans are byte
offsets. Several fields citing the same byte is normal and legal: a flags word
and the bits inside it all cite the same range.

```{note}
A width outside `zpf`'s `prim:` vocabulary (8, 16, 32, 64) has no token of its
own, so at field granularity the value is written in the smallest token that
holds it — a `u4` as `prim:u8`, a `u24` as `prim:u32`. The *value* is correct
and readable by any consumer; the exact width is not recorded, and `cites`
does not recover it either.
```

### `bytes` and `string`

```yaml
type: {bytes: {size: 4}}
type: {string: {size: {terminated: {delimiter: "\r\n"}}, encoding: utf-8}}
```

`bytes` takes only `size`. `string` takes `size` and `encoding` (default
`utf-8`).

A string whose bytes do not decode cleanly is **not** a failure. The bytes are
accounted for either way, so the region stays `ok`, the value is decoded with
replacement characters, and the node records what went wrong. A malformed
string is a fact about the input, not a fault in the decoder.

### `unit`

```yaml
type: {unit: question}                          # no arguments
type: {unit: {name: body, args: ["header.n"]}}  # with arguments
```

Arguments are bound to the unit's `params` positionally, and their types are
checked against the parameter types.

### `switch`

```yaml
type:
  switch:
    on: "kind"
    cases:
      1: {int: {bits: 8}}
      2: {bytes: {size: 2}}
    default: {bytes: {size: {remaining: true}}}
```

`on` is the expression dispatched on, and must be an integer or a string.
`cases` maps a value to the type to decode for it; case keys must match `on`'s
type, and JSON's `"1"` and YAML's `1` mean the same case. `default` is the type
used when nothing matches.

**Without a `default`, an unmatched value makes the region `undecodable`** —
tried and failed — and the enclosing unit stops there. That is legal and often
right; the checker warns about it so that it is a choice rather than an
oversight.

### `computed`

```yaml
type: {computed: "data_offset * 4"}
```

Consumes no input. Its type is its expression's type. It exists so a wire
encoding stops leaking: a length in 32-bit words is converted once and named,
rather than multiplied by four in every expression that wants bytes.

At field granularity it cites the fields its expression read, since citing its
own zero-width position would say nothing about where the value came from.

### `pointer`

```yaml
type:
  pointer:
    at: "((hi & 63) << 8) | lo"
    type: {unit: name}
```

A back-reference: *read `type` at `at`, and carry on where you were.* Both keys
are required. Real DNS needs it — an answer record's owner name is usually two
bytes meaning "the name at offset 12" (RFC 1035 §4.1.4).

`at` is an integer expression giving an offset **from the start of the
message**, which is the only space it can mean. A run holds many messages, so a
pointer that meant stream-absolute would work on a run's first message and
silently misread every later one.

Because `at` is an expression, a pointer **reads nothing where it stands** —
the bytes encoding the reference are read by ordinary fields, exactly as `hi`
and `lo` are above. Like `computed`, it is zero-width at the cursor; unlike
`computed`, it cites the region it read rather than the fields it read from.
That region may already be cited by whatever decoded it in place, and two
records citing one region is legal.

A pointer may only target bytes the message has **already decoded**: at or
after the message start, strictly before the pointer. Anything else — an offset
past the end, a forward reference, a target that does not decode — makes the
region `undecodable`, and never raises. That rule is also what makes chains
finite: each hop must land strictly earlier than the last, so a cycle cannot be
constructed.

## Sizes

| Kind | Form | Meaning |
| --- | --- | --- |
| `fixed` | `{fixed: 4}`, or just `4` | Exactly that many bytes. |
| `expr` | `{expr: "n * 2"}` | An integer expression, evaluated at decode time. |
| `terminated` | `{terminated: {…}}` | Up to a delimiter; see below. |
| `remaining` | `{remaining: true}` | Everything left in the run. |

### `terminated`

```yaml
size:
  terminated:
    delimiter: "\r\n"     # or a list of byte values: [13, 10]
    consume: true         # default
    required: true        # default
```

`delimiter` is the byte sequence to stop at, written as text or as a list of
byte values. `consume` decides whether it is read past. `required` decides what
a missing delimiter means:

- `required: true` (default) — the value is **truncated**. In a byte stream
  that usually means the message continues in a segment we do not have, which
  is an ordinary outcome rather than an error.
- `required: false` — the rest of the run is the value.

A size expression evaluating to a negative number is `undecodable`. A size
larger than what remains is `truncated`.

## Repeats

| Kind | Form | Meaning |
| --- | --- | --- |
| `count` | `{count: "n"}` | An integer expression giving the number of elements. |
| `until` | `{until: "item.tag == 0"}` | Repeat until the condition holds, tested **after** each element. |
| `to_end` | `{to_end: true}` | Repeat until the run is exhausted. |

An `until` expression sees the field it repeats, and there it means **the
element just decoded** rather than the list. That is the one place a repeated
field may be referenced; everywhere else it is refused, because the expression
language has no list type.

Two guards, both reachable from crafted input:

- A repetition whose element consumes nothing is refused as unable to
  terminate.
- An element that fails stops the repetition, rather than the loop retrying a
  failure that cannot resolve.

A negative `count` is `undecodable`.

## Worked example

From [`examples/dns.yaml`](https://github.com/adamkjonsson/zipline-kober/blob/main/examples/dns.yaml),
a DNS name — a run of length-prefixed labels ending in a zero-length one:

```yaml
  name:
    fields:
      - name: labels
        type: {unit: label}
        repeat: {until: "labels.length == 0"}

  label:
    fields:
      - {name: length, type: {int: {bits: 8}}}
      - {name: text, type: {string: {size: {expr: "length"}}}}
```

`labels.length` reads the `length` field of the label just decoded, which is
what stops the repetition on the terminating zero byte.
