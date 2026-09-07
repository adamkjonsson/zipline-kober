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

## Shorthands

The convention above is uniform, and uniformity has a cost: an integer field is
four levels deep to say *count is eight bits*. Three rules shorten it. Each
builds the **identical** spec — nothing downstream can tell which spelling was
used — so a spec may mix them freely.

**A scalar where a mapping is expected fills in the one key that matters.**

```yaml
type: {bytes: {size: {fixed: 4}}}      # long
type: {bytes: {size: 4}}               # a bare size is `fixed`
type: {bytes: 4}                       # a bare bytes/string body is its size
type: {int: 8}                         # a bare int body is its width
type: {unit: question}                 # a bare unit body is its name
repeat: {until: {expr: "n == 0"}}      # long
repeat: {until: "n == 0"}              # a bare until body is its expression
```

Anything carrying a second key writes the long form: `{int: {bits: 4, enum:
opcode}}`, not `{int: 4, enum: opcode}`.

**The kind key may be lifted into the field.** The field keys (`name`, `type`,
`condition`, `repeat`, `emit`, `doc`) and the type keys do not overlap, so there
is nothing to be ambiguous about:

```yaml
- {name: count, type: {int: {bits: 8}}}
- {name: count, int: {bits: 8}}
```

Exactly one key must name a kind. Zero is an error, two is an error, `type:`
beside a lifted kind is an error, and a key in neither set is still an error.

**`bits` names the integer kind**, because the word says what the number counts:

```yaml
- {name: qr, bits: 1}
```

`int: 8` is one character shorter and cannot say whether the 8 is bits or bytes
— Kaitai's `u8` means eight *bytes* — and sub-byte fields are the ordinary case
here rather than the exotic one. The moment a field needs `enum`, `signed` or
`endian` it writes `int: {bits: …, …}`; putting one of those beside `bits:` at
field level is an unknown-key error, which is loud rather than quiet.

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

`bytes` and `string` both say their extent with `size`; `string` also takes
`encoding` (default `utf-8`).

A **`delimiter` may be written beside `size` rather than under it**, which is
what makes the commonest thing a text protocol does shallow rather than deepest.
`consume`, `required` and `within` sit alongside it, with the same defaults they
have in the long form:

```yaml
type: {string: {size: {terminated: {delimiter: "\r\n"}}}}      # long
type: {string: {delimiter: "\r\n"}}                            # the same thing

type: {string: {delimiter: ":", within: "\r\n", required: false}}
```

A body says its extent **once**: `size` and `delimiter` together is an error, as
is `within` or `required` with no `delimiter` to modify. The long form still
works and is what an unusual size uses.

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
    dispatch: "kind"
    cases:
      1: {int: {bits: 8}}
      2: {bytes: {size: 2}}
    default: {bytes: {size: {remaining: true}}}
```

`dispatch` is the expression dispatched on, and must be an integer or a string.
`cases` maps a value to the type to decode for it; case keys must match that
expression's type, and JSON's `"1"` and YAML's `1` mean the same case.
`default` is the type used when nothing matches.

The key was `on` until 0.1.0, which YAML 1.1 reads as the boolean `true` — see
[the YAML trap](document.md#a-yaml-trap). A spec still written that way is
refused with a message naming the rename.

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

### `select`

```yaml
type:
  select:
    from: headers
    where: "lower(headers.name) == 'content-length'"
    value: "to_int(headers.value)"
    default: "-1"
```

Ask a question about a **repeated** field, and get one scalar back. Four keys
are required; `as` is optional.

`from` names a repeated field declared earlier in the same unit. `where` is a
boolean predicate over one element, and the **first** element it holds for is
the one selected. `value` projects that element, and is the field's value.
`default` is the value when nothing matched.

Inside `where` and `value`, one element is bound — under `as` if there is one,
and otherwise under the repeated field's own name, which is the same binding an
`until` uses and is [described with it](#naming-the-element). `default` gets no
binding either way: nothing matched, so there is no element for it to mean.

A select's type is its projection's, so `value` and `default` must agree on
one, and a later field may reference the result like any other scalar:

```yaml
- {name: body, type: {bytes: {size: {expr: "content_length"}}}, condition: "content_length > 0"}
```

This is the one construct that can ask about a repetition, and the reason it
exists is that a message often cannot be framed without one: choosing between
`Content-Length` and chunked encoding means asking whether *any* header said
so. Because `default` is required, "nothing matched" always has an answer the
spec wrote — there is no case left over to guess at.

It consumes no input and moves no position; the repetition is already decoded
by the time it runs. At field granularity it cites **the element it selected**,
which is the honest evidence — this value came from *that* header, not from all
of them. When nothing matched there is nothing to point at, so the default
cites no bytes at all.

An expression in `where` or `value` that cannot be evaluated — `to_int` on a
value that is not a number, say — makes the field `undecodable`, exactly as an
unevaluable size does. It is not quietly treated as "no match", because that
would report the author's default as though it were read from the input.

## Sizes

| Kind | Form | Meaning |
| --- | --- | --- |
| `fixed` | `{fixed: 4}`, or just `4` | Exactly that many bytes. |
| `expr` | `{expr: "n * 2"}` | An integer expression, evaluated at decode time. |
| `terminated` | `{terminated: {…}}` | Up to a delimiter; see below. |
| `remaining` | `{remaining: true}` | Everything left in the run. |
| `fill` | `{fill: true}` | Everything left, **less what the fields after it claim**. |

### `fill`

A body between a header and a fixed footer, which nothing else here can say:

```yaml
fields:
  - {name: count,     bits: 8}
  - {name: data,      bytes: {size: {fill: true}}}
  - {name: data_type, bits: 32}
```

`data` is everything left except the four bytes `data_type` still needs.
`remaining` is the closest and is wrong — it takes those four too, leaving the
trailing field to fail on an empty cursor.

**The trailing width must be computable from the spec alone**, or the spec is
rejected. An integer contributes its `bits`; a `bytes` or `string` sized `fixed`
contributes its length; a nested unit contributes the sum of its own fields; a
`switch` counts only when every case *and* a present `default` agree on a width.
A `computed`, `select` or `pointer` reads nothing where it stands and so claims
none of the trailer.

Refused, because each would make the boundary a guess: a trailing field with a
`condition`, a repeat whose count the spec does not fix, a trailing size that is
itself `expr`, `terminated`, `remaining` or `fill`, a second `fill` in the same
unit, a `fill` that repeats, and a trailer that is not a whole number of bytes.
Each is an error naming the field responsible.

```{warning}
**A run is not a packet.** Under `input: datagram` the two coincide and a fill
is exact. Under `input: stream` a run holds as many messages as fit, so a fill
takes the rest of the *run* — swallowing every message after this one in the
same segment and naming their bytes as one field. The checker warns about that
pairing; it is a warning rather than an error because a stream spec whose
messages each fill a run is coherent, just unusual.
```

### `terminated`

```yaml
size:
  terminated:
    delimiter: "\r\n"     # or a list of byte values: [13, 10]
    consume: true         # default
    required: true        # default
    within: null          # default: search the whole run
```

`delimiter` is the byte sequence to stop at, written as text or as a list of
byte values. `consume` decides whether it is read past. `required` decides what
a missing delimiter means:

- `required: true` (default) — the value is **truncated**. In a byte stream
  that usually means the message continues in a segment we do not have, which
  is an ordinary outcome rather than an error.
- `required: false` — the rest of the run is the value.

`within` bounds the search by a second byte sequence, and the rule is
**whichever comes first**: a delimiter that begins after the bound reads as
though it were not there at all. It is what lets one line split into two
fields —

```yaml
- {name: name,  string: {delimiter: ":", within: "\r\n", required: false}}
- {name: value, string: {delimiter: "\r\n"}}
```

— so an HTTP header *has* a name and a value in the spec, instead of having
them computed back out of the line afterwards. The blank line ending a header
block falls out with no special case: it has no colon before its CRLF, so the
optional bounded terminator takes nothing and both come back empty.

A bound changes only what "absent" means; `required` still decides what to do
about it. The one place the two spellings differ is what an **optional** absent
terminator reads:

| | Delimiter not found | |
| --- | --- | --- |
| | `required: true` | `required: false` |
| no `within` | `truncated` | the rest of the run |
| `within` set | `truncated` | **nothing** |

Bounded, it reads nothing rather than reading up to the bound. The bound is a
limit on the search, never a second terminator — letting the value run to it
would be reading under a delimiter the spec never found.

A size expression evaluating to a negative number is `undecodable`. A size
larger than what remains is `truncated`.

## Repeats

| Kind | Form | Meaning |
| --- | --- | --- |
| `count` | `{count: "n"}` | An integer expression giving the number of elements. |
| `until` | `{until: "item.tag == 0"}` | Repeat until the condition holds, tested **after** each element. |
| `to_end` | `{to_end: true}` | Repeat until the run is exhausted. |

An `until` expression sees the field it repeats, and there it means **the
element just decoded** rather than the list. A [`select`](#select)'s `where`
and `value` bind the same way. Those are the only places a repeated field may
be referenced; everywhere else it is refused, because the expression language
has no list type — and neither binding gives it one, since each names a single
element for the length of one expression.

### Naming the element

Under the rule above the same name means the repetition on one line and one
element on the next, with nothing marking the change. `as:` names the element
instead, on either construct:

```yaml
repeat: {until: {expr: "label.length == 0", as: label}}

select:
  from: headers
  as: header
  where: "lower(header.name) == 'content-length'"
  value: "to_int(header.value)"
  default: "-1"
```

It is optional and changes nothing about what either construct does. Omitted,
the repeated field's own name binds the element, exactly as before — which reads
fine wherever the name is plural enough to survive it.

Writing one makes the repeated field's own name a **list again**, refused like
any other: with `as: header` in force, `headers.name` is an error rather than a
second way to say the same thing. That is the point of the key — exactly one
name means an element, and it is the one the author chose.

Two guards, both reachable from crafted input:

- A repetition whose element consumes nothing is refused as unable to
  terminate.
- An element that fails stops the repetition, rather than the loop retrying a
  failure that cannot resolve.

A negative `count` is `undecodable`.

## Worked example

From [`examples/dns.yaml`](https://github.com/adamkjonsson/zipline-kober/blob/main/examples/dns.yaml),
a DNS name — a run of length-prefixed labels, ending either in a zero-length
label or in a compression pointer:

```yaml
  name:
    fields:
      - name: labels
        unit: label
        repeat: {until: "labels.length == 0 or labels.length >= 192"}

  label:
    fields:
      - {name: length, bits: 8}
      - name: rest
        switch:
          dispatch: "length >> 6"
          cases:
            0: {string: {size: {expr: "length"}}}
            3: {unit: {name: compressed, args: ["length"]}}

  compressed:
    params: [{name: high, type: int}]
    fields:
      - {name: low, bits: 8}
      - name: target
        pointer: {at: "((high & 63) << 8) | low", type: {unit: name}}
```

Four of the types in one place: an `int`, a `string` sized from an earlier
field, a `switch` on the top two bits of that field, and a `pointer` reading a
name that was already decoded somewhere earlier in the message.

`labels.length` reads the `length` field of the label just decoded, which is
what stops the repetition on the terminating zero byte.
