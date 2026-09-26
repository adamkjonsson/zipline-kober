# Types, sizes, and repeats

**A field says what it decodes on the field itself**, with the kind as one of
its keys:

```yaml
- {name: qdcount, bits: 16}
- {name: questions, unit: question, count: qdcount}
- {name: body, bytes: {size: {expr: "length"}}}
```

That is the dialect this project's own examples are written in, and the one to
write. Underneath it every construct follows a single convention — **a tagged
mapping naming the kind** — and the spellings above are three rules over it:

```yaml
type: {int: {bits: 16}}
size: {expr: "header.length"}
repeat: {count: "qdcount"}
```

Two keys in one of those mappings is an error, not a merge — which is why
`{int: {bits: 4}, enum: opcode}` does not work and `{int: {bits: 4, enum:
opcode}}` does.

Every construct also answers **what happens when it does not match**, and that
answer is half its meaning. A decode that fails says which of four things
happened — `undecodable`, `truncated`, `gap`, `skipped` — and the difference
between them is the difference between "we tried and could not" and "we chose
not to".

## The three rules

Each builds the **identical** spec — nothing downstream can tell which spelling
was used — so a spec may mix them freely.

**1. A tagged construct's kind lifts into its parent** where the key sets do
not overlap. That covers both constructs a field carries, its type and its
repetition:

```yaml
- {name: count, type: {int: {bits: 8}}}
- {name: count, int: {bits: 8}}

- {name: questions, unit: question, repeat: {count: "qdcount"}}
- {name: questions, unit: question, count: qdcount}
```

A field's keys therefore come from three sets that share no member: its own
(`name`, `condition`, `const`, `emit`, `doc`, and the `type`/`repeat`
wrappers), the type kinds, and the repeat kinds (`count`, `until`, `to_end`).

Exactly one key must name a type kind, and at most one a repeat kind — a
repetition is optional where a type is not. Two kinds of the same construct is
an error, a kind beside its own wrapper (`count:` and `repeat:`) is an error,
and a key in none of the three sets is still an error, which names the set each
allowed key belongs to.

**2. A scalar where a mapping is expected fills in the one key that matters.**

```yaml
- {name: body, bytes: {size: {fixed: 4}}}   # long
- {name: body, bytes: {size: 4}}            # a bare size is `fixed`
- {name: body, bytes: 4}                    # a bare bytes/string body is its size
- {name: n, int: 8}                         # a bare int body is its width
- {name: q, unit: question}                 # a bare unit body is its name
- {name: ls, unit: label, until: "ls.length == 0"}   # a bare until is its expression
```

**3. `bits` names the integer kind**, because the word says what the number
counts:

```yaml
- {name: qr, bits: 1}
```

`int: 8` is one character shorter and cannot say whether the 8 is bits or bytes
— Kaitai's `u8` means eight *bytes* — and sub-byte fields are the ordinary case
here rather than the exotic one.

## When the long form is needed

It is the fallback rather than the norm, and there are three occasions for it:

- **A body carrying a second key.** `int: {bits: 4, enum: opcode}`, not
  `{int: 4, enum: opcode}`; putting `enum`, `signed` or `endian` beside `bits:`
  at field level is an unknown-key error, which is loud rather than quiet.
- **A type inside a construct rather than on a field.** A `pointer`'s target
  and a `switch`'s cases are written `type:`-style because they are not field
  keys and nothing lifts there.
- **Readability**, where a wrapper says more than a lifted key does. Both
  spellings are equally valid and the checker cannot tell them apart.

Each entry below leads with the short spelling and gives the long one beside
it.

## Field types

### `int`

```yaml
- {name: qr, bits: 1}                                     # the common case
- {name: opcode, int: {bits: 4, enum: opcode}}            # a second key
- {name: id, type: {int: {bits: 16, signed: false}}}      # the long form
```

| Key | Default | Meaning |
| --- | --- | --- |
| `bits` | **required** | Width, 1 to 64. Need not be a multiple of 8. |
| `signed` | `false` | Two's complement. |
| `endian` | the unit's, else the document's, else `big` | `big` or `little`. See [`endian`](document.md#endian). |
| `enum` | none | Name of an enum labelling the value. |

Bits are read **most significant first**, both within a byte and across a byte
boundary from an unaligned position. `endian` applies only to a whole-byte read
from an aligned position — byte order is not a property a four-bit field has,
which is why inheriting one is harmless for a `bits: 4`.

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
- {name: payload, bytes: 4}
- {name: line, string: {delimiter: "\r\n"}}
- {name: body, type: {bytes: {size: {expr: "length"}}}}   # the long form
```

`bytes` and `string` both say their extent with `size`; `string` also takes
`encoding` (default `utf-8`).

A **`delimiter` may be written beside `size` rather than under it**, which is
what makes the commonest thing a text protocol does shallow rather than deepest.
`consume`, `required` and `within` sit alongside it, with the same defaults they
have in the long form:

```yaml
- {name: line, type: {string: {size: {terminated: {delimiter: "\r\n"}}}}}   # long
- {name: line, string: {delimiter: "\r\n"}}                                # the same thing

- {name: key, string: {delimiter: ":", within: "\r\n", required: false}}
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
- {name: q, unit: question}                                 # no arguments
- {name: b, unit: {name: body, args: ["header.n"]}}         # with arguments
- {name: q, type: {unit: question}}                         # the long form
```

Arguments are bound to the unit's `params` positionally, and their types are
checked against the parameter types.

### `switch`

```yaml
- name: body
  switch:
    dispatch: "kind"
    cases:
      1: {int: {bits: 8}}
      2: {bytes: {size: 2}}
    default: {bytes: {size: {remaining: true}}}
```

A case's value is a **type**, so it is written as a tagged mapping and nothing
lifts inside it: `{int: {bits: 8}}`, not `bits: 8`. Only a field has the three
key sets that make lifting unambiguous.

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
- {name: header_bytes, computed: "data_offset * 4"}
- {name: header_bytes, type: {computed: "data_offset * 4"}}   # the long form
```

Consumes no input. Its type is its expression's type. It exists so a wire
encoding stops leaking: a length in 32-bit words is converted once and named,
rather than multiplied by four in every expression that wants bytes.

At field granularity it cites the fields its expression read, since citing its
own zero-width position would say nothing about where the value came from.

### `pointer`

```yaml
- name: target
  pointer:
    at: "((hi & 63) << 8) | lo"
    type: {unit: name}
```

Its target is spelled `type:` and always will be: that is a type inside a
construct rather than a key on a field, so there is nothing for it to lift out
of.

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
- name: content_length
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

### `concat`

```yaml
- name: chunks
  unit: chunk
  until: "chunks.length == 0"
- name: joined
  concat: chunks.data
```

The bytes of one field of every element of a repetition, joined in order: what
a chunked HTTP body carries, as one value. `concat` names the repeated field
and the field of each element, as `repeated.member`. The repeated field is
declared earlier in the same unit, its elements are units, and the member is a
single bytes field.

It reads nothing and moves no position; the repetition has already read every
byte. At field granularity it cites the **hull** of what it joined, from the
first non-empty member's first byte to the last one's last. The size lines and
line endings between the pieces are cited twice, once by their own fields and
once here, which the format allows. An empty member, such as the last chunk's
data, cites nothing.

Its value is bytes, so a later field can reference it, and a `transform` can
read it. That is the point of it being a field: a `switch` with a `concat`
case and a `bytes` case gives one field that holds a body however it was
framed.

A `concat` cannot repeat.

### `transform`

```yaml
- name: content
  transform:
    from: body
    with: gzip
    limit: 16777216
    type: {unit: document}
```

Bytes already decoded, after a named transform, and optionally what they
are.

| Key | Required | Meaning |
| --- | --- | --- |
| `from` | **yes** | An earlier field that is bytes on every branch (`bytes`, a `concat`, a `transform` with no `type`, or a `switch` of those), or a `bytes` parameter. |
| `with` | **yes** | The transform. A core name, or one declared under the document's [`transforms`](document.md#transforms). |
| `limit` | **yes** | The most bytes the output may have. |
| `args` | no | The transform's parameters, as expressions, by name. Exactly those the declaration lists. |
| `type` | no | What the output is. Decoded in the output's own offset space. |
| `content_type` | no | The record label for an output kept as bytes: `prim:…`, `mime:type/subtype` or `dec:…`. Only without `type`. |

It reads nothing where it stands. Like `select`, it reads a field already
decoded, never the position, so a transform may follow a field that reads to
the end of the message. `limit` is required because a transform with no bound
is not total: a kilobyte of gzip inflates to a gigabyte.

With a `type`, the output is decoded as that type, from its first byte. What
the file says about it is always about **input** bytes, since the output has
no offset space a file can name: every record read from the output cites the
transform's source. Without a `type`, the output is the field's value, as
bytes, and its record is labelled `content_type`.

`args` are typed against the transform's declaration by `check`, before any
data exists and with nothing registered: a spec is valid or not the same way
in every process. A key, which a spec cannot hold, is a
[document parameter](document.md#params).

A `transform` cannot repeat, and its source may not be `emit: none`: the
transform's outcome is what speaks for the source's bytes.

```{note}
In this development version, `check` and `show` understand `transform` and
`concat`, and the decoder does not yet: a message that reaches one is
`undecodable`, and `kober compile` refuses a spec with one.
```

#### Transform names

A name means a specification, not a library, so it means the same thing to
every implementation. Names in the **core** tier are bound by every backend
and may be used without declaring them. A spec using an **extended** name
declares it under `transforms`, which is how it says it is not portable; a
backend may decline one.

| Name | Tier | Defined by | What it is | Bound by kober |
| --- | --- | --- | --- | --- |
| `gzip` | core | RFC 1952 | The gzip file format. | yes |
| `deflate` | core | RFC 1950 | The zlib format: DEFLATE with a header and a checksum. | yes |
| `deflate-raw` | core | RFC 1951 | DEFLATE with no header. | yes |
| `br` | extended | RFC 7932 | Brotli. | no: the standard library has no Brotli |
| `zstd` | extended | RFC 8878 | Zstandard. | on Python 3.14 and later |
| `bzip2` | extended | bzip2 1.0.6 file format | bzip2. | yes |
| `xz` | extended | The .xz File Format 1.2.1 | xz, LZMA2 in a container. | yes |

`deflate` is the zlib format, as it is in HTTP's `Content-Encoding` and in the
browser's `DecompressionStream`; raw DEFLATE is `deflate-raw`. So a header's
value can be used as it stands.

Any other name is the spec's own, a cipher say, declared with its parameters.

**What a name is bound to is the program's business, not the spec's.** kober
binds what the Python standard library can run, and a program adds the rest
with {func}`kober.transforms.register`, or a {class}`kober.transforms.Registry`
of its own: a cipher, which the standard library has none of, or `br` from a
Brotli package. A transform is a callable taking the source's bytes, `limit`,
and the spec's `args` by name, and returning at most `limit` bytes. What it
raises makes the source `undecodable`, and its message is never written out: a
cipher's error text can hold a key. A name a spec uses that nothing binds is
refused before any input is read, saying whether it is a well-known name this
backend does not bind or a name of the spec's own that nothing registered.

## `const`

A value the decoded field must equal — the ordinary way a decoder refuses
traffic that is not its own:

```yaml
- {name: magic, bits: 16, const: 0x5345}
- {name: null, bits: 8, const: 0}          # reserved bits that must be zero
- {name: verb, string: 3, const: "GET"}
- {name: sig, bytes: 2, const: [137, 80]}  # or as byte values
```

It goes on `int`, `bytes` and `string` — the types that hold a value. A
`bytes` constant may be written as text, which is encoded for you, so a magic
number reads as what it is.

**A field that disagrees is `undecodable`, and nothing is raised.** That is
this format's vocabulary for *tried and could not*, and the same verdict a
failing `confirm` produces. The bytes are still cited: they were read, they are
real, and the coverage guarantee accounts for them.

### Why not `confirm`

A unit-level `confirm` can say the same thing, and it says it in the wrong
place and at the wrong time:

```yaml
units:
  message:
    fields:
      - {name: magic, bits: 16}
      # … every other field …
    confirm: "magic == 0x5345"
```

`confirm` and `reject` are evaluated **once the unit's fields are decoded**,
which is right for a condition spanning several fields and wrong for a magic
number. A run holds as many messages as fit and the driver decodes the entry
unit again and again, so a message that reads the wrong number of bytes leaves
every message behind it misaligned. A wrong guess caught at byte two ends one
message; the same guess caught after the unit has decoded has already consumed
an arbitrary and probably wrong number of bytes.

`confirm` and `reject` stay, unchanged, for the conditions that span more than
one field or that are not equality. `const` is not a general assertion and is
not meant to grow into one — the moment it wants an expression, it is a
`confirm`.

### What `check` verifies

Each of these is otherwise found by a decode that never matches anything, which
looks like traffic that is not yours rather than like a spec that cannot match:

- the field's type is one that holds a value — not a `unit` or a `switch`;
- the constant's type matches the field's;
- an integer constant fits the field's `bits`.

A constant on a **repeated** field constrains every element, and the repetition
stops at the first that disagrees. `kober show` prints the constant beside the
field, since it is the most useful thing on that line.

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

### `remaining` and `fill` are measured against the message

Both read to the end of the message — `remaining` all of it, `fill` all of it
less its own unit's trailer — and neither knows what its *parent* still needs.
So a unit containing either, at any depth, may only be referenced from the last
position of its own unit, and so on up; and a `remaining` may only be the last
field that reads anything in its unit. A spec that breaks this decodes no
input: the field takes the bytes a later one needs and cites them as its own,
and the later one has nothing left to read.

`check` refuses such a spec. Run anyway — `Decoder(spec, check=False)` — the
starved field is reported **`undecodable`**, with the reason (`'trailer' has no
bytes left: 'body' is unit 'inner', …`), not `truncated`. The bytes all arrived
and the spec read them wrongly. `truncated` would say the message was cut
short, which is a claim about the capture rather than the spec.

```yaml
units:
  m:
    fields:
      - {name: body, unit: inner}     # refused: 'trailer' is decoded after it
      - {name: trailer, bits: 32}
  inner:
    fields:
      - {name: count, bits: 8}
      - {name: data, bytes: {size: {fill: true}}}
```

`inner` is correct on its own. The error is at the reference, which is the
only place the fault is visible, and it names the whole chain:

```text
error: m.yaml:7: m.m.body: 'body' is unit 'inner', which reads to the end of
the message through 'data', but 'trailer' is decoded after it and would have
no bytes left
```

A field that reads nothing where it stands — a `computed`, `select` or
`pointer` — may follow, since nothing starves it. A `remaining` inside a
`pointer`'s target counts for nothing either: the target is read on its own
cursor at another offset. A `remaining` under a `repeat` is refused outright,
as a repeating `fill` is. The rule is the same under `input: stream`, and the
same one packeteer states for its dialect.

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

The kind lifts into the field, as a type kind does, so the short spelling is
the ordinary one and `repeat:` is what an unusual case reaches for.

| Kind | Written | Long form | Meaning |
| --- | --- | --- | --- |
| `count` | `count: n` | `repeat: {count: "n"}` | An integer expression giving the number of elements. |
| `until` | `until: "item.tag == 0"` | `repeat: {until: "item.tag == 0"}` | Repeat until the condition holds, tested **after** each element. |
| `to_end` | `to_end: true` | `repeat: {to_end: true}` | Repeat until the run is exhausted. |

```yaml
- {name: questions, unit: question, count: qdcount}
- {name: answers, unit: rr, count: ancount}
```

An `until` expression sees the field it repeats, and there it means **the
element just decoded** rather than the list. A [`select`](#select)'s `where`
and `value` bind the same way. Those are the only places a repeated field may
be referenced; everywhere else it is refused, because the expression language
has no list type — and neither binding gives it one, since each names a single
element for the length of one expression.

### Naming the element

Under the rule above the same name means the repetition on one line and one
element on the next, with nothing marking the change. `as:` names the element
instead, on either construct — and a lifted `until:` takes the same body the
wrapped one does, so it carries `as` unchanged:

```yaml
until: {expr: "label.length == 0", as: label}

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
        until: "labels.length == 0 or labels.length >= 192"

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
