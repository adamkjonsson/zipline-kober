# What a spec describes

The other pages here are reference: every key, and what each one does. This one
is the part that has to be read first — what the pieces *are*, and what becomes
of them.

A specification names three things.

| | |
| --- | --- |
| **A document** | The whole spec: a name, a version, and which unit a message starts at. |
| **Units** | Named groups of fields. One of them is a message; the rest are the structures inside it. |
| **Fields** | What is actually read, in order, from the bytes. |

Fields do the reading. Units are how the reading is *organised*, and they are
the concept most worth understanding before writing anything, because a unit is
the thing that shows up everywhere afterwards — in the decoded tree, in a
generated decoder's type, and in every field path in the output file.

## Units

**A unit is a named group of fields, decoded in the order they are written.**
That is the whole definition. What makes it worth having a name for is that a
unit is also the boundary at which everything else is expressed:

- **One unit is the message.** `entry:` names it, and decoding "a message"
  means decoding that unit once.
- **A field can be a unit**, which is how structure nests: `type: {unit: person}`
  reads a whole `person` where that field stands.
- **A `switch` chooses between units**, which is how a format that says
  *what comes next depends on this byte* gets written down.
- **A unit may reference itself**, directly or through another, which is how a
  recursive format is described. `examples/dns.yaml` has three units that do.

There is no anonymous nesting: if a group of fields is worth grouping, it gets a
name. That is a deliberate constraint rather than a missing feature — the name
is what an expression refers to, what a generated class is called, and what a
consumer of the output reads in a field path, so a structure with no name would
be unnameable in three places at once.

### One unit, four views

Here is a complete spec. Two units: a message holding a count and that many
people, each person a length and a name.

```yaml
name: greeting
version: "1.0"
entry: message
input: datagram
doc: A toy protocol, for explaining what a unit is.

units:
  message:
    doc: One greeting.
    fields:
      - {name: count, type: {int: {bits: 8}}}
      - {name: people, type: {unit: person}, repeat: {count: "count"}}

  person:
    doc: One person's name, length-prefixed.
    fields:
      - {name: length, type: {int: {bits: 8}}}
      - {name: name, type: {string: {size: {expr: "length"}}}}
```

**As a shape.** `kober show` expands nested units in place, so the tree is what
the spec describes rather than what any one message contains:

```console
$ kober show greeting.yaml
greeting 1.0 — input: datagram, entry: message
  A toy protocol, for explaining what a unit is.

message
├── count: u8
└── people: → person  ×count
    ├── length: u8
    └── name: string[length] utf-8
```

**As a decoded tree.** `kober try` decodes one buffer and prints what came
back. Each `person` is a node with children, and the repeated field is a node
holding the elements:

```console
$ kober try greeting.yaml --hex 0203416e6e054368726973
message  [0, 11)
  count = 2  [0, 1)
  people  [1, 11)
    people[0]  [1, 5)
      length = 3  [1, 2)
      name = 'Ann'  [2, 5)
    people[1]  [5, 11)
      length = 5  [5, 6)
      name = 'Chris'  [6, 11)

11 of 11 byte(s) decoded: ok
```

**As Python.** `kober compile` turns each unit into a frozen dataclass named
after it, with one attribute per named field, typed:

```python
@dataclass(slots=True)
class Message:
    """One greeting."""

    count: int
    people: list[Person]
    __spans__: tuple[int, ...]


@dataclass(slots=True)
class Person:
    """One person's name, length-prefixed."""

    length: int
    name: str
    __spans__: tuple[int, ...]
```

The unit's `doc:` became the class docstring, the repeated field became a
`list`, and `__spans__` carries the byte ranges — read back with
{func}`kober.runtime.span` rather than by indexing it.

**As output.** Decoding a file at field granularity writes one record per leaf,
and the path on each is *the spec's own names*, unit by unit:

```console
$ kober run greeting.yaml in.zpf -o out.zpf --emit field
out.zpf: 5 record(s), 0 undecoded region(s)
```

| Path | Type | Cites | Payload |
| --- | --- | --- | --- |
| `greeting.count` | `prim:u8` | `[0,1)` | `02` |
| `greeting.people[0].length` | `prim:u8` | `[1,2)` | `03` |
| `greeting.people[0].name` | `mime:text/plain` | `[2,5)` | `Ann` |
| `greeting.people[1].length` | `prim:u8` | `[5,6)` | `05` |
| `greeting.people[1].name` | `mime:text/plain` | `[6,11)` | `Chris` |

The spec's `name:` is the root, each unit contributes the field that reached it,
and a repeated field contributes an index. **This is the part worth designing
deliberately:** those paths are what someone reading the decoded file sees, and
they are made of the names chosen in the YAML. Renaming a field renames a column
in everybody's output.

### Parameters

A unit's fields sometimes cannot be read without something the *caller* knows.
`params:` declares what a referencing site must supply, and `args:` supplies it:

```yaml
      - name: rest
        type:
          switch:
            on: "length >> 6"
            cases:
              0: {string: {size: {expr: "length"}}}
              3: {unit: {name: compressed, args: ["length"]}}

  compressed:
    params: [{name: high, type: int}]
    fields:
      - {name: low, type: {int: {bits: 8}}}
      - name: target
        type: {pointer: {at: "((high & 63) << 8) | low", type: {unit: name}}}
```

That is real DNS, from `examples/dns.yaml`. A compression pointer is two bytes
whose low fourteen bits are an offset — but the first byte has already been read
by the *caller*, to decide that this is a pointer at all. `compressed` needs it
and cannot re-read it, so it is passed in.

Arguments bind positionally and their types are checked, so a unit that takes an
`int` cannot be handed text. A parameter is in scope for the unit's expressions
like a field, but it decodes nothing and appears in no output — it is a value,
not a region of bytes.

### Why not just nest the fields?

Two reasons, and neither is style.

**Reuse.** A DNS name appears in a question, in an answer's owner field, and at
the end of a compression pointer. One `name` unit is written once and referenced
three times; inlined, it would be written three times and drift.

**Recursion has nowhere else to live.** A DNS name is a list of labels, and a
label may be a pointer to another name. That is a cycle in the description, and
a description made only of nesting cannot express one — you would be writing an
infinitely deep document. A named unit can refer to itself, and the compiler
detects which units are recursive and generates accordingly.

## What "one message" is

`entry:` names the unit a message starts at, and everything follows from it:
what `try` decodes, what a `message`-granularity record contains, and what the
compiled module's `decode()` returns.

It matters because **a run of bytes may hold more than one message**. The driver
decodes the entry unit, and if bytes remain it decodes another one, until the
run is used up. Fifty pipelined HTTP requests in one TCP run decode as fifty
messages, which works only because each message reads *exactly* its own bytes
and stops.

That is the practical reason framing has to be exact rather than approximately
right. A message that reads one byte too few leaves the next message
misaligned — and a message that reads to the end of the run swallows every
message behind it.

## What a spec cannot say

Worth knowing early, because each is a deliberate line rather than an omission.

- **Nothing moves the read cursor but the declared constructs.** There is no
  hook, no callback, no place to put a snippet of code. Expressions compute
  values; they never decide a position. That is what makes it possible to say
  ahead of time that a spec accounts for its input honestly.
- **There is no list type.** A repeated field cannot be handed around, and an
  expression cannot iterate one. Asking a question about a repetition is what
  [`select`](types.md#select) is for, and it hands back a single value.
- **Fields are read in the order written.** An expression may only name fields
  declared *before* it, because a later one has not been decoded yet. The
  checker enforces this before any data exists.
- **Bytes are not transformed.** Decompression and decryption are not
  expressible; a body that is gzipped decodes as the bytes it is. That is an
  owed extension rather than a rule, and the reasoning is in `DESIGN.md` §11.5.
