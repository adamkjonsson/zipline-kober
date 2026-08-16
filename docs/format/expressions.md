# Expressions

Expressions appear wherever a spec needs a value it cannot know in advance: a
size, a repeat count, a condition, a switch's dispatch, a unit argument, a
guard.

```yaml
size: {expr: "header.length * 4"}
condition: "flags.qr == 0"
repeat: {until: "labels.length == 0"}
```

They are written as strings and parsed when the spec loads, so
{func}`kober.check.check` scopes and types every one of them **before any data
exists**.

## The language

Arithmetic, comparison, boolean operators, references, and literals. No calls,
no loops, no indexing, no conditional expressions.

| | |
| --- | --- |
| Arithmetic | `+` `-` `*` `/` `%` |
| Bitwise | `&` `\|` `^` `~` `<<` `>>` |
| Comparison | `==` `!=` `<` `<=` `>` `>=` |
| Boolean | `and` `or` `not` |
| Literals | `42`, `0x2a`, `0b101010`, `'text'`, `true`, `false` |

Precedence and associativity are Python's, because the parser is Python's —
`ast.parse` in expression mode, with a whitelist of node types. That is why "no
calls, no loops" holds by construction: a construct is refused because it is
absent from the whitelist, and refused **by name** (`a function call is not
allowed in an expression`) rather than by an AST class.

### Four types, and no coercion

`int`, `str`, `bytes`, `bool`. There is no numeric tower and no truthiness.

- Arithmetic and ordering (`<`, `>=`, …) are **integer only**.
- Equality requires both sides to be the same type.
- `and`, `or`, and `not` require booleans. `qdcount and ...` is an error, not a
  test for non-zero — write `qdcount != 0 and ...`.

### `/` is integer division

There is no floating-point type, so `/` and `//` are the same operator and both
floor. For the non-negative values that come off a wire, floor and truncation
agree; they differ only on a negative operand, and floor is the documented
answer there.

A float literal is a parse error rather than a silently truncated integer.

### `and` and `or` short-circuit

This matters more than it usually would. The language has no conditional
expression, so short-circuiting is the **only** way to guard a division:

```yaml
condition: "n != 0 and total / n > 5"
```

Without the guard, `n == 0` makes the expression unanswerable and the field
becomes `undecodable`.

## Scoping

Follows Kaitai. A bare name is shorthand for `this`.

| Prefix | Resolves against |
| --- | --- |
| *(none)* or `this.` | The containing unit |
| `parent.` | The unit that referenced this one |
| `root.` | The entry unit |

Unit parameters are in scope by name. A dotted path descends into a nested
unit: `header.length` reads the `length` field of the `header` field's unit.

### A field may only reference fields declared before it

Because a later field has not been decoded when the expression runs. This is
checked when the spec loads, not when it fails:

```
error: dns.message.body: size: 'length' is declared later in unit 'message';
  a field may only reference fields decoded before it
```

`parent` obeys the same rule from the referencing site's position, and is
checked against **every** site that references the unit — a unit reachable from
two parents cannot rely on a field only one of them has.

`root` is the exception: it has no ordering rule, because how much of the entry
unit has been decoded at arbitrary depth is not knowable before running. It is
a power tool, and misusing it is a decode-time surprise the checker cannot take
back.

### What cannot be referenced

- **Anonymous fields** — they have no name, which is what makes them safe for
  padding.
- **Repeated fields**, except inside their own `until`, where the name means
  the element just decoded. The language has no list type.
- **Switch fields**, whose type depends on the value dispatched on, so they
  have no single type to give.

## What the language deliberately cannot do

It cannot move the read cursor. That is the invariant the whole coverage
guarantee rests on, and it is why the language being small is a choice about
cost rather than a safety measure — no amount of arithmetic here threatens
anything.

What it also cannot do, and where that has already bitten: **there is no string
arithmetic.** No conversion from text to integer, no substring, no case
folding, no search. Equality is all there is.

That is enough for binary protocols and not enough for text ones. Real HTTP
frames its body from a *header value* — `Content-Length` is a decimal string,
a chunk size is a hexadecimal one, and whether chunked framing applies at all
depends on matching a header case-insensitively. None of that is expressible,
so [`examples/http.yaml`](https://github.com/adamkjonsson/zipline-kober/blob/main/examples/http.yaml)
decodes the start line and every header and then claims the body as opaque
bytes, saying so in its own `doc:`.

Three total builtins would close it — `to_int(s, base)`, `starts_with(s, p)`,
`lower(s)` — and none of them could move the cursor. Whether to add them is an
open question in `DESIGN.md` §11.

## Decode-time failure

Two things a total, side-effect-free language still cannot rule out
statically, both of which make the affected region `undecodable` rather than
raising:

- **Division or modulo by zero**, where the divisor came off the wire.
- **A shift count that is negative or absurd.** `1 << n` with `n` from the wire
  is a memory-exhaustion vector, so counts above
  {data}`kober.expr.MAX_SHIFT` are refused rather than computed.
