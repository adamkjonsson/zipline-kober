# The spec format's ergonomics

> **Assessment, not a plan.** Written 2026-09-08 against the format as it stands
> at `0.1.0`, after the three shorthands that release added. It asks one
> question: why does writing a spec still feel like too much typing, and what
> would actually fix it. It decides nothing and proposes no schedule; every
> item is costed so the direction stays a choice.

---

## 1. Verdict

**The core shape is right, and the remaining verbosity is not spread evenly —
it sits in four specific places.** The single-key tagged mapping is a real
convention rather than a habit, the strict schema is a strength, and the
shorthands in `0.1.0` already took the obvious win.

What is left divides cleanly:

| | |
| --- | --- |
| **The friendliness problem** | The reference is written in a dialect the examples do not use. |
| **The writing problem** | Four constructs, one of which is invisible in both shipped examples. |

The first costs nothing to fix and is the larger of the two. The second is
worth about a quarter of the structural text, measured in §4.

---

## 2. The documentation teaches the wrong dialect

[`concepts.md`](../docs/format/concepts.md) and
[`document.md`](../docs/format/document.md) are the two pages an author reads
first, and both spell every field the long way:

```yaml
- {name: count, type: {int: {bits: 8}}}
```

[`examples/dns.yaml`](../examples/dns.yaml) never once uses that spelling. It
writes `bits: 8`. The shorthands are introduced in
[`types.md`](../docs/format/types.md), which is the third page and is organised
as reference rather than as instruction.

So an author learns one language, writes it, and then cannot read this
project's own example in it. Worse, the long form is what they will keep
writing, because nothing told them it was the fallback rather than the norm.

**The fix is to invert the presentation.** Write `concepts.md` and
`document.md` in the terse dialect, and keep the long form in `types.md` as the
escape hatch it actually is — the thing an unusual size or a second key
reaches for. No code changes, no format changes, and it removes the single
largest gap between what the docs say and what the project does.

This is the one item here that should happen regardless of what is decided
about §3.

---

## 3. The four places writing piles up

Ordered by what they cost a real author, not by how easy they are.

### 3.1 Byte order has no default chain

Both shipped examples are big-endian network protocols, so this costs nothing
*here* and is invisible in every measurement the project has taken. It is still
the largest one.

`endian` lives only in `_INT_KEYS` ([`loader.py`](../src/kober/loader.py)), on
the individual integer. There is no unit-level or document-level default. Write
a spec for anything little-endian — a filesystem structure, a USB descriptor,
most things that are not on a wire — and every integer field in it grows from a
shorthand to a nested mapping:

```yaml
- {name: magic,   int: {bits: 32, endian: little}}
- {name: version, int: {bits: 16, endian: little}}
- {name: flags,   int: {bits: 16, endian: little}}
```

None of those may use `bits:`, because the moment a field needs `endian` it
must write the long form — which is correct as a rule and brutal as a default.
A little-endian spec cannot use the format's principal shorthand at all.

**Proposed:** an `endian` key on the document and on the unit, resolved
**lexically at load time** into each `IntType`. Emission granularity already
establishes that a defaulting chain is a thing this format does. Resolving it
in the loader rather than at decode time keeps the property that matters:
nothing downstream can tell which spelling was used, so it stays a shorthand
under the project's own rule rather than becoming a feature.

### 3.2 A size is the only place an expression is not a bare string

Everywhere else in the language an expression is written directly. A
`condition`, a repeat `count`, a switch `dispatch`, a pointer's `at`, a
select's `where` and `value` and `default` all take a plain string. Only a size
makes the author wrap it in a tagged mapping:

```yaml
bytes: {size: {expr: "rdlength"}}
```

**Proposed:** extend the existing scalar rule. An integer scalar already means
`fixed`; let a string scalar mean `expr`.

```yaml
bytes: "rdlength"
string: "length"
```

This is the largest per-occurrence saving available, and it removes two levels
of nesting rather than characters alone. It appears four times across the two
examples, in both of them.

**The cost, stated plainly:** it consumes the string slot. The valueless sizes
could otherwise have been spelled as bare words later — `size: remaining`,
`size: fill` — and after this change they cannot, because `remaining` would
parse as an expression naming a field that does not exist, and fail with a
confusing message. The two ideas are mutually exclusive. The expression is
worth more: it occurs four times in the examples where the bare words occur
zero times.

### 3.3 The repeat kind should lift into the field

The type kind already lifts, and the justification transfers unchanged: the
three repeat kinds (`count`, `until`, `to_end`) collide with no field key and
no type key, so there is nothing to be ambiguous about.

```yaml
- {name: questions, unit: question, repeat: {count: "qdcount"}}   # today
- {name: questions, unit: question, count: qdcount}               # lifted
```

Repetition is the second most common construct in a spec after the type
itself, and it is the only common one still paying for its wrapper.

### 3.4 A parameter costs three words of ceremony

```yaml
params: [{name: high, type: int}]
```

**Proposed:** keep the list and let each entry be a single-key mapping, exactly
like every other tagged construct in the format.

```yaml
params: [{high: int}]
```

The list stays a list deliberately. Arguments bind positionally, and YAML does
not guarantee mapping order, so a bare mapping here would make argument binding
depend on something the format cannot promise. Every other mapping in the
schema — `units`, `enums`, `cases` — is order-independent, so there is no
precedent to lean on for an ordered one.

---

## 4. What the four are worth

The lines in the two examples that carry real structure, before and after all
four changes:

| Before | After |
| --- | --- |
| 373 | 279 |

**25% shorter**, and no design decision is touched. The nesting depth of a
dynamically-sized value drops from four levels to one.

---

## 5. Three smaller things

### 5.1 A type cannot be named without changing the output shape

A unit holding one field is the obvious way to name a recurring type, and it is
not free: it adds a level to every field path, a class to the compiled module,
and a node to the decoded tree. Field paths are the part
[`concepts.md`](../docs/format/concepts.md) says to design deliberately,
because renaming a field renames a column in everybody's output — so a type
alias that changes them is not an alias.

A `types:` section of pure aliases, expanded at load time, would let a text
protocol name its line terminator once. This matters little at the size of the
two shipped examples and considerably above it.

### 5.2 `entry` and `version` could default

Naming the entry unit is ceremony when there is only one unit. A version string
is friction on a spec that is still being iterated on. Both are required today.
`entry` defaulting to the sole unit is safe; defaulting to the *first* of many
would depend on mapping order and should not be done for the reason §3.4 gives.

### 5.3 A select's required `default` forces a sentinel

[`examples/http.yaml`](../examples/http.yaml) spends nine lines of prose
justifying `-1` over `0` for a missing `Content-Length`. That comment is the
format telling on itself. The honest answer is that nothing matched and the
field is **absent**, which is a thing a false `condition` can already produce
and a select cannot.

It is not fixable with a shorthand. The sentinel exists because the expression
language has four types and no optional, so a later field asking
`content_length > 0` needs *some* value to compare. Recording it as a known
tension is the right move; closing it means an optional type, which is a
language change and a much larger one than anything else here.

---

## 6. What not to change

- **The strict schema.** An unknown key being an error is the reason a
  misspelled `conditon:` cannot quietly produce a decoder that does the wrong
  thing. It is not a source of friction; it is what makes the friction
  elsewhere safe to reduce.
- **No anonymous nesting.** The argument in `concepts.md` holds: a structure
  with no name would be unnameable in the field path, the generated class, and
  the expression that refers to it, all at once.
- **`name: null` staying required.** It occurs twice in the two examples.
  Making anonymity a choice rather than an omission is worth those twelve
  characters.
- **Fields as a list of single-key name mappings.** This is the obvious way to
  delete the repeated `name` key, and it was costed. In flow style it saves
  about four characters per field — `{name: qr, bits: 1}` against
  `{qr: {bits: 1}}` — and it introduces a genuine ambiguity on a field named
  `name`, where a one-key mapping cannot be told from the current shape. It is
  not worth it. **Recorded here so it is not chased again.**

---

## 7. One thing that is tooling, not format

There is no scaffold verb. The CLI has `check`, `show`, `run`, `compile`, and
`try` ([`cli.py`](../src/kober/cli.py)) — everything for a spec that exists,
and nothing for the blank page.

A `kober init` writing a minimal working spec would remove the start-up cost
entirely, and it is cheaper to build than any format change proposed above. It
also gives the terse dialect a canonical first impression, which is §2's
problem solved from the other end.
