# Phase plan: speaking about repetitions

**State: Stages 1-5 done, Stages 6-8 open.** Written after the language
phase landed ([`POINTER-PHASE-PLAN.md`](POINTER-PHASE-PLAN.md)), against
`DESIGN.md` revision 8 and `zpf` 0.2.x.

Q1-Q6 are answered below, each with the spike behind it. The spike itself is
scratch and is not checked in; what it established is here. **Three of this
plan's own stated facts were wrong and are corrected in place**, the largest
being that no run holds more than one message - every run of
`http_stream_1.pcap` holds exactly fifty.

`kober` gains a way for a spec to ask a question about a **repeated** field.
That is the last thing standing between `examples/http.yaml` and framing its
own body, and it is `DESIGN.md` §11 question 6.

```
   headers  ─ repeat ─→  [line, line, line, …]
                              │
                              ▼   "is any of them Content-Length, and what does it say?"
                          unsayable today
```

## Why this phase

**Because the previous one proved the diagnosis wrong, and this is what was
actually underneath it.** §13.2 had said for four revisions that HTTP needed
arithmetic on a header *value*. The language phase built that arithmetic —
`to_int`, `lower` — and the boundary did not close. Two things it had not
named:

- a header's value cannot be *extracted* from its line, and
- nothing can ask anything about the **set** of headers, because `headers` is
  repeated and the checker refuses references to repeated fields: there is no
  list type, so no expression can say "any of these".

The second is the real blocker. Even given a substring operation, *choosing*
between `Content-Length` and chunked framing would still be unsayable.

**And because what ships today is the least comfortable thing in the design.**
`examples/http.yaml` assumes chunked framing rather than choosing it. A body
that is not chunk-formatted has no size line, so the read for one comes back
`truncated` — which is **hole**-class (§5), declares a seam, and claims the
stream had a gap it did not have. That is a decoder lying about the input in
the one way this project cares most about. It is documented and asserted in a
test, which makes it honest; it does not make it right.

Removing that is the phase's purpose. Everything else here is in service of it.

## What HTTP actually needs — three things, and we have one

| | Needed for | Have it? |
| --- | --- | --- |
| Convert text to a number | `Content-Length: 1234`, chunk sizes | **Yes** — `to_int` |
| Reach a header's *value*, not its line | `1234` out of `"Content-Length: 1234"` | No |
| Ask something about the *set* of headers | choosing the framing at all | No |

The third is this phase's subject. The second is a smaller question with two
very different answers (Q3), and the phase closes both or closes nothing —
half of them leaves `examples/http.yaml` exactly where it is.

## The corpus, and it is bigger than what has been used

**Remeasured in Stage 1, and the first table was wrong.** The numbers below
come from walking every reassembled run to its last byte and checking that the
walk lands exactly on the end — 46 runs, 0 bytes left over — cross-checked
against a raw count of header terminators. The figures the plan first carried
are kept in the notes underneath, because what they got wrong shaped the plan.

| Capture | Runs | Messages | Framing | What only it has |
| --- | --- | --- | --- | --- |
| `http_example.pcapng` | 2 | 2 (1 request, 1 response) | 1 chunked, 1 neither | The chunked path. Framing works here *because* the spec assumes chunked. |
| `http_stream_1.pcap` | 40 | **2000** (1000 requests, 1000 responses) | 1147 `Content-Length` (63–70 B, 77 722 B total), 853 neither, 0 chunked | Scale, pipelining, and the *absence* case. Never been run. |
| `http.pcap` | 4 (+2 DNS datagrams) | 4 (2 requests, 2 responses) | 2 `Content-Length` (18 070 B and 1 272 B), 2 neither | A body two orders of magnitude larger than anything else, spanning several transport records — and `Content-Length` **with** a transformed body, which separates two variables `http_example.pcapng` confounds. Also the only capture that is not all one protocol. |

All three live in `python-zipline-wire`'s `tests/captures/`, beside the
fourteen the earlier phases used, so the pipeline in the README reaches them
without a special case.

What the remeasurement changed, and each of these shapes the work:

- **Every run of `http_stream_1.pcap` holds exactly fifty messages**, not one.
  The plan's stated finding — "no run holds more than one message, in any of
  the three" — is **false**, and it was the premise under which pipelining was
  set aside. What survives is the conclusion, for a different reason: the
  driver's `_decode_run` already loops until the run is exhausted, so
  pipelining is not something this phase has to *build*. What is gone is the
  safety margin. Exact framing is now load-bearing rather than merely tidy: a
  body that overruns by one byte does not spoil one message, it spoils the
  other forty-nine behind it. `http.pcap` and `http_example.pcapng` do hold
  one message per run, which is presumably where the original claim came from.
- **2000 messages, not 1645.** The response-side figures the plan quoted were
  right and are why the error went unnoticed: 692 responses with
  `Content-Length` and 308 with neither are both exactly correct. It was the
  request side that was miscounted — 1000, not 645 — and requests carry
  `Content-Length` too, 455 of them.
- **853 of 2000 messages have neither framing header**, over two fifths rather
  than the third the plan estimated from responses alone. A bodyless message is
  normal (a `GET`, a `204`, a `304`), so "no framing header at all" is a case
  the spec must get right — and getting it wrong is how a decoder invents a
  hole.
- **`http_stream_1.pcap` has no chunked message at all.** So it and
  `http_example.pcapng` are complementary rather than overlapping, and neither
  alone covers the construct.
- **Bodies are complete once reassembled, and short per record.** Measuring a
  body inside one transport record says it is truncated when it is not; the
  driver's reassembled run is the only honest place to look. Confirmed, and
  still the trap: the first measurement made *for this settlement* also got it
  wrong, reporting 87 messages, before the walk was made to prove itself by
  landing on the run's end.
- **`http.pcap` is where today's spec fails loudest**, and the acceptance
  number is confirmed exactly: the 18 364-byte response decodes 294 bytes of
  headers and then claims the remaining **18 070 bytes `truncated`**.
- **`http_stream_1.pcap` fails far worse, and nobody had looked.** Today's spec
  decodes 309 records and marks **405 421 of its 414 460 bytes `undecodable`** —
  97.8% of the capture — in 40 regions, one per run. The mechanism is the
  pipelining above: the first message of each run decodes its start line and
  headers, then `to_end` reads the *next request* as a chunk size line,
  `to_int` refuses it, and the remaining forty-nine messages are lost with it.

**`http_gzip.pcap` is deliberately not in this table.** Its one response is
gzip under `Content-Length`, which `http.pcap` already provides, so it adds
nothing to the *framing* question. What it has that nothing else does is size:
92 bytes in, 109 out, complete and decompressible — small enough to inline in a
test, which is what the suite's rule about not depending on the sibling
checkout will want. It is the right fixture for the **transforms** phase and
should be kept for it.

## Design questions — all settled

Settled in Stage 1 by a spike: `Select` and a bounded terminator patched into
an installed `kober` from a scratch module, no production code touched, run
over all three captures and 1600 fuzz cases. Each leaning is marked as it
survived or did not.

### Q1 — Does aggregation belong in the expression language or the spec model? — **settled: the model**

The pivotal question, and the two answers lead to different projects.

1. **An expression form**: `any(headers, starts_with(lower(this.line), "content-length:"))`,
   and something like `first(headers, …)` to get a value out.
2. **A field type**: a `select:` that names the repetition, a predicate, and a
   projection.

   ```yaml
   - name: content_length
     type:
       select:
         from: headers
         where: "lower(this.name) == 'content-length'"
         value: "to_int(this.value)"
         default: "0"
   ```

**Leaning: (2), the model rather than the language**, for four reasons that
are worth stating because (1) is the more obvious answer.

- **It needs no new expression *type*.** A `select` yields a scalar whose type
  is its projection's, so `check` types it with machinery that already exists.
  `first(headers, …)` returning an *element* does not: `ExprType` has four
  members and none of them is "an instance of a unit".
- **The binding stays inside one construct.** `where:` and `value:` are
  evaluated with the element in hand, and `check` knows exactly where that is
  true. Option (1) puts a binding form into the general grammar, which is a
  lambda in everything but name — in a language whose case for being small is
  that it is cheap to check and portable to a non-Python reader.
- **Totality is structural.** A `default:` is a required key, so "nothing
  matched" has an answer the author wrote, and there is no partial function to
  argue about.
- **It is the move this project has made twice and been right about.** §11.5:
  make the declarative language say more, rather than letting code in beside
  it. `Pointer` was that; this is the same shape.

`any` falls out rather than needing its own construct: `value: "true"` with
`default: "false"` is exactly it. Whether that is too clever to ship without a
shorthand is part of what Stage 1 should decide by writing the spec out.

**A third option worth refuting explicitly**, because it will occur to someone:
a keyed repeat (`repeat: {key: "lower(name)"}`, then `headers["content-length"]`).
It reads beautifully for headers and badly for everything else, it introduces a
map type *and* indexing syntax, and it has no answer for duplicate keys — which
HTTP has (`Set-Cookie`).

**Settled: (2), and the leaning's first reason is the one that carried it.**
The spike's `select` needed no change to `ExprType` and no new expression form.
Its result is an ordinary scalar the moment it exists: a following field can
say `computed: "picked * 2"` and the checker types it through the projection
with machinery that was already there. That is the whole of the argument, and
it held.

**No shorthand for `any`, on the evidence.** `value: "true"` / `default:
"false"` was written out and it reads acceptably — "when one matches, the
answer is true". But the stronger finding is that **the finished spec never
needs it**. Neither select in it is a bare `any`: one projects the length, the
other tests the value. HTTP asks *what does it say*, not *is it there*. A
shorthand would be surface with nothing behind it, which is what §3.3's table
already refuses on its own account.

### Q2 — What does the element binding look like, and what else is in scope? — **settled: the field's name**

`until` already binds one: `repeat: {until: "labels.length == 0"}` resolves
`labels` to *the element just decoded*, through `element_of` in
[`check.py`](../src/kober/check.py). That is the precedent, and it is narrow on
purpose.

Settle whether a `select`'s element is `this` (a new meaning for a word §3.3
already uses for the enclosing unit) or the repetition's own name, as `until`
does. **Leaning: the field's name**, matching `until`, because two spellings
for one idea is how a small language stops being small.

Settle also what else `where:` and `value:` may see. The enclosing unit's
earlier fields, certainly. `parent` and `root` are the open part, and the
answer should be whatever costs the checker least to be sure about.

**Settled: the repetition's own field name, and the leaning held for a better
reason than the one given.** It is not merely consistent with `until` — it
reuses `until`'s mechanism outright, on both sides. The checker already has
`element_of`, and passing the source field's name through it is the entire
change. The interpreter side is the same: the decode loop already writes
`frame.named[item.name] = element` before evaluating an `until`, and a select
does exactly that per element and restores the container afterwards. Neither
half needed a concept it did not have.

**Scope settled as: the enclosing unit's earlier fields, plus the element.**
`parent` and `root` come along for free, because the scope object is the
existing `_Scope` with one extra argument and those words are resolved by it
already. Nothing had to be added and nothing had to be excluded.

**One asymmetry, and it is deliberate: `default:` does not see the element.**
It is evaluated with the plain scope, so naming the repetition inside a
`default:` is refused with the ordinary "is repeated; the expression language
has no list type". That is right — a default is what there is to say when
*nothing* matched, so there is no element for it to mean. Verified in both
directions.

### Q3 — How does a header's value get separated from its line? — **settled: a bounded terminator**

Two genuinely different answers, and this is the one where the obvious choice
may be wrong.

1. **String functions**: `starts_with(s, p)` and something like `after(s, sep)`.
   Adds two rows to §3.3's table, which the previous phase built and closed.
2. **A bounded terminator**: let a `terminated` size stop at one delimiter but
   not run past another.

   ```yaml
   - {name: name, type: {string: {size: {terminated: {delimiter: ":", within: "\r\n", required: false}}}}}
   - {name: value, type: {string: {size: {terminated: {delimiter: "\r\n"}}}}}
   ```

   A header line splits at decode time, and — the part that makes it work —
   the **blank line** falls out correctly: it has no `:` before its `\r\n`, so
   an optional terminator takes nothing, `name` is `""`, and the repeat's
   `until` still sees a blank.

**Leaning: (2), and it is the more interesting answer.** It needs no new
expression functions at all, so `select` would use only `lower` and `to_int` —
the two the last phase shipped. It also puts the structure where a reader wants
it: a header *has* a name and a value, and saying so in the spec beats
computing it in three expressions. The cost is a new key on one size spec, and
one question the spike must answer: what a bounded search does when the bound
itself is missing.

Option (1) is the fallback and should be measured against (2) by writing both
header units out and reading them.

#### Settled: (2). Both were written and both were run.

Both decode all three captures, and on `http_stream_1.pcap` they **agree on the
framing of all 2000 messages** — same `content_length`, same `chunked`, same
end offset, zero disagreements. So the choice is not about correctness on this
corpus. It is about what each costs, and there the gap is wider than the plan
guessed.

**Option (1) costs three new builtins, not two.**

```yaml
  header:
    fields:
      - name: line
        type: {string: {size: {terminated: {delimiter: "\r\n"}}}}
```

```yaml
      - name: content_length
        type:
          select:
            from: headers
            where: "starts_with(lower(headers.line), 'content-length:')"
            value: "to_int(after(headers.line, ':'))"
            default: "-1"
      - name: chunked
        type:
          select:
            from: headers
            where: "starts_with(lower(headers.line), 'transfer-encoding:')"
            value: "trim(lower(after(headers.line, ':'))) == 'chunked'"
            default: "false"
```

`starts_with` and `after` are the two the plan named. **`trim` is the one it
did not**, and it is not optional: `Transfer-Encoding: chunked` needs an
*equality* test on the value, and `after(line, ':')` yields `" chunked"` with
the leading space RFC 7230 permits. `Content-Length` gets away without it only
because `to_int` strips whitespace internally — a decision the last phase made
explicitly "to save the language a fourth function", and which turns out to
have been saving it from exactly this. The moment a header value is compared
rather than converted, the fourth function is back.

**Option (2) costs one key on one size spec, and no builtins.**

```yaml
  header:
    doc: >
      One header line, split into its name and its value. The blank line that
      ends the headers has no colon before its CRLF, so an optional bounded
      terminator takes nothing and both come back empty.
    fields:
      - name: name
        type:
          string:
            size: {terminated: {delimiter: ":", within: "\r\n", required: false}}
      - name: value
        type: {string: {size: {terminated: {delimiter: "\r\n"}}}}
```

```yaml
      - name: content_length
        type:
          select:
            from: headers
            where: "lower(headers.name) == 'content-length'"
            value: "to_int(headers.value)"
            default: "-1"
      - name: chunked
        type:
          select:
            from: headers
            where: "lower(headers.name) == 'transfer-encoding'"
            value: "lower(headers.value) == 'chunked'"
            default: "false"
```

The prediction held exactly: **only `lower` and `to_int`**, the two the last
phase shipped, and §3.3's table does not grow.

**And the blank line falls out as predicted**, which was the part that had to
be checked rather than argued. `\r\n` has no `:` before its `\r\n`, so the
optional bounded terminator takes nothing, `name` is `""`, `value` is `""`, and
the repeat's `until` sees both empty. It needed no special case.

**A third argument the plan did not anticipate, and it may be the strongest.**
Option (2) splits the header *in the output*, not only inside expressions. On
`http_stream_1.pcap` it emits 30 761 records against option (1)'s 18 954 — the
difference being one record per header line, because a name and a value are
each cited separately. A consumer reading the `.zpf` gets `Content-Length` and
`68` as two addressable, separately-cited values. Under option (1) that split
exists only for the duration of an expression and never reaches the file. For a
project whose entire output is cited decoded data, that is not a side effect;
it is the point.

**What a bounded search does when the bound is missing** — the question the
plan set for the spike. Answer: `within` is checked the same way the delimiter
is, and the rule is *whichever comes first*. If neither is present, or the bound
is present and the delimiter is not before it, the read behaves as though the
delimiter were absent — so `required: false` yields the empty value and
`required: true` is a truncation. That makes `within` orthogonal to `required`
rather than a second spelling of it.

**One loose end for Stage 4.** `required: false` on `header.name` trips an
existing checker warning: *"a non-required terminator on a string makes
truncation invisible"*. On a bounded terminator the warning is wrong — `within`
*is* the guarantee the warning says is missing, since the read cannot run past
the bound and swallow the rest of the input. Stage 4 should suppress it when
`within` is set, and not by loosening the warning for the unbounded case.

### Q4 — What does a `select` cite? — **settled: the element it selected**

It decodes nothing, so it has the shape `Computed` already has (§3.2) — and
`Computed`'s answer was "the fields its expression read", because citing its
own zero-width position would say nothing.

**Leaning: the element it selected**, not the whole repetition, because that is
the honest evidence: this value came from *that* header. Settle what a
`default:` cites when nothing matched — probably nothing, which needs the
zero-width-emission path `Computed` already exercises.

Whatever the answer, the fuzz invariant is unchanged and must stay so: a byte
is never both cited and marked undecoded.

**Settled, both halves as leaned, and both paths exercised.** A match cites the
selected element's own range — for `Content-Length: 5\r\n` at the head of a
message, `[0, 19)`, the whole header line. A default cites nothing: zero width
at the cursor, `[11, 11)`, on the `Computed` path that already existed.

Not academic: **853 of the 2000 messages have no framing header**, so the
default path is the majority case for `content_length` and runs on real input
rather than on a contrived test.

**The fuzz invariant holds and is unchanged.** 1600 mutated cases across four
seeds — a bodyless request, a `Content-Length` request, a chunked response, and
a `204` — with zero raises, zero over-claims, zero bytes both cited and marked,
and every reason one `zpf` classifies. Both paths were reached: 348 matched,
1605 defaulted.

**Deliberately *not* `Computed`'s answer.** Citing "the fields the expression
read" would cite the whole repetition, since `where:` names it — every header,
for a value that came from one. The element is the narrower and truer claim,
and it is why `select` wants its own citation rule rather than inheriting one.

### Q5 — Does this stay inside §2.1's cursor rule? — **settled: yes, and it needs its own assertion**

It should, and the argument is short: a `select` reads no input, moves no
position, and evaluates over a repetition that has **already been decoded**.
It is value computation, which §2.1's table puts on the unconstrained side.

Two things to confirm rather than assume:

- **Ordering.** The existing rule is that a field may reference only fields
  declared before it. A `select` obeys it — the repetition is complete by the
  time the select runs — but the checker has to be told that the repeated
  field is legal *here*, having refused it everywhere else, and the exemption
  must not leak back into ordinary references.
- **Totality.** Every element is visited at most once and the input is finite,
  so a select terminates. That is worth one sentence in the design and one
  fuzz case, not an argument.

**Ordering: settled, and the exemption does not leak.** Eight cases, run in
both directions:

| Spec says | Result |
| --- | --- |
| a select names the repetition | accepted |
| an ordinary `computed` names the same repetition | refused — *"'items' is repeated; the expression language has no list type"* |
| a select names a field that is not repeated | refused — *"there is nothing to select from"* |
| a select names a field declared later | refused — *"a select may only ask about a repetition already decoded"* |
| a select names a field that does not exist | refused |
| `where:` is not boolean | refused |
| `value:` and `default:` disagree on type | refused — *"either can be the field's value"* |
| `default:` names the element | refused, per Q2 |
| a later field references the select's result | accepted, typed through the projection |

The exemption is scoped to `where:` and `value:` and reaches nothing else.

**Totality: settled, but the plan's proposed evidence would not have proved
it.** "One fuzz case" is not enough, and this is the settlement's sharpest
finding. A deliberately broken select that *consumes a byte* was run against
the full invariant set — no raises, no over-claim, no byte both cited and
marked, coverage whole. **It passed everything.** The byte it ate is simply
covered by whatever field or undecoded region follows, so the coverage
guarantee, which is what those invariants protect, is undisturbed by a select
that quietly reads.

So §2.1's claim needs asserting **directly, at the seam where it is made**:
record `cursor.tell()` either side of decoding a select and require equality.
That assertion catches the broken implementation immediately — 579 movements
across 977 selects — where every indirect invariant saw nothing. Stage 3 owes
that test, and it must be checked against a consuming implementation, not
merely observed to pass.

**A second break, and it settles a design question the plan had not asked.**
An implementation letting an `EvalError` escape from `where:` was also not
caught — because `Decoder._one` already wraps `_value` and turns an `EvalError`
into an `undecodable` node. Totality is therefore *structural*, exactly as Q1
argued, provided the select is dispatched from inside `_value`.

Which makes the spike's own `try/except EvalError: matched = False` around the
predicate not merely redundant but **wrong**, and it should not be carried into
Stage 3. With a predicate of `to_int(headers.value) > 100` and a header reading
`Length: not-a-number`:

- guarded: `value=0, status=ok` — a fabricated, plausible answer,
- unguarded: `status=undecodable` — the truth.

The guarded reading is the precise failure this project exists to avoid. An
unevaluable predicate must make the field undecodable, exactly as an
unevaluable size already does.

### Q6 — What does the compiler generate, and what does the plan carry? — **unchanged, and Stage 5 still owes it**

The neutral layer (`ops.py`) should describe a select as *what it means* — a
repetition, a predicate, a projection, a default — with the spec's own names
and no Python in it. The Python backend renders a loop.

The thing to watch is the one the last phase was caught by twice: the plan's
walks. A `select` names a field, evaluates two expressions, and does not
consume — so `_referenced`, `_kind_exprs`, and `_kind_consumes` all have to
learn about it, and forgetting one produced a module that called a function it
had not generated.

**Not settled by the spike, deliberately: it built no compiler side.** The
interpreter was enough to answer Q1–Q5, and Q6 is a question about generated
code that only writing it answers. What the spike did establish is that the
list of walks is **longer than three**. Reading [`ops.py`](../src/kober/ops.py)
against the construct, a `select` also has to reach:

- `_unit_exprs`, which yields every expression a unit evaluates — a select has
  three (`where`, `value`, `default`), and `_outer` reads *that* walk to decide
  what `parent`/`root` values a unit needs threading in. Miss it and a select
  naming `root.x` compiles to a function without the argument.
- `_types`, which flattens a field type to the alternatives it can decode as.
  A select decodes none, and it is not a `Switch`, so it flattens to itself —
  fine by default, but it should be a decision rather than an accident.

`_referenced` needs nothing added: a select names no unit. `_kind_consumes`
returns `False` for it, which is the existing fall-through — and, per Q5's
finding, that answer is *load-bearing* rather than incidental. A unit whose
only field is a select cannot terminate a repeat, exactly as for a `Pointer`.
The existing comment there says so about pointers and should be widened.

## What the spike measured

The headline: **the construct works, and on the corpus it closes the boundary
completely.**

| Capture | Today | With `select` |
| --- | --- | --- |
| `http_stream_1.pcap` | 309 records, **405 421 B undecodable** in 40 regions | 30 761 records, **0 undecoded regions** |
| `http.pcap` (HTTP sessions) | 42 records, **19 342 B truncated** — the 18 070 B region among them | 90 records, **0 undecoded regions** |
| `http_example.pcapng` | 32 records, 0 undecoded | 59 records, 0 undecoded |

- Acceptance 1's sharp form is met: the 18 070-byte `truncated` region is gone,
  because the body is there and a length-framed decode reads it.
- Acceptance 2 holds: the chunked capture still decodes with nothing left over.
  The record count rises because a header is now a name and a value rather than
  a line, which is Q3's third argument showing up as a number.
- All 2000 messages of the big capture decode, including the 1147 with
  `Content-Length` and the 853 with neither, and including all fifty in each
  run.

## Three findings the spike turned up, none of them about `select`

### 1. A pre-existing bug in the checker, and it blocks the phase's own spec

Referencing a `computed` field of a **nested** unit from outside re-types that
computed's expression against the *referrer's* visible-name set. It belongs to
the inner unit, so every field of the inner unit looks "declared later".
Reproduced on stock `kober` with no spike loaded:

```yaml
units:
  outer:
    fields:
      - {name: alpha, type: {int: {bits: 8}}}
      - {name: inner, type: {unit: leaf}}
      - {name: probe, type: {computed: "inner.doubled"}}
  leaf:
    fields:
      - {name: raw, type: {int: {bits: 8}}}
      - {name: doubled, type: {computed: "raw * 2"}}
```

```
error: probe.outer.probe: computed: 'raw' is declared later in unit 'leaf'
```

It is in `_Scope._type_of` in [`check.py`](../src/kober/check.py), whose
`Computed` branch builds `_Scope(self.checker, unit, self.visible)` — right
unit, wrong visible set. The `UnitRef` branch immediately above already makes
the argument for the fix, in a comment: *ordering inside a nested unit is that
unit's business, because by the time it can be referenced, all of it has been
decoded.* Passing `None` does not weaken the ordering rule — a computed's own
expression is checked in its own position by `_check_field`, and the head of
the path is checked against the referrer's visible set by `_in_unit`.

**Why it blocks this phase:** `until: "chunks.length == 0"` is the natural way
to end a chunked body, and it is refused. No test covers it — the suite's 1047
tests pass with the bug present. It should be fixed with its own regression
test, checked against the bug, before or during Stage 2.

### 2. `http_stream_1.pcap` cannot be "coverage-clean", and never could

Acceptance 1 asks for coverage-clean at both granularities. The capture's TCP
streams **never close** — 20 sessions, no FIN — so their declared extent runs
to `4294967295` and `check_coverage` reports the tail of all 40 participants as
a `coverage-gap`. Baseline and spike produce the **same 80 findings**, and a
DNS control produces 0, so this is the capture and not the spec. `http.pcap`
carries the same thing at smaller scale: 4 findings, identical before and
after, including `extent-mismatch`.

`http_example.pcapng` is the only capture in the corpus whose streams close,
and both spikes are conformance- and coverage-clean on it with 0 findings.

Acceptance 1 needs restating as *no coverage finding other than the unterminated
stream tails, which are identical to the baseline's* — or the criterion should
move to a capture that closes. Choosing between those is Stage 7's, but it must
be a decision, not a surprise at the end.

### 3. The framing lie is closed; a smaller one remains at the dispatch boundary

`http.pcap` holds a DNS-over-UDP session beside its HTTP. Running the HTTP spec
over those two datagrams reports **193 bytes `truncated`** — and `truncated` is
**hole**-class, so it declares a seam and says the stream had a gap. It did
not: those bytes are simply not HTTP. This is the same lie the phase exists to
remove, relocated from framing to dispatch.

It is **pre-existing and unchanged by the spike** — baseline `http.pcap` is
19 535 B truncated, being 19 342 B of HTTP bodies plus exactly these 193 B, and
after the spike only the 193 B remain. The mechanism is `start_line`'s required
terminator: DNS bytes contain no CRLF, so the read is a `TruncatedRead` before
any `confirm:` guard could run.

Out of scope for this phase, and it should not be smuggled in. But Stage 7
runs `http.pcap` whole precisely to exercise shape dispatch on a file that is
not all one protocol, so it will meet this — and the phase should say plainly
that it met it and left it, rather than letting the number look like a
regression. It is a candidate for its own work: a unit needs a way to decline
input before a required read turns a mismatch into a hole.

## Stages

### Stage 1 — settle Q1–Q6, with a spike — **done**

Write the finished `examples/http.yaml` **by hand, twice** — once under Q3's
option (1) and once under option (2) — and read them against each other. Then
prototype whichever `select` shape Q1 lands on, in scratch, and run it over
`http_stream_1.pcap`'s messages.

No production code. The deliverable is this file's Q sections marked settled,
the two hand-written header units, and the numbers from the big capture.

The spike is what says whether `value: "true"` / `default: "false"` is an
acceptable spelling for `any`, which is not a question prose can answer.

**Done.** Q1–Q6 are settled above, the two header units are written out under
Q3, and the numbers are in the two sections above. Every leaning survived,
which is worth stating plainly because the last two phases each had one that
did not — the corrections this stage produced were to the plan's *facts about
the corpus*, not to its design judgment. `git status` was clean throughout and
the 1047-test suite passes unchanged.

### Stage 2 — the construct in the model, loader, and checker — **done**

The dataclass, the schema key, and the checks: the named field exists and is
repeated, `where:` types as bool, `value:` and `default:` agree on a type, and
the element binding resolves. Plus the exemption from Q5, tested in both
directions — that a select may name a repetition, and that nothing else may.

**Done**, and two things came with it that the stage had not scoped.

- **Finding 1's checker bug is fixed**, with a regression test verified against
  it: reverting the fix fails the test, and fails `kober check` on the Stage 1
  spec with six errors. Acceptance 6 is met.
- **`Decoder._value` now says out loud that it does not implement a type.** It
  had been falling off the end of its `isinstance` chain into `_sized`, so a
  type the model gained before the engine did raised an `AttributeError` out of
  a decode that promises never to raise — which is exactly the state this stage
  leaves the tree in, `select` being loadable and checkable but not yet
  runnable. An honest `undecodable` region is what the checker cannot say,
  since such a spec is well formed and valid.

**One test failed and was not fixed, deliberately.** A repeated `select` is not
refused — but neither is a repeated `computed` or `pointer`. All three consume
nothing and all three are caught only by the decoder's runtime "cannot
terminate" guard. Special-casing `select` would leave it inconsistent with its
siblings, and a static check for the family is not this phase's work, so the
test now pins all three together with a note saying why. Whoever decides to
catch it statically moves the family.

### Stage 3 — the interpreter — **done**

Evaluate it: walk the decoded elements, test the predicate, project the first
match, fall back to the default. It reads no input and moves no position, and
a fuzz case should hold it to that.

Two things Stage 1 pins down, both from Q5:

- **The no-movement claim needs a direct assertion**, not a fuzz case. Record
  `cursor.tell()` either side and require equality; the indirect invariants do
  not catch a select that consumes. Check it against a consuming implementation.
- **Do not guard the predicate.** Let an `EvalError` out of `where:` and
  `value:` — `Decoder._one` turns it into an `undecodable` node, which is the
  honest answer. Swallowing it yields a fabricated default.

**Done, and both instructions carried out and checked against their
opposites** — a consuming select makes the position assertion fire, and
restoring the guard makes the unevaluable-predicate test fail.

**The engine reproduces the Stage 1 spike exactly.** Run with only `within:`
patched in from scratch, `examples`-shaped specs over all three captures give
output identical to the settlement's in **every record, span, and reason** —
30 761 blocks on `http_stream_1.pcap`, 92 on `http.pcap`, 59 on
`http_example.pcapng` — with conformance clean and coverage findings matching
the baseline. So the numbers in *What the spike measured* are now the numbers
the shipped engine produces, not a prototype's.

The fuzz spec lives in `tests/fuzzing.py` beside the mutators, for the reason
that module gives: both implementations are held to these promises and cannot
be compared over inputs that differ, so Stage 5 will want this one. It frames a
body from its projection, so a select returning the wrong number shows up as a
claim on bytes rather than a quiet wrong value.

### Stage 4 — Q3's answer: the bounded terminator — **done**

`within:` on a `terminated` size, in the size model and the decoder's
`_read_terminated`. The rule is *whichever comes first*: if the delimiter does
not occur before the bound, the read behaves as though it were absent, so
`required` still decides between an empty value and a truncation.

It lands with the tests that pin what it does when what it looks for is not
there — no delimiter, no bound, neither, and the bound before the delimiter —
and with the checker-warning fix from Q3: the "non-required terminator makes
truncation invisible" warning must not fire when `within` is set.

**Done.** The search itself went into `Cursor.find`, which takes the bound as a
second argument — searching is what a cursor is for, and it makes "whichever
comes first" a property with tests of its own rather than two `find` calls in
the decoder. All four absence cases are pinned, in the cursor and again through
a decode, and checked against two broken implementations: ignoring the bound
fails two tests, and reading to the bound instead of taking nothing fails three.

**One rule the stage had to decide and the plan had not stated.** An *optional*
bounded terminator that finds nothing reads **nothing** — not the rest of the
run, which is what an unbounded one does, and not up to the bound either. The
bound is a limit on the search and never a second terminator; letting the value
run to it would be reading under a delimiter that was never found. Both
spellings are now in a table in the format reference, because the difference is
the part a reader will otherwise get wrong.

**The finished spec now runs on stock `kober`.** No patches: `kober check`
reports `ok` with no warning, and the three captures decode identically to the
Stage 1 spike in every record, span, and reason. What is left for Stage 6 is
the prose and moving it into `examples/`.

**The compiler refuses a bound rather than dropping it**, which it had to be
told to do: `ops.py` hands a backend the spec's own size object, so a `within`
no backend reads would go missing in silence — and a compiled decoder ignoring
it would not fail, it would *disagree*, reading past a boundary the interpreter
stopped at. It now raises at plan time, as it already did for `Select`. Stage 5
implements both.

### Stage 5 — the compiler — **done**

`ops.py` then `pygen.py`, per Q6. The differential is the acceptance test, and
on the last two phases' record it will find something; expect it in whichever
implementation was written second.

**Done, and the prediction held twice over.**

- **Q6's named walk was in fact wrong.** `_kind_exprs` yielded none of a
  select's three expressions, so `_unit_exprs` did not see them and `_outer`
  left `needs_root` empty — a select naming `root.x` in its predicate compiled
  to a function without the argument, which is the exact failure Q6 described.
  The other walks were fine: `_referenced` correctly yields nothing (a select
  names no unit), `_kind_consumes` correctly says False, and `_types` flattens
  it to itself.
- **The differential found the citation**, in the implementation written
  second, as predicted. A select's *extent* is the element it chose — not only
  what its record cites — and the compiled side had it zero-width at the
  cursor. A decoded element carries no offsets, so the backend has to keep them
  as the repetition goes past: a parallel span list, at every granularity, since
  a consumer can ask a decoded object where a field came from whether or not
  any record was written.

**A select renders as a small nested function**, not an inline loop, and this
was a design decision rather than a formatting one. Three reasons, in order of
weight: in a function it can simply `return`, so "the first match" is a return
inside the loop and "nothing matched" is the line after it — no flag to clear
and no `for`/`else` clause half of Python's readers misread. It is *nested*
rather than module-level so it closes over what it reads, which removes the
free-variable analysis outright — and getting that wrong is precisely the
mistake this backend has made twice. And it keeps the branch count of the
decode function down, which is not cosmetic: generated modules are linted with
this project's own configuration, and the finished spec inlined pushed
`_decode_message` to 25 branches against a limit of 20.

**One shape the backend refuses**, and it is documented with the others: a
`switch` with a select in only *some* cases. A select's extent is the element
it chose and an ordinary read's is where it stands; one pair of span locals
cannot hold both, written down as they are before the branch is chosen.

**One unrelated bug fell out.** The `sink.record` call for a computed integer
was emitted on one line however long it got, where every other record call is
wrapped — so a field named `content_length` generated a module that failed this
project's own lint.

**The acceptance number:** the compiled decoder and the interpreter produce
identical output — every record, span and reason — on all three captures, on
every prefix of the fuzz seed, on four seeds of mutations at both
granularities, and through the README's deeper pipeline (`packeteer fuzz` →
`zpfwire` → both), which puts real gaps and truncations in front of them.

### Stage 6 — `examples/http.yaml` finished

The body framed by `Content-Length` **or** chunked encoding **or** neither, by
asking the headers rather than assuming. The assumption disclaimer is deleted.

Stage 1 wrote it; it is the option-(2) listing under Q3, and it decodes the
whole corpus. What Stage 6 owes beyond transcribing it is the prose: the doc
strings that say *why* `-1` and not `0` is the "no such header" sentinel
(`Content-Length: 0` is a real header meaning something else), and why chunked
wins over a length when both are present.

This is the phase's acceptance criterion, and the measurable form of it is the
big capture: 2000 messages decoding with no `truncated` region that is not a
real truncation.

### Stage 7 — fuzz, and the corpus that has never been run

`http_stream_1.pcap` and `http.pcap` through `zpfwire` and the full pipeline,
at both granularities, conformance-clean and coverage-clean **in the restated
sense of finding 2** — the unterminated stream tails are the capture's, and the
finding set must match the baseline's rather than being empty. Mutated variants
through the fuzz suite and the differential. A capture with 2000 real messages
is a better adversary than anything hand-built, and this project's findings
have all come from that kind of input.

`http.pcap` also carries a DNS-over-UDP session beside its HTTP, so running it
whole exercises the driver's shape dispatch on a file that is not all one
protocol — which no capture used so far does. Finding 3 is what that turns up,
and Stage 7 should record that it met it and left it rather than treating the
193 bytes as a regression.

### Stage 8 — documentation, and what has to be restated

- **§13.2 becomes closed**, and its correction from revision 8 stays visible:
  the record of a diagnosis that was wrong for four revisions is worth more
  than a tidy section.
- **§11 question 6 is answered**, and question 5's line moves again — this is
  more declarative language, so it should say which side it landed on and why
  that is still not hooks.
- **§3.3 or §3.2 gains the new construct**, and the format reference gains its
  key. `test_docs.py` fails if the second is forgotten.
- **The totality argument** from Q5, stated once where §2.1 can point at it.

## What this phase does not do

- **Byte transforms.** Compression and decryption are the other owed phase,
  and the seam for them exists and is documented. A `select` is value
  computation; a transform is bytes to bytes. Different layers, and §11.5 says
  so.
- **A general list type.** Nothing here should make `headers` a value an
  expression can pass around. The construct asks a question and yields a
  scalar, and that is the whole of it.
- **Hooks.** Still deferred, still for the reason §11.5 gives.
- **Pipelining — and this entry was written on a false premise.** Every run of
  `http_stream_1.pcap` holds fifty messages, so the capture that "turns up" was
  in the corpus from the start. It is still not work this phase does, but for
  the opposite reason to the one given: the driver's `_decode_run` already
  loops until a run is exhausted, so pipelining works as soon as a message
  stops claiming bytes that are not its own. That is precisely what `select`
  makes possible, and the spike decodes all fifty per run without touching the
  driver. What does go is the `to_end` body — not as an enhancement but as the
  thing that was eating the other forty-nine.
- **A release.** 0.1.0 is still entangled with §11.4.

## Acceptance

Restated against Stage 1's measurements. Items 1 and 4 changed materially;
the spike meets 1, 2 and the interpreter half of 4 already.

1. `examples/http.yaml` frames its body by asking the headers, and decodes
   **all 2000 messages** of `http_stream_1.pcap` — including the 1147 with
   `Content-Length`, the 853 with no framing header, and all fifty in every
   run — conformance-clean at both granularities, with **no undecoded region at
   all**, which is the stronger claim the spike showed is reachable. Its
   assumption disclaimer is deleted.

   **Coverage** on this capture is clean *except* the unterminated stream
   tails, which are the capture's and not the spec's: the finding set must be
   identical to the baseline's 80. `http_example.pcapng` is the capture that
   closes its streams and it must be coverage-clean outright, 0 findings.

   And the sharper form, on `http.pcap`: the 18 070-byte region today's spec
   calls `truncated` is **gone**, because the body is there and a length-framed
   decode reads it. The 193 bytes of DNS-over-UDP that today's spec also calls
   `truncated` remain, unchanged and out of scope — finding 3 above.
2. `http_example.pcapng` still decodes exactly as it does today: the chunked
   body into its chunks, nothing left over. Closing the general case must not
   cost the case that already works. Its record count *rises* (32 → 59), which
   is the header split and not a regression.
3. The differential agrees on every input in both corpora and their mutations,
   at both granularities.
4. Fuzzing a select-bearing spec raises nothing, never cites and marks the same
   byte, and terminates. Checked against a broken implementation, not merely
   observed to pass — **and Stage 1 showed those invariants are not sufficient
   on their own.** A select that consumes input passes every one of them. So
   the criterion additionally requires a direct assertion that decoding a
   select leaves the cursor where it found it, itself checked against a
   consuming implementation.
5. `DESIGN.md` closes §13.2 and answers §11 question 6, and the format
   reference documents both keys added — `select:` and `within:`.
6. The nested-computed checker bug (finding 1) is fixed with a regression test
   checked against the bug. It is not part of this construct, but this phase's
   own spec cannot be written without it.
