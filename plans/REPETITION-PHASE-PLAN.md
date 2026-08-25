# Phase plan: speaking about repetitions

**State: not started.** Written after the language phase landed
([`POINTER-PHASE-PLAN.md`](POINTER-PHASE-PLAN.md)), against `DESIGN.md`
revision 8 and `zpf` 0.2.x.

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

| Capture | What it holds | What only it has |
| --- | --- | --- |
| `http_example.pcapng` | 2 messages: a request with no body, a chunked gzip response | The chunked path. Framing works here *because* the spec assumes chunked. |
| `http_stream_1.pcap` | **1645 messages** — 645 requests, 1000 responses, 692 with `Content-Length` (65–70 B), 308 with no framing header at all | Scale, and the *absence* case. Never been run. |
| `http.pcap` | 4 HTTP messages and a DNS-over-UDP session. Two `Content-Length` responses, both **exact** once reassembled: 18 070 B plain, and 1 272 B gzip | A body two orders of magnitude larger than anything else, spanning several transport records — and `Content-Length` **with** a transformed body, which separates two variables `http_example.pcapng` confounds. |

All three live in `python-zipline-wire`'s `tests/captures/`, beside the
fourteen the earlier phases used, so the pipeline in the README reaches them
without a special case.

Established by reading them before planning, and each shapes the work:

- **No run holds more than one message**, in any of the three. So the phase
  does not have to solve pipelining as well, and `to_end` on the body is not
  immediately wrong.
- **308 of `http_stream_1.pcap`'s responses have neither framing header.** A
  bodyless response is normal (`204`, `304`, a `HEAD` reply), so "no framing
  header at all" is a case the spec must get right — and getting it wrong is
  how a decoder invents a hole. It is not an edge case; it is a third of them.
- **Bodies are complete once reassembled, and short per record.** Measuring a
  body inside one transport record says it is truncated when it is not; the
  driver's reassembled run is the only honest place to look. Worth stating
  because the first measurement made for this plan made exactly that mistake.
- **`http.pcap` is where today's spec fails loudest**, and it is a ready-made
  acceptance number: the 18 364-byte response decodes 294 bytes of headers and
  then claims the remaining **18 070 bytes `truncated`** — a hole declared on a
  stream where nothing was missing. That single region is larger than every
  body in `http_stream_1.pcap` put together.

**`http_gzip.pcap` is deliberately not in this table.** Its one response is
gzip under `Content-Length`, which `http.pcap` already provides, so it adds
nothing to the *framing* question. What it has that nothing else does is size:
92 bytes in, 109 out, complete and decompressible — small enough to inline in a
test, which is what the suite's rule about not depending on the sibling
checkout will want. It is the right fixture for the **transforms** phase and
should be kept for it.

## Design questions to settle first

None of these is settled. Stage 1 settles them with a spike, as the previous
two phases settled theirs — a written answer with code behind it.

### Q1 — Does aggregation belong in the expression language or the spec model?

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

### Q2 — What does the element binding look like, and what else is in scope?

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

### Q3 — How does a header's value get separated from its line?

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

### Q4 — What does a `select` cite?

It decodes nothing, so it has the shape `Computed` already has (§3.2) — and
`Computed`'s answer was "the fields its expression read", because citing its
own zero-width position would say nothing.

**Leaning: the element it selected**, not the whole repetition, because that is
the honest evidence: this value came from *that* header. Settle what a
`default:` cites when nothing matched — probably nothing, which needs the
zero-width-emission path `Computed` already exercises.

Whatever the answer, the fuzz invariant is unchanged and must stay so: a byte
is never both cited and marked undecoded.

### Q5 — Does this stay inside §2.1's cursor rule?

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

### Q6 — What does the compiler generate, and what does the plan carry?

The neutral layer (`ops.py`) should describe a select as *what it means* — a
repetition, a predicate, a projection, a default — with the spec's own names
and no Python in it. The Python backend renders a loop.

The thing to watch is the one the last phase was caught by twice: the plan's
walks. A `select` names a field, evaluates two expressions, and does not
consume — so `_referenced`, `_kind_exprs`, and `_kind_consumes` all have to
learn about it, and forgetting one produced a module that called a function it
had not generated.

## Stages

### Stage 1 — settle Q1–Q6, with a spike

Write the finished `examples/http.yaml` **by hand, twice** — once under Q3's
option (1) and once under option (2) — and read them against each other. Then
prototype whichever `select` shape Q1 lands on, in scratch, and run it over
`http_stream_1.pcap`'s 1645 messages.

No production code. The deliverable is this file's Q sections marked settled,
the two hand-written header units, and the numbers from the big capture.

The spike is what says whether `value: "true"` / `default: "false"` is an
acceptable spelling for `any`, which is not a question prose can answer.

### Stage 2 — the construct in the model, loader, and checker

The dataclass, the schema key, and the checks: the named field exists and is
repeated, `where:` types as bool, `value:` and `default:` agree on a type, and
the element binding resolves. Plus the exemption from Q5, tested in both
directions — that a select may name a repetition, and that nothing else may.

### Stage 3 — the interpreter

Evaluate it: walk the decoded elements, test the predicate, project the first
match, fall back to the default. It reads no input and moves no position, and
a fuzz case should hold it to that.

### Stage 4 — Q3's answer, whichever it is

A bounded terminator in `cursor.py` and the size model, or two more rows in
§3.3's table. Either way it lands with the tests that pin what it does when
what it looks for is not there.

### Stage 5 — the compiler

`ops.py` then `pygen.py`, per Q6. The differential is the acceptance test, and
on the last two phases' record it will find something; expect it in whichever
implementation was written second.

### Stage 6 — `examples/http.yaml` finished

The body framed by `Content-Length` **or** chunked encoding **or** neither, by
asking the headers rather than assuming. The assumption disclaimer is deleted.

This is the phase's acceptance criterion, and the measurable form of it is the
big capture: 1645 messages decoding with no `truncated` region that is not a
real truncation.

### Stage 7 — fuzz, and the corpus that has never been run

`http_stream_1.pcap` and `http.pcap` through `zpfwire` and the full pipeline,
at both granularities, conformance- and coverage-clean. Mutated variants
through the fuzz suite and the differential. A capture with 1645 real messages
is a better adversary than anything hand-built, and this project's findings
have all come from that kind of input.

`http.pcap` also carries a DNS-over-UDP session beside its HTTP, so running it
whole exercises the driver's shape dispatch on a file that is not all one
protocol — which no capture used so far does.

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
- **Pipelining.** No run in either capture holds two messages, so the `to_end`
  body and the message-per-run assumption stay as they are. If a capture turns
  up that does, it is a finding and its own work.
- **A release.** 0.1.0 is still entangled with §11.4.

## Acceptance

1. `examples/http.yaml` frames its body by asking the headers, and decodes
   **all 1645 messages** of `http_stream_1.pcap` — including the 692 with
   `Content-Length` and the 308 with no framing header — conformance- and
   coverage-clean at both granularities, with no `truncated` region that is not
   a real truncation. Its assumption disclaimer is deleted.

   And the sharper form of the same criterion, on `http.pcap`: the 18 070-byte
   region today's spec calls `truncated` is **gone**, because the body is there
   and a length-framed decode reads it.
2. `http_example.pcapng` still decodes exactly as it does today: the chunked
   body into its chunks, nothing left over. Closing the general case must not
   cost the case that already works.
3. The differential agrees on every input in both corpora and their mutations,
   at both granularities.
4. Fuzzing a select-bearing spec raises nothing, never cites and marks the same
   byte, and terminates. Checked against a broken implementation, not merely
   observed to pass.
5. `DESIGN.md` closes §13.2 and answers §11 question 6, and the format
   reference documents whatever key was added.
