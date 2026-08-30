# Testing

The suite is native `pytest`, in `tests/`, run with `.venv/bin/pytest`. It takes
about ten seconds, most of it fuzzing, and every test must stay green on every
change.

What makes it worth reading before writing a test here: **example-based tests
verify the code against its author's reading of the format.** Real captures and
adversarial input verify the *design*. Every bug this project has found in
itself came from the second kind, and none of them needed a clever test.

## Test map

| File | Covers |
| ---- | ------ |
| `test_expr.py` | The expression language's parser: precedence, the whitelist, and every construct it refuses by name. |
| `test_eval.py` | Evaluation, and the cross-check that inferred type and evaluated value agree — if those two halves disagreed, everything `check` proves would be void. |
| `test_spec.py` | The model's local invariants: integer widths, blank names, duplicate fields, normalization to tuples and read-only mappings. |
| `test_loader.py` | The YAML/JSON schema: strictness, path-carrying errors, the tagged-mapping forms, and YAML's implicit-typing traps. |
| `test_check.py` | Whole-spec validation: scoping, ordering, `parent`/`root` resolution, argument matching, recursion. |
| `test_cursor.py` | The bit-level cursor: MSB-first reads, sub-byte spans rounding outward, alignment refusal, truncation. |
| `test_node.py` | The tree: walking, statuses, rendering. |
| `test_decoder.py` | The engine: every field type, size, and repeat, plus guards, truncation, and the bounded loops. |
| `test_emit.py` | What the emitter *decides*, with no file involved: granularity resolution, `prim:` widening, field paths, coverage arithmetic. |
| `test_emit_conformance.py` | What `zpf` *accepts*: real files written through a decode stage and put past `ConformanceChecker` and `check_coverage`. |
| `test_stage.py` | The driver: gaps, seams, shape dispatch, chaining, timestamps, `content_registry`. |
| `test_cli.py` | All five verbs, driving `main()` directly. |
| `test_examples.py` | The shipped `examples/` specs — they must check clean, carry documentation, and still decode. |
| `test_ops.py` | The compiler's neutral plan: what it carries about a format, and what it deliberately does not carry about a target. |
| `test_pygen.py` | The Python backend: names and the refusals, expression rendering, and that its output passes `ruff` and is the module checked into `tests/compiled_dns.py`. |
| `test_compiled_dns.py` | That checked-in module from a consumer's side: typed fields, byte ranges, enum labels. |
| `test_compiled.py` | **The differential**, and the fuzzing of it. See below. |
| `test_fuzz.py` | **The interpreter's invariants**, over adversarial input. See below. |
| `fuzzing.py` | Not a test: the mutators, shared so both implementations are fuzzed with the same inputs. |

## Two implementations, and the test that compares them

`kober` decodes a spec two ways: `Decoder` interprets it, and `kober compile`
turns it into a module. Neither's own tests can catch a decoder that is
confidently wrong, so the strongest test here is that **they agree**:

- the same values and the same byte ranges, field by field, unit by unit;
- the same records and the same undecoded regions, in the same order;
- the same **file**, block for block, when both are driven over a capture;
- and where a decode fails, the same offset with the same reason.

That comparison is `test_compiled.py`, and it earns its cost. Four bugs have
come out of it so far, every one of them in the *interpreter* or in code both
share: two places a partial decode was thrown away, a `switch` case that wrote
no record, and a computed value too wide for `prim:` raising out of the emitter.
None had a failing test before, and none would have been found by reading.

**A construct the shipped examples do not use gets a spec in that file's
awkward corpus**, not only an example — bitfields that do not divide a byte, a
switch whose branches differ in width, a computed value, every size a spec can
write. The compiler's arithmetic about *where a field is* is exactly the kind of
thing that stays right on `dns.yaml` and wrong everywhere else.

## Fuzzing is standard, not optional

`tests/test_fuzz.py` runs with the suite and depends on nothing outside the
standard library. It asserts the promises that **cannot be tested by example**,
because they are claims about all input rather than some:

- a decode never raises;
- a decode never claims more than it was given;
- no byte is ever both cited and marked undecoded;
- every reason is one `zpf` classifies.

Mutations are seeded, so a failure reproduces from the bytes it prints, and an
escaping exception is re-raised with a note rather than reported through
`pytest.fail`, so the traceback survives.

**A new invariant of that kind gets a fuzz test, not just an example.**

It generates payload-level mutations — truncate, extend, bit-flip, boundary,
replace — because that is what actually reaches a decoder. By the time bytes
get there the transport layers are gone.

**Both implementations are fuzzed with the same inputs**, from `fuzzing.py`.
That is not tidiness: the differential can only compare results over inputs that
match, and the mutations that break one are the ones worth showing the other.

### A seed is only worth the code it reaches

Check what a seed *enters*, not only that its variants pass. `fuzzing.py` seeds
`examples/http.yaml` with a request that has no framing header — so every
variant of it took the third path, and neither arm that chooses a framing was
ever entered. A wrong comparison in the chunked arm survived five stages of this
project behind that gap, agreeing with every measurement taken, because the
measurements ran the arm that worked.

So `HTTP_CHUNKED` and `HTTP_COUNTED` sit beside it, and
`test_the_framing_seeds_reach_every_arm` asserts that all three arms are still
entered. A mutation set that stopped reaching one would otherwise go unnoticed
exactly as the original did — which is the same reason `DNS_RESPONSE` exists
beside the query: the query reaches no pointer.

### A byte count is not a criterion

Coverage says every byte was accounted for. It does not say the decode was
*right*, and the two come apart in one specific way worth knowing: a message
that stops early leaves its tail to the driver, which decodes it as further
messages — and those cite it. Zero undecoded regions, conformance clean,
coverage whole, decode nonsense.

That is how a chunked response was read as headers followed by twenty
imaginary messages while every check passed. Where a spec frames its own
content, assert the **shape**: one message consuming its whole extent, its body
in the parts it should have. `tests/test_examples.py` does this for HTTP.

## The deeper pipeline

The in-suite fuzzing covers the engine and the emitter. It **cannot reach the
stage driver**, which needs real stream structure: gaps, truncated messages
between whole ones, several records per run. That is exactly where the seam bug
lived, and it is why this pipeline exists.

Two sibling checkouts, neither a dependency of this project:

```bash
# Adversarial variants of a real capture, then convert, then decode.
../packeteer/.venv/bin/packeteer fuzz \
    ../python-zipline-wire/tests/captures/dns_example.pcapng \
    --pcap /tmp/fuzz.pcap --seed 1
../python-zipline-wire/.venv/bin/zpfwire convert /tmp/fuzz.pcap -o /tmp/fuzz.zpf
.venv/bin/kober run examples/dns.yaml /tmp/fuzz.zpf -o /tmp/out.zpf --emit field
```

Then put the output past `zpf.ConformanceChecker` and `zpf.check_coverage`.
**Run this before a release, or after touching `stage.py`.**

The compiled path is worth running over the same file, since both drive the same
`stage.py` and should write the same one:

```bash
.venv/bin/kober compile examples/dns.yaml -o /tmp/dns.py --emit field
.venv/bin/python -c "import sys; sys.path.insert(0, '/tmp'); import dns; \
    from kober.stage import run_compiled; \
    run_compiled(dns, '/tmp/fuzz.zpf', '/tmp/compiled.zpf', \
                 produced_by='kober', produced_at=0)"
```

- [`python-zipline-wire`](https://github.com/adamkjonsson/python-zipline-wire)
  converts real captures to `.zpf`. Its `tests/captures/` holds sixteen,
  including DNS, HTTP, and packet loss.
- [`packeteer`](https://github.com/adamkjonsson/packeteer) generates synthetic
  traffic and adversarial variants, and can produce impairments directly
  (`packeteer stream --packet-loss --gap-jitter …`) — a better source of gap
  and reordering cases than hand-built fixtures. Since its 0.11.0 a protocol it
  lacks can be **written** rather than filed: it has a protocol spec language of
  its own, with `packeteer protocol check|show|compile`, and `--load-protocol`
  puts the result on the command line. Filing an issue is now for what that
  language cannot express.

  **Its 0.9.0 closed the two limits this project had filed against it**, and
  both were closed in the direction that matters here. `--payload http` now
  honours every TCP anomaly rather than warning and ignoring it, so an impaired
  *HTTP* stream no longer has to come from fuzzing a real capture. And it can
  now frame a response with `Transfer-Encoding: chunked` — with `--chunked-rate`
  for the proportion, `--min-chunk` / `--max-chunk` for the split, and
  `--trailer-rate` for the trailer section after the terminating chunk.

  That last one earns its keep immediately. The chunked path had **one** real
  message behind it across all sixteen captures, against 1151 with a
  `Content-Length`, and no capture in reach has a trailer at all — so the
  spec's handling of one had never been executed by anything. It was wrong:
  see *A trailer section is not a chunk* below.

  Generate the hard case rather than the average one:

  ```bash
  ../packeteer/.venv/bin/packeteer stream --payload http \
      --client-ip 10.0.0.2 --server-ip 10.0.0.1 --requests 30 \
      --chunked-rate 0.5 --trailer-rate 0.5 --min-chunk 8 --max-chunk 32 \
      --mss 200 --packet-loss 0.05 --seed 3 --pcap /tmp/http.pcap
  ```

  `--mss` is doing as much work as `--packet-loss`. At the default 1460 a
  generated message fits inside one segment, so a loss takes a whole message
  and never lands mid-body; at 200 a chunk boundary falls across a segment
  boundary, which is where a streaming decoder is likeliest to be wrong.

  A note on the seed. Its 0.9.0 also made a generated SYN advertise TCP options
  by default, so **a capture regenerated with an old seed is not the old
  capture**; `--no-tcp-options` restores the previous bytes. Nothing in this
  project pins those bytes — the suite depends on no capture at all — so it
  costs nothing here, but a remembered seed no longer means a remembered file.
  Its 0.12.0 changed rebuilt bytes again, so the caution stands generally.

### Generated DNS, and what 0.12.0 changed about the fuzzed kind

Two things arrived in `packeteer` 0.12.0 that matter here, and both are about
**compression pointers** — the construct `examples/dns.yaml` follows with
`pointer:`, and the one no in-suite test can supply adversarially.

**A compressed DNS message now round-trips.** Before, `parse` decoded name
compression correctly and `build` wrote every name out in full, so a compressed
message re-encoded larger than captured and no packet carrying one ever rebuilt
— 118 of 238 in one of packeteer's own captures. Whatever `packeteer fuzz`
produced from a DNS capture, it was not the compressed majority of it. It is
now: one run of the pipeline above over `dns_example.pcapng` yields 340 messages
in which **1932 compression pointers are followed**, conformant and with every
byte accounted for.

**DNS can now be generated rather than only fuzzed.** `--payload` takes any
registered protocol, and `--protocol-messages` says which messages to send — so
the "generate the hard case rather than the average one" that HTTP got in 0.9.0
is available for DNS, impairments and all:

```bash
# messages.json: [{"raw": "<query hex>"}, {"raw": "<compressed response hex>"}]
../packeteer/.venv/bin/packeteer stream --payload dns --protocol udp \
    --protocol-messages messages.json --client-ip 10.0.0.2 --server-ip 10.0.0.1 \
    --packets 40 --packet-loss 0.05 --gap-jitter 0.01 --seed 5 --pcap /tmp/dns.pcap
```

`raw:` is what makes this worth doing. A *generated* DNS message is built from
decoded fields and writes every name in full, so it carries no pointer at all;
supplying the bytes yourself is the only way to put a compressed response into
an impaired stream, and a compressed response behind a lost datagram is exactly
the case nothing else here can produce.

**One trap, since it cost a run to find.** Each element of the file is a
protocol **section body** — `{"raw": …}` — not the `{"dns": {…}}` shape that
`packeteer parse` writes. The wrapped form is accepted in silence and builds an
empty 12-byte header, so the pipeline runs, the output is conformant, coverage
is complete, and every message is a bare DNS header. Assert the shape: counting
`.target` records is the cheapest way to know a pointer was followed at all.

### A trailer section is not a chunk

The bug `packeteer` 0.9.0 made reachable, kept here because it is the same
shape as the one above and was found the same way.

RFC 7230 §4.1 ends a chunked body with `trailer-part CRLF`, and the terminating
chunk carries **no CRLF of its own** — what follows it is the trailer section,
not another chunk. `examples/http.yaml` read two bytes after every chunk's
data, terminating chunk included. With no trailers those two bytes happen to be
the body's final CRLF, so the spec was right by coincidence on every message any
capture could show it. With a trailer they are the first two characters of the
first trailer line, and the remainder was left to the driver, which read it as
further messages.

Coverage was whole and conformance was clean, on both. What separated them was
counting start lines: 40 messages from a capture of 20 request/response pairs
without trailers, **52** from the same capture with them. The fix gives the
section a unit of its own and reuses `header` for its elements, which is what
the grammar says it is.

## A regression test must be checked against its bug

Revert the fix, watch the test fail, restore. **Several tests written in this
project passed either way on the first attempt** and were worthless until
corrected — including two versions of the seam regression test, which passed
because a seam needs a record *before* it and a stream's first record has
nothing to not-join.

The same discipline applies to a fuzz property: the cited-and-undecoded
property was verified by reverting the emitter's interval subtraction and
watching all four parametrisations fail.

## `pressure_test.py`

Not part of the suite. It is an executable probe of the `zpf` behaviour this
project depends on — stage chaining, overlapping spans, `prim:` normalization,
message timestamps, per-field naming — and prints conformance and coverage at
each step:

```bash
.venv/bin/python pressure_test.py
```

It is the source of every **[verified]** claim in `DESIGN.md`, and the reason
three upstream issues were filed rather than worked around. Run it after
changing anything about how records are written.
