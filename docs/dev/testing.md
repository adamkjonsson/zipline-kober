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
.venv/bin/python -c "import sys; sys.path.insert(0, '/tmp'); import dns, kober; \
    kober.run_compiled(dns, '/tmp/fuzz.zpf', '/tmp/compiled.zpf', \
                       produced_by='kober', produced_at=0)"
```

- [`python-zipline-wire`](https://github.com/adamkjonsson/python-zipline-wire)
  converts real captures to `.zpf`. Its `tests/captures/` holds fourteen,
  including DNS, HTTP, and packet loss.
- [`packeteer`](https://github.com/adamkjonsson/packeteer) generates synthetic
  traffic and adversarial variants, and can produce impairments directly
  (`packeteer stream --packet-loss --gap-jitter …`) — a better source of gap
  and reordering cases than hand-built fixtures. If it lacks a protocol you
  need, that is an issue to file on *that* project.

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
