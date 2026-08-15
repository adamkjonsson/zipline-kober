# kober

Creates decoders for zipline from a specification.

Given a declarative description of a protocol, `kober` decodes network payloads
into a [Zipline](https://github.com/adamkjonsson/zipline) decode stage — a
`.zpf` file whose records are application messages (or fields), each citing the
input bytes it came from. It is a CLI backed by a Python API, and everything
the CLI does is reachable from the API.

> ⚠️ **Early, and not released.** All four CLI verbs work and a spec decodes
> real `.zpf` files at message or field granularity, checked against `zpf`'s
> own conformance and coverage checkers. It has been exercised on small
> hand-built captures rather than in anger. See [DESIGN.md](DESIGN.md) for the
> reasoning, and for which claims were verified against `zpf` rather than
> merely reasoned about.

## Writing and checking a spec

A spec is YAML (or JSON — the core is stdlib-only, and YAML is the optional
`yaml` extra). `check` validates it and types every expression in it *before
any data exists*, which is what lets coverage be proved from the spec alone:

```console
$ kober check dns.yaml
dns 1.0: ok

$ kober check broken.yaml
error: bad.message.body: size: 'length' is declared later in unit 'message';
  a field may only reference fields decoded before it
error: bad.message.length: unknown enum 'nope'; declared enums: none
warning: bad.orphan: unit is never referenced from the entry unit
bad 1.0: 2 error(s), 1 warning(s)
```

It reports every fault it can see rather than stopping at the first, so a spec
gets fixed in one pass. `--strict` makes warnings fail too.

`show` prints the field tree a spec describes, expanding nested units in place:

```console
$ kober show dns.yaml
dns 1.0 — input: either, entry: message

enum opcode: 0=query, 1=iquery, 2=status

message
├── id: u16
│     Copied into the reply; matches responses to requests.
├── flags: → flags
│   ├── qr: u1
│   ├── opcode: u4 enum opcode
│   └── (anonymous): u2
├── qdcount: u16
└── questions: → question  ×this.qdcount
    ├── qname: string[until b'\x00'] utf-8
    └── qtype: u16
```

## Decoding

`run` turns a transport-layer `.zpf` file into a decode stage — one record per
protocol message, or one per field:

```console
$ kober run dns.yaml capture.zpf -o decoded.zpf
decoded.zpf: 1 record(s), 0 undecoded region(s)

$ kober run dns.yaml capture.zpf -o fields.zpf --emit field
fields.zpf: 12 record(s), 0 undecoded region(s)
```

Every record cites the input bytes it came from, and every byte is either cited
or named as `undecodable`, `truncated`, `gap`, or `skipped` — never both, and
never silently. An undecodable region is a conformant result rather than a
failure, so `run` reports it and still succeeds.

`try` decodes one buffer with no file at all, which is the fastest way to see
what a spec does to some bytes:

```console
$ kober try dns.yaml --hex 123401000001000000000000076578616d706c6503636f6d0000010001
message  [0, 29)
  id = 4660  [0, 2)
  flags  [2, 4)
    qr = 0  [2, 3)
    opcode = 0  [2, 3)
  qdcount = 1  [4, 6)
  qname = b'\x07example\x03com'  [12, 25)

29 of 29 byte(s) decoded: ok
```

Unlike `run`, it fails when the decode did not complete — answering that is the
point of it.

Everything the CLI does is reachable from the API:

```python
from kober import Decoder, Spec, check

spec = Spec.from_file("dns.yaml")   # or from_dict / from_json / from_yaml
for finding in check(spec):
    print(finding)

decoder = Decoder(spec)
decoder.run("capture.zpf", "decoded.zpf", produced_by="my-tool 1", produced_at=1)

tree = decoder.decode_bytes(payload)   # no file: a Node tree
print(tree.render())
```

## The name

[Alice Kober](https://en.wikipedia.org/wiki/Alice_Kober) spent years on the
structural groundwork that made Linear B readable — cataloguing sign patterns
on hand-cut index cards, and proving the script's inflection without ever
guessing at meaning. Michael Ventris made the final leap and got the credit;
Kober did the part where you work out what the structure *is* before anything
can be read.

Which is this tool's job exactly: not guessing what bytes mean, but applying a
specification of their structure and citing the evidence for every claim it
makes.

## Development

Requires Python 3.11+ and a checkout of
[python-zipline](https://github.com/adamkjonsson/python-zipline) beside this
one.

```bash
python3 -m venv .venv
.venv/bin/pip install -e ../python-zipline    # see note below
.venv/bin/pip install -e . -r requirements.txt
```

**Why `zpf` is installed from a checkout.** This project depends on
`zpf>=0.2.0,<0.3` — it is built on `zpf.decode_stage`, and on `comment=`,
which are `0.2.0` work. `zpf` `0.2.0` is released and tagged, but at the time
of writing PyPI still publishes only `0.1.0`, so the dependency has to come
from a local (or git) install. Once `0.2.0` reaches PyPI the checkout becomes a
convenience rather than a requirement, and the first line below can be dropped.

The pin covers a single `zpf` minor deliberately: that library is in `0.x`,
where every minor is a break with no upgrade path promised.

```bash
.venv/bin/pytest                                  # run tests
ruff check .                                      # lint
.venv/bin/sphinx-build docs docs/_build/html      # build docs
.venv/bin/python -m build                         # build wheel + sdist
```

`pressure_test.py` probes the `zpf` behaviour this project depends on —
stage chaining, overlapping spans, `prim:` payload normalization, and message
timestamps — and prints conformance and coverage results at each step:

```bash
.venv/bin/python pressure_test.py
```

### Fuzzing

`tests/test_fuzz.py` runs with the suite and needs nothing external. It asserts
the promises that cannot be tested by example: a decode never raises, a decode
never claims more than it was given, and no byte is ever both cited and marked
undecoded. Mutations are seeded, so a failure reproduces from the bytes it
prints.

There is a **deeper pipeline** worth running before a release or after touching
the stage driver, using two sibling checkouts. It is what found the seam bug
that the entire hand-built suite missed:

```bash
# Adversarial variants of a real capture, then convert, then decode.
../packeteer/.venv/bin/packeteer fuzz \
    ../python-zipline-wire/tests/captures/dns_example.pcapng \
    --pcap /tmp/fuzz.pcap --seed 1
../python-zipline-wire/.venv/bin/zpfwire convert /tmp/fuzz.pcap -o /tmp/fuzz.zpf
.venv/bin/kober run examples/dns.yaml /tmp/fuzz.zpf -o /tmp/out.zpf --emit field
```

Then check the output with `zpf.ConformanceChecker` and `zpf.check_coverage`.
The in-suite fuzzing covers the decoder and emitter; only this covers the
**stage driver**, because reaching it needs real stream structure — gaps,
truncated messages between whole ones, several records per run — rather than
one adversarial buffer.

[`packeteer`](https://github.com/adamkjonsson/packeteer) can also generate
traffic with impairments directly (`packeteer stream --packet-loss
--gap-jitter …`), which is a better source of gap and reordering cases than
hand-built fixtures.

## License

MIT — see [LICENSE](LICENSE).
