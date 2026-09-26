# kober

Creates decoders for zipline from a specification.

Given a declarative description of a protocol, `kober` decodes network payloads
into a [Zipline](https://github.com/adamkjonsson/zipline) decode stage — a
`.zpf` file whose records are application messages (or fields), each citing the
input bytes it came from. It is a CLI backed by a Python API, and everything
the CLI does is reachable from the API.

> ⚠️ **Early: `0.x`, tagged but not on PyPI.** All five CLI verbs work: a spec
> decodes real `.zpf` files at message or field granularity, checked against
> `zpf`'s own conformance and coverage checkers, and `compile` turns one into a
> Python module that does the same about twenty times faster. It has been
> exercised on real captures, generated impaired traffic and adversarial input
> rather than in anger, and `zpf` itself is `0.x`, where every minor is a
> break — each kober minor pins one. See [DESIGN.md](DESIGN.md) for the
> reasoning, and for which claims were verified against `zpf` rather than
> merely reasoned about; [CHANGELOG.md](CHANGELOG.md) for what each release
> changed.

## Writing and checking a spec

A spec is YAML (or JSON — the core is stdlib-only, and YAML is the optional
`yaml` extra). `check` validates it and types every expression in it *before
any data exists*, which is what lets coverage be proved from the spec alone:

```console
$ kober check dns.yaml
dns 1.0: ok

$ kober check broken.yaml
error: broken.yaml:24: bad.message.body: size: 'length' is declared later in
  unit 'message'; a field may only reference fields decoded before it
error: broken.yaml:31: bad.message.length: unknown enum 'nope'; declared enums: none
warning: broken.yaml:52: bad.orphan: unit is never referenced from the entry unit
bad 1.0: 2 error(s), 1 warning(s)
```

It reports every fault it can see rather than stopping at the first, so a spec
gets fixed in one pass, and each one names the line to fix. `--strict` makes
warnings fail too. JSON reports no positions, so a spec read from JSON — or
built as a mapping in memory — carries the path alone.

### What a spec can say

Eight field types, and each one's answer for *what happens when it does not
match* is half of what it means — a construct with no such answer is how a
decoder ends up guessing.

| | |
| --- | --- |
| `int` | Any width from 1 to 64 bits, signed or not, either endianness, optionally labelled by an enum. Sub-byte fields cite the bytes containing them, so a flags word and the bits inside it are both expressible. |
| `bytes`, `string` | Sized by a constant, an expression, a delimiter, the rest of the run, or the rest **less what the fields after it claim**. |
| `unit` | An instance of another unit, optionally with arguments. |
| `switch` | Choose a type from an earlier value. No default means the region is marked `undecodable` rather than guessed at. |
| `computed` | A value derived from earlier fields. Reads nothing; cites the fields its expression read. |
| `pointer` | *Read this type at that offset, and carry on where you were.* Real DNS needs it — an answer's owner name is usually two bytes meaning "the name at offset 12". |
| `select` | Ask a question about a **repeated** field and get one scalar back. What lets an HTTP message frame its own body by asking whether any header said `chunked`. |
| `concat` | One field of every element of a repetition, joined into one value: a chunked body as the bytes it carries. Reads nothing. |
| `transform` | Bytes already decoded, after a named transform (`gzip`, or a cipher the spec declares), and optionally what they decode as, in an offset space of their own. Reads nothing, and a `limit` bounds its output. |

Fields repeat by count, by a condition tested after each element, or to the end
of the run; they can be conditional; and a field can carry a `const` — a magic
number, or reserved bits that must be zero — which refuses traffic that is not
this protocol's at the field that says so, rather than after a whole message
has been read against the wrong one. The expression language behind all of that
is small on purpose — arithmetic, comparison, field references, and a
closed table of five functions an author cannot add to.

What it deliberately cannot do is move the read cursor. That is the invariant
the coverage guarantee rests on, and it is why constructs get added rather than
hooks: `pointer` and `select` both exist because a real capture needed
something sayable, and saying it declaratively kept `check` able to answer
before any data exists.

The [spec format reference](docs/format/index.md) documents every key;
[`examples/dns.yaml`](examples/dns.yaml) and
[`examples/http.yaml`](examples/http.yaml) are complete specs for real
protocols, exercised by the test suite against real captures.

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

A stream is **confirmed** by its first whole message, and nothing kober writes
for it is kept until then. One that fails before that, or ends without one, is
taken to be in another protocol and is **declined**: no record for any of it,
what was tried marked `undecodable` and the rest `skipped`, each region saying
why (`not dns: …`). A stream in the right protocol whose first message is
corrupt, or whose only message was cut short, is declined too. The bytes cannot
tell it apart from a foreign one ([What a spec meets in someone else's
stream](docs/format/concepts.md)).

A field-granularity file also says what its records are: a **unit sequence**
(`adjacency=units`, spec 0.21), meaning no two adjacent records may be assumed
to join — `flags.qr` is *inside* `flags`, not after it. A message-granularity
file declares nothing and carries its input's adjacency forward, so a stage
chained over a unit sequence keeps saying so. The value is derived from the
granularity, never passed.

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

## Compiling

`compile` turns a spec into a Python module with a typed API. The module reads
bytes without this project's loader, checker, or spec model — only
`kober.runtime` — so a protocol decoder becomes something you can ship:

```console
$ kober compile dns.yaml -o dns.py --emit field
dns.py: 5 unit(s), field granularity
```

```python
>>> import dns
>>> from kober.runtime import span
>>> message = dns.decode(payload)
>>> message.questions[0].qname.labels[0].text
'example'
>>> span(message, "qdcount")
(4, 6)
```

Fields are `int` and `str` rather than a generic tree, so an editor can complete
them and a typo is an error at import time instead of `None` at runtime. Byte
ranges live beside the values rather than wrapping them, which is what keeps a
decode cheap. `kober.stage.run_compiled` drives such a module over a `.zpf`
file exactly as `run` drives the interpreter: the module records the
granularity it was built at in `EMIT`, beside `NAME` and `VERSION`, and the
driver reads it to declare the output's adjacency the same way. A module
compiled by a kober before 0.3.0 has no `EMIT` and is refused — recompile it.

The interpreter is not going anywhere: it is what `try` should always use, and
it is the reference implementation the generated code is tested against — the
two must produce the same file for the same input.

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
`zpf>=0.5.0,<0.6` — it is built on `zpf.decode_stage` and its `adjacency=`
keyword, which is `0.5.0` work, on the per-record `role=` label, and on a
record timestamp derived from `cites`. `zpf` `0.5.0` is released and tagged,
but at the time of writing PyPI publishes only `0.1.0`, so the dependency has
to come from a local (or git) install. Once it reaches PyPI the checkout becomes a convenience rather
than a requirement, and the first line above can be dropped.

The pin covers a single `zpf` minor deliberately: that library is in `0.x`,
where every minor is a break with no upgrade path promised.

```bash
.venv/bin/pytest                                  # run tests
ruff check .                                      # lint
.venv/bin/sphinx-build -W docs docs/_build/html   # build docs (warnings are errors)
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

There is a **deeper pipeline** to run before a release or after touching the
stage driver. It is what found the seam bug that the entire hand-built suite
missed, and it is one command:

```bash
.venv/bin/python tools/pipeline.py
```

It needs two sibling checkouts with their own venvs,
[`packeteer`](https://github.com/adamkjonsson/packeteer) and
[`python-zipline-wire`](https://github.com/adamkjonsson/python-zipline-wire)
(`--packeteer` and `--wire` if they are not at `../`). It fuzzes and generates
DNS and chunked HTTP, converts them and four real captures to `.zpf`, and runs
both example specs through the interpreter and a freshly compiled module at both
granularities. Every output must be conformant and account for every byte; each
interpreter/compiled pair must be identical block for block; and the decoded
**shape** must be right — counted against an independent reader where the
stream is lossless — because coverage alone cannot tell a chunked body from
twenty imaginary messages. `--baseline DIR` compares every output with an
earlier run's `--work DIR`. The in-suite fuzzing covers the decoder and emitter;
only this covers the **stage driver**, because reaching it needs real stream
structure — gaps, truncated messages between whole ones, several records per
run. [Testing](docs/dev/testing.md) says what each input is for.

## License

MIT — see [LICENSE](LICENSE).
