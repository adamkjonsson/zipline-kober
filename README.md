# kober

Creates decoders for zipline from a specification.

Given a declarative description of a protocol, `kober` decodes network payloads
into a [Zipline](https://github.com/adamkjonsson/zipline) decode stage — a
`.zpf` file whose records are application messages (or fields), each citing the
input bytes it came from. It is a CLI backed by a Python API, and everything
the CLI does is reachable from the API.

> ⚠️ **The decoder is not built yet.** What works today is the spec side: the
> model, the expression language, the loaders, the checker, and the `check` and
> `show` CLI verbs. Nothing decodes bytes yet — `run` and `try` come with the
> decoder. See [DESIGN.md](DESIGN.md) for where this is going, and for which
> parts have been verified against `zpf` rather than merely reasoned about.

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

Everything the CLI does is reachable from the API:

```python
from kober import Spec, check

spec = Spec.from_file("dns.yaml")   # or from_dict / from_json / from_yaml
for finding in check(spec):
    print(finding)
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
`zpf>=0.2.0.dev0,<0.3` — it is built on `zpf.decode_stage`, which is `0.2.0`
work — but PyPI currently publishes only `zpf` `0.1.0`. Until `0.2.0` is
released, the dependency has to come from a local (or git) install. The pin
covers a single `zpf` minor deliberately: that library is in `0.x`, where every
minor is a break with no upgrade path promised.

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

## License

MIT — see [LICENSE](LICENSE).
