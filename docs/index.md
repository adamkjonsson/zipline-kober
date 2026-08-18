# kober — decoders from a specification

`kober` turns a **declarative protocol specification** into a
[Zipline](https://github.com/adamkjonsson/zipline) decode stage: it reads a
`.zpf` file of reassembled session bytes and writes another `.zpf` whose
records are application messages — or individual protocol fields — each citing
the input bytes it came from.

It is a CLI backed by a Python API, and everything the CLI does is reachable
from the API.

```{note}
**Early, and not released.** The spec model, checker, decode engine, emitter,
stage driver, all five CLI verbs and the compiler work, and are exercised
against real captures and adversarial input. Nothing is tagged, and `zpf` itself
is `0.x` where every minor is a break. Interfaces will move.
```

## What it is for

A `.zpf` file answers *what did the endpoints say*. It does not say what those
bytes **mean** — that is a decoder's job, and writing one by hand for every
protocol is the work this avoids. Given a specification like:

```yaml
name: dns
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: id, type: {int: {bits: 16}}}
      - {name: flags, type: {unit: flags}}
```

`kober` produces a decode stage from it, and guarantees something a
hand-written decoder rarely does: **every input byte is either cited by a
record or named as undecoded, never both, and never silently.** A region the
decoder could not read says so, with a reason — `undecodable`, `truncated`,
`gap`, or `skipped` — rather than disappearing.

```console
$ kober check dns.yaml
dns 1.0: ok

$ kober run dns.yaml capture.zpf -o decoded.zpf --emit field
decoded.zpf: 176 record(s), 1 undecoded region(s)
  skipped: 4
```

## Two ways to run a spec

`run` above **interprets** the spec: no build step, change the YAML and run it
again. `compile` turns the same spec into a Python module with a typed API,
which reads bytes without this project's loader, checker or spec model:

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

Fields are `int` and `str` rather than a generic tree, so an editor completes
them and a typo fails at import rather than returning `None` at runtime. It is
also about twenty times faster, for the same reason: the tree a generic decoder
builds is where the time goes.

The interpreter is not going anywhere. It is the reference implementation the
generated code is tested against — the two must produce the same file for the
same input — and that comparison has found more bugs in this project than any
other test in it.

## Where to go next

This documentation is being written, in the order the work needs it:

- **Working on kober itself?** The [developer guide](dev/index.md) covers the
  module map, the invariants a change must not break, [the compiler](dev/compiler.md),
  and the testing practice.
- **Writing a specification?** The [spec format](format/index.md) reference
  documents every key the loader accepts.
- **Looking something up?** The [API reference](api/index.md) covers each
  public module.

User-facing tutorials and guides come once the API settles. Until then,
[`README.md`](https://github.com/adamkjonsson/zipline-kober) is the short
version, [`DESIGN.md`](https://github.com/adamkjonsson/zipline-kober/blob/main/DESIGN.md)
is the reasoning, and `plans/` records how it was built.

```{toctree}
:hidden:
:maxdepth: 2

dev/index
format/index
api/index
```
