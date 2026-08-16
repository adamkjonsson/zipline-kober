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
stage driver, and all four CLI verbs work, and are exercised against real
captures and adversarial input. Nothing is tagged, and `zpf` itself is `0.x`
where every minor is a break. Interfaces will move.
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

## Where to go next

This documentation is being written, in the order the work needs it:

- **Working on kober itself?** The [developer guide](dev/index.md) covers the
  module map, the invariants a change must not break, and the testing practice.
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
