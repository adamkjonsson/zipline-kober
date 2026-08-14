# zipline_decoder

Creates decoders for zipline from a specification.

Given a declarative description of a protocol, this decodes network payloads
into a [Zipline](https://github.com/adamkjonsson/zipline) decode stage — a
`.zpf` file whose records are application messages (or fields), each citing the
input bytes it came from. It is a CLI backed by a Python API, and everything
the CLI does is reachable from the API.

> ⚠️ **Nothing is implemented yet.** This is a design in progress. See
> [DESIGN.md](DESIGN.md) for the intended spec model, decode semantics, and
> public API, and for which parts have been verified against `zpf` rather than
> merely reasoned about.

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
