# Developer guide

For working on `kober` itself. It assumes you have read the
[README](https://github.com/adamkjonsson/zipline-kober) and can run the tests.

- [Architecture](architecture.md) — the module map, how a decode flows through
  it, and the **invariants a change must not break**.
- [The compiler](compiler.md) — the second way to run a spec, the seam a future
  backend attaches to, and the invariants generated code has to keep.
- [Testing](testing.md) — the test map, why fuzzing is standard here, and the
  deeper pipeline that is the only thing exercising the stage driver.
- [Contributing](contributing.md) — environment, style, changelog, and the
  house rules.
- [Where decisions live](decisions.md) — an index of the reasoning, which is
  spread across `DESIGN.md`, `plans/`, upstream issues, and the commit log.

```{toctree}
:hidden:

architecture
compiler
testing
contributing
decisions
```
