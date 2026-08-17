# `kober.runtime`

```{eval-rst}
.. automodule:: kober.runtime
   :no-members:
```

The rest of what a generated module imports is re-exported here rather than
defined here: `Cursor`, `TruncatedRead`, `EvalError`, `Undecodable`,
`shift_left`, and `shift_right`. They are documented under the modules that
define them — [`kober.cursor`](cursor.md), [`kober.errors`](errors.md), and
[`kober.expr`](expr.md) — because a generated decoder and the interpreter use
the same ones, which is what makes the two comparable.

```{eval-rst}
.. autofunction:: kober.runtime.read_int_le

.. autoclass:: kober.runtime.Spanned
   :members:

.. autofunction:: kober.runtime.span
```
