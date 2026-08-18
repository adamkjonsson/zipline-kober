# `kober.runtime`

```{eval-rst}
.. automodule:: kober.runtime
   :no-members:
```

`Cursor`, `TruncatedRead`, `EvalError`, `Undecodable`, `shift_left`, and
`shift_right` are re-exported here rather than defined here, and are documented
under the modules that define them — [`kober.cursor`](cursor.md),
[`kober.errors`](errors.md), and [`kober.expr`](expr.md). A generated decoder
and the interpreter use the same ones, which is what makes the two comparable.

## Reading

```{eval-rst}
.. autofunction:: kober.runtime.read_int_le
```

## What a record is made of

```{eval-rst}
.. autoclass:: kober.runtime.Sink
   :members:

.. autodata:: kober.runtime.PRIM_WIDTHS

.. autodata:: kober.runtime.TEXT_CONTENT_TYPE

.. autofunction:: kober.runtime.prim_token

.. autofunction:: kober.runtime.normalize_int

.. autofunction:: kober.runtime.prim_int

.. autofunction:: kober.runtime.cited
```

## Byte ranges

```{eval-rst}
.. autoclass:: kober.runtime.Spanned
   :members:

.. autofunction:: kober.runtime.span
```
