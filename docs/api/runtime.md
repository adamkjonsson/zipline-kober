# `kober.runtime`

```{eval-rst}
.. automodule:: kober.runtime
   :no-members:
```

`Cursor`, `TruncatedRead`, `EvalError`, `Undecodable`, `TransformError`,
`shift_left`, and `shift_right` are re-exported here rather than defined here, and are documented
under the modules that define them — [`kober.cursor`](cursor.md),
[`kober.errors`](errors.md), [`kober.transforms`](transforms.md), and
[`kober.expr`](expr.md). A generated decoder
and the interpreter use the same ones, which is what makes the two comparable.

## Reading

```{eval-rst}
.. autofunction:: kober.runtime.read_int_le
```

## What a record is made of

```{eval-rst}
.. autoclass:: kober.runtime.Sink
   :members:

.. autoclass:: kober.runtime.Held
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

## Transforms

What a generated module calls for a `transform` or a `concat`. Each contains
its own failures, worded as the interpreter words them, so the generated code
has a call where it would otherwise have a `try` per step.

```{eval-rst}
.. autofunction:: kober.runtime.bind_transforms

.. autofunction:: kober.runtime.run_transform

.. autofunction:: kober.runtime.take_over

.. autofunction:: kober.runtime.concat

.. autoclass:: kober.runtime.TransformFailed
   :members:

.. autofunction:: kober.runtime.first_failed

.. autoclass:: kober.runtime.Output
   :members:
```

## Parameters

```{eval-rst}
.. autofunction:: kober.runtime.document_params

.. autofunction:: kober.runtime.params_digest
```
