"""Exception hierarchy for the kober package.

Every error kober raises is a :class:`KoberError`. Below that the split is by
*when* the fault is detectable, because that is what a caller can act on:

- :class:`SpecError` — the specification is wrong, and it is wrong before any
  data exists. Raised while *building* a spec: by the loader for a malformed
  document, and by the model for a fault one object can see by itself.
- :class:`ExprError` — an expression is malformed, out of scope, or wrongly
  typed. A :class:`SpecError`, since expressions live in the spec and are
  resolved against it at load time.
- :class:`EvalError` — an expression could not produce a value *for this
  input*. Not a spec fault: the spec may be perfectly valid and the wire value
  simply zero where something divided by it.

:func:`kober.check.check` deliberately does **not** raise. A validator that
stops at the first fault makes an author fix a spec one line per run, so it
returns every :class:`~kober.check.Finding` it can see instead. Raising is for
faults that stop a spec from being *built* at all.

**No decode-time error escapes a decode.** A decoder that cannot make sense of
its input does not raise at its caller: it records the region as undecoded and
carries on, because the coverage guarantee is a promise about *output*, and an
exception would leave the input unaccounted for (``DESIGN.md`` §2).
:class:`EvalError` is the one tier that exists *inside* that boundary — it is
how an expression tells the decode engine "no value", so the engine can mark
the region and continue. Letting one out of a decode is a bug.
"""

from __future__ import annotations


class KoberError(Exception):
    """Base class for all errors raised by the kober package."""


class SpecError(KoberError):
    """The specification is invalid, independently of any input data.

    Raised by :meth:`kober.Spec.from_dict` and friends for a structural
    fault — an unknown key, a wrong value type, a reference to a unit that
    does not exist — and by :func:`kober.check` for the faults that need the
    whole spec in view, such as a cycle in the unit graph.
    """


class ExprError(SpecError):
    """An expression is unparseable, out of scope, or wrongly typed.

    Carries the offending source text so a message can quote it, since an
    expression is authored as a string and the string is what the author
    will look for.

    Attributes:
        message: What is wrong.
        source: The expression text as authored.
        where: Dotted path to the field or unit the expression belongs to,
            when the raiser knows it.

    """

    def __init__(self, message: str, source: str, where: str | None = None) -> None:
        self.message = message
        self.source = source
        self.where = where
        location = f" at {where}" if where else ""
        super().__init__(f"{message}{location}: {source!r}")


class EvalError(KoberError):
    """An expression could not produce a value for this input.

    Deliberately **not** a :class:`SpecError`. A spec that divides by a length
    field is correct; a packet carrying zero in that field is what makes the
    expression unanswerable, and the same spec answers fine on the next
    packet. Blaming the spec would send an author looking in the wrong place.

    The decode engine catches this and marks the affected region
    ``undecodable`` rather than letting it escape — see the module docstring.
    Its cases are the ones a total, side-effect-free language still cannot
    rule out statically: division or modulo by zero, and a shift count that is
    negative or absurd.
    """
