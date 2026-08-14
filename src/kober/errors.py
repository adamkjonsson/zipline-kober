"""Exception hierarchy for the kober package.

Every error kober raises is a :class:`KoberError`. Below that the split is by
*when* the fault is detectable, because that is what a caller can act on:

- :class:`SpecError` — the specification is wrong, and it is wrong before any
  data exists. Raised by loading and by :func:`kober.check`. A spec that
  loads and checks clean cannot raise this later.
- :class:`ExprError` — an expression is malformed, out of scope, or wrongly
  typed. A :class:`SpecError`, since expressions live in the spec and are
  resolved against it at load time.

There is deliberately no decode-time error tier here. A decoder that cannot
make sense of its input does not raise: it records the region as undecoded
and carries on, because the coverage guarantee is a promise about *output*,
and an exception would leave the input unaccounted for. See ``DESIGN.md`` §2.
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
