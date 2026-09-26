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
- :class:`Undecodable` — the input was read and made no sense of. A decode-time
  signal like :class:`EvalError`, and the compiled counterpart of a verdict the
  interpreter records on a node rather than raising. With
  :class:`TruncatedRead` it shares :class:`Stopped`, which carries *where* a
  decode stopped for generated code that keeps its position in a local.
- :class:`CompileError` — a valid spec cannot be expressed in the language
  being generated. Not a spec fault either: what collides differs by target.

**A spec fault says where it is.** :class:`SpecError` carries a
:class:`~kober.source.Location`, so a message names the file and the line as
well as the construct — the difference between a description of a problem and a
way to find it, on a format whose whole surface is hand-written. A source that
reports no positions leaves the line ``None`` and the message reads as it
always did; see :mod:`kober.source`.

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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kober.source import Location


class KoberError(Exception):
    """Base class for all errors raised by the kober package."""


class SpecError(KoberError):
    """The specification is invalid, independently of any input data.

    Raised by :meth:`kober.spec.Spec.from_dict` and friends for a structural
    fault — an unknown key, a wrong value type, a reference to a unit that
    does not exist — and by :func:`kober.check.check` for the faults that need the
    whole spec in view, such as a cycle in the unit graph.

    Carries a :class:`~kober.source.Location` when the raiser knows one, which
    the loader always does and the model rarely does. The rendered message
    leads with whatever the location has: ``dns.yaml:27: path: message`` from a
    file, and ``path: message`` from JSON or a mapping, which is what was
    printed before locations existed.

    Attributes:
        message: What is wrong, without the location.
        loc: Where it is, when that is known.

    """

    message: str
    loc: Location | None

    def __init__(self, message: str, loc: Location | None = None) -> None:
        self.message = message
        self.loc = loc
        super().__init__(message if loc is None else f"{loc}: {message}")


class ExprError(SpecError):
    """An expression is unparseable, out of scope, or wrongly typed.

    Carries the offending source text so a message can quote it, since an
    expression is authored as a string and the string is what the author
    will look for.

    Its location is :attr:`~kober.errors.SpecError.loc`, inherited rather than
    a second attribute of its own: an expression fault is in a place, and one
    name for that is enough. The constructor still spells the argument
    ``where``, because that is what it is at a call site.

    Attributes:
        message: What is wrong, without the location or the quoted source.
        source: The expression text as authored.

    """

    def __init__(self, message: str, source: str, where: Location | None = None) -> None:
        super().__init__(f"{message}: {source!r}", where)
        # Restated bare: `message` is what a caller reports on its own terms —
        # `check` puts it in a Finding — where the rendered form quotes the
        # source, which is the whole reason this class exists.
        self.message = message
        self.source = source


class Stopped(KoberError):
    """A decode-time failure that knows where it stopped.

    Generated code keeps the read position in a local, so nothing else can be
    asked afterwards where a decode got to — the exception has to carry it. The
    offset is in **bytes** and absolute, and it is the first byte no record
    claims: whoever catches this marks from there.

    Attributes:
        at: Where the decode stopped, or ``None`` when it was raised by
            something that does not track a position — the cursor, which is
            asked instead.

    """

    def __init__(self, message: str = "", at: int | None = None) -> None:
        super().__init__(message)
        self.at = at


class Undecodable(Stopped):
    """A generated decoder read its input and could not make sense of it.

    A ``switch`` with no matching case and no default, a size or count that came
    off the wire negative, a ``confirm`` that did not hold, a repetition that
    consumed nothing, unit nesting past :data:`kober.decoder.MAX_DEPTH`. In
    every one of them the bytes exist and were read; what failed is the reading.

    The interpreter has no equivalent because it needs none: it records the
    verdict on a :class:`~kober.node.Node` and unwinds internally. Generated
    code has no tree to record it on, so it says so by raising, and the entry
    point of a generated module turns it into an ``undecodable`` region. Like
    :class:`EvalError`, letting one escape a decode is a bug.
    """


class Refused(Undecodable):
    """A unit's own ``confirm`` or ``reject`` refused what its fields read.

    Raised only inside a generated module, by a guarded unit's reading
    function, and caught by the wrapper around it, which names the unit's
    bytes ``undecodable`` and raises a plain :class:`Undecodable` in its place.
    A distinct type because the wrapper must tell the unit's *own* refusal from
    any other failure passing through it: only the refusal drops the unit's
    records, since a guess that did not hold up is not written as a field tree
    (``DESIGN.md`` §3.1). The conversion is what stops an enclosing guarded unit
    mistaking a nested refusal for its own.
    """


class CompileError(KoberError):
    """A valid spec cannot be expressed in the language being generated.

    Deliberately **not** a :class:`SpecError`. The spec may be perfectly valid
    and run under the interpreter; what is wrong is that two of its names
    collide in the target language, or that one of them is not an identifier
    there. Rust reserves different words than Python and mangles different
    characters, so this is a fact about a *compilation*, not about the spec —
    which is why it is raised by a backend and never by the checker.

    Silence is the alternative this exists to refuse: a decoder whose field
    quietly changed name is worse than one that would not compile.
    """


class TruncatedRead(Stopped):
    """A read ran past the end of the available bytes.

    The sibling of :class:`EvalError`, and the same kind of signal: not a
    fault in anything, just the end of what we have. In ``STREAM`` shape it is
    an ordinary outcome — the message may simply continue in a segment we do
    not hold (``DESIGN.md`` §3.2) — so the decode engine turns it into a
    ``truncated`` region and carries on. It must not escape a decode.

    Attributes:
        reach: Where the message would have ended, as an absolute byte
            offset, when the read that ran out was its last and its length was
            already decided (:func:`kober.check.message_tail_fields`); else
            ``None``. The stage driver resumes there after a gap (#49).

    """

    def __init__(self, message: str = "", at: int | None = None, reach: int | None = None) -> None:
        super().__init__(message, at)
        self.reach = reach


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
