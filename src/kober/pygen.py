"""The Python backend: a :class:`~kober.ops.Plan` rendered as Python source.

Everything Python-specific about the compiler lives here, which is the point of
the split described in :mod:`kober.ops`. Three kinds of decision are in this
file and belong nowhere else:

**Names** (the phase plan's Q4). A unit becomes a class in ``CamelCase``; a
field becomes an attribute with its spec name unchanged. A Python keyword gets a
trailing underscore. Anything else that is not already a Python identifier is a
:class:`~kober.errors.CompileError` — **never a silent rename**, because a
decoder whose field quietly changed name is worse than one that would not
compile. Two names that would land on the same identifier are the same
refusal, and this backend also reserves a namespace of its own: every
identifier beginning with an underscore, plus the handful of plain names its
generated functions use.

**Spans** (Q2). One flat ``__spans__`` tuple per object — the object's own
extent, then a pair per attribute — with the name-to-position map as a class
attribute, since it is known when the spec is compiled and a dict per object
per message is the allocation this phase exists to remove.

**Safety.** Names, enum labels and ``doc:`` strings are author-supplied text
reaching source code, which is the one place "a spec cannot run code" could be
lost by carelessness. Identifiers are validated against a whitelist and
everything else becomes an escaped literal or an escaped docstring; nothing is
interpolated. :func:`render` parses its own output before returning it, so a
generator bug becomes a refusal rather than a broken module.
"""

from __future__ import annotations

import ast
import keyword
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kober.decoder import MAX_DEPTH
from kober.errors import CompileError, SpecError
from kober.expr import (
    MAX_SHIFT,
    PRECEDENCE,
    SCOPE_WORDS,
    UNARY_PRECEDENCE,
    BinOp,
    BoolLiteral,
    BoolOp,
    Compare,
    IntLiteral,
    Ref,
    StrLiteral,
    UnaryOp,
    references,
    unparse,
)
from kober.ops import Kind, Plan, nonnegative, walk_path
from kober.runtime import TEXT_CONTENT_TYPE, prim_token
from kober.spec import Count, Emit, Fixed, FromExpr, Remaining, Terminated, ToEnd, Until

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from kober.expr import Expr
    from kober.ops import FieldPlan, ObjectPlan, ValueType
    from kober.spec import Spec

#: Longest line the backend emits, matching this project's ``ruff.toml``.
#: Generated modules are source this project ships, so they lint like it.
LINE_LENGTH = 100

#: Width prose is wrapped to — docstrings and comments. Narrower than the code
#: limit on purpose, and for the same reason this project's own docstrings are:
#: a paragraph is read, not scanned.
DOC_WIDTH = 79

#: Width the ``# --- section ---`` rules are padded to.
RULE_WIDTH = 77

#: What an identifier must look like before this backend will emit it. A
#: leading underscore is deliberately excluded: see :data:`RESERVED_PREFIX`.
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]*")

#: The namespace this backend keeps for itself — locals, helpers, and the span
#: bookkeeping. A spec name that would land in it is refused rather than
#: renamed, which is what keeps generated code free to introduce a temporary
#: without wondering whether a field is called the same thing.
RESERVED_PREFIX = "_"

#: Module-level names the backend emits itself. Includes what later stages of
#: the compiler phase emit, so a spec that compiles today does not stop
#: compiling when the decoder body lands.
RESERVED_MODULE = frozenset(
    {
        "Cursor",
        "MESSAGE_CONTENT_TYPE",
        "MappingProxyType",
        "Mapping",
        "NAME",
        "Protocol",
        "Sink",
        "Spanned",
        "shift_left",
        "shift_right",
        "TEXT_CONTENT_TYPE",
        "TYPE_CHECKING",
        "TruncatedRead",
        "VERSION",
        "ClassVar",
        "annotations",
        "dataclass",
        "decode",
        "decode_message",
        "span",
    }
)

#: Plain names the generated decode functions use. Empty — every name they
#: introduce begins with an underscore, which :data:`RESERVED_PREFIX` already
#: keeps — and kept as the place to put one if that stops being true.
RESERVED_LOCAL: frozenset[str] = frozenset()

#: Everything :mod:`kober.runtime` offers a generated module. What a given
#: module imports is whatever it turns out to use.
RUNTIME_NAMES = frozenset(
    {
        "Cursor",
        "EvalError",
        "Sink",
        "Stopped",
        "TruncatedRead",
        "Undecodable",
        "cited",
        "prim_int",
        "read_int_le",
        "shift_left",
        "shift_right",
    }
)

#: How a ``parent.x`` reference reaches its value: a parameter the caller
#: passes. The parent's fields are locals in a function that has not finished
#: running, so there is no object to ask — but the compiler knows *which* of
#: them are referenced, which is why a frame chain is not needed for this.
PARENT_PREFIX = "_parent_"

#: How a ``root.x`` reference reaches its value: the same, threaded down from
#: the entry unit through every function on the way.
ROOT_PREFIX = "_root_"

#: The local holding the element an ``until`` clause is testing. That clause
#: names the field it repeats, and means the one instance just decoded.
ELEMENT_LOCAL = "_element"

#: The local a generated decoder keeps its read position in, as a byte offset
#: into the run. Generated code owns the position rather than a cursor, which is
#: what ``DESIGN.md`` §2.1 has to be restated around: the invariant becomes a
#: property of this generator, which only emits patterns that claim what they
#: read and hands the position back when the message is done.
ANCHOR = "_at"

#: The local holding ``_base + _at``, so a byte range is an addition rather than
#: a translation. Reset wherever the anchor is.
ORIGIN = "_b"

#: The runtime helpers a shift compiles to when its count is not provably in
#: range. ``1 << n`` with ``n`` off the wire is a memory-exhaustion bug, which
#: is why the interpreter bounds it; the bound has to survive compilation.
SHIFT_HELPERS: Mapping[str, str] = {"<<": "shift_left", ">>": "shift_right"}

#: How a value's kind is spelled as a Python annotation.
ANNOTATIONS: Mapping[Kind, str] = {
    Kind.INT: "int",
    Kind.BOOL: "bool",
    Kind.TEXT: "str",
    Kind.BYTES: "bytes",
}


class Names:
    """The Python identifiers one plan compiles to.

    Resolved once, up front, so that a name is decided in exactly one place and
    a collision is refused before any source text exists. Every problem found
    is reported together: an author fixing a spec one message per run is the
    same complaint :func:`kober.check.check` collects findings to avoid.

    Args:
        plan: The plan to name.

    Raises:
        CompileError: If any name is not a Python identifier, lands in the
            namespace this backend reserves, or collides with another.

    Example:
        >>> names = Names(plan)
        >>> names.class_of("message"), names.attribute_of("message", "id")
        ('Message', 'id')

    """

    def __init__(self, plan: Plan) -> None:
        self._classes: dict[str, str] = {}
        self._constants: dict[str, str] = {}
        self._attributes: dict[tuple[str, str], str] = {}
        self._params: dict[tuple[str, str], str] = {}
        problems: list[str] = []
        module: dict[str, str] = dict.fromkeys(RESERVED_MODULE, "the generated module itself")

        for name in plan.enums:
            constant = _keyword_safe(name.upper())
            problems.extend(_bad(f"enum {name!r}", constant))
            problems.extend(_taken(f"enum {name!r}", constant, module, f"enum {name!r}"))
            self._constants[name] = constant

        for obj in plan.objects:
            cls = _keyword_safe(_camel(obj.unit))
            problems.extend(_bad(f"unit {obj.unit!r}", cls))
            problems.extend(_taken(f"unit {obj.unit!r}", cls, module, f"unit {obj.unit!r}"))
            self._classes[obj.unit] = cls

        for obj in plan.objects:
            # Parameters and fields share one namespace: both are locals of the
            # function that decodes the unit, so a name used twice is a clash
            # even though only one of them becomes an attribute.
            taken: dict[str, str] = {}
            for param in obj.params:
                where = f"parameter {param.name!r} of unit {obj.unit!r}"
                local = _keyword_safe(param.name)
                problems.extend(_bad(where, local))
                problems.extend(_shadowed(where, local))
                problems.extend(_taken(where, local, taken, where))
                self._params[obj.unit, param.name] = local
            for item in obj.fields:
                if item.name is None:
                    continue
                where = f"field {item.name!r} of unit {obj.unit!r}"
                attribute = _keyword_safe(item.name)
                problems.extend(_bad(where, attribute))
                problems.extend(_shadowed(where, attribute))
                problems.extend(_taken(where, attribute, taken, where))
                self._attributes[obj.unit, item.name] = attribute

        if problems:
            listed = "\n  ".join(problems)
            msg = (
                f"spec {plan.name!r} cannot be compiled to Python: "
                f"{len(problems)} naming problem(s):\n  {listed}"
            )
            raise CompileError(msg)

    def class_of(self, unit: str) -> str:
        """Return the class name a unit compiles to.

        Args:
            unit: The unit's name as the spec spells it.

        Returns:
            The class name.

        """
        return self._classes[unit]

    def attribute_of(self, unit: str, field: str) -> str:
        """Return the attribute name one of a unit's fields compiles to.

        Args:
            unit: The unit's name as the spec spells it.
            field: The field's name as the spec spells it.

        Returns:
            The attribute name.

        """
        return self._attributes[unit, field]

    def param_of(self, unit: str, param: str) -> str:
        """Return the local one of a unit's parameters compiles to.

        Args:
            unit: The unit's name as the spec spells it.
            param: The parameter's name as the spec spells it.

        Returns:
            The local's name.

        """
        return self._params[unit, param]

    def function_of(self, unit: str) -> str:
        """Return the name of the function that decodes a unit.

        Derived from the class name, so two units that would collide here have
        already been refused for colliding there. It begins with an underscore
        because the whole namespace does: a generated module's decode functions
        are its own business, and a consumer calls its ``decode``.

        Args:
            unit: The unit's name as the spec spells it.

        Returns:
            The function's name.

        """
        return f"_decode_{self.class_of(unit).lower()}"

    def constant_of(self, enum: str) -> str:
        """Return the module constant an enum's labels compile to.

        Args:
            enum: The enum's name as the spec spells it.

        Returns:
            The constant name.

        """
        return self._constants[enum]


def _camel(name: str) -> str:
    """Turn a spec name into a class name: ``header_v4`` becomes ``HeaderV4``."""
    return "".join(part[:1].upper() + part[1:] for part in name.split("_") if part)


def _keyword_safe(name: str) -> str:
    """Append an underscore to a Python keyword, and leave everything else alone.

    Soft keywords — ``match``, ``case``, ``type``, ``_`` — are left as they are,
    because Python still accepts them as identifiers. A target that does not
    would map them here instead, which is the reason this decision is in the
    backend.
    """
    return f"{name}_" if keyword.iskeyword(name) else name


def _bad(where: str, name: str) -> list[str]:
    """Report a name this backend will not emit, rather than mangling it."""
    stem = name.removesuffix("_")
    if not stem:
        return [f"{where} has no name left once mapped to Python; rename it in the spec"]
    if stem.startswith(RESERVED_PREFIX):
        return [
            f"{where} becomes {name!r}, and the Python backend reserves every name "
            f"beginning with {RESERVED_PREFIX!r} for its own locals; rename it in the spec"
        ]
    if IDENTIFIER.fullmatch(stem) is None:
        return [
            f"{where} becomes {name!r}, which is not a Python identifier; rename it in "
            f"the spec — the backend will not rename it silently"
        ]
    return []


def _shadowed(where: str, name: str) -> list[str]:
    """Report a name that would shadow one the generated functions already use."""
    if name not in RESERVED_LOCAL:
        return []
    return [
        f"{where} becomes the local {name!r}, which every generated decode function "
        f"already takes as a parameter; rename it in the spec"
    ]


def _taken(where: str, name: str, seen: dict[str, str], claim: str) -> list[str]:
    """Report a collision, naming both sides, and record the claim either way."""
    owner = seen.get(name)
    seen.setdefault(name, claim)
    if owner is None or owner == claim:
        return []
    return [
        f"{where} becomes {name!r}, which is already {owner}; two names cannot share "
        f"one identifier, so rename one of them in the spec"
    ]


# --- literals and text -----------------------------------------------------


def _literal(value: object) -> str:
    """Render an author-supplied constant as a Python literal.

    Always through :func:`repr`, never by interpolation: this is the boundary a
    spec's data crosses into source text. Text prefers double quotes, which is
    only a matter of matching the code around it — :func:`repr` has already
    made it safe by then.
    """
    rendered = repr(value)
    if isinstance(value, str) and rendered.startswith("'") and '"' not in value:
        return f'"{rendered[1:-1]}"'
    return rendered


def _safe(text: str) -> str:
    """Make author-supplied text safe to place inside a triple-quoted docstring.

    Escapes backslashes, neutralizes any run of quotes that could close the
    docstring, and drops control characters other than newline and tab. What is
    left is text — a docstring cannot execute, and the only way it could reach
    code is by escaping its own quoting, which is what this prevents.
    """
    text = "".join(ch for ch in text if ch >= " " or ch in "\n\t")
    text = text.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    stripped = text.rstrip('"')
    return stripped + '\\"' * (len(text) - len(stripped))


def _wrap(text: str, indent: int, *, hang: int = 0, width: int = DOC_WIDTH) -> list[str]:
    """Wrap one paragraph to ``width``, hanging continuation lines by ``hang``."""
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    pad = " " * indent
    current = pad + words[0]
    for word in words[1:]:
        if len(current) + 1 + len(word) <= width:
            current = f"{current} {word}"
            continue
        lines.append(current)
        pad = " " * (indent + hang)
        current = pad + word
    lines.append(current)
    return lines


def _paragraphs(text: str) -> list[str]:
    """Split author text into paragraphs, collapsing the whitespace inside each."""
    blocks = re.split(r"\n\s*\n", _safe(text).strip())
    return [" ".join(block.split()) for block in blocks if block.strip()]


def _comment(text: str, marker: str = "#", indent: int = 0) -> list[str]:
    """Wrap a paragraph as a comment, marking every line rather than the first.

    Sphinx reads a ``#:`` block as documentation only while each of its lines
    carries the marker, so a continuation that lost it would silently stop being
    documentation — and in generated *code* a continuation without the marker is
    not a comment at all, which the parse check at the end of :func:`render`
    catches as the syntax error it is.
    """
    width = DOC_WIDTH - len(marker) - 1 - indent
    pad = " " * indent
    return [f"{pad}{marker} {line}".rstrip() for line in _wrap(text, 0, width=width)]


def _rule(title: str) -> str:
    """Render a ``# --- title ---`` section rule."""
    return f"# --- {title} ".ljust(RULE_WIDTH, "-")


def _call(head: str, arguments: Sequence[str], indent: int) -> list[str]:
    """Render a call, widening it only as far as the line length forces.

    One line if it fits, then all the arguments on one continued line, then one
    argument per line. Generated code is read, and a call broken across six lines
    when it would fit on two is harder to read than the protocol it decodes.
    """
    pad = " " * indent
    joined = ", ".join(arguments)
    if len(pad) + len(head) + len(joined) + 2 <= LINE_LENGTH:
        return [f"{pad}{head}({joined})"]
    if len(pad) + 4 + len(joined) <= LINE_LENGTH:
        return [f"{pad}{head}(", f"{pad}    {joined}", f"{pad})"]
    return [f"{pad}{head}(", *(f"{pad}    {argument}," for argument in arguments), f"{pad})"]


def _dict_call(prefix: str, entries: Sequence[str], indent: int) -> list[str]:
    """Render ``prefix(...)`` around a dict literal, widening only as needed."""
    pad = " " * indent
    inline = "{" + ", ".join(entries) + "}"
    if len(pad) + len(prefix) + len(inline) + 2 <= LINE_LENGTH:
        return [f"{pad}{prefix}({inline})"]
    if len(pad) + 4 + len(inline) <= LINE_LENGTH:
        return [f"{pad}{prefix}(", f"{pad}    {inline}", f"{pad})"]
    lines = [f"{pad}{prefix}(", f"{pad}    {{"]
    lines.extend(f"{pad}        {entry}," for entry in entries)
    lines.extend([f"{pad}    }}", f"{pad})"])
    return lines


# --- expressions -----------------------------------------------------------


@dataclass(frozen=True)
class Binding:
    """Where the values an expression names live, in the function being generated.

    Scope binding is the new work in rendering an expression, and it is all
    here. A spec says ``qdcount``, ``this.qdcount``, ``parent.qdcount`` or
    ``root.id``; Python has to say which local or attribute that is, and the
    answer depends on the function the expression is being rendered into.

    The rules, in one place:

    - A **field of this unit** is a local, named as the field is. It has been
      decoded already — the checker's ordering rule guarantees that — so there
      is a variable holding it.
    - A **parameter** is a local too, for the same reason: it is an argument of
      the function.
    - A **dotted path** is attribute access on whatever the first name reached,
      with every hop mapped by :class:`Names`.
    - ``parent.x`` and ``root.x`` are **parameters the caller passes**, named
      with :data:`PARENT_PREFIX` and :data:`ROOT_PREFIX`. The parent's fields
      are locals in a function that is still running, so there is nothing to
      ask; but the compiler knows which of them are referenced, so it can pass
      exactly those and skip the frame chain the interpreter needs.
    - ``root.x`` **inside the entry unit** is that unit's own local, since there
      is nothing above it to thread a value down from.
    - Inside an ``until`` clause, the repeated field's own name means **the
      element just decoded**, not the list so far, and resolves to
      :attr:`element`.

    Attributes:
        plan: The plan being compiled.
        names: Its resolved identifiers.
        unit: The unit whose decode function is being generated.
        parent: The unit that referenced it, when ``parent`` may appear. Left
            ``None`` where nothing does, so a stray ``parent`` is refused
            rather than rendered against a guess.
        element_of: Name of the field an enclosing ``until`` repeats, if any.
        element: The local holding that element.
        index: Position of the field the expression belongs to, when the caller
            knows it. What lets a ``root`` reference into the entry unit be
            refused at compile time if the field it names has not been decoded
            by then — the one ordering rule :func:`kober.check.check`
            deliberately does not enforce, because it cannot know the depth an
            expression runs at and a compiler does.

    """

    plan: Plan
    names: Names
    unit: str
    parent: str | None = None
    element_of: str | None = None
    element: str = ELEMENT_LOCAL
    index: int | None = None

    def render(self, path: Sequence[str]) -> str:
        """Render one reference as a Python expression.

        Args:
            path: The reference's components, scope word included.

        Returns:
            Python source for the value it names.

        Raises:
            CompileError: If the path names ``parent`` where nothing is bound,
                or does not resolve at all.

        """
        parts = tuple(path)
        word = parts[0] if parts and parts[0] in SCOPE_WORDS else None
        rest = parts[1:] if word else parts
        start, prefix = self._start(word, parts)
        try:
            steps = walk_path(self.plan, start, rest)
        except SpecError as exc:
            msg = f"cannot compile the reference {'.'.join(parts)!r} in unit {self.unit!r}: {exc}"
            raise CompileError(msg) from exc
        head, *tail = steps
        if head.param:
            local = self.names.param_of(head.unit, head.name)
        else:
            local = self.names.attribute_of(head.unit, head.name)
        if word in (None, "this") and head.name == self.element_of:
            local = self.element
        else:
            local = prefix + local
        return local + "".join(
            f".{self.names.attribute_of(step.unit, step.name)}" for step in tail
        )

    def _start(self, word: str | None, path: Sequence[str]) -> tuple[str, str]:
        """Return the unit a path resolves in, and the prefix its local carries."""
        if word == "parent":
            if self.parent is None:
                msg = (
                    f"the reference {'.'.join(path)!r} names 'parent', but nothing "
                    f"references unit {self.unit!r} at the point being compiled"
                )
                raise CompileError(msg)
            return self.parent, PARENT_PREFIX
        if word == "root":
            if self.unit == self.plan.entry:
                self._require_decoded(path)
                return self.unit, ""
            return self.plan.entry, ROOT_PREFIX
        return self.unit, ""

    def _require_decoded(self, path: Sequence[str]) -> None:
        """Refuse a ``root`` reference to a field of the entry unit not read yet.

        ``root`` has no ordering rule in the checker, on the grounds that how
        much of the entry unit has been decoded at an arbitrary depth is not
        knowable statically. Inside the entry unit itself it is knowable, and a
        value that is not there yet has no local to read — so this is a
        compile-time refusal where the interpreter has a decode-time surprise.
        """
        if self.index is None or len(path) < 2:
            return
        obj = self.plan.object(self.plan.entry)
        named = [item.name for item in obj.fields]
        if path[1] in named and named.index(path[1]) >= self.index:
            msg = (
                f"the reference {'.'.join(path)!r} names a field of the entry unit "
                f"{self.plan.entry!r} that is decoded later than the field reading it; "
                f"nothing holds its value yet"
            )
            raise CompileError(msg)


def render_expr(expr: Expr, binding: Binding) -> str:
    """Render an expression as Python source, meaning what the interpreter means.

    Three differences from Python's reading of the same text, and each one is
    handled rather than hoped about:

    - ``/`` is **integer division** in a spec, so it becomes ``//``. Both
      floor, and both agree with the interpreter on a negative operand.
    - ``and`` and ``or`` **short-circuit**, which Python's do identically. That
      matters more than it looks: a spec guards a division with
      ``n != 0 and total / n > 1``, and evaluating the right side anyway would
      turn a valid expression into a failure.
    - A **shift count** off the wire is bounded. ``1 << n`` with a wire value
      for ``n`` exhausts memory, which is why the interpreter refuses counts
      above :data:`kober.expr.MAX_SHIFT`; a count this backend cannot see to be
      in range becomes a call to a runtime helper that keeps the bound.

    What is *not* here is the interpreter's type checking. ``_as_int`` and
    ``_as_bool`` exist because it discovers types at decode time; the checker
    has already proved them, so the compiled form skips them. Division by zero
    is the one failure that survives compilation, and it survives as
    ``ZeroDivisionError`` for the entry point to turn into an ``undecodable``
    region — the same outcome by a shorter road.

    Args:
        expr: The expression to render.
        binding: Where the values it names live.

    Returns:
        Python source for the expression, parenthesized only where the grouping
        needs it.

    Raises:
        CompileError: If one of its references cannot be reached.

    Example:
        >>> render_expr(parse("total / n"), binding)
        'total // n'

    """
    return _expr(expr, binding, 0)


def _expr(expr: Expr, binding: Binding, limit: int) -> str:
    """Render one node, parenthesized if it binds looser than ``limit``."""
    if isinstance(expr, IntLiteral):
        return str(expr.value)
    if isinstance(expr, StrLiteral):
        return _literal(expr.value)
    if isinstance(expr, BoolLiteral):
        return "True" if expr.value else "False"
    if isinstance(expr, Ref):
        return binding.render(expr.path)
    if isinstance(expr, UnaryOp):
        level = PRECEDENCE["not"] if expr.op == "not" else UNARY_PRECEDENCE
        space = " " if expr.op == "not" else ""
        return _group(f"{expr.op}{space}{_expr(expr.operand, binding, level)}", level, limit)
    if isinstance(expr, BoolOp):
        level = PRECEDENCE[expr.op]
        joined = f" {expr.op} ".join(_expr(operand, binding, level) for operand in expr.operands)
        return _group(joined, level, limit)
    if isinstance(expr, Compare):
        level = PRECEDENCE[expr.op]
        left = _expr(expr.left, binding, level + 1)
        right = _expr(expr.right, binding, level + 1)
        return _group(f"{left} {expr.op} {right}", level, limit)
    return _binary(expr, binding, limit)


def _binary(expr: BinOp, binding: Binding, limit: int) -> str:
    """Render an arithmetic or bitwise operator, guarding a shift if it needs it."""
    if expr.op in SHIFT_HELPERS and not _safe_shift(expr.right):
        left = _expr(expr.left, binding, 0)
        right = _expr(expr.right, binding, 0)
        return f"{SHIFT_HELPERS[expr.op]}({left}, {right})"
    op = "//" if expr.op == "/" else expr.op
    level = PRECEDENCE[expr.op]
    left = _expr(expr.left, binding, level)
    right = _expr(expr.right, binding, level + 1)
    return _group(f"{left} {op} {right}", level, limit)


def _safe_shift(count: Expr) -> bool:
    """Whether a shift count is a literal the runtime's bound already allows."""
    return isinstance(count, IntLiteral) and 0 <= count.value <= MAX_SHIFT


def _group(text: str, level: int, limit: int) -> str:
    """Parenthesize only what the grouping needs."""
    return f"({text})" if level < limit else text


# --- emission --------------------------------------------------------------


def granularity(plan: Plan, default: Emit) -> Mapping[str, Emit]:
    """Return the granularity in force inside each unit.

    ``plan()`` resolves this per node while it walks a finished tree: a field's
    own ``emit`` wins, then its unit's, then whatever encloses it, then the
    decoder's. A compiler resolves it once, which is the same rule read from the
    other end — and it can, because what a unit inherits is decided by the sites
    that reference it.

    Args:
        plan: The plan being compiled.
        default: The granularity the decoder was asked for.

    Returns:
        The default in force inside each unit, by unit name.

    Raises:
        CompileError: If a unit is reached with two different granularities. The
            interpreter handles that by resolving per node; a compiler would
            have to emit the unit's decoder twice, which is worth doing only
            once a real spec asks for it. Refusing says so rather than silently
            picking one.

    """
    inside: dict[str, Emit] = {plan.entry: default}
    pending = [plan.entry]
    while pending:
        unit = pending.pop()
        for item in plan.object(unit).fields:
            for value in item.types:
                if value.kind is not Kind.OBJECT or value.unit is None:
                    continue
                target = plan.object(value.unit)
                wanted = item.emit or target.emit or inside[unit]
                if value.unit in inside and inside[value.unit] is not wanted:
                    msg = (
                        f"unit {value.unit!r} is reached at {inside[value.unit].value} "
                        f"granularity and at {wanted.value} granularity; compiling it "
                        f"twice is not supported, so give it one ``emit`` setting"
                    )
                    raise CompileError(msg)
                if value.unit not in inside:
                    inside[value.unit] = wanted
                    pending.append(value.unit)
    return inside


def content_type_of(plan: Plan, value: ValueType) -> str:
    """Return the content type a value's record is labelled with.

    Baked, which is most of why direct emission is cheap: the ``prim:`` token of
    a declared integer is known from its width, and a text field's label is the
    same string every time. Only a ``computed:`` integer is decided at decode
    time — nothing declares its width — and that one goes through
    :func:`kober.runtime.prim_int`.
    """
    if value.kind is Kind.TEXT:
        return TEXT_CONTENT_TYPE
    if value.kind is Kind.BYTES:
        return "prim:bytes"
    if value.kind is Kind.BOOL:
        return "prim:u8"
    if value.bits is None:  # pragma: no cover - reached through prim_int instead
        msg = "a computed integer has no content type until it has a value"
        raise CompileError(msg)
    return f"prim:{prim_token(value.bits, value.signed)}"


def payload_of(value: ValueType, local: str) -> str:
    """Return the expression that builds one record's payload.

    ``prim:`` is little-endian by definition, so a big-endian wire value is
    re-encoded — which is honest, because a decode stage's records are *created*
    rather than copied, and the number is what the record is about.
    """
    if value.kind is Kind.TEXT:
        return f'{local}.encode("utf-8", errors="replace")'
    if value.kind is Kind.BYTES:
        return local
    if value.kind is Kind.BOOL:
        return f"bytes([int({local})])"
    width = int(prim_token(value.bits or 8, value.signed)[1:]) // 8
    signed = ", signed=True" if value.signed else ""
    return f'{local}.to_bytes({width}, "little"{signed})'


# --- the decoder -----------------------------------------------------------


def _outer_annotation(plan: Plan, names: Names, unit: str, name: str) -> str:
    """Render the type of an outer value a unit is handed.

    Typed like everything else: the value is a field or a parameter of another
    unit, and that unit's plan says what it holds.
    """
    obj = plan.object(unit)
    param = obj.param(name)
    if param is not None:
        return ANNOTATIONS[param.kind]
    item = obj.field(name)
    if item is None:  # pragma: no cover - the checker resolved it already
        return "object"
    return _value_annotation(item.types, names)


class _Function:
    """Renders the function that decodes one unit.

    What the interpreter works out at decode time is decided here instead:
    which locals exist, which guards are needed, what each read is. It is a
    class because that is a lot of small state — the lines so far, and the value
    and span locals in attribute order — and threading it through free functions
    would read worse than holding it.
    """

    def __init__(
        self, plan: Plan, names: Names, obj: ObjectPlan, inside: Emit, module: Emit
    ) -> None:
        self.plan = plan
        self.names = names
        self.obj = obj
        #: The granularity in force inside this unit.
        self.inside = inside
        #: The granularity the module was compiled for. Only ``FIELD`` puts
        #: records inside a unit at all, which is why it decides whether these
        #: functions carry a sink and a path.
        self.module = module
        self.lines: list[str] = []
        self.values: list[str] = []
        self.spans: list[str] = []
        #: Bits read since :data:`ANCHOR` was last set. **The compiler tracks
        #: this so the generated code does not have to**: every read, every
        #: bounds check and every byte range below is the anchor plus a number
        #: known now, which is worth about five times the arithmetic a running
        #: position costs. It resets wherever the position stops being knowable
        #: — a length off the wire, a nested unit, a loop.
        self.delta = 0
        #: Which field is being rendered, for the expressions inside it.
        self.index_of = 0

    # --- where the reads are ------------------------------------------------

    def byte(self, bits: int = 0) -> str:
        """Return the index of the byte holding the position ``bits`` further on."""
        offset = (self.delta + bits) // 8
        return ANCHOR if offset == 0 else f"{ANCHOR} + {offset}"

    def index(self, bits: int) -> str:
        """Return the byte index just past a read of ``bits`` from here."""
        offset = -(-(self.delta + bits) // 8)
        return ANCHOR if offset == 0 else f"{ANCHOR} + {offset}"

    def start(self) -> str:
        """Return the byte range's start at the current position."""
        offset = self.delta // 8
        return ORIGIN if offset == 0 else f"{ORIGIN} + {offset}"

    def end(self, bits: int = 0) -> str:
        """Return the byte range's end after reading ``bits`` more.

        Rounded **up**, which is §1's rule: a field that ends part-way through a
        byte cites the whole byte, because `zpf` spans are byte offsets.
        """
        offset = -(-(self.delta + bits) // 8)
        return ORIGIN if offset == 0 else f"{ORIGIN} + {offset}"

    def stopped(self) -> str:
        """Return where a failure at the current position stopped, in bytes.

        Rounded up for the same reason :func:`_stopped_at` rounds up in the
        generated module: the bits before it were read by a field that cited the
        whole byte.
        """
        offset = -(-self.delta // 8)
        return ANCHOR if offset == 0 else f"{ANCHOR} + {offset}"

    def need(self, bits: int, indent: int) -> None:
        """Emit the bounds check for reading ``bits`` from the current position.

        One per field, never merged. A merged check would report the failure at
        the start of the run rather than at the field that ran out, and the
        interpreter stops at the field — so a merged check would be a different
        answer about which bytes were decoded.
        """
        needed = -(-(self.delta + bits) // 8)
        pad = " " * indent
        self.emit(f"{pad}if _size - {ANCHOR} < {needed}:")
        self.emit(f'{pad}    raise TruncatedRead("truncated", {self.stopped()})')

    def advance(self, bits: int) -> None:
        """Note that ``bits`` more have been read, without emitting anything."""
        self.delta += bits

    def rebase(self, expr: str, indent: int) -> None:
        """Move the anchor to a position only the running decode knows."""
        pad = " " * indent
        if expr != ANCHOR:
            self.emit(f"{pad}{ANCHOR} = {expr}")
        self.emit(f"{pad}{ORIGIN} = _base + {ANCHOR}")
        self.delta = 0

    def settle(self, indent: int) -> None:
        """Fold what is known into the anchor, for code that must agree on it.

        A loop, a branch and a nested call all leave the position somewhere only
        the running decode knows, so the compiler's arithmetic has to be paid in
        before any of them and started again afterwards.
        """
        self.aligned("this position")
        if self.delta:
            self.rebase(f"{ANCHOR} + {self.delta // 8}", indent)
        else:
            self.delta = 0

    def aligned(self, where: str) -> None:
        """Refuse to read whole bytes from part-way through one."""
        if self.delta % 8 == 0:
            return
        msg = (
            f"unit {self.obj.unit!r} reaches {where} {self.delta % 8} bit(s) into a byte; "
            f"the Python backend reads whole bytes there, so the bitfields before it have "
            f"to add up to a whole number of them"
        )
        raise CompileError(msg)

    @property
    def threads(self) -> bool:
        """Whether this function carries a sink and a field path."""
        return self.module is Emit.FIELD

    def emits(self, item: FieldPlan) -> bool:
        """Whether one field's leaves write records."""
        return self.threads and (item.emit or self.inside) is not Emit.NONE

    def skips(self, item: FieldPlan) -> bool:
        """Whether one field's bytes are named ``skipped`` instead of cited.

        ``emit: none`` means the field was decoded for control flow only. The
        bytes were deliberately passed over, which is exactly what ``skipped``
        says — and §2 wants it said rather than left to be auto-filled.
        """
        return self.threads and (item.emit or self.inside) is Emit.NONE

    # --- the whole function ------------------------------------------------

    def render(self) -> str:
        """Return the function's source."""
        self.lines = []
        self.delta = 0
        for index, item in enumerate(self.obj.fields):
            self.field(index, item)
        head = [*self.definition(), *self.docstring()]
        if self.plan.recursive:
            head.extend(self.depth_guard())
        head.extend([f"    {ORIGIN} = _base + {ANCHOR}", f"    _extent = {ORIGIN}"])
        tail = ["", *self.guards(), f"    _s, _e = _extent, {self.end()}", *self.construct()]
        return "\n".join([*head, *self.lines, *tail])

    def definition(self) -> list[str]:
        """Return the ``def`` line, wrapped if its parameters do not fit."""
        name = self.names.function_of(self.obj.unit)
        parameters = self.parameters()
        returns = f"tuple[{self.cls}, int]"
        one = f"def {name}({', '.join(parameters)}) -> {returns}:"
        if len(one) <= LINE_LENGTH:
            return [one]
        return [
            f"def {name}(",
            *(f"    {parameter}," for parameter in parameters),
            f") -> {returns}:",
        ]

    def parameters(self) -> list[str]:
        """Return the parameters this unit's decode function takes.

        Every one of them is something the compiler worked out that this unit
        needs: its own declared parameters, the outer values its expressions
        name, and a depth counter only where recursion can grow one.
        """
        parameters = ["_data: bytes", "_size: int", f"{ANCHOR}: int", "_base: int"]
        if self.threads:
            parameters.extend(["_sink: Sink | None", "_path: str"])
        parameters.extend(
            f"{self.names.param_of(self.obj.unit, param.name)}: {ANNOTATIONS[param.kind]}"
            for param in self.obj.params
        )
        parent = self.obj.parents[0] if self.obj.parents else self.obj.unit
        parameters.extend(
            f"{PARENT_PREFIX}{name}: {_outer_annotation(self.plan, self.names, parent, name)}"
            for name in self.obj.needs_parent
        )
        # The entry unit takes none: `root` is itself, so those values are its
        # own locals. What its plan lists is what it has to *pass down*.
        parameters.extend(
            f"{ROOT_PREFIX}{name}: "
            f"{_outer_annotation(self.plan, self.names, self.plan.entry, name)}"
            for name in self.threaded()
        )
        if self.plan.recursive:
            parameters.append("_depth: int")
        return parameters

    def threaded(self) -> tuple[str, ...]:
        """Return the ``root`` values this unit is handed rather than holding."""
        if self.obj.unit == self.plan.entry:
            return ()
        return self.obj.needs_root

    @property
    def cls(self) -> str:
        """The class this function returns."""
        return self.names.class_of(self.obj.unit)

    def docstring(self) -> list[str]:
        """Return the function's docstring."""
        lines = [
            f'    """Decode one ``{_safe(self.obj.unit)}``.',
            "",
            "    Args:",
            "        _data: The run being decoded.",
            "        _size: Its length, passed rather than measured again here.",
            f"        {ANCHOR}: Where in it to start, as a byte offset.",
            "        _base: Stream offset of ``_data[0]``, so byte ranges are absolute.",
        ]
        if self.threads:
            lines.extend(
                [
                    "        _sink: Where records go, or ``None`` to decode without",
                    "            emitting anything.",
                    "        _path: This instance's field path, which its records carry.",
                ]
            )
        for param in self.obj.params:
            local = self.names.param_of(self.obj.unit, param.name)
            lines.extend(
                _wrap(f"{local}: The ``{_safe(param.name)}`` its caller supplies.", 8, hang=4)
            )
        for name in self.obj.needs_parent:
            lines.extend(
                _wrap(
                    f"{PARENT_PREFIX}{name}: The caller's ``{_safe(name)}``, which this unit "
                    f"names as ``parent.{_safe(name)}``.",
                    8,
                    hang=4,
                )
            )
        for name in self.threaded():
            lines.extend(
                _wrap(
                    f"{ROOT_PREFIX}{name}: The entry unit's ``{_safe(name)}``, threaded down "
                    f"for ``root.{_safe(name)}``.",
                    8,
                    hang=4,
                )
            )
        if self.plan.recursive:
            lines.extend(
                _wrap("_depth: How many units deep this decode already is.", 8, hang=4)
            )
        lines.extend(
            [
                "",
                "    Returns:",
                f"        The decoded ``{_safe(self.obj.unit)}``, and the byte offset",
                "        after it.",
                "",
            ]
        )
        raises = self.raises()
        if raises:
            lines.extend(["    Raises:", *raises, ""])
        lines.append('    """')
        return lines

    def raises(self) -> list[str]:
        """Return the Raises entries this unit can actually produce."""
        lines: list[str] = []
        if any(self.reads(item) for item in self.obj.fields):
            lines.extend(_wrap("TruncatedRead: If the input ends inside it.", 8, hang=4))
        if self.can_refuse():
            lines.extend(
                _wrap("Undecodable: If the input is not what this unit describes.", 8, hang=4)
            )
        return lines

    def reads(self, item: FieldPlan) -> bool:
        """Whether a field reads bytes at all, rather than being computed."""
        return any(value.expr is None for value in item.types)

    def can_refuse(self) -> bool:
        """Whether anything in this unit can decide the input is not decodable."""
        if self.obj.confirm is not None or self.obj.reject is not None:
            return True
        if self.plan.recursive:
            return True
        return any(
            not item.exhaustive
            or (item.repeat is not None and not item.consumes)
            or (isinstance(item.repeat, Count) and not self.provable(item.repeat.expr))
            or any(
                isinstance(value.size, FromExpr) and not self.provable(value.size.expr)
                for value in item.types
            )
            for item in self.obj.fields
        )

    def evaluate(self, expr: Expr, indent: int, element_of: str | None = None) -> str:
        """Render an expression, catching the two ways one can fail for this input.

        Division by zero and a shift count off the wire are the only failures a
        total, side-effect-free language still has, and so the only ones a
        compiled expression can raise. Where an expression contains neither this
        is exactly :func:`render_expr` and costs nothing; where it can, the value
        is taken in a ``try`` so the failure can say **where** it happened.
        Nothing else can — the position is a local in this function.
        """
        pad = " " * indent
        rendered = render_expr(expr, self.binding(self.index_of, element_of=element_of))
        if not _fallible(rendered):
            return rendered
        self.emit(f"{pad}try:")
        self.emit(f"{pad}    _value = {rendered}")
        self.emit(f"{pad}except (EvalError, ZeroDivisionError) as _exc:")
        self.emit(f"{pad}    raise Undecodable(str(_exc), {self.stopped()}) from _exc")
        return "_value"

    def provable(self, expr: Expr) -> bool:
        """Whether a count or size is provably not negative."""
        return nonnegative(self.plan, self.obj.unit, expr)

    def depth_guard(self) -> list[str]:
        """Return the depth check, for a plan where recursion can grow one."""
        return [
            f"    if _depth > {MAX_DEPTH}:",
            *_wrap(
                f'raise Undecodable("unit nesting passed {MAX_DEPTH} levels", {ANCHOR})',
                8,
                hang=4,
            ),
            "",
        ]

    def guards(self) -> list[str]:
        """Return ``confirm`` and ``reject``, applied once the fields are read.

        §3.1: a guess that did not hold up becomes an honest ``undecodable``
        region rather than a fabricated field tree.
        """
        lines: list[str] = []
        binding = self.binding(len(self.obj.fields))
        unit = _literal(self.obj.unit)
        where = self.stopped()
        if self.obj.confirm is not None:
            lines.append(f"    if not ({render_expr(self.obj.confirm, binding)}):")
            lines.append(
                f'        raise Undecodable(f"unit {{{unit}}} did not confirm", {where})'
            )
        if self.obj.reject is not None:
            lines.append(f"    if {render_expr(self.obj.reject, binding)}:")
            lines.append(
                f'        raise Undecodable(f"unit {{{unit}}} rejected the input", {where})'
            )
        if lines:
            lines.append("")
        return lines

    def construct(self) -> list[str]:
        """Return the statement that builds the decoded object."""
        self.aligned("its end")
        after = self.byte()
        spans = ["_s", "_e", *self.spans]
        arguments = [*self.values, "(" + ", ".join(spans) + ")"]
        one = f"    return {self.cls}({', '.join(arguments)}), {after}"
        if len(one) <= LINE_LENGTH:
            return [one]
        lines = [f"    return {self.cls}("]
        lines.extend(f"        {value}," for value in self.values)
        inline = "        (" + ", ".join(spans) + "),"
        if len(inline) <= LINE_LENGTH:
            lines.append(inline)
        else:
            lines.append("        (")
            lines.extend(f"            {name}," for name in spans)
            lines.append("        ),")
        lines.append(f"    ), {after}")
        return lines

    # --- one field ---------------------------------------------------------

    def binding(self, index: int, element_of: str | None = None) -> Binding:
        """Return the binding for an expression at one field's position."""
        return Binding(
            self.plan,
            self.names,
            self.obj.unit,
            parent=self.obj.parents[0] if self.obj.parents else None,
            element_of=element_of,
            index=index,
        )

    def local_of(self, item: FieldPlan, index: int) -> str | None:
        """Return the local a field's value lives in, or ``None`` if nothing needs it.

        An anonymous field has no attribute and no expression may name it, so
        nothing holds its value — unless it is emitted, because a record still
        has to carry what was read. Its path segment is ``_``, which is the only
        name it ever gets.
        """
        if item.name is not None:
            return self.names.attribute_of(self.obj.unit, item.name)
        if self.emits(item) or self.skips(item):
            return f"_anon{index}"
        return None

    def field(self, index: int, item: FieldPlan) -> None:
        """Emit one field: its read, and whatever it has to say about its bytes."""
        target = self.local_of(item, index)
        if target is not None and item.name is not None:
            self.values.append(target)
            self.spans.extend([f"_s_{target}", f"_e_{target}"])
        self.emit("")
        if item.condition is None:
            self.present(index, item, target, 4)
            return
        # Both branches have to leave the position somewhere the code after them
        # agrees on, so what the compiler knows is paid in before the branch.
        self.settle(4)
        self.index_of = index
        condition = self.evaluate(item.condition, 4)
        self.emit(f"    if {condition}:")
        self.present(index, item, target, 8)
        self.settle(8)
        if target is not None and item.name is not None:
            self.emit("    else:")
            self.emit("        # Absent, not empty: it read nothing, so it cites nothing.")
            self.emit(f"        {target} = None")
            self.emit(f"        _s_{target} = _e_{target} = {ORIGIN}")
        elif target is None:
            self.emit("    else:")
            self.emit("        pass")

    def segment(self, item: FieldPlan, index: int) -> str:
        """Return the path segment one field adds, as a Python expression."""
        name = "_" if item.name is None else self.names.attribute_of(self.obj.unit, item.name)
        return f"_path + {_literal('.' + name)}"

    def account(
        self,
        index: int,
        item: FieldPlan,
        target: str,
        comment: str,
        start: str,
        end: str,
        indent: int,
    ) -> None:
        """Emit what one leaf says about the bytes it read."""
        pad = " " * indent
        if self.skips(item):
            self.emit(f"{pad}if _sink is not None and {end} > {start}:")
            self.emit(f'{pad}    _sink.undecoded({start}, {end}, "skipped")')
            return
        if not self.emits(item):
            return
        self.emit(f"{pad}if _sink is not None:")
        if item.selector is None:
            self.record(index, item.types[0], target, comment, start, end, indent + 4)
            return
        # A switch decides which type the payload is, so the record does too. The
        # selector is still in hand, which is cheaper than asking the value.
        keyword = "if"
        for branch in item.branches:
            if branch.type.kind is Kind.OBJECT:
                continue
            test = (
                "else" if branch.case is None else f"{keyword} _selector == {_literal(branch.case)}"
            )
            self.emit(f"{pad}    {test}:")
            self.record(index, branch.type, target, comment, start, end, indent + 8)
            keyword = "elif"

    def record(
        self,
        index: int,
        value: ValueType,
        local: str,
        comment: str,
        start: str,
        end: str,
        indent: int,
    ) -> None:
        """Emit one ``sink.record`` call, with everything known baked into it."""
        pad = " " * indent
        if value.expr is not None:
            start, end = self.cites(index, value, start, end, indent)
        if value.kind is Kind.INT and value.bits is None:
            # The one payload a compiler cannot bake: nothing declares the width
            # of a computed integer, so it is sized by its value — and a value
            # too wide for the vocabulary gets no record at all.
            self.emit(f"{pad}_labelled = prim_int({local})")
            self.emit(f"{pad}if _labelled is not None:")
            self.emit(f"{pad}    _sink.record(*_labelled, {start}, {end}, {comment})")
            return
        payload = payload_of(value, local)
        content = _literal(content_type_of(self.plan, value))
        arguments = [payload, content, start, end, comment]
        self.lines.extend(_call("_sink.record", arguments, indent))

    def cites(
        self, index: int, value: ValueType, start: str, end: str, indent: int
    ) -> tuple[str, str]:
        """Return the range a computed field's record cites, emitting any setup.

        §3.2: it consumed nothing, so citing its own position would claim an
        empty range and say nothing about where the value came from. It cites the
        fields its expression read — which the compiler knows — dropping the ones
        that turned out to be empty, which it does not.
        """
        pad = " " * indent
        assert value.expr is not None  # noqa: S101 - the caller checked
        ranges: list[str] = []
        for ref in references(value.expr):
            local = self.reachable(ref.path)
            if local is not None and f"_s_{local}" in self.spans:
                ranges.append(f"(_s_{local}, _e_{local})")
        if not ranges:
            return start, end
        self.emit(f"{pad}_cites = cited([{', '.join(ranges)}], ({start}, {end}))")
        return "_cites[0]", "_cites[1]"

    def reachable(self, path: tuple[str, ...]) -> str | None:
        """Return the local a reference names, if it is one of this unit's fields.

        ``parent`` and ``root`` reach outside what this function holds spans for,
        so a computed field citing one of those cites its siblings instead —
        which is the same approximation the interpreter makes.
        """
        if path[0] in SCOPE_WORDS and path[0] != "this":
            return None
        parts = path[1:] if path[0] == "this" else path
        if len(parts) != 1:
            return None
        item = self.plan.object(self.obj.unit).field(parts[0])
        if item is None or item.name is None:
            return None
        return self.names.attribute_of(self.obj.unit, item.name)

    def container(self, item: FieldPlan) -> bool:
        """Whether a field holds only decoded objects, never a value of its own.

        A container writes no record: its leaves do, which is what keeps a
        repeated field from being spelled twice in the paths under it. **Only**
        when every alternative is one, though — a ``switch`` with a unit case
        and an integer case still has an integer to write when it takes that
        branch, and the record emitted for it dispatches on the same selector.
        """
        return all(value.kind is Kind.OBJECT for value in item.types)

    def present(self, index: int, item: FieldPlan, target: str | None, indent: int) -> None:
        """Emit a field's read, at whatever indentation its condition left."""
        pad = " " * indent
        if target is None:
            self.emit(f"{pad}# Anonymous: read and accounted for, but never named.")
        if target is not None:
            # Written down before the read, because a read that does not know
            # its own length moves the anchor the range is measured from.
            self.emit(f"{pad}_s_{target} = {self.start()}")
        if item.repeat is not None:
            self.settle(indent)
            self.repetition(index, item, target, indent)
        else:
            self.value(index, item, target, indent)
        if target is None:
            return
        self.emit(f"{pad}_e_{target} = {self.end()}")
        if item.repeat is None and not self.container(item):
            self.account(
                index,
                item,
                target,
                self.segment(item, index),
                f"_s_{target}",
                f"_e_{target}",
                indent,
            )

    def repetition(self, index: int, item: FieldPlan, target: str | None, indent: int) -> None:
        """Emit a repeated field's loop.

        The repetition itself writes no record. Its elements are already named
        ``field[0]``, ``field[1]``, so counting the container as well would spell
        every repeat twice — ``questions.questions[0]``.
        """
        pad = " " * indent
        inner = " " * (indent + 4)
        counted = isinstance(item.repeat, Count)
        indexed = self.threads
        if target is not None:
            self.emit(f"{pad}{target}: list[{_value_annotation(item.types, self.names)}] = []")
        if indexed and not counted:
            self.emit(f"{pad}_index = 0")
        if counted:
            self.count(index, item.repeat, indent, indexed=indexed)
        elif isinstance(item.repeat, ToEnd):
            self.emit(f"{pad}while {ANCHOR} < _size:")
        else:
            self.emit(f"{pad}while True:")
        if not item.consumes:
            self.emit(f"{inner}_before = {ANCHOR}")
        marked = not self.container(item) and (self.emits(item) or self.skips(item))
        if marked:
            self.emit(f"{inner}_emark = {ORIGIN}")
        self.value(index, item, ELEMENT_LOCAL, indent + 4, self.element_path(item))
        if marked:
            self.emit(f"{inner}_es, _ee = _emark, {self.end()}")
            self.account(
                index,
                item,
                ELEMENT_LOCAL,
                self.element_path(item),
                "_es",
                "_ee",
                indent + 4,
            )
        if target is not None:
            self.emit(f"{inner}{target}.append({ELEMENT_LOCAL})")
        self.settle(indent + 4)
        if not item.consumes:
            # A repetition whose element reads nothing would spin forever, and a
            # count off the wire can ask for billions of them.
            self.emit(f"{inner}if {ANCHOR} == _before:")
            self.emit(
                f'{inner}    raise Undecodable("a repetition consumed no input", {ANCHOR})'
            )
        if isinstance(item.repeat, Until):
            self.index_of = index
            self.emit(f"{inner}if {self.evaluate(item.repeat.expr, indent + 4, item.name)}:")
            self.emit(f"{inner}    break")
        if indexed and not counted:
            self.emit(f"{inner}_index += 1")

    def element_path(self, item: FieldPlan) -> str:
        """Return the path expression for one element of a repeated field."""
        name = "_" if item.name is None else self.names.attribute_of(self.obj.unit, item.name)
        return 'f"{_path}.' + name + '[{_index}]"'


    def count(self, index: int, repeat: Count, indent: int, *, indexed: bool) -> None:
        """Emit the head of a counted loop, refusing a negative count if it can be one."""
        pad = " " * indent
        self.index_of = index
        rendered = self.evaluate(repeat.expr, indent)
        variable = "_index" if indexed else "_"
        if self.provable(repeat.expr):
            # The count is unsigned on the wire, so there is no negative to refuse.
            self.emit(f"{pad}for {variable} in range({rendered}):")
            return
        self.emit(f"{pad}_count = {rendered}")
        self.emit(f"{pad}if _count < 0:")
        self.emit(
            f'{pad}    raise Undecodable(f"negative repeat count {{_count}}", {ANCHOR})'
        )
        self.emit(f"{pad}for {variable} in range(_count):")

    def value(
        self,
        index: int,
        item: FieldPlan,
        target: str | None,
        indent: int,
        comment: str | None = None,
    ) -> None:
        """Emit one value's read, dispatching a ``switch`` if there is one."""
        pad = " " * indent
        path = comment if comment is not None else self.segment(item, index)
        if item.selector is None:
            self.read(index, item.types[0], target, indent, path)
            return
        self.index_of = index
        self.emit(f"{pad}_selector = {self.evaluate(item.selector, indent)}")
        keyword = "if"
        for branch in item.branches:
            if branch.case is None:
                continue
            self.emit(f"{pad}{keyword} _selector == {_literal(branch.case)}:")
            _here = self.delta
            self.read(index, branch.type, target, indent + 4, path)
            self.settle(indent + 4)
            self.delta = _here
            keyword = "elif"
        self.emit(f"{pad}else:")
        default = next((branch for branch in item.branches if branch.case is None), None)
        if default is not None:
            self.read(index, default.type, target, indent + 4, path)
            self.settle(indent + 4)
            return
        # §2: no case and no default is "tried and failed", and the extent is
        # unknowable, so the unit stops here.
        self.emit(
            f'{pad}    raise Undecodable(f"no case for {{_selector!r}} and no default", '
            f"{self.stopped()})"
        )
        self.delta = 0

    def read(
        self, index: int, value: ValueType, target: str | None, indent: int, comment: str
    ) -> None:
        """Emit the statements that read one value into ``target``."""
        pad = " " * indent
        if value.expr is not None:
            # Computed: it reads nothing, so an anonymous one leaves no trace.
            if target is not None:
                self.index_of = index
                self.emit(f"{pad}{target} = {self.evaluate(value.expr, indent)}")
            return
        if value.kind is Kind.OBJECT:
            call = self.call(index, value, comment)
            self.statement(call, f"{target or '_ignored'}, {ANCHOR}", indent)
            self.rebase(ANCHOR, indent)
            return
        if value.kind is Kind.INT:
            self.integer(value, target, indent)
            return
        raw = None if target is None else ("_raw" if value.kind is Kind.TEXT else target)
        self.sized(index, value, raw, indent)
        if value.kind is Kind.TEXT and target is not None:
            encoding = _literal(value.encoding or "utf-8")
            self.emit(f"{pad}try:")
            self.emit(f"{pad}    {target} = _raw.decode({encoding})")
            self.emit(f"{pad}except UnicodeDecodeError:")
            self.emit(f"{pad}    # A malformed string is a fact about the input, not a")
            self.emit(f"{pad}    # failure of the decoder: §3.2. The bytes are accounted")
            self.emit(f"{pad}    # for either way, so the region stays decoded.")
            self.emit(f'{pad}    {target} = _raw.decode({encoding}, errors="replace")')

    def statement(self, call: str, target: str | None, indent: int) -> None:
        """Emit a read, assigning it only if anything can name the value."""
        opened = call.index("(")
        prefix = "" if target is None else f"{target} = "
        head = prefix + call[:opened]
        self.lines.extend(_call(head, _split_arguments(call[opened + 1 : -1]), indent))

    def integer(self, value: ValueType, target: str | None, indent: int) -> None:
        """Emit the read of one integer, as arithmetic on the bytes it sits in.

        Every offset, shift and mask below is a number the compiler worked out,
        which is the whole of why this is faster than asking a cursor: the cursor
        has to be told where it is, and this already knows.
        """
        pad = " " * indent
        bits = value.bits or 0
        self.need(bits, indent)
        expression = self.extract(bits, value.signed, value.endian)
        self.advance(bits)
        if target is None:
            # Anonymous and unemitted: the bytes still have to be passed over,
            # and here that is arithmetic the compiler did rather than a read.
            return
        self.emit(f"{pad}{target} = {expression}")

    def extract(self, bits: int, signed: bool, endian: str) -> str:
        """Return the expression for ``bits`` bits at the current position."""
        offset = self.delta % 8
        order = "little" if endian == "little" else "big"
        if offset == 0 and bits % 8 == 0:
            if bits == 8 and not signed:
                return f"_data[{self.byte()}]"
            sign = ", signed=True" if signed else ""
            span = f"{self.byte()}:{self.index(bits)}"
            return f'int.from_bytes(_data[{span}], "{order}"{sign})'
        # Bits are taken most significant first, within a byte and across one,
        # which is what every protocol that packs flags does — and `endian` has
        # no meaning below a byte, so it is not consulted here.
        whole = -(-(offset + bits) // 8)
        shift = whole * 8 - offset - bits
        mask = (1 << bits) - 1
        if whole == 1:
            word = f"_data[{self.byte()}]"
        else:
            span = f"{self.byte()}:{self.index(whole * 8)}"
            word = f'int.from_bytes(_data[{span}], "big")'
        if shift:
            word = f"({word} >> {shift})"
        value = word if mask == (1 << (whole * 8)) - 1 and not shift else f"{word} & {mask}"
        return self.signed(value, bits) if signed else value

    def signed(self, value: str, bits: int) -> str:
        """Wrap an extracted value as two's complement of its declared width."""
        return f"_signed({value}, {bits})"

    def sized(self, index: int, value: ValueType, target: str | None, indent: int) -> None:
        """Emit the read of a value whose extent comes from its size."""
        pad = " " * indent
        size = value.size
        self.aligned("a sized field")
        prefix = "" if target is None else f"{target} = "
        if isinstance(size, Fixed):
            self.need(size.count * 8, indent)
            first, after = self.byte(), self.byte(size.count * 8)
            self.emit(f"{pad}{prefix}_data[{first}:{after}]")
            self.advance(size.count * 8)
        elif isinstance(size, Remaining):
            self.emit(f"{pad}{prefix}_data[{self.byte()}:]")
            self.rebase("_size", indent)
        elif isinstance(size, FromExpr):
            self.counted(index, size, prefix, indent)
        elif isinstance(size, Terminated):
            self.terminated(size, prefix, indent)

    def counted(self, index: int, size: FromExpr, prefix: str, indent: int) -> None:
        """Emit a read of as many bytes as an earlier field says."""
        pad = " " * indent
        self.index_of = index
        rendered = self.evaluate(size.expr, indent)
        self.emit(f"{pad}_want = {rendered}")
        if not self.provable(size.expr):
            self.emit(f"{pad}if _want < 0:")
            self.emit(f'{pad}    raise Undecodable(f"negative size {{_want}}", {self.stopped()})')
        start = self.byte()
        room = f"_size - {start}" if start == ANCHOR else f"_size - ({start})"
        self.emit(f"{pad}if {room} < _want:")
        self.emit(f'{pad}    raise TruncatedRead("truncated", {self.stopped()})')
        self.emit(f"{pad}{prefix}_data[{start}:{start} + _want]")
        self.rebase(f"{start} + _want", indent)

    def terminated(self, size: Terminated, prefix: str, indent: int) -> None:
        """Emit a delimited read, with only the branch the spec asked for."""
        pad = " " * indent
        delimiter = _literal(size.delimiter)
        start = self.byte()
        past = len(size.delimiter) if size.consume else 0
        self.emit(f"{pad}_found = _data.find({delimiter}, {start})")
        self.emit(f"{pad}if _found < 0:")
        if size.required:
            # Not an error: in STREAM shape the value may continue in a segment
            # this run does not hold (§3.2). The `else` is left off because the
            # branch above leaves, which is also what ruff asks for.
            self.emit(
                f'{pad}    raise TruncatedRead("no terminator in what remains", '
                f"{self.stopped()})"
            )
            self.emit(f"{pad}{prefix}_data[{start}:_found]")
            self.rebase(f"_found + {past}" if past else "_found", indent)
            return
        self.emit(f"{pad}    {prefix}_data[{start}:]")
        self.emit(f"{pad}    _stop = _size")
        self.emit(f"{pad}else:")
        self.emit(f"{pad}    {prefix}_data[{start}:_found]")
        self.emit(f"{pad}    _stop = _found + {past}" if past else f"{pad}    _stop = _found")
        self.rebase("_stop", indent)

    def call(self, index: int, value: ValueType, comment: str) -> str:
        """Return the call that decodes a nested unit."""
        unit = value.unit or ""
        target = self.plan.object(unit)
        binding = self.binding(index)
        self.aligned(f"the call to unit {unit!r}")
        arguments = ["_data", "_size", self.byte(), "_base"]
        if self.threads:
            arguments.extend(["_sink", comment])
        arguments.extend(render_expr(argument, binding) for argument in value.args)
        arguments.extend(self.outer(index, target))
        if self.plan.recursive:
            arguments.append("_depth + 1")
        return f"{self.names.function_of(unit)}({', '.join(arguments)})"

    def outer(self, index: int, target: ObjectPlan) -> list[str]:
        """Return the outer values a nested unit needs, from where this one holds them.

        ``parent`` is this unit's own local, since this unit *is* the parent.
        ``root`` is threaded: the entry unit passes its local, and everyone else
        passes the parameter it was handed.
        """
        binding = self.binding(index)
        arguments = [binding.render((name,)) for name in target.needs_parent]
        for name in target.needs_root:
            if self.obj.unit == self.plan.entry:
                arguments.append(binding.render(("root", name)))
            else:
                arguments.append(f"{ROOT_PREFIX}{name}")
        return arguments

    def emit(self, line: str) -> None:
        """Append one line of the body."""
        self.lines.append(line)


def _fallible(rendered: str) -> bool:
    """Whether a rendered expression can fail for some input.

    Integer division, modulo, and a bounded shift. Everything else in this
    language answers for every value it can be handed, which is what makes
    checking worth the two lines it costs.
    """
    return any(token in rendered for token in ("//", " % ", "shift_left(", "shift_right("))


def _split_arguments(text: str) -> list[str]:
    """Split a rendered argument list on the commas that separate arguments."""
    parts: list[str] = []
    depth = 0
    current = ""
    for char in text:
        if char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
            continue
        depth += {"(": 1, "[": 1, ")": -1, "]": -1}.get(char, 0)
        current += char
    if current.strip():
        parts.append(current.strip())
    return parts


def render_decoder(plan: Plan, names: Names | None = None, *, emit: Emit = Emit.MESSAGE) -> str:
    """Render the decode functions, one per unit.

    Args:
        plan: The plan to render.
        names: Its resolved identifiers, built if not supplied.
        emit: The granularity to compile for. **A compile-time choice**, which
            is the phase plan's answer to Q1's open sub-question: at
            ``MESSAGE`` these functions build no field paths and take no sink at
            all, and at ``FIELD`` the path is threaded through every one of
            them. That is a difference in the code rather than in a flag.

    Returns:
        Python source for the functions, without a trailing newline.

    Raises:
        CompileError: If a unit is reached at two different granularities.

    """
    names = names or Names(plan)
    inside = granularity(plan, emit)
    functions = [
        _Function(plan, names, obj, inside[obj.unit], emit).render() for obj in plan.objects
    ]
    body = "\n\n\n".join(functions)
    if "_signed(" not in body:
        return body
    return "\n\n\n".join([_SIGNED_HELPER, body])


#: Reinterpreting a sub-byte field as two's complement. Emitted only when a
#: spec has such a field, because most do not — a whole-byte one is read as
#: signed by ``int.from_bytes`` and never comes here.
_SIGNED_HELPER = '''def _signed(value: int, bits: int) -> int:
    """Reinterpret ``bits`` bits as a two's complement number.

    Only sub-byte fields need this. A signed field of whole bytes is read as
    signed where it is read, and a signed field narrower than a byte has no
    sign bit until its width is known — which it is, here, as a constant.

    Args:
        value: The bits, as an unsigned number.
        bits: How many of them the field declared.

    Returns:
        The signed value.

    """
    return value - (1 << bits) if value >= 1 << (bits - 1) else value'''


def render_entry(plan: Plan, names: Names | None = None, *, emit: Emit = Emit.MESSAGE) -> str:
    """Render a module's entry points.

    Two of them, because a caller and a driver want different things. A caller
    has a datagram: it wants the typed object, ``None`` if the input could not be
    decoded, and every byte of that datagram accounted for. A driver owns the
    cursor — it has a run with several messages in it — so it wants the failure
    itself, and it accounts for the tail, because only it knows whether another
    message follows.

    Args:
        plan: The plan to render.
        names: Its resolved identifiers, built if not supplied.
        emit: The granularity to compile for.

    Returns:
        Python source for the entry points, without a trailing newline.

    """
    names = names or Names(plan)
    cls = names.class_of(plan.entry)
    unit = _safe(plan.entry)
    arguments = ["cur"]
    if emit is Emit.FIELD:
        arguments.extend(["sink", "NAME"])
    if plan.recursive:
        arguments.append("0")
    lines = [
        f"def decode_from(cur: Cursor, sink: Sink | None = None) -> {cls}:",
        f'    """Decode one ``{unit}`` from wherever ``cur`` stands.',
        "",
        *_wrap(
            "The driver's entry point. The cursor is left after the last byte read, "
            "which is how a caller decoding several messages from one run knows where "
            "the next one starts — and the bytes after it are the driver's to account "
            "for, since only it knows whether another message follows.",
            4,
        ),
        "",
        "    Args:",
        "        cur: The cursor to read from.",
        "        sink: Where records and undecoded regions go.",
        "",
        "    Returns:",
        f"        The decoded ``{unit}``.",
        "",
        "    Raises:",
        "        TruncatedRead: If the input ends inside the message.",
        "        Undecodable: If it is not what the specification describes.",
        "",
        '    """',
    ]
    arguments = ["_data", "_size", "_at", "cur.base"]
    if emit is Emit.FIELD:
        arguments.extend(["sink", "NAME"])
    if plan.recursive:
        arguments.append("0")
    call = f"{names.function_of(plan.entry)}({', '.join(arguments)})"
    lines.extend(
        [
            "    _data = cur.data",
            "    _size = len(_data)",
            *_comment(
                "The cursor owns the position between messages; inside one, the "
                "generated code below owns it, because a byte offset in a local is what "
                "makes every read an index rather than a call. It is handed back at "
                "every exit, including the failures.",
                indent=4,
            ),
            "    _start = cur.tell() >> 3",
            "    _at = _start",
            "    try:",
            f"        _message, _at = {call}",
            "    except Stopped as _exc:",
            "        _at = _start if _exc.at is None else _exc.at",
            "        cur.seek(_at << 3)",
        ]
    )
    if emit is Emit.MESSAGE:
        lines.extend(
            [
                *_comment(
                    "Nothing cited these bytes: only a *whole* message is a message, "
                    "and this one is not. A region no record claims is the only honest "
                    "thing to say about them.",
                    indent=8,
                ),
                "        if sink is not None and _at > _start:",
                "            _s, _e = cur.base + _start, cur.base + _at",
                "            sink.undecoded(_s, _e, _reason(_exc))",
            ]
        )
    elif emit is Emit.NONE:
        lines.extend(
            [
                "        if sink is not None and _at > _start:",
                '            sink.undecoded(cur.base + _start, cur.base + _at, "skipped")',
            ]
        )
    lines.append("        raise")
    lines.append("    cur.seek(_at << 3)")
    if emit is Emit.MESSAGE:
        lines.extend(
            [
                "    if sink is not None and _at > _start:",
                *_comment(
                    "Its payload is a copy of the input rather than anything the decode "
                    "created, which is what a `dec:` type means.",
                    indent=8,
                ),
                "        _payload = _data[_start:_at]",
                "        _s, _e = cur.base + _start, cur.base + _at",
                "        sink.record(_payload, MESSAGE_CONTENT_TYPE, _s, _e, None)",
            ]
        )
    elif emit is Emit.NONE:
        lines.extend(
            [
                *_comment(
                    "Nothing is written at this granularity, so the message's own bytes "
                    "are named instead: read, understood, and deliberately not reported.",
                    indent=4,
                ),
                "    if sink is not None and _at > _start:",
                '        sink.undecoded(cur.base + _start, cur.base + _at, "skipped")',
            ]
        )
    lines.append("    return _message")
    lines.extend(
        [
            "",
            "",
            f"def decode(data: bytes, *, base: int = 0, sink: Sink | None = None) -> {cls} | None:",
            f'    """Decode one ``{unit}`` from ``data``, accounting for all of it.',
            "",
            *_wrap(
                "``data`` is one contiguous run holding one message, which is what a "
                "datagram is. Everything in it is accounted for: what the message "
                "decoded is cited by the records, and whatever is left over is named.",
                4,
            ),
            "",
            *_wrap(
                "Failure returns ``None`` rather than a half-built object. The typed "
                "model has no half-built state to offer — that is the trade it makes "
                "for not being a generic tree — and what *was* decoded has already "
                "reached the sink, which is where provenance lives.",
                4,
            ),
            "",
            "    Args:",
            "        data: The bytes to decode.",
            "        base: Stream offset of ``data[0]``, so every byte range is",
            "            absolute.",
            "        sink: Where records and undecoded regions go. ``None`` decodes",
            "            without emitting anything, for a caller who wants only the",
            "            typed objects.",
            "",
            "    Returns:",
            "        The message, or ``None`` if it could not be decoded.",
            "",
            '    """',
            "    cur = Cursor(data, base)",
            "    _end = base + len(data)",
            "    try:",
            "        _message = decode_from(cur, sink)",
            "    except Stopped as _exc:",
            "        if sink is not None:",
            *_comment(
                "From where the cursor stopped. Whatever this message could account "
                "for it has already said; what is left is what was never decoded.",
                indent=12,
            ),
            "            sink.undecoded(_stopped_at(cur, base), _end, _reason(_exc))",
            "        return None",
            "    if sink is not None:",
            *_comment(
                "Whatever this message did not claim is this datagram's alone: a "
                "following message cannot use it, so it is skipped rather than left.",
                indent=8,
            ),
            "        _stop = _stopped_at(cur, base)",
            "        if _stop < _end:",
            '            sink.undecoded(_stop, _end, "skipped")',
            "    return _message",
            "",
            "",
            "def _stopped_at(cur: Cursor, base: int) -> int:",
            '    """Return the first byte no field has claimed, in stream offsets.',
            "",
            *_wrap(
                "Rounded **up**: the cursor can only sit inside a byte because an "
                "earlier field read part of it, and that field cited the whole byte. "
                "Starting an undecoded region there would name a byte a record already "
                "claims.",
                4,
            ),
            "",
            "    Args:",
            "        cur: The cursor, wherever the decode left it.",
            "        base: Stream offset of the run's first byte.",
            "",
            "    Returns:",
            "        The offset the caller's accounting resumes at.",
            "",
            '    """',
            "    return base + (cur.tell() + 7) // 8",
            "",
            "",
            "def _reason(exc: Exception) -> str:",
            '    """Return the `zpf` ``reason=`` a failed decode is marked with.',
            "",
            *_wrap(
                "Truncation is the only failure that means the bytes were never there. "
                "Everything else — a switch with no case, a guard that did not hold, an "
                "expression that could not answer — read the bytes and could not make "
                "sense of them.",
                4,
            ),
            "",
            "    Args:",
            "        exc: What the decode raised.",
            "",
            "    Returns:",
            '        ``"truncated"`` or ``"undecodable"``.',
            "",
            '    """',
            '    return "truncated" if isinstance(exc, TruncatedRead) else "undecodable"',
            "",
            "",
        ]
    )
    return "\n".join(lines)


# --- the typed model -------------------------------------------------------


#: Widths that read as "an" rather than "a". Listed rather than derived, since
#: the model allows 1 to 64 bits and these are all of them.
AN_BITS = frozenset({8, 11, 18})


def _noun(value: ValueType, names: Names) -> str:
    """Describe one value in prose, for a field the spec did not document.

    A noun phrase with its article, so that a caller can put it after either
    "One" or "Each element is" and get a sentence either way.
    """
    if value.kind is Kind.OBJECT:
        return f"one :class:`{names.class_of(value.unit or '')}`"
    if value.kind is Kind.TEXT:
        return f"text, decoded as ``{_safe(value.encoding or '')}``"
    if value.kind is Kind.BYTES:
        return "raw bytes"
    if value.kind is Kind.BOOL:
        return "a boolean, computed from earlier fields"
    if value.bits is None:
        return "an integer, computed from earlier fields"
    article = "an" if value.bits in AN_BITS else "a"
    sign = "signed" if value.signed else "unsigned"
    order = ", little-endian" if value.endian == "little" and value.bits > 8 else ""
    return f"{article} {value.bits}-bit {sign} integer{order}"


def _describe(item: FieldPlan, names: Names) -> str:
    """Return the Attributes text for one field: the spec's words, or ours."""
    if item.doc and item.doc.strip():
        text = " ".join(_safe(item.doc).split())
    else:
        nouns = " or ".join(_noun(value, names) for value in item.types)
        text = f"Each element is {nouns}" if item.repeated else nouns[:1].upper() + nouns[1:]
    labelled = [value.labels for value in item.types if value.labels]
    for enum in dict.fromkeys(labelled):
        text = f"{_sentence(text)} Labelled by :data:`{names.constant_of(enum)}`."
    if item.condition is not None:
        # The spec's spelling, not Python's: `_parent_x` and `//` are this
        # backend's business and would be noise to whoever reads the doc.
        when = _safe(unparse(item.condition))
        text = f"{_sentence(text)} Present only when ``{when}``."
    return _sentence(text)


def _sentence(text: str) -> str:
    """End text with a full stop, so another sentence can follow it."""
    return text if text.endswith((".", "!", "?", ":")) else f"{text}."


def _value_annotation(values: Sequence[ValueType], names: Names) -> str:
    """Render what one value can be, as a Python type."""
    parts = dict.fromkeys(
        names.class_of(value.unit or "") if value.kind is Kind.OBJECT else ANNOTATIONS[value.kind]
        for value in values
    )
    return " | ".join(parts)


def _annotation(item: FieldPlan, names: Names) -> str:
    """Render one field's Python type."""
    kind = _value_annotation(item.types, names)
    if item.repeated:
        kind = f"list[{kind}]"
    if item.optional:
        kind = f"{kind} | None"
    return kind


def _attributes(obj: ObjectPlan, names: Names) -> list[tuple[str, FieldPlan]]:
    """Pair every named field of a unit with the attribute it becomes, in order."""
    return [
        (names.attribute_of(obj.unit, item.name), item)
        for item in obj.fields
        if item.name is not None
    ]


def _class_doc(obj: ObjectPlan, names: Names) -> list[str]:
    """Render one class's docstring."""
    described = _attributes(obj, names)
    anonymous = [index for index, item in enumerate(obj.fields, 1) if item.name is None]

    body: list[str] = []
    summary = f"One decoded ``{_safe(obj.unit)}``."
    paragraphs = _paragraphs(obj.doc) if obj.doc else []
    if paragraphs and len(paragraphs[0]) + 7 <= LINE_LENGTH:
        summary, paragraphs = paragraphs[0], paragraphs[1:]
    lines = [f'    """{summary}']

    for paragraph in paragraphs:
        body.extend(["", *_wrap(paragraph, 4)])
    if anonymous:
        positions = ", ".join(str(index) for index in anonymous)
        plural = "s" if len(anonymous) > 1 else ""
        body.extend(
            [
                "",
                *_wrap(
                    f"The spec's field{plural} at position {positions} "
                    f"{'are' if plural else 'is'} anonymous: read and cited, but with no "
                    f"attribute here — a field with no name is not something a caller can "
                    f"ask for.",
                    4,
                ),
            ]
        )

    body.extend(["", "    Attributes:"])
    for attribute, item in described:
        body.extend(_wrap(f"{attribute}: {_describe(item, names)}", 8, hang=4))
    body.extend(
        _wrap(
            "__spans__: Byte ranges: this object's own extent first, then one pair per "
            "attribute above, in order.",
            8,
            hang=4,
        )
    )
    lines.extend(body)
    lines.extend(["", '    """'])
    return lines


def render_model(plan: Plan, names: Names | None = None) -> str:
    """Render the typed model: one class per unit.

    Args:
        plan: The plan to render.
        names: Its resolved identifiers, built if not supplied.

    Returns:
        Python source for the classes, without a trailing newline.

    """
    names = names or Names(plan)
    blocks: list[str] = []
    for obj in plan.objects:
        lines = ["@dataclass(slots=True)", f"class {names.class_of(obj.unit)}:"]
        lines.extend(_class_doc(obj, names))
        lines.append("")
        index: list[str] = []
        for attribute, item in _attributes(obj, names):
            lines.append(f"    {attribute}: {_annotation(item, names)}")
            index.append(f"{_literal(attribute)}: {len(index)}")
        lines.append("    __spans__: tuple[int, ...]")
        lines.append("")
        lines.extend(
            _dict_call("__span_index__: ClassVar[Mapping[str, int]] = MappingProxyType", index, 4)
        )
        blocks.append("\n".join(lines))
    return "\n\n\n".join(blocks)


def render_enums(plan: Plan, names: Names | None = None) -> str:
    """Render a spec's ``enums:`` as module constants.

    Mappings rather than :class:`enum.IntEnum` subclasses, which is the answer
    the phase plan's Q4 settles on: a value with no label is normal on the wire
    — DNS opcode 3 has none — and a decoder may not raise, so a labelled field
    stays an ``int`` and the labels are a lookup beside it.

    Args:
        plan: The plan to render.
        names: Its resolved identifiers, built if not supplied.

    Returns:
        Python source for the constants, or ``""`` if the spec declares none.

    """
    names = names or Names(plan)
    if not plan.enums:
        return ""
    lines = _comment(
        "A spec's enums are mappings, not enum.IntEnum subclasses: a value with no label "
        "is normal on the wire, and a decoder may not raise. A labelled field stays an "
        "int, and the labels are a lookup beside it."
    )
    for name, enum in plan.enums.items():
        entries = [f"{value}: {_literal(label)}" for value, label in enum.members.items()]
        described = f"Labels declared as ``{name}``"
        summary = " ".join(_safe(enum.doc).split()) if enum.doc else described
        declaration = f"{names.constant_of(name)}: Mapping[int, str] = MappingProxyType"
        lines.append("")
        lines.extend(_comment(_sentence(summary), "#:"))
        lines.extend(_dict_call(declaration, entries, 0))
    return "\n".join(lines)


def _granularity_constants(plan: Plan, emit: Emit) -> list[str]:
    """Return the content-type constants a module needs for its granularity."""
    lines = [
        "#: The specification this module was generated from.",
        f"NAME = {_literal(plan.name)}",
        f"VERSION = {_literal(plan.version)}",
        "",
    ]
    if emit is Emit.MESSAGE:
        return lines + [
            "#: How a whole-message record is labelled. A ``dec:`` type means",
            "#: whatever its decoder documents, and what this one documents is the",
            "#: specification above.",
            f"MESSAGE_CONTENT_TYPE = {_literal(f'dec:{plan.name}-message')}",
            "",
        ]
    if emit is not Emit.FIELD or not _has_text(plan):
        return lines
    return lines + [
        "#: How a text field's payload is labelled. Not ``prim:`` — that scheme",
        "#: has no text token — so the format's other fully specified one is used.",
        f"TEXT_CONTENT_TYPE = {_literal(TEXT_CONTENT_TYPE)}",
        "",
    ]


def _has_text(plan: Plan) -> bool:
    """Whether any field decodes to text, and so needs the text content type."""
    return any(
        value.kind is Kind.TEXT
        for obj in plan.objects
        for item in obj.fields
        for value in item.types
    )


def _runtime_import(body: str) -> list[str]:
    """Return the ``kober.runtime`` import a rendered module needs.

    Read off the source rather than worked out ahead of it, which is both
    simpler and exact: a name the module does not use would be an unused import,
    and generated modules are linted like everything else here. It also means a
    reader can see what a generated decoder depends on by reading one line,
    which is the whole of Q3's answer.
    """
    used = {node.id for node in ast.walk(ast.parse(body)) if isinstance(node, ast.Name)}
    wanted = sorted(RUNTIME_NAMES & used)
    if not wanted:
        return []
    one = f"from kober.runtime import {', '.join(wanted)}"
    if len(one) <= LINE_LENGTH:
        return [one, ""]
    return [
        "from kober.runtime import (",
        *(f"    {name}," for name in wanted),
        ")",
        "",
    ]


def _guards(obj: ObjectPlan) -> list[Expr]:
    """Return every expression a unit evaluates that a backend renders."""
    found = [expr for expr in (obj.confirm, obj.reject) if expr is not None]
    for item in obj.fields:
        if item.condition is not None:
            found.append(item.condition)
        if item.selector is not None:
            found.append(item.selector)
        if isinstance(item.repeat, (Count, Until)):
            found.append(item.repeat.expr)
        for value in item.types:
            if value.expr is not None:
                found.append(value.expr)
            if isinstance(value.size, FromExpr):
                found.append(value.size.expr)
    return found


def _shifts(expr: Expr) -> bool:
    """Whether an expression contains a shift the backend cannot see to be safe."""
    return bool(_shift_names(expr))


def _shift_names(expr: Expr) -> set[str]:
    """Return the shift helpers an expression needs."""
    found: set[str] = set()
    if isinstance(expr, BinOp):
        if expr.op in SHIFT_HELPERS and not _safe_shift(expr.right):
            found.add(SHIFT_HELPERS[expr.op])
        found |= _shift_names(expr.left) | _shift_names(expr.right)
    elif isinstance(expr, Compare):
        found |= _shift_names(expr.left) | _shift_names(expr.right)
    elif isinstance(expr, BoolOp):
        for operand in expr.operands:
            found |= _shift_names(operand)
    elif isinstance(expr, UnaryOp):
        found |= _shift_names(expr.operand)
    return found


def render(plan: Plan, names: Names | None = None, *, emit: Emit = Emit.MESSAGE) -> str:
    """Render a whole module for a plan.

    What that module contains grows with the compiler: at this stage it is the
    typed model and the enum labels, which is already enough to import, to
    construct, and to read a decode's byte ranges back out of.

    Args:
        plan: The plan to render.
        names: Its resolved identifiers, built if not supplied.
        emit: The granularity to compile for, which decides what the module
            emits and therefore what it is shaped like.

    Returns:
        Python source, newline terminated.

    Raises:
        CompileError: If a name cannot be emitted, or if the rendered source
            does not parse — which would be a bug in this backend, and is
            worth catching here rather than in whatever imports the result.

    """
    names = names or Names(plan)
    granularity(plan, emit)
    title = f"Decoder for the ``{_safe(plan.name)}`` specification, version {_safe(plan.version)}."
    lines = [f'"""{title}']
    for paragraph in _paragraphs(plan.doc) if plan.doc else []:
        lines.extend(["", *_wrap(paragraph, 0)])
    lines.extend(
        [
            "",
            *_wrap(
                "Generated from a specification by kober. Do not edit: change the spec and "
                "compile it again.",
                0,
            ),
            '"""',
            "",
            "from __future__ import annotations",
            "",
            "from dataclasses import dataclass",
            "from types import MappingProxyType",
            "from typing import TYPE_CHECKING, ClassVar",
            "",
        ]
    )
    body: list[str] = []
    enums = render_enums(plan, names)
    if enums:
        body.extend(["", _rule("enums"), "", enums, ""])
    body.extend(["", _rule("the typed model"), "", "", render_model(plan, names), "", ""])
    body.extend([_rule("the decoder"), "", "", render_decoder(plan, names, emit=emit), "", ""])
    body.extend([_rule("entry points"), "", "", render_entry(plan, names, emit=emit), ""])
    rendered = "\n".join(body)
    lines.extend(_runtime_import(rendered))
    lines.extend(["if TYPE_CHECKING:", "    from collections.abc import Mapping", ""])
    lines.extend(_granularity_constants(plan, emit))
    source = "\n".join([*lines, rendered])
    try:
        ast.parse(source)
    except SyntaxError as exc:  # pragma: no cover - a backend bug, not a spec fault
        msg = f"the Python backend produced source that does not parse: {exc}"
        raise CompileError(msg) from exc
    return source


def render_spec(spec: Spec, *, emit: Emit = Emit.MESSAGE, check: bool = True) -> str:
    """Render a module for a spec, planning it first.

    The one-call form, for a caller with no reason to hold the plan.

    Args:
        spec: The spec to compile.
        emit: The granularity to compile for.
        check: Validate it before compiling, as
            :meth:`kober.ops.Plan.from_spec` does.

    Returns:
        Python source, newline terminated.

    """
    return render(Plan.from_spec(spec, check=check), emit=emit)
