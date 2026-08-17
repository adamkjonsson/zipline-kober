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
    unparse,
)
from kober.ops import Kind, Plan, walk_path

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

#: Names the generated decode functions take as parameters. A field becomes a
#: local inside one of those functions, so a field with one of these names
#: would shadow it.
RESERVED_LOCAL = frozenset({"cur", "path", "sink"})

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


def _comment(text: str, marker: str = "#") -> list[str]:
    """Wrap a paragraph as a comment, marking every line rather than the first.

    Sphinx reads a ``#:`` block as documentation only while each of its lines
    carries the marker, so a continuation that lost it would silently stop
    being documentation.
    """
    width = DOC_WIDTH - len(marker) - 1
    return [f"{marker} {line}".rstrip() for line in _wrap(text, 0, width=width)]


def _rule(title: str) -> str:
    """Render a ``# --- title ---`` section rule."""
    return f"# --- {title} ".ljust(RULE_WIDTH, "-")


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

    """

    plan: Plan
    names: Names
    unit: str
    parent: str | None = None
    element_of: str | None = None
    element: str = ELEMENT_LOCAL

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
            return self.plan.entry, ROOT_PREFIX
        return self.unit, ""


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


def _annotation(item: FieldPlan, names: Names) -> str:
    """Render one field's Python type."""
    parts = dict.fromkeys(
        names.class_of(value.unit or "") if value.kind is Kind.OBJECT else ANNOTATIONS[value.kind]
        for value in item.types
    )
    kind = " | ".join(parts)
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


def render(plan: Plan, names: Names | None = None) -> str:
    """Render a whole module for a plan.

    What that module contains grows with the compiler: at this stage it is the
    typed model and the enum labels, which is already enough to import, to
    construct, and to read a decode's byte ranges back out of.

    Args:
        plan: The plan to render.
        names: Its resolved identifiers, built if not supplied.

    Returns:
        Python source, newline terminated.

    Raises:
        CompileError: If a name cannot be emitted, or if the rendered source
            does not parse — which would be a bug in this backend, and is
            worth catching here rather than in whatever imports the result.

    """
    names = names or Names(plan)
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
            "if TYPE_CHECKING:",
            "    from collections.abc import Mapping",
            "",
            "#: The specification this module was generated from.",
            f"NAME = {_literal(plan.name)}",
            f"VERSION = {_literal(plan.version)}",
            "",
        ]
    )
    enums = render_enums(plan, names)
    if enums:
        lines.extend(["", _rule("enums"), "", enums, ""])
    lines.extend(["", _rule("the typed model"), "", "", render_model(plan, names), ""])
    source = "\n".join(lines)
    try:
        ast.parse(source)
    except SyntaxError as exc:  # pragma: no cover - a backend bug, not a spec fault
        msg = f"the Python backend produced source that does not parse: {exc}"
        raise CompileError(msg) from exc
    return source


def render_spec(spec: Spec, *, check: bool = True) -> str:
    """Render a module for a spec, planning it first.

    The one-call form, for a caller with no reason to hold the plan.

    Args:
        spec: The spec to compile.
        check: Validate it before compiling, as
            :meth:`kober.ops.Plan.from_spec` does.

    Returns:
        Python source, newline terminated.

    """
    return render(Plan.from_spec(spec, check=check))
