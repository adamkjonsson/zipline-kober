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
from typing import TYPE_CHECKING

from kober.errors import CompileError
from kober.expr import unparse
from kober.ops import Kind, Plan

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
            taken: dict[str, str] = {}
            for item in obj.fields:
                if item.name is None:
                    continue
                where = f"field {item.name!r} of unit {obj.unit!r}"
                attribute = _keyword_safe(item.name)
                problems.extend(_bad(where, attribute))
                if attribute in RESERVED_LOCAL:
                    problems.append(
                        f"{where} becomes the local {attribute!r}, which every generated "
                        f"decode function already takes as a parameter; rename it in the spec"
                    )
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
        when = _safe(_condition(item.condition))
        text = f"{_sentence(text)} Present only when ``{when}``."
    return _sentence(text)


def _condition(expr: Expr) -> str:
    """Render a presence condition for prose.

    :func:`kober.expr.unparse` parenthesizes fully, because it exists for error
    messages where being unambiguous beats being pretty. The outermost pair
    says nothing here and only the outermost pair is safe to drop.
    """
    text = unparse(expr)
    if text.startswith("(") and text.endswith(")"):
        return text[1:-1]
    return text


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
