"""The expression language: a small, total, side-effect-free AST.

Expressions are authored as strings in a spec (``size: "header.length * 4"``)
and parsed here to an AST at load time, so :func:`kober.check` can scope and
type them against the spec before any data exists. See ``DESIGN.md`` §3.3.

**Parsing borrows Python's own parser.** :func:`ast.parse` in ``eval`` mode
gives correct precedence and associativity for free, and the translation
below accepts a whitelist of node types — so "no calls, no loops" holds by
construction rather than by a rule someone has to remember. Anything outside
the whitelist is refused by name.

Two deliberate departures from Python's semantics, both because the language
has no floating-point type at all:

- ``/`` is **integer division**, as is ``//``. There is nothing else it could
  mean here, and Kaitai reads it the same way.
- A float literal is a parse error rather than a silently truncated int.

The language is *total* in the sense that matters for the coverage guarantee
(§2): it cannot call out, loop, or mutate. It is not total over division by
zero, which is a decode-time condition a spec cannot be checked free of.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

from kober.errors import ExprError

if TYPE_CHECKING:
    from collections.abc import Mapping


class ExprType(Enum):
    """The type of an expression's value.

    Deliberately four members and no numeric tower: a spec's arithmetic is
    integer arithmetic on wire values, and widening rules would be surface
    with nothing behind it.
    """

    INT = "int"
    BOOL = "bool"
    STR = "str"
    BYTES = "bytes"


@dataclass(frozen=True)
class IntLiteral:
    """An integer constant.

    Attributes:
        value: The constant.

    """

    value: int


@dataclass(frozen=True)
class StrLiteral:
    """A string constant.

    Attributes:
        value: The constant.

    """

    value: str


@dataclass(frozen=True)
class BoolLiteral:
    """A boolean constant.

    Attributes:
        value: The constant.

    """

    value: bool


@dataclass(frozen=True)
class Ref:
    """A reference to a field, a unit parameter, or a scope root.

    The path is stored as authored, including any leading scope word, so an
    error message can quote what the author wrote. ``length`` and
    ``this.length`` are different paths that resolve the same way.

    Attributes:
        path: Dotted components, e.g. ``("this", "header", "length")``.

    """

    path: tuple[str, ...]


@dataclass(frozen=True)
class UnaryOp:
    """Negation (``-``), identity (``+``), bitwise inverse (``~``), or ``not``.

    Attributes:
        op: The operator as authored.
        operand: What it applies to.

    """

    op: str
    operand: Expr


@dataclass(frozen=True)
class BinOp:
    """An arithmetic or bitwise operator over two integers.

    Attributes:
        op: The operator as authored (``/`` means integer division).
        left: Left operand.
        right: Right operand.

    """

    op: str
    left: Expr
    right: Expr


@dataclass(frozen=True)
class BoolOp:
    """``and`` / ``or`` over two or more booleans.

    Attributes:
        op: ``"and"`` or ``"or"``.
        operands: Two or more operands, as authored.

    """

    op: str
    operands: tuple[Expr, ...]


@dataclass(frozen=True)
class Compare:
    """A single comparison. Chained comparisons are refused at parse time.

    Attributes:
        op: One of ``== != < <= > >=``.
        left: Left operand.
        right: Right operand.

    """

    op: str
    left: Expr
    right: Expr


Expr = IntLiteral | StrLiteral | BoolLiteral | Ref | UnaryOp | BinOp | BoolOp | Compare

#: Scope words that may lead a reference path. ``this`` is the containing
#: unit, ``parent`` the unit that referenced it, ``root`` the entry unit.
SCOPE_WORDS = frozenset({"this", "parent", "root"})

_BIN_OPS: dict[type[ast.operator], str] = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.FloorDiv: "/",
    ast.Mod: "%",
    ast.LShift: "<<",
    ast.RShift: ">>",
    ast.BitAnd: "&",
    ast.BitOr: "|",
    ast.BitXor: "^",
}

_UNARY_OPS: dict[type[ast.unaryop], str] = {
    ast.USub: "-",
    ast.UAdd: "+",
    ast.Invert: "~",
    ast.Not: "not",
}

_COMPARE_OPS: dict[type[ast.cmpop], str] = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
}

_ORDERING_OPS = frozenset({"<", "<=", ">", ">="})


class Scope(Protocol):
    """What :func:`infer_type` needs in order to type a reference.

    Kept to one method so this module stays free of spec knowledge: the
    implementation in :mod:`kober.check` is what knows about units, fields,
    and declaration order.
    """

    def resolve(self, path: tuple[str, ...]) -> ExprType:
        """Return the type named by ``path``, or raise :class:`ExprError`."""
        ...


def parse(source: str, where: str | None = None) -> Expr:
    """Parse expression text to an AST.

    Args:
        source: The expression as authored.
        where: Dotted path to the field or unit it belongs to, for messages.

    Returns:
        The parsed expression.

    Raises:
        ExprError: If the text is unparseable or uses a construct outside
            the language.

    Example:
        >>> parse("qdcount > 0")
        Compare(op='>', left=Ref(path=('qdcount',)), right=IntLiteral(value=0))

    """
    if not source.strip():
        msg = "empty expression"
        raise ExprError(msg, source, where)
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        msg = f"cannot parse ({exc.msg})"
        raise ExprError(msg, source, where) from exc
    return _translate(tree.body, source, where)


def _translate(node: ast.expr, source: str, where: str | None) -> Expr:
    """Translate one whitelisted Python AST node to ours."""
    if isinstance(node, ast.Constant):
        return _translate_constant(node, source, where)
    if isinstance(node, (ast.Name, ast.Attribute)):
        return Ref(path=_flatten_path(node, source, where))
    if isinstance(node, ast.UnaryOp):
        op = _lookup(_UNARY_OPS, type(node.op), node, source, where)
        return UnaryOp(op=op, operand=_translate(node.operand, source, where))
    if isinstance(node, ast.BinOp):
        op = _lookup(_BIN_OPS, type(node.op), node, source, where)
        return BinOp(
            op=op,
            left=_translate(node.left, source, where),
            right=_translate(node.right, source, where),
        )
    if isinstance(node, ast.BoolOp):
        op = "and" if isinstance(node.op, ast.And) else "or"
        return BoolOp(
            op=op,
            operands=tuple(_translate(value, source, where) for value in node.values),
        )
    if isinstance(node, ast.Compare):
        return _translate_compare(node, source, where)
    msg = f"{_describe(node)} is not allowed in an expression"
    raise ExprError(msg, source, where)


def _translate_constant(node: ast.Constant, source: str, where: str | None) -> Expr:
    """Translate a literal, refusing the types the language has no use for."""
    value = node.value
    # bool before int: bool is a subclass of int, and True is Constant(True).
    if isinstance(value, bool):
        return BoolLiteral(value=value)
    if isinstance(value, int):
        return IntLiteral(value=value)
    if isinstance(value, str):
        return StrLiteral(value=value)
    if isinstance(value, float):
        msg = (
            f"float literal {value!r} is not allowed; the expression language is "
            "integer-only, and '/' is integer division"
        )
        raise ExprError(msg, source, where)
    msg = f"literal {value!r} is not allowed in an expression"
    raise ExprError(msg, source, where)


def _translate_compare(node: ast.Compare, source: str, where: str | None) -> Expr:
    """Translate a comparison, refusing Python's chained form."""
    if len(node.ops) != 1:
        msg = (
            "chained comparison is not allowed; write it as two comparisons "
            "joined with 'and'"
        )
        raise ExprError(msg, source, where)
    op = _lookup(_COMPARE_OPS, type(node.ops[0]), node, source, where)
    return Compare(
        op=op,
        left=_translate(node.left, source, where),
        right=_translate(node.comparators[0], source, where),
    )


def _lookup(
    table: Mapping[Any, str], key: type[ast.AST], node: ast.AST, source: str, where: str | None
) -> str:
    """Look an operator up in its table, refusing it by name if absent."""
    try:
        return table[key]
    except KeyError:
        msg = f"{_describe(node)} is not allowed in an expression"
        raise ExprError(msg, source, where) from None


def _flatten_path(node: ast.expr, source: str, where: str | None) -> tuple[str, ...]:
    """Flatten ``a.b.c`` into ``("a", "b", "c")``."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        msg = "only plain dotted names may be referenced"
        raise ExprError(msg, source, where)
    parts.append(current.id)
    return tuple(reversed(parts))


#: Constructs refused by name, so the message says what the author wrote
#: rather than an AST class name.
_CONSTRUCT_NAMES: dict[type[ast.AST], str] = {
    ast.Call: "a function call",
    ast.Lambda: "a lambda",
    ast.IfExp: "a conditional expression",
    ast.Subscript: "an index or slice",
    ast.ListComp: "a comprehension",
    ast.SetComp: "a comprehension",
    ast.DictComp: "a comprehension",
    ast.GeneratorExp: "a generator",
    ast.List: "a list literal",
    ast.Tuple: "a tuple literal",
    ast.Dict: "a dict literal",
    ast.Set: "a set literal",
    ast.Starred: "unpacking",
    ast.NamedExpr: "an assignment expression",
    ast.Await: "await",
    ast.JoinedStr: "an f-string",
}

#: The operators Python has and this language does not.
_REFUSED_OPS: dict[type[ast.AST], str] = {
    ast.Pow: "**",
    ast.MatMult: "@",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
}


def _describe(node: ast.AST) -> str:
    """Name a refused construct in words an author will recognize."""
    for node_type, name in _CONSTRUCT_NAMES.items():
        if isinstance(node, node_type):
            return name
    # Reached from _lookup, where the node is allowed but its operator is not.
    operators: list[ast.AST] = []
    if isinstance(node, (ast.BinOp, ast.UnaryOp)):
        operators = [node.op]
    elif isinstance(node, ast.Compare):
        operators = list(node.ops)
    for operator in operators:
        symbol = _REFUSED_OPS.get(type(operator))
        if symbol is not None:
            return f"operator {symbol!r}"
    return f"{type(node).__name__}"


def infer_type(expr: Expr, scope: Scope, source: str, where: str | None = None) -> ExprType:
    """Infer an expression's type, resolving references through ``scope``.

    Args:
        expr: The parsed expression.
        scope: Resolver for reference paths.
        source: The expression as authored, for error messages.
        where: Dotted path to the field or unit it belongs to.

    Returns:
        The expression's type.

    Raises:
        ExprError: If a reference is out of scope or an operator is applied
            to the wrong type.

    """
    if isinstance(expr, IntLiteral):
        return ExprType.INT
    if isinstance(expr, StrLiteral):
        return ExprType.STR
    if isinstance(expr, BoolLiteral):
        return ExprType.BOOL
    if isinstance(expr, Ref):
        return scope.resolve(expr.path)
    if isinstance(expr, UnaryOp):
        return _infer_unary(expr, scope, source, where)
    if isinstance(expr, BinOp):
        return _infer_binary(expr, scope, source, where)
    if isinstance(expr, BoolOp):
        return _infer_boolop(expr, scope, source, where)
    return _infer_compare(expr, scope, source, where)


def _require(
    actual: ExprType, wanted: ExprType, context: str, source: str, where: str | None
) -> None:
    """Raise unless ``actual`` is ``wanted``."""
    if actual is not wanted:
        msg = f"{context} needs {wanted.value}, got {actual.value}"
        raise ExprError(msg, source, where)


def _infer_unary(expr: UnaryOp, scope: Scope, source: str, where: str | None) -> ExprType:
    """Type a unary operator."""
    operand = infer_type(expr.operand, scope, source, where)
    wanted = ExprType.BOOL if expr.op == "not" else ExprType.INT
    _require(operand, wanted, f"operator {expr.op!r}", source, where)
    return wanted


def _infer_binary(expr: BinOp, scope: Scope, source: str, where: str | None) -> ExprType:
    """Type an arithmetic or bitwise operator: integers only, both sides."""
    left = infer_type(expr.left, scope, source, where)
    right = infer_type(expr.right, scope, source, where)
    _require(left, ExprType.INT, f"left side of {expr.op!r}", source, where)
    _require(right, ExprType.INT, f"right side of {expr.op!r}", source, where)
    return ExprType.INT


def _infer_boolop(expr: BoolOp, scope: Scope, source: str, where: str | None) -> ExprType:
    """Type ``and``/``or``: every operand must already be boolean.

    No truthiness. A spec saying ``qdcount and ...`` is either a mistake or a
    reliance on a coercion rule this language does not have, and both are
    better reported than guessed at.
    """
    for operand in expr.operands:
        actual = infer_type(operand, scope, source, where)
        _require(actual, ExprType.BOOL, f"operand of {expr.op!r}", source, where)
    return ExprType.BOOL


def _infer_compare(expr: Compare, scope: Scope, source: str, where: str | None) -> ExprType:
    """Type a comparison: ordering is integer-only, equality is same-type."""
    left = infer_type(expr.left, scope, source, where)
    right = infer_type(expr.right, scope, source, where)
    if expr.op in _ORDERING_OPS:
        _require(left, ExprType.INT, f"left side of {expr.op!r}", source, where)
        _require(right, ExprType.INT, f"right side of {expr.op!r}", source, where)
    elif left is not right:
        msg = f"cannot compare {left.value} with {right.value} using {expr.op!r}"
        raise ExprError(msg, source, where)
    return ExprType.BOOL


def references(expr: Expr) -> tuple[Ref, ...]:
    """Return every reference in ``expr``, in source order.

    Used by the checker to enforce that a field only refers to fields already
    decoded when it is reached.

    Args:
        expr: The parsed expression.

    Returns:
        Every :class:`Ref` the expression contains.

    """
    found: list[Ref] = []
    _collect(expr, found)
    return tuple(found)


def _collect(expr: Expr, found: list[Ref]) -> None:
    """Walk ``expr``, appending references in source order."""
    if isinstance(expr, Ref):
        found.append(expr)
    elif isinstance(expr, UnaryOp):
        _collect(expr.operand, found)
    elif isinstance(expr, (BinOp, Compare)):
        _collect(expr.left, found)
        _collect(expr.right, found)
    elif isinstance(expr, BoolOp):
        for operand in expr.operands:
            _collect(operand, found)


def unparse(expr: Expr) -> str:
    """Render an expression back to text, fully parenthesized.

    Not a round-trip of the author's formatting — it is for ``kober show``
    and error messages, where being unambiguous beats being pretty.

    Args:
        expr: The parsed expression.

    Returns:
        The rendered text.

    Example:
        >>> unparse(parse("a + b * 2"))
        '(a + (b * 2))'

    """
    if isinstance(expr, IntLiteral):
        return str(expr.value)
    if isinstance(expr, StrLiteral):
        return repr(expr.value)
    if isinstance(expr, BoolLiteral):
        return "true" if expr.value else "false"
    if isinstance(expr, Ref):
        return ".".join(expr.path)
    if isinstance(expr, UnaryOp):
        space = " " if expr.op == "not" else ""
        return f"({expr.op}{space}{unparse(expr.operand)})"
    if isinstance(expr, BoolOp):
        joined = f" {expr.op} ".join(unparse(operand) for operand in expr.operands)
        return f"({joined})"
    return f"({unparse(expr.left)} {expr.op} {unparse(expr.right)})"
