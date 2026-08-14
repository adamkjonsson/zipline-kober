"""Tests for the expression language."""

from __future__ import annotations

import pytest

from kober.errors import ExprError
from kober.expr import (
    BinOp,
    BoolLiteral,
    BoolOp,
    Compare,
    ExprType,
    IntLiteral,
    Ref,
    Scope,
    StrLiteral,
    UnaryOp,
    infer_type,
    parse,
    references,
    unparse,
)


class FakeScope:
    """A scope backed by a plain mapping from dotted path to type."""

    def __init__(self, **names: ExprType) -> None:
        self._names = names

    def resolve(self, path: tuple[str, ...]) -> ExprType:
        key = "_".join(path)
        if key not in self._names:
            msg = f"unknown name {'.'.join(path)}"
            raise ExprError(msg, ".".join(path))
        return self._names[key]


def typed(source: str, **names: ExprType) -> ExprType:
    scope: Scope = FakeScope(**names)
    return infer_type(parse(source), scope, source)


# --- parsing ---------------------------------------------------------------


def test_literals():
    assert parse("42") == IntLiteral(42)
    assert parse("0x10") == IntLiteral(16)
    assert parse("'tcp'") == StrLiteral("tcp")
    assert parse("True") == BoolLiteral(True)
    assert parse("False") == BoolLiteral(False)


def test_reference_paths():
    assert parse("length") == Ref(("length",))
    assert parse("this.header.length") == Ref(("this", "header", "length"))
    assert parse("root.id") == Ref(("root", "id"))
    assert parse("parent.count") == Ref(("parent", "count"))


def test_precedence_follows_python():
    assert unparse(parse("a + b * 2")) == "(a + (b * 2))"
    assert unparse(parse("(a + b) * 2")) == "((a + b) * 2)"
    assert unparse(parse("a < b and c > d")) == "((a < b) and (c > d))"


def test_operators_translate():
    assert parse("1 + 2") == BinOp("+", IntLiteral(1), IntLiteral(2))
    assert parse("-x") == UnaryOp("-", Ref(("x",)))
    assert parse("not x") == UnaryOp("not", Ref(("x",)))
    assert parse("a == b") == Compare("==", Ref(("a",)), Ref(("b",)))
    assert parse("a and b") == BoolOp("and", (Ref(("a",)), Ref(("b",))))


def test_slash_is_integer_division():
    """Both spellings mean the same thing; there are no floats to divide."""
    assert parse("a / 2") == parse("a // 2")
    assert parse("a / 2").op == "/"


@pytest.mark.parametrize(
    ("source", "fragment"),
    [
        ("len(x)", "function call"),
        ("a ** 2", "'**'"),
        ("a @ b", "'@'"),
        ("a is b", "'is'"),
        ("a in b", "'in'"),
        ("1 < b < 3", "chained comparison"),
        ("[1, 2]", "list literal"),
        ("(1, 2)", "tuple literal"),
        ("{1: 2}", "dict literal"),
        ("x[0]", "index or slice"),
        ("x if y else z", "conditional expression"),
        ("lambda: 1", "lambda"),
        ("f'{x}'", "f-string"),
        ("1.5", "float literal"),
        ("", "empty expression"),
        ("a +", "cannot parse"),
    ],
)
def test_refused_constructs(source: str, fragment: str):
    with pytest.raises(ExprError) as caught:
        parse(source)
    assert fragment in str(caught.value)


def test_error_carries_source_and_location():
    with pytest.raises(ExprError) as caught:
        parse("len(x)", where="dns.message.size")
    assert caught.value.source == "len(x)"
    assert caught.value.where == "dns.message.size"
    assert "dns.message.size" in str(caught.value)


# --- typing ----------------------------------------------------------------


def test_literal_types():
    assert typed("1") is ExprType.INT
    assert typed("'a'") is ExprType.STR
    assert typed("True") is ExprType.BOOL


def test_reference_type_comes_from_scope():
    assert typed("length", length=ExprType.INT) is ExprType.INT
    assert typed("name", name=ExprType.STR) is ExprType.STR


def test_arithmetic_is_integer_only():
    assert typed("a * 4", a=ExprType.INT) is ExprType.INT
    with pytest.raises(ExprError, match="needs int, got str"):
        typed("a * 4", a=ExprType.STR)


def test_comparison_yields_bool():
    assert typed("a > 1", a=ExprType.INT) is ExprType.BOOL
    assert typed("a == 'x'", a=ExprType.STR) is ExprType.BOOL


def test_ordering_refuses_strings():
    with pytest.raises(ExprError, match="needs int, got str"):
        typed("a < b", a=ExprType.STR, b=ExprType.STR)


def test_equality_refuses_mixed_types():
    with pytest.raises(ExprError, match="cannot compare int with str"):
        typed("a == b", a=ExprType.INT, b=ExprType.STR)


def test_boolean_operators_refuse_truthiness():
    """An int operand is a mistake or a coercion we do not have. Say so."""
    with pytest.raises(ExprError, match="needs bool, got int"):
        typed("a and b", a=ExprType.INT, b=ExprType.BOOL)


def test_not_requires_bool():
    assert typed("not a", a=ExprType.BOOL) is ExprType.BOOL
    with pytest.raises(ExprError, match="needs bool, got int"):
        typed("not a", a=ExprType.INT)


def test_unknown_reference_raises():
    with pytest.raises(ExprError, match="unknown name"):
        typed("mystery + 1")


def test_dotted_reference_resolves_whole_path():
    assert typed("this.flags.qr == 1", this_flags_qr=ExprType.INT) is ExprType.BOOL


# --- helpers ---------------------------------------------------------------


def test_references_in_source_order():
    found = references(parse("a + this.b.c * root.d"))
    assert [ref.path for ref in found] == [("a",), ("this", "b", "c"), ("root", "d")]


def test_references_of_a_literal_is_empty():
    assert references(parse("42")) == ()


def test_unparse_is_fully_parenthesized():
    assert unparse(parse("a + b + c")) == "((a + b) + c)"
    assert unparse(parse("not a")) == "(not a)"
    assert unparse(parse("True")) == "true"
    assert unparse(parse("'x'")) == "'x'"
