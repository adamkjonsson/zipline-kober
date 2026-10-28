"""Tests for the expression language."""

from __future__ import annotations

import pytest

from kober.errors import EvalError, ExprError
from kober.expr import (
    BinOp,
    BoolLiteral,
    BoolOp,
    Compare,
    ExprType,
    Index,
    IntLiteral,
    MapType,
    Ref,
    Scope,
    StrLiteral,
    UnaryOp,
    evaluate,
    infer_type,
    map_entry,
    parse,
    references,
    unparse,
)
from kober.source import Location


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


def test_a_field_named_like_a_python_keyword_cannot_be_referenced():
    """A consequence of borrowing `ast.parse`, and worth knowing rather than finding.

    The spec model accepts a field called `class`; an expression cannot name it,
    because the text never reaches this module's whitelist — Python's parser
    refuses it first. The compiler maps such a field to `class_`, so it is
    reachable from generated code and from a consumer, just not from a spec.
    """
    with pytest.raises(ExprError, match="cannot parse"):
        parse("header.class")


def test_the_documented_boolean_literals_are_literals():
    """The literals the format reference documents, which used to be references.

    `docs/format/expressions.md` lists `true` and `false` among the literals.
    Borrowing Python's parser made them names, so a spec writing them got a
    field lookup and a confusing error.
    """
    assert parse("true") == BoolLiteral(True)
    assert parse("false") == BoolLiteral(False)
    assert parse("True") == BoolLiteral(True)
    assert parse("a.true") == Ref(("a", "true"))


def test_reference_paths():
    assert parse("length") == Ref(("length",))
    assert parse("this.header.length") == Ref(("this", "header", "length"))
    assert parse("root.id") == Ref(("root", "id"))
    assert parse("parent.count") == Ref(("parent", "count"))


def test_precedence_follows_python():
    assert unparse(parse("a + b * 2")) == "a + b * 2"
    assert unparse(parse("(a + b) * 2")) == "(a + b) * 2"
    assert unparse(parse("a < b and c > d")) == "a < b and c > d"


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
        ("abs(x)", "not one of the expression language's functions"),
        ("a ** 2", "'**'"),
        ("a @ b", "'@'"),
        ("a is b", "'is'"),
        ("a in b", "'in'"),
        ("1 < b < 3", "chained comparison"),
        ("[1, 2]", "list literal"),
        ("(1, 2)", "tuple literal"),
        ("{1: 2}", "dict literal"),
        ("x[0:1]", "slice"),
        ("x[0, 1]", "one expression"),
        ("a.b[0]", "only a map parameter"),
        ("this[0]", "only a map parameter"),
        ("f(x)[0]", "only a map parameter"),
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
    where = Location("dns.message.size")
    with pytest.raises(ExprError) as caught:
        parse("abs(x)", where=where)
    assert caught.value.source == "abs(x)"
    assert caught.value.loc == where
    assert "dns.message.size" in str(caught.value)


def test_the_location_puts_the_line_in_front_of_the_message():
    """An expression fault reads like every other one: file, line, path, why."""
    where = Location("dns.message.size", line=27, source="dns.yaml")
    with pytest.raises(ExprError) as caught:
        parse("abs(x)", where=where)
    assert str(caught.value).startswith("dns.yaml:27: dns.message.size: ")


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


def test_unparse_groups_only_what_needs_grouping():
    assert unparse(parse("a + b + c")) == "a + b + c"
    assert unparse(parse("a - (b - c)")) == "a - (b - c)"
    assert unparse(parse("not a")) == "not a"
    assert unparse(parse("True")) == "true"
    assert unparse(parse("'x'")) == "'x'"


def test_a_nested_comparison_keeps_its_parentheses():
    """Dropping them would come back as a chain, which the parser refuses."""
    assert unparse(parse("(a == b) == c")) == "(a == b) == c"


@pytest.mark.parametrize(
    "source",
    [
        "a + b * 2",
        "(a + b) * 2",
        "a - b - c",
        "a - (b - c)",
        "a / b % c",
        "a / (b % c)",
        "a << b + c",
        "(a << b) + c",
        "a | b & c",
        "(a | b) & c",
        "a ^ b | c",
        "not a == b",
        "(not a) == b",
        "a and b or not c",
        "a and (b or c)",
        "-a * ~b",
        "-(a * b)",
        "x.y.z > 3",
        "true",
        "false and a > 1",
        "(a == b) == c",
        "a % b * c",
        "a * (b % c)",
        "1 + 2 * 3 - 4 / 5 % 6",
        "(a > 1 or b > 2) and not c",
    ],
)
def test_what_unparse_writes_parses_back_to_the_same_tree(source: str):
    """The property the parentheses exist for, over every shape that has them.

    Minimal grouping is only safe if it is *sufficient*, and the way to know
    that is to read the text back rather than to reason about the table.
    """
    tree = parse(source)
    assert parse(unparse(tree)) == tree


# --- functions -------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "to_int(s)",
        "to_int(s, 16)",
        "lower(name)",
        "to_int(s) + 1",
        "lower(a) == 'x'",
        "trim(s)",
        "trim(lower(a)) == 'x'",
        "startswith(s, 'HTTP/')",
        "endswith(trim(lower(s)), 'chunked')",
        "not startswith(s, 'x') and endswith(s, 'y')",
        "to_int(before(s, ';'), 16)",
    ],
)
def test_a_call_round_trips(source: str):
    """`unparse` has to produce something that parses back to the same tree."""
    assert parse(unparse(parse(source))) == parse(source)


def test_a_call_is_an_atom_and_needs_no_brackets():
    assert unparse(parse("to_int(s) * 2")) == "to_int(s) * 2"
    assert unparse(parse("to_int(a + b)")) == "to_int(a + b)"


@pytest.mark.parametrize(
    ("source", "fragment"),
    [
        ("abs(x)", "not one of the expression language's functions"),
        ("s.lower()", "not one of the expression language's functions"),
        ("to_int()", "takes 1 or 2 argument(s), got 0"),
        ("to_int(a, 16, 2)", "takes 1 or 2 argument(s), got 3"),
        ("lower(a, b)", "takes 1 argument(s), got 2"),
        ("startswith(a)", "takes 2 argument(s), got 1"),
        ("endswith(a, b, c)", "takes 2 argument(s), got 3"),
        ("before(a)", "takes 2 argument(s), got 1"),
        ("to_int(a, base=16)", "positional arguments only"),
    ],
)
def test_a_call_outside_the_table_is_refused(source: str, fragment: str):
    """The table is closed, and matched by name — nothing is built from a spec."""
    with pytest.raises(ExprError) as caught:
        parse(source)
    assert fragment in str(caught.value)


def test_the_refusal_names_what_does_exist():
    with pytest.raises(ExprError) as caught:
        parse("upper(x)")
    assert "lower()" in str(caught.value)
    assert "to_int()" in str(caught.value)


@pytest.mark.parametrize(
    ("source", "called"),
    [
        ("a.len(body) == 4", "'a.len'"),
        ("keys[0](x)", "'keys[0]'"),
        ("(1)(x)", "'1'"),
        ('"s"(x)', "\"'s'\""),
        ("(a + b)(x)", "'a + b'"),
        ("f(x)(y)", "'f(x)'"),
        ("lower(tag)(1)", "'lower(tag)'"),
    ],
)
def test_a_refused_callee_is_named_as_written(source: str, called: str):
    """Not by the AST class it parses to, which the author never wrote (#57)."""
    with pytest.raises(ExprError) as caught:
        parse(source)
    message = str(caught.value)
    assert f"{called} is not one of the expression language's functions" in message
    for name in ("Attribute", "Subscript", "Constant", "BinOp", "Call"):
        assert name not in message
    assert "a function call" not in message


@pytest.mark.parametrize(
    ("source", "advice"),
    [
        ("tag.lower() == 'abc'", "write lower(tag)"),
        ("this.len(body)", "write len(this, body)"),
        ("a.b.startswith('x')", "write startswith(a.b, 'x')"),
        ("s.to_int(16)", "write to_int(s, 16)"),
    ],
)
def test_a_method_spelling_of_a_function_says_how_to_write_it(source: str, advice: str):
    """`tag.lower()` is the likeliest way to meet the refusal, from Python (#58)."""
    with pytest.raises(ExprError) as caught:
        parse(source)
    message = str(caught.value)
    assert "a method call is not allowed" in message
    assert advice in message


def test_a_method_that_is_not_a_function_gets_the_list_instead():
    with pytest.raises(ExprError) as caught:
        parse("tag.upper()")
    message = str(caught.value)
    assert "'tag.upper' is not one of the expression language's functions" in message
    assert "there are only" in message
    assert "method" not in message


@pytest.mark.parametrize(
    ("source", "fragment"),
    [
        ("(yield x)", "yield is not allowed"),
        ("(yield from x)", "yield is not allowed"),
    ],
)
def test_a_yield_is_refused_in_words(source: str, fragment: str):
    with pytest.raises(ExprError) as caught:
        parse(source)
    assert fragment in str(caught.value)
    assert "Yield" not in str(caught.value)


class _Values:
    def __init__(self, **values: object) -> None:
        self.values = values

    def lookup(self, path: tuple[str, ...]) -> object:
        return self.values[path[0]]


@pytest.mark.parametrize(
    ("source", "text", "expected"),
    [
        ("to_int(s)", "1234", 1234),
        ("to_int(s)", "  1234  ", 1234),
        ("to_int(s)", "-5", -5),
        ("to_int(s)", "+5", 5),
        ("to_int(s, 16)", "1a2b", 0x1A2B),
        ("to_int(s, 16)", "776", 0x776),
        ("to_int(s, 2)", "1011", 0b1011),
        ("lower(s)", "Chunked", "chunked"),
        ("lower(s)", "CHUNKED", "chunked"),
        ("trim(s)", " chunked", "chunked"),
        ("trim(s)", "chunked ", "chunked"),
        ("trim(s)", "\t chunked \r\n", "chunked"),
        ("trim(s)", "chunked", "chunked"),
        ("trim(s)", "   ", ""),
        ("trim(lower(s))", " Chunked ", "chunked"),
        ("startswith(s, 'HTTP/')", "HTTP/1.1 200 OK", True),
        ("startswith(s, 'HTTP/')", "GET / HTTP/1.1", False),
        ("startswith(s, 'http/')", "HTTP/1.1 200 OK", False),
        ("startswith(s, '')", "anything", True),
        ("startswith(s, 'longer than s')", "short", False),
        ("endswith(s, 'HTTP/1.1')", "GET / HTTP/1.1", True),
        ("endswith(s, 'HTTP/1.1')", "HTTP/1.1 200 OK", False),
        ("endswith(trim(lower(s)), 'chunked')", "gzip, Chunked ", True),
        ("endswith(s, '')", "", True),
        ("before(s, ';')", "4;name=value", "4"),
        ("before(s, ';')", "4", "4"),
        ("before(s, ';')", "4;a=1;b=2", "4"),
        ("before(s, ';')", ";x", ""),
        ("before(s, ';')", "", ""),
        ("before(s, '')", "anything", ""),
        ("before(s, '\\r\\n')", "a\r\nb", "a"),
        ("to_int(before(s, ';'), 16)", "1A ;ext", 0x1A),
    ],
)
def test_calls_evaluate(source: str, text: str, expected: object):
    assert evaluate(parse(source), _Values(s=text)) == expected


@pytest.mark.parametrize(
    "text",
    ["", "   ", "abc", "1_0", "0x10", "12.5", "1 2", "١٢٣"],
)
def test_to_int_refuses_what_is_not_a_number(text: str):
    """Stricter than Python's `int`, on purpose.

    `int("1_0")` is ten, and reading a malformed wire length as a plausible
    number is the failure mode this project exists to avoid. The refusal is an
    `EvalError`, which the decoder turns into an undecodable region.
    """
    with pytest.raises(EvalError, match="cannot read"):
        evaluate(parse("to_int(s)"), _Values(s=text))


def test_to_int_refuses_a_hex_prefix_even_in_base_16():
    with pytest.raises(EvalError, match="cannot read"):
        evaluate(parse("to_int(s, 16)"), _Values(s="0x10"))


def test_to_int_refuses_an_unusable_base():
    with pytest.raises(EvalError, match="base must be"):
        evaluate(parse("to_int(s, 99)"), _Values(s="10"))


def test_to_int_refuses_a_digit_its_base_does_not_have():
    with pytest.raises(EvalError, match="cannot read"):
        evaluate(parse("to_int(s, 2)"), _Values(s="12"))


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("to_int(s)", ExprType.INT),
        ("to_int(s, 16)", ExprType.INT),
        ("lower(s)", ExprType.STR),
        ("trim(s)", ExprType.STR),
        ("startswith(s, 'x')", ExprType.BOOL),
        ("endswith(s, s)", ExprType.BOOL),
        ("before(s, s)", ExprType.STR),
    ],
)
def test_a_call_has_the_type_its_table_row_says(source: str, expected: ExprType):
    assert infer_type(parse(source), FakeScope(s=ExprType.STR), source) is expected


@pytest.mark.parametrize(
    ("source", "scope", "fragment"),
    [
        ("to_int(n)", {"n": ExprType.INT}, "argument 1 of to_int()"),
        ("lower(n)", {"n": ExprType.INT}, "argument 1 of lower()"),
        ("trim(n)", {"n": ExprType.INT}, "argument 1 of trim()"),
        ("to_int(s, s)", {"s": ExprType.STR}, "argument 2 of to_int()"),
        ("startswith(n, 'x')", {"n": ExprType.INT}, "argument 1 of startswith()"),
        ("endswith(s, n)", {"s": ExprType.STR, "n": ExprType.INT}, "argument 2 of endswith()"),
        ("before(n, ';')", {"n": ExprType.INT}, "argument 1 of before()"),
        ("before(s, n)", {"s": ExprType.STR, "n": ExprType.INT}, "argument 2 of before()"),
    ],
)
def test_a_call_checks_its_argument_types(source: str, scope: dict, fragment: str):
    with pytest.raises(ExprError, match=fragment.replace("(", r"\(").replace(")", r"\)")):
        infer_type(parse(source), FakeScope(**scope), source)


def test_a_call_reports_the_references_inside_it():
    """The checker's forward-reference rule has to see through an argument."""
    assert [ref.path for ref in references(parse("to_int(a.b, c)"))] == [("a", "b"), ("c",)]


# --- an entry of a map parameter ---------------------------------------------


class _MapScope(FakeScope):
    """A scope that also knows map parameters."""

    def __init__(self, maps: dict[str, MapType], **names: ExprType) -> None:
        super().__init__(**names)
        self._maps = maps

    def resolve_map(self, name: str) -> MapType:
        if name not in self._maps:
            msg = f"unknown map parameter {name!r}"
            raise ExprError(msg, name)
        return self._maps[name]


class _Tables(_Values):
    def __init__(self, tables: dict[str, dict[object, object]], **values: object) -> None:
        super().__init__(**values)
        self.tables = tables

    def lookup_map(self, name: str) -> dict[object, object]:
        return self.tables[name]


KEYS = MapType(ExprType.INT, ExprType.BYTES)


def test_an_index_parses_to_a_named_table_and_a_key_expression():
    assert parse("keys[receiver + 1]") == Index(
        "keys", BinOp("+", Ref(("receiver",)), IntLiteral(1))
    )


@pytest.mark.parametrize(
    "source", ["keys[receiver]", "keys[a + 1] == b", "lower(names[peer])", "keys[keys2[a]]"]
)
def test_an_index_round_trips(source: str):
    assert parse(unparse(parse(source))) == parse(source)
    assert unparse(parse(source)) == source


def test_an_index_is_an_atom_and_needs_no_brackets():
    assert unparse(parse("(keys[a]) == b")) == "keys[a] == b"


def test_an_index_has_the_maps_value_type():
    scope = _MapScope({"keys": KEYS}, receiver=ExprType.INT)
    assert infer_type(parse("keys[receiver]"), scope, "keys[receiver]") is ExprType.BYTES


def test_an_index_checks_its_key_against_the_maps_key_type():
    scope = _MapScope({"keys": KEYS}, name=ExprType.STR)
    with pytest.raises(ExprError) as caught:
        infer_type(parse("keys[name]"), scope, "keys[name]")
    assert "the key of 'keys' needs int, got str" in str(caught.value)


def test_an_index_names_the_field_it_was_chosen_by_and_not_the_table():
    """The key is what chose the entry, so it is cited; the table is a parameter."""
    assert references(parse("keys[receiver]")) == (Ref(("receiver",)),)


def test_an_index_evaluates_to_the_entry():
    env = _Tables({"keys": {7: b"seven"}}, receiver=7)
    assert evaluate(parse("keys[receiver]"), env) == b"seven"


def test_a_missing_entry_names_the_key_and_never_a_value():
    with pytest.raises(EvalError) as caught:
        map_entry({1: b"secret-key"}, 2, "keys")
    assert str(caught.value) == "'keys' has no entry for 2"
    assert "secret" not in str(caught.value)


# --- len ---------------------------------------------------------------------------------------


def test_len_is_the_bytes_length_and_an_int():
    assert typed("len(sealed)", sealed=ExprType.BYTES) is ExprType.INT
    assert evaluate(parse("len(sealed) == 16"), _Values(sealed=b"\x00" * 16)) is True


def test_len_takes_bytes_only():
    with pytest.raises(ExprError) as caught:
        typed("len(name)", name=ExprType.STR)
    assert "argument 1 of len() needs bytes, got str" in str(caught.value)
