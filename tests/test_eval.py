"""Tests for expression evaluation."""

from __future__ import annotations

import pytest

from kober.errors import EvalError
from kober.expr import (
    MAX_SHIFT,
    Environment,
    ExprType,
    ExprValue,
    evaluate,
    infer_type,
    parse,
)


class FakeEnv:
    """An environment backed by a mapping from dotted path to value."""

    def __init__(self, **values: ExprValue) -> None:
        self._values = values
        self.reads: list[str] = []

    def lookup(self, path: tuple[str, ...]) -> ExprValue:
        key = "_".join(path)
        self.reads.append(".".join(path))
        if key not in self._values:
            msg = f"unknown name {'.'.join(path)}"
            raise EvalError(msg)
        return self._values[key]


def value(source: str, **names: ExprValue) -> ExprValue:
    env: Environment = FakeEnv(**names)
    return evaluate(parse(source), env)


# --- literals and references ----------------------------------------------


def test_literals():
    assert value("42") == 42
    assert value("0x10") == 16
    assert value("'tcp'") == "tcp"
    assert value("True") is True
    assert value("False") is False


def test_references():
    assert value("length", length=16) == 16
    assert value("this.header.length", this_header_length=9) == 9


def test_unknown_reference_raises():
    with pytest.raises(EvalError, match="unknown name"):
        value("mystery")


# --- arithmetic ------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("2 + 3", 5),
        ("7 - 2", 5),
        ("3 * 4", 12),
        ("7 / 2", 3),
        ("7 % 2", 1),
        ("1 << 4", 16),
        ("256 >> 4", 16),
        ("0b1100 & 0b1010", 0b1000),
        ("0b1100 | 0b1010", 0b1110),
        ("0b1100 ^ 0b1010", 0b0110),
        ("-5", -5),
        ("+5", 5),
        ("~0", -1),
        ("2 + 3 * 4", 14),
        ("(2 + 3) * 4", 20),
    ],
)
def test_arithmetic(source: str, expected: int):
    assert value(source) == expected


def test_the_motivating_case():
    """A length in 32-bit words, which is why Computed exists."""
    assert value("data_offset * 4", data_offset=5) == 20


def test_slash_and_double_slash_are_the_same_operator():
    assert value("7 / 2") == value("7 // 2") == 3


def test_division_floors_on_negatives():
    """Documented: floor, matching the `//` spelling folded into `/`."""
    assert value("-7 / 2") == -4


# --- the non-total cases ---------------------------------------------------


def test_division_by_zero():
    with pytest.raises(EvalError, match="division by zero"):
        value("4 / n", n=0)


def test_modulo_by_zero():
    with pytest.raises(EvalError, match="modulo by zero"):
        value("4 % n", n=0)


def test_negative_shift_count():
    with pytest.raises(EvalError, match="negative shift count"):
        value("1 << n", n=-1)


def test_absurd_shift_count_is_refused_not_computed():
    """A shift amount can come off the wire; 1 << 2**32 is a memory bug."""
    with pytest.raises(EvalError, match="exceeds the"):
        value("1 << n", n=2**32)


def test_shift_at_the_limit_is_allowed():
    assert value("1 << n", n=MAX_SHIFT) == 1 << MAX_SHIFT


def test_eval_error_is_not_a_spec_error():
    """The spec is fine; this packet is not. Blaming the spec misdirects."""
    from kober.errors import SpecError

    with pytest.raises(EvalError) as caught:
        value("4 / n", n=0)
    assert not isinstance(caught.value, SpecError)


# --- comparison and boolean ------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("1 == 1", True),
        ("1 != 1", False),
        ("1 < 2", True),
        ("2 <= 2", True),
        ("3 > 4", False),
        ("4 >= 4", True),
        ("'a' == 'a'", True),
        ("'a' != 'b'", True),
    ],
)
def test_comparison(source: str, expected: bool):
    assert value(source) is expected


def test_boolean_operators():
    assert value("True and True") is True
    assert value("True and False") is False
    assert value("False or True") is True
    assert value("False or False") is False
    assert value("not True") is False


def test_and_short_circuits():
    """Load-bearing: the language has no `if`, so this is the only guard."""
    env = FakeEnv(n=0)
    assert evaluate(parse("n != 0 and 100 / n > 5"), env) is False


def test_or_short_circuits():
    env = FakeEnv(n=0)
    assert evaluate(parse("n == 0 or 100 / n > 5"), env) is True


def test_short_circuit_does_not_read_the_right_side():
    env = FakeEnv(a=False, b=True)
    evaluate(parse("a and b"), env)
    assert env.reads == ["a"]


def test_without_short_circuit_the_guard_would_raise():
    """The guard only works because the right side goes unevaluated."""
    with pytest.raises(EvalError, match="division by zero"):
        value("100 / n > 5", n=0)


# --- operand guards --------------------------------------------------------


def test_string_repetition_is_refused_not_improvised():
    """Python would make 'ab' * 3 a string; here it is a type error."""
    with pytest.raises(EvalError, match="needs an integer, got str"):
        value("a * 3", a="ab")


def test_booleans_are_not_integers_in_arithmetic():
    with pytest.raises(EvalError, match="needs an integer, got bool"):
        value("a + 1", a=True)


def test_ordering_refuses_non_integers():
    with pytest.raises(EvalError, match="needs an integer, got str"):
        value("a < b", a="x", b="y")


def test_boolean_operators_refuse_truthiness():
    with pytest.raises(EvalError, match="needs a boolean, got int"):
        value("a and True", a=1)


def test_not_refuses_non_boolean():
    with pytest.raises(EvalError, match="needs a boolean, got int"):
        value("not a", a=1)


# --- evaluation agrees with the checker's typing ---------------------------

TYPED_NAMES = {"n": 7, "m": 2, "s": "tcp", "flag": True, "raw": b"\r\n"}
TYPES = {
    "n": ExprType.INT,
    "m": ExprType.INT,
    "s": ExprType.STR,
    "flag": ExprType.BOOL,
    "raw": ExprType.BYTES,
}

PYTHON_TYPE = {
    ExprType.INT: int,
    ExprType.STR: str,
    ExprType.BOOL: bool,
    ExprType.BYTES: bytes,
}


class TypeScope:
    def resolve(self, path: tuple[str, ...]) -> ExprType:
        return TYPES[path[-1]]


@pytest.mark.parametrize(
    "source",
    [
        "n + m",
        "n * 4 - m",
        "n / m",
        "n % m",
        "n << 1",
        "n > m",
        "n == m",
        "s == 'tcp'",
        "raw == raw",
        "flag",
        "not flag",
        "flag and n > m",
        "flag or s == 'udp'",
        "(n + m) * 2",
        "~n & 0xFF",
    ],
)
def test_inferred_type_matches_evaluated_value(source: str):
    """The two halves of the language must agree, or check() proves nothing.

    A spec's expressions are typed before any data exists; if evaluation then
    produced a different kind, every guarantee the checker offers would be
    void at exactly the moment it mattered.
    """
    tree = parse(source)
    inferred = infer_type(tree, TypeScope(), source)
    produced = evaluate(tree, FakeEnv(**TYPED_NAMES))
    # bool before int: bool subclasses int, so the loose check would pass a
    # boolean off as an integer.
    assert type(produced) is PYTHON_TYPE[inferred]


def test_bytes_equality():
    assert value("a == b", a=b"\r\n", b=b"\r\n") is True


def test_nested_expression():
    assert value("(a + b) * 2 - c", a=3, b=4, c=5) == 9


def test_deeply_nested_evaluates():
    assert value("((a * 2) + (b * 3)) % 7", a=5, b=4) == (10 + 12) % 7
