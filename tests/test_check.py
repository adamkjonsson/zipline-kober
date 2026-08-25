"""Tests for whole-spec validation."""

from __future__ import annotations

import pytest

from kober.check import Severity, check
from kober.expr import ExprType, parse
from kober.spec import (
    BytesType,
    Computed,
    Count,
    EnumDef,
    Field,
    FieldType,
    Fixed,
    FromExpr,
    IntType,
    Param,
    Pointer,
    Remaining,
    Spec,
    StringType,
    Switch,
    Unit,
    UnitRef,
    Until,
)


def build(units: list[Unit], *, entry: str = "message", **kwargs: object) -> Spec:
    return Spec(
        name="dns",
        version="1.0",
        entry=entry,
        units={unit.name: unit for unit in units},
        **kwargs,  # type: ignore[arg-type]
    )


def errors(spec: Spec) -> list[str]:
    return [f.message for f in check(spec) if f.severity is Severity.ERROR]


def warnings(spec: Spec) -> list[str]:
    return [f.message for f in check(spec) if f.severity is Severity.WARNING]


def only_error(spec: Spec) -> str:
    found = errors(spec)
    assert len(found) == 1, f"expected exactly one error, got {found}"
    return found[0]


# --- a valid spec produces nothing ----------------------------------------


def test_valid_spec_has_no_findings():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="id", type=IntType(bits=16)),
                    Field(name="qdcount", type=IntType(bits=16)),
                    Field(
                        name="body",
                        type=BytesType(size=FromExpr(parse("qdcount * 2"))),
                        condition=parse("qdcount > 0"),
                    ),
                ],
            )
        ]
    )
    assert check(spec) == ()


# --- structure -------------------------------------------------------------


def test_entry_must_exist():
    spec = build([Unit(name="other", fields=[])], entry="missing")
    assert "does not exist" in only_error(spec)


def test_entry_must_not_take_parameters():
    unit = Unit(name="message", fields=[], params=[Param(name="n", type=ExprType.INT)])
    assert "cannot take parameters" in only_error(build([unit]))


def test_unknown_unit_reference():
    unit = Unit(name="message", fields=[Field(name="h", type=UnitRef(unit="nope"))])
    assert "unknown unit 'nope'" in only_error(build([unit]))


def test_unknown_enum():
    unit = Unit(name="message", fields=[Field(name="op", type=IntType(bits=4, enum="nope"))])
    assert "unknown enum 'nope'" in only_error(build([unit]))


def test_known_enum_passes():
    spec = build(
        [Unit(name="message", fields=[Field(name="op", type=IntType(bits=4, enum="opcode"))])],
        enums={"opcode": EnumDef(name="opcode", members={0: "query"})},
    )
    assert check(spec) == ()


def test_unreachable_unit_warns():
    spec = build(
        [
            Unit(name="message", fields=[Field(name="id", type=IntType(bits=8))]),
            Unit(name="orphan", fields=[Field(name="x", type=IntType(bits=8))]),
        ]
    )
    assert any("never referenced" in w for w in warnings(spec))
    assert errors(spec) == []


def test_empty_unit_warns():
    spec = build([Unit(name="message", fields=[])])
    assert any("no fields" in w for w in warnings(spec))


def test_left_recursion_is_refused():
    """A unit whose first field is itself can never consume input."""
    unit = Unit(name="message", fields=[Field(name="inner", type=UnitRef(unit="message"))])
    assert "cannot terminate" in only_error(build([unit]))


def test_mutual_left_recursion_is_refused():
    spec = build(
        [
            Unit(name="message", fields=[Field(name="a", type=UnitRef(unit="other"))]),
            Unit(name="other", fields=[Field(name="b", type=UnitRef(unit="message"))]),
        ]
    )
    assert any("cannot terminate" in e for e in errors(spec))


def test_recursion_after_a_consuming_field_is_allowed():
    """Nested structures need recursion; only the guaranteed case is refused."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="len", type=IntType(bits=8)),
                    Field(name="next", type=UnitRef(unit="message"), condition=parse("len > 0")),
                ],
            )
        ]
    )
    assert errors(spec) == []


# --- ordering and scoping --------------------------------------------------


def test_forward_reference_is_refused():
    unit = Unit(
        name="message",
        fields=[
            Field(name="body", type=BytesType(size=FromExpr(parse("length")))),
            Field(name="length", type=IntType(bits=16)),
        ],
    )
    assert "declared later" in only_error(build([unit]))


def test_unknown_name_lists_what_is_in_scope():
    unit = Unit(
        name="message",
        fields=[
            Field(name="length", type=IntType(bits=16)),
            Field(name="body", type=BytesType(size=FromExpr(parse("mystery")))),
        ],
    )
    message = only_error(build([unit]))
    assert "unknown name 'mystery'" in message
    assert "in scope: length" in message


def test_anonymous_fields_are_not_referenceable():
    unit = Unit(
        name="message",
        fields=[
            Field(name=None, type=IntType(bits=8)),
            Field(name="body", type=BytesType(size=FromExpr(parse("padding")))),
        ],
    )
    assert "unknown name 'padding'" in only_error(build([unit]))


def test_this_prefix_is_the_same_as_a_bare_name():
    unit = Unit(
        name="message",
        fields=[
            Field(name="length", type=IntType(bits=16)),
            Field(name="body", type=BytesType(size=FromExpr(parse("this.length")))),
        ],
    )
    assert check(build([unit])) == ()


def test_nested_unit_field_is_reachable():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="header", type=UnitRef(unit="header")),
                    Field(name="body", type=BytesType(size=FromExpr(parse("header.length")))),
                ],
            ),
            Unit(name="header", fields=[Field(name="length", type=IntType(bits=16))]),
        ]
    )
    assert check(spec) == ()


def test_reference_into_a_non_unit_is_refused():
    unit = Unit(
        name="message",
        fields=[
            Field(name="length", type=IntType(bits=16)),
            Field(name="body", type=BytesType(size=FromExpr(parse("length.inner")))),
        ],
    )
    assert "is not a unit" in only_error(build([unit]))


def test_repeated_field_has_no_list_type():
    unit = Unit(
        name="message",
        fields=[
            Field(name="items", type=IntType(bits=8), repeat=Count(parse("2"))),
            Field(name="body", type=BytesType(size=FromExpr(parse("items")))),
        ],
    )
    assert "has no list type" in only_error(build([unit]))


def test_switch_field_cannot_be_referenced_directly():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="kind", type=IntType(bits=8)),
                    Field(
                        name="payload",
                        type=Switch(on=parse("kind"), cases={1: IntType(bits=8)}, default=None),
                    ),
                    Field(name="body", type=BytesType(size=FromExpr(parse("payload")))),
                ],
            )
        ]
    )
    assert any("is a switch" in e for e in errors(spec))


def test_parameters_are_in_scope():
    spec = build(
        [
            Unit(
                name="message",
                fields=[Field(name="inner", type=UnitRef(unit="body", args=[parse("4")]))],
            ),
            Unit(
                name="body",
                params=[Param(name="size", type=ExprType.INT)],
                fields=[Field(name="data", type=BytesType(size=FromExpr(parse("size"))))],
            ),
        ]
    )
    assert check(spec) == ()


# --- parent and root -------------------------------------------------------


def test_parent_resolves_through_the_referencing_site():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="length", type=IntType(bits=16)),
                    Field(name="body", type=UnitRef(unit="body")),
                ],
            ),
            Unit(
                name="body",
                fields=[Field(name="data", type=BytesType(size=FromExpr(parse("parent.length"))))],
            ),
        ]
    )
    assert check(spec) == ()


def test_parent_respects_the_referencing_sites_ordering():
    """A parent's later fields are not decoded when the child runs."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="body", type=UnitRef(unit="body")),
                    Field(name="length", type=IntType(bits=16)),
                ],
            ),
            Unit(
                name="body",
                fields=[Field(name="data", type=BytesType(size=FromExpr(parse("parent.length"))))],
            ),
        ]
    )
    assert any("declared later" in e for e in errors(spec))


def test_parent_is_unresolvable_without_a_caller():
    spec = build(
        [
            Unit(name="message", fields=[Field(name="id", type=IntType(bits=8))]),
            Unit(
                name="orphan",
                fields=[Field(name="data", type=BytesType(size=FromExpr(parse("parent.length"))))],
            ),
        ]
    )
    assert any("nothing references" in e for e in errors(spec))


def test_root_resolves_against_the_entry_unit():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="length", type=IntType(bits=16)),
                    Field(name="body", type=UnitRef(unit="body")),
                ],
            ),
            Unit(
                name="body",
                fields=[Field(name="data", type=BytesType(size=FromExpr(parse("root.length"))))],
            ),
        ]
    )
    assert check(spec) == ()


# --- expression types ------------------------------------------------------


def test_condition_must_be_boolean():
    unit = Unit(
        name="message",
        fields=[
            Field(name="n", type=IntType(bits=8)),
            Field(name="body", type=BytesType(size=Fixed(1)), condition=parse("n")),
        ],
    )
    assert "condition must be bool, got int" in only_error(build([unit]))


def test_size_must_be_integer():
    unit = Unit(
        name="message",
        fields=[
            Field(name="tag", type=StringType(size=Fixed(2))),
            Field(name="body", type=BytesType(size=FromExpr(parse("tag")))),
        ],
    )
    assert "size must be int, got str" in only_error(build([unit]))


def test_repeat_count_must_be_integer():
    unit = Unit(
        name="message",
        fields=[
            Field(name="tag", type=StringType(size=Fixed(2))),
            Field(name="items", type=IntType(bits=8), repeat=Count(parse("tag"))),
        ],
    )
    assert "repeat count must be int, got str" in only_error(build([unit]))


def test_repeat_until_must_be_boolean_and_sees_its_own_field():
    unit = Unit(
        name="message",
        fields=[Field(name="b", type=IntType(bits=8), repeat=Until(parse("b == 0")))],
    )
    assert check(build([unit])) == ()


def test_until_element_scope_covers_only_the_repeated_field():
    """Another repeated field is still a list, even inside an until."""
    unit = Unit(
        name="message",
        fields=[
            Field(name="a", type=IntType(bits=8), repeat=Count(parse("2"))),
            Field(name="b", type=IntType(bits=8), repeat=Until(parse("a == 0"))),
        ],
    )
    assert "has no list type" in only_error(build([unit]))


def test_repeat_until_must_still_be_boolean():
    unit = Unit(
        name="message",
        fields=[Field(name="b", type=IntType(bits=8), repeat=Until(parse("b")))],
    )
    assert "repeat until must be bool, got int" in only_error(build([unit]))


def test_confirm_and_reject_must_be_boolean():
    unit = Unit(
        name="message",
        fields=[Field(name="magic", type=IntType(bits=8))],
        confirm=parse("magic"),
        reject=parse("magic"),
    )
    found = errors(build([unit]))
    assert any("confirm must be bool" in e for e in found)
    assert any("reject must be bool" in e for e in found)


def test_confirm_sees_the_whole_unit():
    """A guard is decided once the unit is done, so every field is in scope."""
    unit = Unit(
        name="message",
        fields=[
            Field(name="a", type=IntType(bits=8)),
            Field(name="b", type=IntType(bits=8)),
        ],
        confirm=parse("b == 0"),
    )
    assert check(build([unit])) == ()


def test_computed_field_types_from_its_expression():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="n", type=IntType(bits=8)),
                    Field(name="doubled", type=Computed(parse("n * 2"))),
                    Field(name="body", type=BytesType(size=FromExpr(parse("doubled")))),
                ],
            )
        ]
    )
    assert check(spec) == ()


# --- unit arguments --------------------------------------------------------


def test_argument_count_must_match():
    spec = build(
        [
            Unit(name="message", fields=[Field(name="b", type=UnitRef(unit="body"))]),
            Unit(
                name="body",
                params=[Param(name="size", type=ExprType.INT)],
                fields=[Field(name="d", type=BytesType(size=Remaining()))],
            ),
        ]
    )
    assert any("takes 1 argument(s), got 0" in e for e in errors(spec))


def test_argument_type_must_match():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="tag", type=StringType(size=Fixed(2))),
                    Field(name="b", type=UnitRef(unit="body", args=[parse("tag")])),
                ],
            ),
            Unit(
                name="body",
                params=[Param(name="size", type=ExprType.INT)],
                fields=[Field(name="d", type=BytesType(size=Remaining()))],
            ),
        ]
    )
    assert any("must be int, got str" in e for e in errors(spec))


def test_duplicate_parameter_names():
    spec = build(
        [
            Unit(name="message", fields=[Field(name="b", type=UnitRef(unit="body", args=[]))]),
            Unit(
                name="body",
                params=[Param(name="n", type=ExprType.INT), Param(name="n", type=ExprType.INT)],
                fields=[Field(name="d", type=BytesType(size=Remaining()))],
            ),
        ]
    )
    assert any("duplicate parameter names" in e for e in errors(spec))


# --- switches --------------------------------------------------------------


def test_switch_case_keys_must_match_the_dispatch_type():
    unit = Unit(
        name="message",
        fields=[
            Field(name="kind", type=IntType(bits=8)),
            Field(
                name="payload",
                type=Switch(
                    on=parse("kind"),
                    cases={"text": IntType(bits=8)},
                    default=IntType(bits=8),
                ),
            ),
        ],
    )
    assert "does not match the int expression" in only_error(build([unit]))


def test_switch_without_a_default_warns():
    unit = Unit(
        name="message",
        fields=[
            Field(name="kind", type=IntType(bits=8)),
            Field(
                name="payload",
                type=Switch(on=parse("kind"), cases={1: IntType(bits=8)}, default=None),
            ),
        ],
    )
    assert any("no default" in w for w in warnings(build([unit])))


def test_switch_dispatching_on_bytes_is_refused():
    unit = Unit(
        name="message",
        fields=[
            Field(name="raw", type=BytesType(size=Fixed(2))),
            Field(
                name="payload",
                type=Switch(on=parse("raw"), cases={1: IntType(bits=8)}, default=IntType(bits=8)),
            ),
        ],
    )
    assert "use int or str" in only_error(build([unit]))


def test_types_nested_in_switch_cases_are_checked():
    unit = Unit(
        name="message",
        fields=[
            Field(name="kind", type=IntType(bits=8)),
            Field(
                name="payload",
                type=Switch(
                    on=parse("kind"),
                    cases={1: UnitRef(unit="nope")},
                    default=IntType(bits=8),
                ),
            ),
        ],
    )
    assert any("unknown unit 'nope'" in e for e in errors(build([unit])))


# --- findings ---------------------------------------------------------------


def test_findings_are_collected_not_raised():
    """Every fault in one run, so an author fixes a spec once, not line by line."""
    unit = Unit(
        name="message",
        fields=[
            Field(name="a", type=IntType(bits=8, enum="nope")),
            Field(name="b", type=UnitRef(unit="missing")),
            Field(name="c", type=BytesType(size=FromExpr(parse("mystery")))),
        ],
    )
    assert len(errors(build([unit]))) == 3


def test_finding_renders_readably():
    unit = Unit(name="message", fields=[Field(name="op", type=IntType(bits=4, enum="nope"))])
    finding = check(build([unit]))[0]
    assert str(finding).startswith("error: dns.message.op: ")


@pytest.mark.parametrize("severity", list(Severity))
def test_severity_values(severity: Severity):
    assert severity.value in {"error", "warning"}


# --- pointer ---------------------------------------------------------------


def pointer_spec(at: str = "lo", *, target: str = "name") -> Spec:
    """Build a spec whose `ptr` unit reads an offset and reads a name there."""
    return build(
        [
            Unit(name="message", fields=[Field(name="p", type=UnitRef(unit="ptr"))]),
            Unit(
                name="ptr",
                fields=[
                    Field(name="lo", type=IntType(bits=8)),
                    Field(name="target", type=Pointer(at=parse(at), type=UnitRef(unit=target))),
                ],
            ),
            Unit(name="name", fields=[Field(name="length", type=IntType(bits=8))]),
        ]
    )


def test_a_valid_pointer_has_no_findings():
    assert check(pointer_spec()) == ()


def test_pointer_offset_must_be_an_integer():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="s", type=StringType(size=Fixed(2))),
                    Field(
                        name="target",
                        type=Pointer(at=parse("s"), type=IntType(bits=8)),
                    ),
                ],
            )
        ]
    )
    assert any("pointer at" in message for message in errors(spec))


def test_pointer_offset_cannot_read_a_later_field():
    """The forward-reference rule applies to `at` as it does to a size."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="target", type=Pointer(at=parse("lo"), type=IntType(bits=8))),
                    Field(name="lo", type=IntType(bits=8)),
                ],
            )
        ]
    )
    assert any("lo" in message for message in errors(spec))


def test_pointer_target_unit_must_exist():
    assert any("nowhere" in message for message in errors(pointer_spec(target="nowhere")))


def test_a_unit_reached_only_through_a_pointer_is_reachable():
    """`name` is referenced from nowhere but a pointer, and is still reached."""
    assert warnings(pointer_spec()) == []


def test_parent_inside_a_pointer_target_resolves_at_the_pointing_site():
    """A pointer does not create a new parent: the site is where it stands."""
    spec = build(
        [
            Unit(name="message", fields=[Field(name="p", type=UnitRef(unit="ptr"))]),
            Unit(
                name="ptr",
                fields=[
                    Field(name="lo", type=IntType(bits=8)),
                    Field(name="target", type=Pointer(at=parse("lo"), type=UnitRef(unit="name"))),
                ],
            ),
            Unit(
                name="name",
                fields=[Field(name="n", type=BytesType(size=FromExpr(parse("parent.lo"))))],
            ),
        ]
    )
    assert errors(spec) == []


def test_a_pointer_to_its_own_unit_is_not_left_recursion():
    """It terminates by the offset rule: each hop lands strictly earlier."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[Field(name="t", type=Pointer(at=parse("0"), type=UnitRef(unit="message")))],
            )
        ]
    )
    assert errors(spec) == []


# --- builtins --------------------------------------------------------------


def sized_by(expr: str, *, first: FieldType | None = None) -> Spec:
    """Build a two-field unit whose second field's size comes from ``expr``."""
    head = first if first is not None else StringType(size=Fixed(4))
    return build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="head", type=head),
                    Field(name="body", type=BytesType(size=FromExpr(parse(expr)))),
                ],
            )
        ]
    )


def test_a_builtin_types_as_its_table_row_says():
    assert check(sized_by("to_int(head, 16)")) == ()


def test_a_builtin_on_the_wrong_type_is_an_error():
    spec = sized_by("to_int(head)", first=IntType(bits=8))
    assert any("argument 1 of to_int()" in message for message in errors(spec))


def test_a_builtin_returning_text_cannot_size_a_field():
    assert any("size must be int" in message for message in errors(sized_by("lower(head)")))


def test_a_builtin_cannot_reach_a_later_field():
    """The forward-reference rule has to see through an argument."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="body", type=BytesType(size=FromExpr(parse("to_int(tail)")))),
                    Field(name="tail", type=StringType(size=Fixed(2))),
                ],
            )
        ]
    )
    assert any("tail" in message for message in errors(spec))
