"""Tests for whole-spec validation."""

from __future__ import annotations

import pytest

from kober.check import Severity, check, trailing_width
from kober.expr import ExprType, parse
from kober.loader import from_yaml
from kober.spec import (
    BytesType,
    Computed,
    Count,
    EnumDef,
    Field,
    FieldType,
    Fill,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Param,
    Pointer,
    Remaining,
    Select,
    Spec,
    StringType,
    Switch,
    Terminated,
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
                        type=Switch(
                            dispatch=parse("kind"), cases={1: IntType(bits=8)}, default=None
                        ),
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
                    dispatch=parse("kind"),
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
                type=Switch(dispatch=parse("kind"), cases={1: IntType(bits=8)}, default=None),
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
                type=Switch(
                    dispatch=parse("raw"), cases={1: IntType(bits=8)}, default=IntType(bits=8)
                ),
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
                    dispatch=parse("kind"),
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


# --- select ----------------------------------------------------------------


def select_spec(
    *,
    source: str = "items",
    where: str = "items.tag == 1",
    value: str = "items.tag",
    default: str = "0",
    extra: list[Field] | None = None,
) -> Spec:
    """Build a unit with a repeated `items` and a select over it."""
    return build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="n", type=IntType(bits=8)),
                    Field(
                        name="items",
                        type=UnitRef(unit="item"),
                        repeat=Count(parse("n")),
                    ),
                    Field(
                        name="picked",
                        type=Select(
                            source=source,
                            where=parse(where),
                            value=parse(value),
                            default=parse(default),
                        ),
                    ),
                    *(extra or []),
                ],
            ),
            Unit(name="item", fields=[Field(name="tag", type=IntType(bits=8))]),
        ]
    )


def test_a_valid_select_has_no_findings():
    assert check(select_spec()) == ()


def test_select_source_must_be_repeated():
    """Without a repetition there is nothing to select from."""
    assert "not repeated" in only_error(
        select_spec(source="n", where="n == 1", value="n")
    )


def test_select_source_must_exist():
    assert "unknown name" in only_error(
        select_spec(source="absent", where="true", value="1")
    )


def test_select_source_may_not_be_a_parameter():
    """A parameter holds a scalar, so there is no repetition behind it."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[Field(name="inner", type=UnitRef(unit="leaf", args=[parse("1")]))],
            ),
            Unit(
                name="leaf",
                params=[Param(name="p", type=ExprType.INT)],
                fields=[
                    Field(
                        name="picked",
                        type=Select(
                            source="p",
                            where=parse("true"),
                            value=parse("1"),
                            default=parse("0"),
                        ),
                    )
                ],
            ),
        ]
    )
    assert "not a repeated field" in only_error(spec)


def test_select_cannot_reach_a_later_repetition():
    """The ordinary ordering rule: the repetition must already be decoded."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="picked",
                        type=Select(
                            source="items",
                            where=parse("items.tag == 1"),
                            value=parse("items.tag"),
                            default=parse("0"),
                        ),
                    ),
                    Field(
                        name="items",
                        type=UnitRef(unit="item"),
                        repeat=Until(parse("items.tag == 0")),
                    ),
                ],
            ),
            Unit(name="item", fields=[Field(name="tag", type=IntType(bits=8))]),
        ]
    )
    assert "declared later" in only_error(spec)


def test_select_where_must_be_boolean():
    assert "must be bool" in only_error(select_spec(where="items.tag"))


def test_select_value_and_default_must_agree():
    """Either one can end up being the field's value, so both must be one type."""
    assert "must agree" in only_error(select_spec(default="'none'"))


def test_select_default_cannot_see_the_element():
    """Nothing matched, so there is no element for a default to mean."""
    assert "no list type" in only_error(select_spec(default="items.tag"))


def test_select_result_is_a_scalar_a_later_field_can_use():
    """The whole case for putting aggregation in the model."""
    assert check(
        select_spec(extra=[Field(name="doubled", type=Computed(parse("picked * 2")))])
    ) == ()


def test_select_result_types_as_its_projection():
    """A str projection makes the field str, and sizing on it is an error."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="n", type=IntType(bits=8)),
                    Field(
                        name="items",
                        type=UnitRef(unit="item"),
                        repeat=Count(parse("n")),
                    ),
                    Field(
                        name="picked",
                        type=Select(
                            source="items",
                            where=parse("items.text == 'x'"),
                            value=parse("items.text"),
                            default=parse("''"),
                        ),
                    ),
                    Field(name="body", type=BytesType(size=FromExpr(parse("picked")))),
                ],
            ),
            Unit(name="item", fields=[Field(name="text", type=StringType(size=Fixed(1)))]),
        ]
    )
    assert "size must be int, got str" in only_error(spec)


def test_the_element_binding_does_not_leak_to_other_expressions():
    """A select exempts its own `where` and `value`, and nothing else."""
    assert "no list type" in only_error(
        select_spec(extra=[Field(name="bad", type=Computed(parse("items.tag")))])
    )


@pytest.mark.parametrize(
    "kind",
    [
        Computed(parse("1")),
        Pointer(at=parse("0"), type=IntType(bits=8)),
        Select(
            source="items",
            where=parse("items.tag == 1"),
            value=parse("items.tag"),
            default=parse("0"),
        ),
    ],
    ids=["computed", "pointer", "select"],
)
def test_a_repeated_zero_width_field_is_a_decode_time_finding(kind: FieldType):
    """All three consume nothing, and the checker lets all three through.

    A repetition of any of them cannot terminate, and the decoder's own guard
    is what says so — *"consumed no input; the repetition cannot terminate"*.
    Pinned as one test over all three rather than asserted for `select` alone,
    so that whoever decides to catch this statically moves the family together
    instead of leaving `select` inconsistent with its two siblings.
    """
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="n", type=IntType(bits=8)),
                    Field(name="items", type=UnitRef(unit="item"), repeat=Count(parse("n"))),
                    Field(name="picked", type=kind, repeat=Until(parse("true"))),
                ],
            ),
            Unit(name="item", fields=[Field(name="tag", type=IntType(bits=8))]),
        ]
    )
    assert errors(spec) == []


def test_a_nested_units_computed_can_be_referenced_from_outside():
    """Regression: typing the reference used the *referrer's* visible names.

    Reached through `inner`, `doubled`'s own expression was re-checked against
    `outer`'s names, where `raw` is not declared — so a valid spec was refused
    with *"'raw' is declared later in unit 'leaf'"*. The ordering rule is about
    where the reference stands, and `doubled` was checked at its own site.
    """
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="alpha", type=IntType(bits=8)),
                    Field(name="inner", type=UnitRef(unit="leaf")),
                    Field(name="probe", type=Computed(parse("inner.doubled"))),
                ],
            ),
            Unit(
                name="leaf",
                fields=[
                    Field(name="raw", type=IntType(bits=8)),
                    Field(name="doubled", type=Computed(parse("raw * 2"))),
                ],
            ),
        ]
    )
    assert check(spec) == ()


def test_ordering_still_holds_inside_the_unit_that_declares_a_computed():
    """The fix must not buy the above by dropping the rule where it belongs."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="early", type=Computed(parse("later * 2"))),
                    Field(name="later", type=IntType(bits=8)),
                ],
            )
        ]
    )
    assert "declared later" in only_error(spec)


def test_an_optional_terminator_on_a_string_warns():
    """It swallows the rest of the run, so a truncated message reads as whole."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="s",
                        type=StringType(size=Terminated(b":", required=False)),
                    )
                ],
            )
        ]
    )
    assert any("truncation invisible" in message for message in warnings(spec))


def test_a_bounded_optional_terminator_does_not_warn():
    """`within` is the guarantee the warning exists to notice the absence of.

    An unbounded optional terminator hides a truncation by reading to the end
    of the run; a bounded one cannot reach past its bound, so there is nothing
    to hide and the warning would be noise on the one spelling that is safe.
    """
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="s",
                        type=StringType(
                            size=Terminated(b":", required=False, within=b"\r\n")
                        ),
                    )
                ],
            )
        ]
    )
    assert warnings(spec) == []


# --- fill: the size decided by the fields after it -------------------------
#
# Every rule here refuses rather than approximates. A fill whose trailer cannot
# be measured is a boundary the decoder would have to guess at, and §2 exists
# to stop exactly that — so the checker's job is to say which trailing field
# made the sum unknowable, by name.


def filled(*trailing: Field, **kwargs: object) -> Spec:
    """Build a unit with a fill in the middle and ``trailing`` after it."""
    return build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="count", type=IntType(bits=8)),
                    Field(name="data", type=BytesType(size=Fill())),
                    *trailing,
                ],
            )
        ],
        **kwargs,
    )


def test_a_fill_with_a_measurable_trailer_is_valid():
    spec = filled(Field(name="kind", type=IntType(bits=32)))
    assert check(spec) == ()
    assert trailing_width(spec, "message", 1) == 4


def test_a_fill_with_nothing_after_it_is_valid():
    """It is `remaining` written the long way, and refusing it would be noise."""
    spec = filled()
    assert check(spec) == ()
    assert trailing_width(spec, "message", 1) == 0


def test_a_trailer_summed_across_a_nested_unit():
    """The case a wrong sum would get plausibly wrong rather than obviously."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="data", type=BytesType(size=Fill())),
                    Field(name="foot", type=UnitRef(unit="foot")),
                    Field(name="crc", type=IntType(bits=16)),
                ],
            ),
            Unit(
                name="foot",
                fields=[
                    Field(name="kind", type=IntType(bits=8)),
                    Field(name="length", type=IntType(bits=32)),
                ],
            ),
        ]
    )
    assert check(spec) == ()
    assert trailing_width(spec, "message", 0) == 7


def test_a_computed_after_a_fill_claims_nothing():
    """It reads no input where it stands, so it is not part of the trailer."""
    spec = filled(
        Field(name="doubled", type=Computed(expr=parse("count * 2"))),
        Field(name="kind", type=IntType(bits=32)),
    )
    assert check(spec) == ()
    assert trailing_width(spec, "message", 1) == 4


def test_a_conditional_field_after_a_fill_is_refused():
    spec = filled(
        Field(name="kind", type=IntType(bits=32), condition=parse("count > 0"))
    )
    assert "conditional" in only_error(spec)


def test_a_dynamically_sized_field_after_a_fill_is_refused():
    spec = filled(Field(name="tail", type=BytesType(size=FromExpr(parse("count")))))
    assert "size is not fixed" in only_error(spec)


def test_a_remaining_field_after_a_fill_is_refused():
    spec = filled(Field(name="tail", type=BytesType(size=Remaining())))
    assert "size is not fixed" in only_error(spec)


def test_a_data_dependent_repeat_after_a_fill_is_refused():
    spec = filled(
        Field(name="tail", type=IntType(bits=8), repeat=Count(expr=parse("count")))
    )
    assert "does not fix" in only_error(spec)


def test_a_literal_repeat_after_a_fill_is_counted():
    """The spec fixes the number, so the trailer has a width after all."""
    spec = filled(
        Field(name="tail", type=IntType(bits=8), repeat=Count(expr=parse("3")))
    )
    assert check(spec) == ()
    assert trailing_width(spec, "message", 1) == 3


def test_a_trailer_that_is_not_a_whole_number_of_bytes_is_refused():
    spec = filled(Field(name="nibble", type=IntType(bits=4)))
    assert "not a whole number of bytes" in only_error(spec)


def test_a_switch_after_a_fill_needs_agreeing_widths():
    spec = filled(
        Field(
            name="tail",
            type=Switch(
                dispatch=parse("count"),
                cases={1: IntType(bits=8), 2: IntType(bits=32)},
                default=IntType(bits=8),
            ),
        )
    )
    assert "differing widths" in only_error(spec)


def test_a_switch_after_a_fill_with_one_width_is_counted():
    spec = filled(
        Field(
            name="tail",
            type=Switch(
                dispatch=parse("count"),
                cases={1: IntType(bits=16), 2: BytesType(size=Fixed(2))},
                default=IntType(bits=16),
            ),
        )
    )
    assert errors(spec) == []
    assert trailing_width(spec, "message", 1) == 2


def test_a_switch_after_a_fill_without_a_default_is_refused():
    spec = filled(
        Field(
            name="tail",
            type=Switch(dispatch=parse("count"), cases={1: IntType(bits=16)}),
        )
    )
    assert any("no default" in message for message in errors(spec))


def test_a_recursive_unit_after_a_fill_is_refused():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="data", type=BytesType(size=Fill())),
                    Field(name="tail", type=UnitRef(unit="chain")),
                ],
            ),
            Unit(
                name="chain",
                fields=[
                    Field(name="n", type=IntType(bits=8)),
                    Field(name="next", type=UnitRef(unit="chain")),
                ],
            ),
        ]
    )
    assert any("recursive" in message for message in errors(spec))


def test_two_fills_in_one_unit_are_refused():
    """Each would be sized against the other's unknown extent."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(name="a", type=BytesType(size=Fill())),
                    Field(name="b", type=BytesType(size=Fill())),
                ],
            )
        ]
    )
    assert "more than one fill" in only_error(spec)


def test_a_repeated_fill_is_refused():
    """The first element would take everything, leaving the rest nothing."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="a",
                        type=BytesType(size=Fill()),
                        repeat=Count(expr=parse("2")),
                    )
                ],
            )
        ]
    )
    assert "cannot repeat" in only_error(spec)


def test_a_fill_under_input_stream_warns():
    """A run holds many messages, so a fill there swallows the ones after it."""
    spec = filled(
        Field(name="kind", type=IntType(bits=32)), input=InputShape.STREAM
    )
    assert any("rest of the run" in message for message in warnings(spec))


def test_a_fill_under_input_datagram_does_not_warn():
    """One datagram is one message, so a run and a message coincide."""
    spec = filled(
        Field(name="kind", type=IntType(bits=32)), input=InputShape.DATAGRAM
    )
    assert warnings(spec) == []


# --- naming the element a construct binds ----------------------------------
#
# The rule the binding exists to make obvious: exactly one name means one
# element. Without an alias it is the repeated field's own name, which is the
# shorthand; with one it is the alias, and the repeated field goes back to
# being a list nothing may hold.


def bound_spec(select_as: str | None, until_as: str | None, predicate: str) -> Spec:
    """Build a repetition and a select over it, each optionally aliased."""
    return build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="items",
                        type=UnitRef(unit="item"),
                        repeat=Until(expr=parse("items.x == 0"), alias=until_as),
                    ),
                    Field(
                        name="found",
                        type=Select(
                            source="items",
                            where=parse(predicate),
                            value=parse(f"{predicate.split('.')[0]}.x"),
                            default=parse("0"),
                            alias=select_as,
                        ),
                    ),
                ],
            ),
            Unit(name="item", fields=[Field(name="x", type=IntType(bits=8))]),
        ]
    )


def test_a_select_alias_resolves_to_the_element():
    assert check(bound_spec("pick", None, "pick.x == 1")) == ()


def test_the_source_name_still_binds_without_an_alias():
    """Every spec written before `as:` existed must go on checking clean."""
    assert check(bound_spec(None, None, "items.x == 1")) == ()


def test_an_aliased_select_refuses_the_source_name():
    """The whole value of writing `as:`: one name means an element, not two."""
    spec = bound_spec("pick", None, "items.x == 1")
    assert any("is repeated" in message for message in errors(spec))


def test_an_unknown_alias_is_not_silently_in_scope():
    """An alias binds one name, not any name — a typo must still be a typo."""
    spec = bound_spec("pick", None, "picked.x == 1")
    assert any("unknown name" in message for message in errors(spec))


def test_an_until_alias_resolves_to_the_element():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="items",
                        type=UnitRef(unit="item"),
                        repeat=Until(expr=parse("e.x == 0"), alias="e"),
                    )
                ],
            ),
            Unit(name="item", fields=[Field(name="x", type=IntType(bits=8))]),
        ]
    )
    assert check(spec) == ()


def test_an_aliased_until_refuses_the_field_name():
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="items",
                        type=UnitRef(unit="item"),
                        repeat=Until(expr=parse("items.x == 0"), alias="e"),
                    )
                ],
            ),
            Unit(name="item", fields=[Field(name="x", type=IntType(bits=8))]),
        ]
    )
    assert any("is repeated" in message for message in errors(spec))


def test_a_selects_default_sees_no_element_under_either_name():
    """Nothing matched, so there is no element for the fallback to mean."""
    spec = build(
        [
            Unit(
                name="message",
                fields=[
                    Field(
                        name="items",
                        type=UnitRef(unit="item"),
                        repeat=Until(expr=parse("items.x == 0")),
                    ),
                    Field(
                        name="found",
                        type=Select(
                            source="items",
                            where=parse("pick.x == 1"),
                            value=parse("pick.x"),
                            default=parse("pick.x"),
                            alias="pick",
                        ),
                    ),
                ],
            ),
            Unit(name="item", fields=[Field(name="x", type=IntType(bits=8))]),
        ]
    )
    assert any("unknown name" in message for message in errors(spec))


# --- findings say where they are -------------------------------------------
#
# `check` reports every fault rather than stopping at the first, so a dozen
# faults with no line numbers is a dozen things to go hunting for.

BAD_SPEC_YAML = """\
name: dns
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: id, bits: 16}
      - {name: body, bytes: {size: {expr: "later"}}}
      - {name: later, bits: 8}
"""


def test_a_finding_carries_the_line_it_is_about():
    spec = from_yaml(BAD_SPEC_YAML, source="dns.yaml")
    findings = check(spec)
    assert findings
    assert findings[0].where.source == "dns.yaml"
    assert findings[0].where.line == 8
    assert findings[0].where.path == "dns.message.body"


def test_a_finding_renders_file_line_path_then_message():
    spec = from_yaml(BAD_SPEC_YAML, source="dns.yaml")
    rendered = str(check(spec)[0])
    assert rendered.startswith("error: dns.yaml:8: dns.message.body: ")


def test_a_finding_from_a_mapping_reads_as_it_always_did():
    """`from_dict` has no source, and the message must not degrade beyond that."""
    spec = Spec.from_dict(
        {
            "name": "dns",
            "version": "1.0",
            "entry": "message",
            "units": {
                "message": {
                    "fields": [
                        {"name": "body", "bytes": {"size": {"expr": "later"}}},
                        {"name": "later", "bits": 8},
                    ]
                }
            },
        }
    )
    finding = check(spec)[0]
    assert finding.where.line is None
    assert str(finding).startswith("error: dns.message.body: ")


# --- const ------------------------------------------------------------------
#
# Each of these is otherwise found by a decode that never matches anything,
# which looks like traffic that is not ours rather than a spec that cannot
# match — so they are worth catching before any data exists.


def const_spec(kind: FieldType, const: object) -> Spec:
    return build([Unit(name="message", fields=[Field(name="f", type=kind, const=const)])])


def test_a_constant_needs_a_field_that_holds_a_value():
    kind = Switch(dispatch=parse("1"), cases={1: IntType(bits=8)})
    assert "a constant needs a field that holds a value" in only_error(const_spec(kind, 1))


def test_a_constant_on_a_unit_is_refused():
    spec = build(
        [
            Unit(name="message", fields=[Field(name="f", type=UnitRef("other"), const=1)]),
            Unit(name="other", fields=[Field(name="g", type=IntType(bits=8))]),
        ]
    )
    assert "a constant needs a field that holds a value" in only_error(spec)


@pytest.mark.parametrize(
    ("kind", "const"),
    [
        (IntType(bits=8), "GET"),
        (StringType(size=Fixed(3)), 7),
        (BytesType(size=Fixed(2)), "no"),
    ],
)
def test_a_constant_must_be_the_type_the_field_decodes(kind: FieldType, const: object):
    assert "and the field decodes" in only_error(const_spec(kind, const))


@pytest.mark.parametrize("const", [256, -1])
def test_an_integer_constant_must_fit_the_field(const: int):
    assert "does not fit 8 bits" in only_error(const_spec(IntType(bits=8), const))


def test_a_signed_field_holds_a_negative_constant():
    assert not errors(const_spec(IntType(bits=8, signed=True), -1))
    assert "does not fit 8 signed bits" in only_error(
        const_spec(IntType(bits=8, signed=True), 128)
    )


def test_a_constant_that_fits_is_no_finding():
    assert not errors(const_spec(IntType(bits=16), 0x5345))
    assert not errors(const_spec(StringType(size=Fixed(3)), "GET"))
    assert not errors(const_spec(BytesType(size=Fixed(2)), b"\x89P"))
