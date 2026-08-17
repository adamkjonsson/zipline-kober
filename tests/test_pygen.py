"""The Python backend: names, source text, and the two properties that matter.

**It converges on the spike.** ``compiled_dns.py`` is the module stage 1 said
the compiler should produce, and the blocks this stage generates are compared
against it character for character. As each stage lands, the block it generates
replaces the hand-written one; the comparison is what stops the target from
drifting while nobody is looking.

**It refuses rather than renames.** A spec name that is not a Python identifier,
or that two fields would share, or that lands in the namespace the backend keeps
for itself, is a :class:`~kober.errors.CompileError`. A decoder whose field
quietly changed name is worse than one that would not compile, so every one of
those refusals has a test.

And the generated source is checked the two ways that make it real: it passes
``ruff`` with this project's own configuration, and it imports.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import compiled_dns
import pytest

from kober.errors import CompileError, EvalError
from kober.expr import ExprValue, evaluate, parse, shift_left, shift_right
from kober.ops import Plan
from kober.pygen import (
    Binding,
    Names,
    render,
    render_enums,
    render_expr,
    render_model,
    render_spec,
)
from kober.spec import Spec

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def load(name: str) -> Spec:
    return Spec.from_file(EXAMPLES / name)


def plan_of(source: str) -> Plan:
    """Plan a spec written inline."""
    return Plan.from_spec(Spec.from_yaml(source))


def imported(source: str, tmp_path: Path, name: str = "generated") -> ModuleType:
    """Write generated source out and import it, the way a consumer would."""
    path = tmp_path / f"{name}.py"
    path.write_text(source)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


def block(title: str) -> str:
    """Return one ``# --- title ---`` section of the hand-written spike.

    Sliced from the file rather than imported, because what is being compared
    is the *text* — a class that merely behaves the same is not convergence.
    """
    lines = Path(compiled_dns.__file__).read_text().splitlines()
    rule = f"# --- {title} "
    start = next(index for index, line in enumerate(lines) if line.startswith(rule))
    after = range(start + 1, len(lines))
    end = next((index for index in after if lines[index].startswith("# --- ")), len(lines))
    return "\n".join(lines[start + 1 : end]).strip("\n")


# --- converging on the spike -----------------------------------------------


def test_the_typed_model_is_what_the_spike_says_it_should_be():
    assert render_model(Plan.from_spec(load("dns.yaml"))) == block("the typed model")


def test_the_enum_labels_are_what_the_spike_says_they_should_be():
    assert render_enums(Plan.from_spec(load("dns.yaml"))) == block("enums")


def test_the_generated_classes_hold_what_the_spike_holds(tmp_path: Path):
    """The same shape reached from the other side: attributes, in order, typed."""
    module = imported(render_spec(load("dns.yaml")), tmp_path, "dns_model")
    for name in ("Message", "Flags", "Question", "Name", "Label"):
        generated = getattr(module, name)
        handwritten = getattr(compiled_dns, name)
        assert generated.__annotations__ == handwritten.__annotations__
        assert generated.__span_index__ == handwritten.__span_index__


# --- names -----------------------------------------------------------------


def test_a_unit_becomes_a_class_and_a_field_keeps_its_name():
    names = Names(Plan.from_spec(load("dns.yaml")))
    assert names.class_of("message") == "Message"
    assert names.attribute_of("message", "qdcount") == "qdcount"
    assert names.constant_of("rrtype") == "RRTYPE"


def test_an_underscored_unit_name_becomes_camel_case():
    names = Names(
        plan_of("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields: [{name: h, type: {unit: header_v4}}]
              header_v4:
                fields: [{name: a, type: {int: {bits: 8}}}]
        """)
    )
    assert names.class_of("header_v4") == "HeaderV4"


def test_a_keyword_gets_a_trailing_underscore():
    """The one documented mapping, because `class` cannot be an attribute."""
    names = Names(
        plan_of("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields: [{name: class, type: {int: {bits: 8}}}]
        """)
    )
    assert names.attribute_of("m", "class") == "class_"


def test_a_unit_whose_class_name_would_be_a_keyword_gets_the_same_treatment():
    """`none` would become `None`, which cannot be a class name."""
    names = Names(
        plan_of("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields: [{name: a, type: {unit: none}}]
              none:
                fields: [{name: x, type: {int: {bits: 8}}}]
        """)
    )
    assert names.class_of("none") == "None_"


def test_a_soft_keyword_is_left_alone():
    """Python still accepts `match` as a name; a target that did not would map it."""
    names = Names(
        plan_of("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields: [{name: match, type: {int: {bits: 8}}}]
        """)
    )
    assert names.attribute_of("m", "match") == "match"


def test_two_units_that_would_share_a_class_name_are_refused():
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: a, type: {unit: header_v4}}
              - {name: b, type: {unit: headerV4}}
          header_v4:
            fields: [{name: x, type: {int: {bits: 8}}}]
          headerV4:
            fields: [{name: y, type: {int: {bits: 8}}}]
    """
    with pytest.raises(CompileError, match="HeaderV4"):
        Names(plan_of(source))


def test_two_fields_that_would_share_an_attribute_are_refused():
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: class, type: {int: {bits: 8}}}
              - {name: class_, type: {int: {bits: 8}}}
    """
    with pytest.raises(CompileError, match="class_"):
        Names(plan_of(source))


def test_a_name_that_is_not_an_identifier_is_refused_rather_than_mangled():
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields: [{name: content-length, type: {int: {bits: 8}}}]
    """
    with pytest.raises(CompileError, match="not a Python identifier"):
        Names(plan_of(source))


def test_a_name_in_the_backends_own_namespace_is_refused():
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields: [{name: _mark, type: {int: {bits: 8}}}]
    """
    with pytest.raises(CompileError, match="reserves every name"):
        Names(plan_of(source))


def test_a_field_named_like_a_generated_parameter_is_refused():
    """`sink` becomes a local in the function that already has a `sink`."""
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields: [{name: sink, type: {int: {bits: 8}}}]
    """
    with pytest.raises(CompileError, match="already takes as a parameter"):
        Names(plan_of(source))


def test_an_enum_named_like_a_module_constant_is_refused():
    source = """
        name: t
        version: "1"
        entry: m
        enums:
          name: {0: zero}
        units:
          m:
            fields: [{name: a, type: {int: {bits: 8, enum: name}}}]
    """
    with pytest.raises(CompileError, match="the generated module itself"):
        Names(plan_of(source))


def test_every_naming_problem_is_reported_at_once():
    """An author should not fix a spec one message per run."""
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: content-length, type: {int: {bits: 8}}}
              - {name: _mark, type: {int: {bits: 8}}}
              - {name: sink, type: {int: {bits: 8}}}
    """
    with pytest.raises(CompileError) as caught:
        Names(plan_of(source))
    assert "3 naming problem(s)" in str(caught.value)


# --- the source it renders -------------------------------------------------


@pytest.mark.parametrize("name", ["dns.yaml", "http.yaml"])
def test_a_generated_module_passes_this_projects_ruff(name: str, tmp_path: Path):
    """Generated modules are source this project ships, so they lint like it."""
    if shutil.which("ruff") is None:
        pytest.skip("ruff is not on PATH")
    path = tmp_path / "generated.py"
    path.write_text(render_spec(load(name)))
    result = subprocess.run(
        ["ruff", "check", "--config", str(ROOT / "ruff.toml"), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("name", ["dns.yaml", "http.yaml"])
def test_a_generated_module_imports(name: str, tmp_path: Path):
    module = imported(render_spec(load(name)), tmp_path, name.split(".")[0] + "_model")
    assert name.split(".")[0] == module.NAME
    assert module.VERSION == "1.0"


def test_a_generated_object_carries_its_spans(tmp_path: Path):
    """Q2, reached through generated code rather than the hand-written copy."""
    module = imported(render_spec(load("dns.yaml")), tmp_path, "dns_spans")
    label = module.Label(3, "com", (20, 24, 20, 21, 21, 24))
    assert compiled_dns.span(label) == (20, 24)
    assert compiled_dns.span(label, "text") == (21, 24)


def test_a_generated_class_has_slots_and_no_dict(tmp_path: Path):
    """The allocation this phase exists to remove is not allowed back in."""
    module = imported(render_spec(load("dns.yaml")), tmp_path, "dns_slots")
    label = module.Label(0, "", (0, 0, 0, 0, 0, 0))
    assert not hasattr(label, "__dict__")
    with pytest.raises(AttributeError):
        label.surprise = 1


def test_an_optional_field_is_optional_and_a_repeat_is_a_list():
    source = render_model(Plan.from_spec(load("dns.yaml")))
    assert "questions: list[Question]" in source
    assert "resource_records: bytes | None" in source


def test_a_switch_becomes_a_union():
    source = render_model(
        plan_of("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: kind, type: {int: {bits: 8}}}
                  - name: body
                    type:
                      switch:
                        on: kind
                        cases:
                          1: {int: {bits: 16}}
                          2: {bytes: {size: {fixed: 4}}}
        """)
    )
    assert "body: int | bytes" in source


def test_a_documented_field_keeps_the_specs_words():
    source = render_model(Plan.from_spec(load("dns.yaml")))
    assert "qdcount: Number of entries in the question section." in source


def test_an_undocumented_field_is_described_from_its_type():
    """The generator knows more than the spec's silence does."""
    source = render_model(Plan.from_spec(load("dns.yaml")))
    assert "length: An 8-bit unsigned integer." in source
    assert "text: Text, decoded as ``utf-8``." in source
    assert "qtype: A 16-bit unsigned integer. Labelled by :data:`RRTYPE`." in source


def test_a_conditional_field_documents_when_it_is_there():
    source = render_model(Plan.from_spec(load("dns.yaml")))
    assert "Present only when" in source


def test_a_spec_with_no_enums_renders_none():
    assert render_enums(Plan.from_spec(load("http.yaml"))) == ""


# --- author text reaching source code --------------------------------------

HOSTILE = '''
name: t
version: "1"
entry: m
doc: 'ends with a quote "'
enums:
  kinds: {0: '""" + __import__(''os'').system(''touch /tmp/kober-pwned'') + """'}
units:
  m:
    doc: 'closes the docstring """ and keeps going \\ '
    fields:
      - name: a
        type: {int: {bits: 8, enum: kinds}}
        doc: 'a field doc with """ in it'
'''


def test_author_text_cannot_escape_into_code(tmp_path: Path):
    """"A spec cannot run code" is partly a security property; this is where it would go.

    The label below is written to look like a docstring being closed and an
    import being called. If any of it reached source text unescaped the module
    would either fail to parse or run it, so the assertions are that it
    imports, that the label is still *data*, and that it is unchanged.
    """
    module = imported(render_spec(Spec.from_yaml(HOSTILE)), tmp_path, "hostile")
    label = module.KINDS[0]
    assert label == '""" + __import__(\'os\').system(\'touch /tmp/kober-pwned\') + """'
    assert not Path("/tmp/kober-pwned").exists()


def test_a_docstring_that_closes_itself_is_escaped(tmp_path: Path):
    module = imported(render_spec(Spec.from_yaml(HOSTILE)), tmp_path, "hostile_docs")
    assert 'closes the docstring """ and keeps going' in module.M.__doc__
    assert '"""' in module.M.__doc__


def test_a_control_character_does_not_reach_the_source():
    """A raw carriage return inside a docstring is legal Python and a lie in a diff."""
    spec = Spec.from_yaml("""
        name: t
        version: "1"
        entry: m
        units:
          m:
            doc: "before\\u0007after\\rtail"
            fields: [{name: a, type: {int: {bits: 8}}}]
    """)
    source = render(Plan.from_spec(spec))
    assert "\x07" not in source
    assert "\r" not in source


def test_a_spec_name_that_is_not_an_identifier_still_renders(tmp_path: Path):
    """Only *names that become identifiers* are refused; the rest are literals."""
    spec = Spec.from_yaml("""
        name: my-protocol/2
        version: "1"
        entry: m
        units:
          m:
            fields: [{name: a, type: {int: {bits: 8}}}]
    """)
    module = imported(render_spec(spec), tmp_path, "odd_name")
    assert module.NAME == "my-protocol/2"

# --- expressions -----------------------------------------------------------

ARITHMETIC = """
name: t
version: "1"
entry: m
units:
  m:
    fields:
      - {name: a, type: {int: {bits: 16, signed: true}}}
      - {name: b, type: {int: {bits: 16, signed: true}}}
      - {name: c, type: {int: {bits: 16, signed: true}}}
      - {name: p, type: {computed: "a > 0"}}
      - {name: q, type: {computed: "b > 0"}}
"""


class Values:
    """An interpreter environment over a flat mapping of names."""

    def __init__(self, values: dict[str, ExprValue]) -> None:
        self.values = values

    def lookup(self, path: tuple[str, ...]) -> ExprValue:
        """Resolve a bare name, which is all these expressions use."""
        return self.values[path[-1]]


def binding_for(source: str, unit: str = "m", **kwargs: object) -> Binding:
    """Build a binding for a spec written inline."""
    plan = plan_of(source)
    return Binding(plan, Names(plan), unit, **kwargs)  # type: ignore[arg-type]


def rendered(source: str, unit: str = "m", **kwargs: object) -> str:
    """Render one expression against ``ARITHMETIC``'s unit."""
    return render_expr(parse(source), binding_for(ARITHMETIC, unit, **kwargs))


def test_a_field_of_this_unit_is_a_local():
    """It has been decoded already: the ordering rule guarantees a variable holds it."""
    assert rendered("a + b") == "a + b"
    assert rendered("this.a + b") == "a + b"


def test_a_dotted_path_is_attribute_access():
    plan = Plan.from_spec(load("dns.yaml"))
    binding = Binding(plan, Names(plan), "question")
    assert render_expr(parse("qname.labels"), binding) == "qname.labels"


def test_a_parent_reference_is_a_parameter_the_caller_passes():
    """There is no parent object to ask: its fields are locals of a running function."""
    plan = Plan.from_spec(load("dns.yaml"))
    binding = Binding(plan, Names(plan), "name", parent="question")
    assert render_expr(parse("parent.qtype"), binding) == "_parent_qtype"


def test_a_root_reference_is_a_parameter_too():
    plan = Plan.from_spec(load("dns.yaml"))
    binding = Binding(plan, Names(plan), "label")
    assert render_expr(parse("root.qdcount"), binding) == "_root_qdcount"


def test_a_parent_reference_where_nothing_is_bound_is_refused():
    """Better than rendering it against a guess."""
    with pytest.raises(CompileError, match="names 'parent'"):
        rendered("parent.a")


def test_an_until_clause_names_the_element_it_just_decoded():
    plan = Plan.from_spec(load("dns.yaml"))
    binding = Binding(plan, Names(plan), "name", element_of="labels")
    assert render_expr(parse("labels.length"), binding) == "_element.length"


def test_a_parameter_is_a_local():
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields: [{name: h, type: {unit: {name: body, args: [4]}}}]
          body:
            params: [{name: size, type: int}]
            fields: [{name: raw, type: {bytes: {size: {expr: "size"}}}}]
    """
    binding = binding_for(source, "body")
    assert render_expr(parse("size"), binding) == "size"


def test_a_parameter_sharing_a_fields_name_is_refused():
    """Both are locals of the same function, so one would shadow the other."""
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields: [{name: h, type: {unit: {name: body, args: [4]}}}]
          body:
            params: [{name: raw, type: int}]
            fields: [{name: raw, type: {int: {bits: 8}}}]
    """
    with pytest.raises(CompileError, match="already"):
        Names(plan_of(source))


def test_a_parameter_named_like_a_generated_parameter_is_refused():
    source = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields: [{name: h, type: {unit: {name: body, args: [4]}}}]
          body:
            params: [{name: cur, type: int}]
            fields: [{name: raw, type: {int: {bits: 8}}}]
    """
    with pytest.raises(CompileError, match="already takes as a parameter"):
        Names(plan_of(source))


def test_division_is_integer_division():
    """The one operator a spec spells like Python and does not mean like Python."""
    assert rendered("a / b") == "a // b"
    assert rendered("a / b / c") == "a // b // c"


def test_grouping_is_kept_where_it_is_needed_and_dropped_where_it_is_not():
    assert rendered("a + b * c") == "a + b * c"
    assert rendered("(a + b) * c") == "(a + b) * c"
    assert rendered("a - (b - c)") == "a - (b - c)"
    assert rendered("a - b - c") == "a - b - c"
    assert rendered("(a | b) & c") == "(a | b) & c"


def test_a_nested_comparison_is_parenthesized_rather_than_chained():
    """`a == b == c` in Python is a chain, and would mean something else."""
    assert rendered("(a == b) == p") == "(a == b) == p"


def test_a_shift_by_a_literal_is_the_operator():
    assert rendered("a << 3") == "a << 3"


def test_a_shift_by_a_wire_value_goes_through_the_bounded_helper():
    """`1 << n` with n off the wire allocates until the process dies."""
    assert rendered("a << b") == "shift_left(a, b)"
    assert rendered("a >> b") == "shift_right(a, b)"
    assert rendered("a << 99999") == "shift_left(a, 99999)"


def test_a_boolean_literal_is_spelled_pythons_way():
    assert rendered("p and true") == "p and True"


def test_a_string_literal_keeps_its_value():
    plan = Plan.from_spec(load("http.yaml"))
    binding = Binding(plan, Names(plan), "header")
    assert render_expr(parse("line == 'x'"), binding) == 'line == "x"'


# --- the same answers as the interpreter -----------------------------------

EXPRESSIONS = [
    "a + b * c",
    "(a + b) * c",
    "a - b - c",
    "a - (b - c)",
    "a / b",
    "a / b / c",
    "a % b",
    "a / b + c",
    "a * b % c",
    "-a / b",
    "a & b | c",
    "a ^ b & c",
    "~a + b",
    "a << 3",
    "a >> 1",
    "a << b",
    "a >> b",
    "a > b",
    "a >= b and b >= c",
    "p or q",
    "not p",
    "p and not q",
    "a == b",
    "a != b or p",
    "b != 0 and a / b > 1",
    "a > 0 or a / 0 > 1",
    "(a > b) == p",
]

CASES = [
    {"a": 7, "b": 3, "c": 2},
    {"a": 0, "b": 0, "c": 1},
    {"a": -9, "b": 4, "c": -2},
    {"a": 5, "b": 0, "c": 0},
    {"a": 1, "b": 70000, "c": 3},
    {"a": -1, "b": -1, "c": -1},
]


@pytest.mark.parametrize("source", EXPRESSIONS)
@pytest.mark.parametrize("values", CASES, ids=[str(case["a"]) for case in CASES])
def test_rendered_python_answers_what_the_interpreter_answers(
    source: str, values: dict[str, int]
):
    """The differential test, at the level of one expression.

    Rendering is only correct if it *means* the same thing, and precedence,
    integer division, short-circuiting and the shift bound are all places where
    it could mean something else while looking right. So both sides are run: the
    interpreter over its own AST, and Python over the source this backend
    produced. Either they agree, or they fail — and failing the same way counts,
    because `a / 0` is a decode-time outcome rather than a wrong answer.
    """
    expr = parse(source)
    env = Values({**values, "p": values["a"] > 0, "q": values["b"] > 0})
    rendering = render_expr(expr, binding_for(ARITHMETIC))

    try:
        expected = evaluate(expr, env)
    except EvalError:
        expected = None
    try:
        actual = eval(  # noqa: S307 - the source under test is what is being checked
            rendering,
            {"shift_left": shift_left, "shift_right": shift_right},
            dict(env.values),
        )
    except (EvalError, ZeroDivisionError):
        actual = None
    assert actual == expected, f"{source!r} rendered as {rendering!r}"
