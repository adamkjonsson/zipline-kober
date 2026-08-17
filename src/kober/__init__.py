"""Decode network protocols from a declarative specification.

Named for Alice Kober, whose structural groundwork made Linear B readable —
working out what a script's structure *is* before anyone could read it, which
is this package's job too.

There are two ways to run a spec, and both are here. :class:`kober.decoder.Decoder`
**interprets** one — no build step, change the YAML and run it again — and the
compiler turns one into a Python module with a typed API: a
:class:`kober.ops.Plan` reduces a spec to what any backend needs, and
:mod:`kober.pygen` renders that as Python. The interpreter is the reference
implementation the generated code is checked against, so neither replaces the
other.

The ``kober compile`` CLI verb and the runtime generated decoders import are
still being built; see ``plans/COMPILER-PHASE-PLAN.md``.

Example:
    >>> spec = Spec.from_file("dns.yaml")
    >>> for finding in check(spec):
    ...     print(finding)

"""

from __future__ import annotations

from importlib.metadata import version as _distribution_version

__version__: str = _distribution_version("kober")

from kober.check import Finding, Severity, check, require_valid, scope_at
from kober.decoder import Decoder
from kober.emit import Emission, Unclaimed, field_path, plan
from kober.errors import (
    CompileError,
    EvalError,
    ExprError,
    KoberError,
    SpecError,
    Stopped,
    TruncatedRead,
    Undecodable,
)
from kober.expr import ExprType, shift_left, shift_right
from kober.loader import from_dict, from_file, from_json, from_yaml
from kober.node import Node, NodeStatus
from kober.ops import (
    Branch,
    FieldPlan,
    Kind,
    ObjectPlan,
    ParamPlan,
    Plan,
    Step,
    ValueType,
    nonnegative,
    walk_path,
)
from kober.pygen import (
    Binding,
    Names,
    content_type_of,
    granularity,
    payload_of,
    render,
    render_decoder,
    render_entry,
    render_enums,
    render_expr,
    render_model,
    render_spec,
)
from kober.runtime import (
    PRIM_WIDTHS,
    TEXT_CONTENT_TYPE,
    Sink,
    Spanned,
    cited,
    normalize_int,
    prim_int,
    prim_token,
    read_int_le,
    span,
)
from kober.spec import (
    MAX_INT_BITS,
    BytesType,
    Computed,
    Count,
    Emit,
    Endian,
    EnumDef,
    Field,
    FieldType,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Param,
    Remaining,
    Repeat,
    SizeSpec,
    Spec,
    StringType,
    Switch,
    Terminated,
    ToEnd,
    Unit,
    UnitRef,
    Until,
)
from kober.stage import content_registry, decode_stream, run

__all__ = [
    "MAX_INT_BITS",
    "PRIM_WIDTHS",
    "TEXT_CONTENT_TYPE",
    "Binding",
    "Branch",
    "BytesType",
    "CompileError",
    "Computed",
    "Count",
    "Decoder",
    "Emission",
    "Emit",
    "Endian",
    "EnumDef",
    "EvalError",
    "ExprError",
    "ExprType",
    "Field",
    "FieldPlan",
    "FieldType",
    "Finding",
    "Fixed",
    "FromExpr",
    "InputShape",
    "IntType",
    "Kind",
    "KoberError",
    "Names",
    "Node",
    "NodeStatus",
    "ObjectPlan",
    "Param",
    "ParamPlan",
    "Plan",
    "Remaining",
    "Repeat",
    "Severity",
    "Sink",
    "SizeSpec",
    "Spanned",
    "Spec",
    "SpecError",
    "Stopped",
    "Step",
    "StringType",
    "Switch",
    "Terminated",
    "ToEnd",
    "TruncatedRead",
    "Unclaimed",
    "Undecodable",
    "Unit",
    "UnitRef",
    "Until",
    "ValueType",
    "check",
    "cited",
    "content_registry",
    "content_type_of",
    "decode_stream",
    "field_path",
    "from_dict",
    "from_file",
    "from_json",
    "from_yaml",
    "granularity",
    "nonnegative",
    "normalize_int",
    "payload_of",
    "plan",
    "prim_int",
    "prim_token",
    "read_int_le",
    "render",
    "render_decoder",
    "render_entry",
    "render_enums",
    "render_expr",
    "render_model",
    "render_spec",
    "require_valid",
    "run",
    "scope_at",
    "shift_left",
    "shift_right",
    "span",
    "walk_path",
    "__version__",
]
