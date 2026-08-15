"""Decode network protocols from a declarative specification.

Named for Alice Kober, whose structural groundwork made Linear B readable —
working out what a script's structure *is* before anyone could read it, which
is this package's job too.

The spec model, its loaders, and its checker are implemented. The decoder is
not: ``Decoder``, ``Node``, and the ``run``/``try`` CLI verbs from
``DESIGN.md`` §6 land in a later phase.

Example:
    >>> spec = Spec.from_file("dns.yaml")
    >>> for finding in check(spec):
    ...     print(finding)

"""

from __future__ import annotations

from importlib.metadata import version as _distribution_version

__version__: str = _distribution_version("kober")

from kober.check import Finding, Severity, check
from kober.decoder import Decoder
from kober.emit import Emission, Unclaimed, field_path, plan, prim_token
from kober.errors import EvalError, ExprError, KoberError, SpecError, TruncatedRead
from kober.expr import ExprType
from kober.loader import from_dict, from_file, from_json, from_yaml
from kober.node import Node, NodeStatus
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
    "BytesType",
    "Computed",
    "Count",
    "Decoder",
    "Emit",
    "Endian",
    "Emission",
    "EnumDef",
    "EvalError",
    "ExprError",
    "ExprType",
    "Field",
    "FieldType",
    "Finding",
    "Fixed",
    "FromExpr",
    "InputShape",
    "IntType",
    "KoberError",
    "Node",
    "NodeStatus",
    "Param",
    "Remaining",
    "Repeat",
    "Severity",
    "SizeSpec",
    "Spec",
    "SpecError",
    "StringType",
    "Switch",
    "Terminated",
    "ToEnd",
    "Unclaimed",
    "TruncatedRead",
    "Unit",
    "UnitRef",
    "Until",
    "__version__",
    "check",
    "content_registry",
    "decode_stream",
    "field_path",
    "from_dict",
    "from_file",
    "from_json",
    "from_yaml",
    "plan",
    "prim_token",
    "run",
]
