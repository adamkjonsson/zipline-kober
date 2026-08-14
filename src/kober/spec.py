"""The spec model: frozen dataclasses describing a protocol.

This is ``DESIGN.md`` §3 in code. A :class:`Spec` is data, not behaviour —
nothing here decodes anything, and nothing here runs author-supplied code.
That is the property §2 leans on: because a spec cannot express arbitrary
logic, coverage can be proved from the spec alone.

**Where validation lives.** These classes check only what a single object can
see by itself: an integer width in range, a non-negative size, a name that is
not blank. Everything needing the whole spec in view — that ``entry`` names a
real unit, that a :class:`UnitRef` resolves, that an expression is in scope and
well typed — belongs to :func:`kober.check.check`, which runs once the spec is
assembled. Constructing a :class:`Spec` therefore does *not* mean it is valid;
it means it is well formed.

Mappings and sequences are normalized on construction — sequences to tuples,
mappings to read-only views — so a model handed out by the loader cannot be
mutated behind its owner's back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING

from kober.errors import SpecError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from kober.expr import Expr, ExprType

#: Widest integer field the model accepts. Not a format limit — `zpf`'s
#: ``prim:`` tokens stop at 64 bits, and a wider field would have nowhere to
#: go at emit time.
MAX_INT_BITS = 64


class InputShape(Enum):
    """The stream shape a spec is written against.

    Declaring it lets :func:`kober.check.check` reject a spec run against the
    wrong transport instead of producing garbage. It does **not** decide
    which iterator the runtime uses: a decoded input is always packet-oriented
    whatever the original transport, so the runtime dispatches on
    ``stream.is_stream_oriented``. See ``DESIGN.md`` §3 and §9.2.
    """

    STREAM = "stream"
    DATAGRAM = "datagram"
    EITHER = "either"


class Endian(Enum):
    """Byte order of an integer field."""

    BIG = "big"
    LITTLE = "little"


class Emit(Enum):
    """How much of the field tree reaches the output file.

    See ``DESIGN.md`` §4. ``MESSAGE`` writes one record per top-level unit
    instance; ``FIELD`` writes one per leaf field, each citing the exact bytes
    it came from; ``NONE`` decodes for control flow and writes nothing.
    """

    MESSAGE = "message"
    FIELD = "field"
    NONE = "none"


# --- sizes and repetition --------------------------------------------------


@dataclass(frozen=True)
class Fixed:
    """A size known from the spec alone.

    Attributes:
        count: Size in bytes.

    """

    count: int

    def __post_init__(self) -> None:
        if self.count < 0:
            msg = f"fixed size must not be negative, got {self.count}"
            raise SpecError(msg)


@dataclass(frozen=True)
class FromExpr:
    """A size read from an earlier field.

    Attributes:
        expr: An integer expression giving the size in bytes.

    """

    expr: Expr


@dataclass(frozen=True)
class Terminated:
    """A size delimited by a byte sequence.

    In ``STREAM`` shape a missing terminator at the end of the available data
    means *truncated*, which may simply mean the message continues in a
    segment we do not have. That is a normal outcome, not an error — see
    ``DESIGN.md`` §3.2.

    Attributes:
        delimiter: The bytes that end the value.
        consume: Whether the delimiter is consumed from the input.
        required: Whether its absence is a truncation (``True``) or an
            ordinary end of value (``False``).

    """

    delimiter: bytes
    consume: bool = True
    required: bool = True

    def __post_init__(self) -> None:
        if not self.delimiter:
            msg = "terminator delimiter must not be empty"
            raise SpecError(msg)


@dataclass(frozen=True)
class Remaining:
    """Everything left in the enclosing unit or segment."""


SizeSpec = Fixed | FromExpr | Terminated | Remaining


@dataclass(frozen=True)
class Count:
    """Repeat a fixed or computed number of times.

    Attributes:
        expr: An integer expression giving the number of elements.

    """

    expr: Expr


@dataclass(frozen=True)
class Until:
    """Repeat until a condition holds, tested after each element.

    Attributes:
        expr: A boolean expression. ``this`` refers to the element just
            decoded.

    """

    expr: Expr


@dataclass(frozen=True)
class ToEnd:
    """Repeat until the enclosing unit or segment runs out."""


Repeat = Count | Until | ToEnd


# --- field types -----------------------------------------------------------


@dataclass(frozen=True)
class IntType:
    """An integer field, not necessarily a whole number of bytes.

    A sub-byte field still cites the bytes containing it, since `zpf` spans
    are byte offsets. Overlapping citations are legal, which is what makes
    bitfields expressible (``DESIGN.md`` §4).

    Attributes:
        bits: Width in bits, from 1 to :data:`MAX_INT_BITS`.
        signed: Two's-complement when ``True``.
        endian: Byte order; network order is the default.
        enum: Name of an :class:`EnumDef` labelling the value, if any.

    """

    bits: int
    signed: bool = False
    endian: Endian = Endian.BIG
    enum: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.bits <= MAX_INT_BITS:
            msg = f"integer width must be 1..{MAX_INT_BITS} bits, got {self.bits}"
            raise SpecError(msg)


@dataclass(frozen=True)
class BytesType:
    """A run of raw bytes.

    Attributes:
        size: How its extent is determined.

    """

    size: SizeSpec


@dataclass(frozen=True)
class StringType:
    """Text, decoded from bytes.

    Attributes:
        size: How its extent is determined.
        encoding: Codec name. Decode errors are recorded on the node, never
            raised — a malformed string is a fact about the input, not a
            failure of the decoder.

    """

    size: SizeSpec
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        if not self.encoding.strip():
            msg = "string encoding must not be blank"
            raise SpecError(msg)


@dataclass(frozen=True)
class UnitRef:
    """An instance of another unit.

    Attributes:
        unit: Name of the unit to decode.
        args: Arguments bound to that unit's parameters, positionally.

    """

    unit: str
    args: Sequence[Expr] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))


@dataclass(frozen=True)
class Switch:
    """Choose a type from an earlier value.

    Attributes:
        on: The expression dispatched on.
        cases: Value to type. Keys are integers or strings.
        default: Type used when no case matches. ``None`` means the region is
            marked ``undecodable`` rather than guessed at, per §2.

    """

    on: Expr
    cases: Mapping[int | str, FieldType]
    default: FieldType | None = None

    def __post_init__(self) -> None:
        if not self.cases:
            msg = "switch must have at least one case"
            raise SpecError(msg)
        object.__setattr__(self, "cases", MappingProxyType(dict(self.cases)))


@dataclass(frozen=True)
class Computed:
    """A value derived from earlier fields. Decodes nothing.

    It consumes no input, so it cites the ranges of the fields its expression
    reads rather than a range of its own.

    Attributes:
        expr: The expression giving the value.

    """

    expr: Expr


FieldType = IntType | BytesType | StringType | UnitRef | Switch | Computed


# --- units and specs -------------------------------------------------------


@dataclass(frozen=True)
class Param:
    """A value passed into a unit by whoever references it.

    Attributes:
        name: Parameter name, referable in the unit's expressions.
        type: The type callers must supply.

    """

    name: str
    type: ExprType

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "parameter name must not be blank"
            raise SpecError(msg)


@dataclass(frozen=True)
class EnumDef:
    """Named values for an integer field.

    Attributes:
        name: The enum's name, as referenced by :attr:`IntType.enum`.
        members: Value to label.
        doc: Free-text description.

    """

    name: str
    members: Mapping[int, str]
    doc: str | None = None

    def __post_init__(self) -> None:
        if not self.members:
            msg = f"enum {self.name!r} has no members"
            raise SpecError(msg)
        object.__setattr__(self, "members", MappingProxyType(dict(self.members)))


@dataclass(frozen=True)
class Field:
    """One field of a unit.

    Attributes:
        name: Field name, or ``None`` for an anonymous region (padding,
            reserved bits) that is decoded but never named.
        type: What to decode.
        condition: Decode this field only when the expression holds.
        repeat: Decode it repeatedly.
        emit: Emission granularity for this field; ``None`` inherits from the
            unit, and then from the decoder.
        doc: Free-text description — the reason specs are authored in YAML.

    """

    name: str | None
    type: FieldType
    condition: Expr | None = None
    repeat: Repeat | None = None
    emit: Emit | None = None
    doc: str | None = None

    def __post_init__(self) -> None:
        if self.name is not None and not self.name.strip():
            msg = "field name must not be blank; use null for an anonymous field"
            raise SpecError(msg)


@dataclass(frozen=True)
class Unit:
    """A named, reusable group of fields.

    ``confirm`` and ``reject`` are how a wrong protocol guess becomes an
    honest ``undecodable`` region instead of a fabricated field tree: a unit
    that rejects is abandoned and its extent marked, rather than raising.

    Attributes:
        name: The unit's name.
        fields: Its fields, in decode order.
        params: Values callers must supply.
        confirm: The dispatch guess held up, if this expression is true.
        reject: Abandon the unit when this expression is true.
        emit: Default emission granularity for this unit's fields.
        doc: Free-text description.

    """

    name: str
    fields: Sequence[Field]
    params: Sequence[Param] = ()
    confirm: Expr | None = None
    reject: Expr | None = None
    emit: Emit | None = None
    doc: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "unit name must not be blank"
            raise SpecError(msg)
        object.__setattr__(self, "fields", tuple(self.fields))
        object.__setattr__(self, "params", tuple(self.params))
        named = [item.name for item in self.fields if item.name is not None]
        duplicates = {name for name in named if named.count(name) > 1}
        if duplicates:
            listed = ", ".join(sorted(duplicates))
            msg = f"unit {self.name!r} declares duplicate field names: {listed}"
            raise SpecError(msg)

    def field(self, name: str) -> Field | None:
        """Return the named field, or ``None``.

        Args:
            name: The field name to look for.

        Returns:
            The field, or ``None`` when the unit has no such field.

        """
        for item in self.fields:
            if item.name == name:
                return item
        return None


@dataclass(frozen=True)
class Spec:
    """A protocol specification.

    Well-formedness is checked here; validity is checked by
    :func:`kober.check.check`, which needs the whole spec in view.

    Attributes:
        name: Becomes the `zpf` decoder name.
        version: Becomes the `zpf` decoder version.
        entry: Name of the root unit.
        units: Every unit, by name.
        enums: Every enum, by name.
        input: The stream shape this spec is written against.
        doc: Free-text description.

    """

    name: str
    version: str
    entry: str
    units: Mapping[str, Unit]
    enums: Mapping[str, EnumDef] = field(default_factory=dict)
    input: InputShape = InputShape.EITHER
    doc: str | None = None

    def __post_init__(self) -> None:
        for label, value in (("name", self.name), ("version", self.version)):
            if not value.strip():
                msg = f"spec {label} must not be blank"
                raise SpecError(msg)
        if not self.units:
            msg = "spec declares no units"
            raise SpecError(msg)
        mismatched = [key for key, unit in self.units.items() if key != unit.name]
        if mismatched:
            listed = ", ".join(sorted(mismatched))
            msg = f"unit key does not match its name: {listed}"
            raise SpecError(msg)
        object.__setattr__(self, "units", MappingProxyType(dict(self.units)))
        object.__setattr__(self, "enums", MappingProxyType(dict(self.enums)))

    def unit(self, name: str) -> Unit:
        """Return a unit by name.

        Args:
            name: The unit name.

        Returns:
            The unit.

        Raises:
            SpecError: If no such unit exists.

        """
        try:
            return self.units[name]
        except KeyError:
            known = ", ".join(sorted(self.units)) or "none"
            msg = f"no unit named {name!r}; known units: {known}"
            raise SpecError(msg) from None
