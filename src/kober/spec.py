"""The spec model: frozen dataclasses describing a protocol.

This is ``DESIGN.md`` §3 in code. A :class:`Spec` is data, not behaviour —
nothing here decodes anything, and nothing here runs author-supplied code.

What that buys is narrower than it looks, and §2.1 is worth reading before
relying on it. Coverage is made true by ``fill_undecoded=True``, not by the
absence of code. These constructs matter because each has a *total, declared
failure behaviour*, which is what lets the checker say ahead of time that a
spec will account for its input honestly — and because none of them lets an
author move the read cursor, which is the invariant the decode loop enforces.

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
from kober.source import SourceMap

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

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
    """A size delimited by a byte sequence, optionally bounded by a second.

    In ``STREAM`` shape a missing terminator at the end of the available data
    means *truncated*, which may simply mean the message continues in a
    segment we do not have. That is a normal outcome, not an error — see
    ``DESIGN.md`` §3.2.

    **``within`` is what lets one line split into two fields.** An HTTP header
    is a name, a colon, and a value, all inside one CRLF-terminated line — and
    reading the name as "up to the next colon" without a bound would run into
    the *next* header, or past the end of the headers entirely, whenever a line
    has no colon in it. Bounding the search makes a header *have* a name and a
    value in the spec, rather than having them computed back out of the line by
    three expressions afterwards.

    The rule is **whichever comes first**. When the delimiter does not occur
    before the bound, the read behaves exactly as though the delimiter were not
    there at all, so :attr:`required` still decides what that means. Note what
    that is *not*: the value does not quietly extend to the bound instead. The
    bound is a limit on the search, never a second terminator, because
    substituting one delimiter for another is the kind of quiet guess this
    project exists to avoid.

    The blank line ending a header block falls out of that without a special
    case: it has no colon before its CRLF, so an optional bounded terminator
    takes nothing and the name comes back empty.

    Attributes:
        delimiter: The bytes that end the value.
        consume: Whether the delimiter is consumed from the input.
        required: Whether its absence is a truncation (``True``) or an
            ordinary end of value (``False``).
        within: A second byte sequence the search must not run past. ``None``
            searches the rest of the run.

    """

    delimiter: bytes
    consume: bool = True
    required: bool = True
    within: bytes | None = None

    def __post_init__(self) -> None:
        if not self.delimiter:
            msg = "terminator delimiter must not be empty"
            raise SpecError(msg)
        if self.within is not None and not self.within:
            msg = "terminator bound must not be empty; omit it to search the whole run"
            raise SpecError(msg)


@dataclass(frozen=True)
class Remaining:
    """Everything left in the enclosing unit or segment."""


@dataclass(frozen=True)
class Fill:
    """Everything left, **less what the fields after it still claim**.

    The ordinary shape of a body between a header and a fixed footer, which
    nothing else in ``SizeSpec`` can say. :class:`Remaining` is the closest
    and is wrong: it takes the trailer's bytes too, leaving the trailing field
    to fail on an empty cursor.

    ``fill`` rather than ``dynamic``, because ``expr`` and ``terminated`` are
    dynamic as well; this field *fills* the space the trailing fields do not
    claim.

    **The trailing width must be computable from the spec alone**, or the spec
    is rejected at check time by :func:`kober.check.trailing_width`. Anything
    else would be the decoder guessing at a boundary, which is what §2 exists
    to prevent — so a trailing ``condition``, a data-dependent repeat, or a
    trailing size that is itself dynamic all refuse rather than approximate.

    **A run is not a packet**, and this is the one hazard the construct
    inherits. In ``DATAGRAM`` shape the two coincide and a fill is exact; in
    ``STREAM`` shape a run holds as many messages as fit, so a fill would
    swallow every following message in the segment and name it one field. The
    checker warns about that pairing, as it does for a non-required terminator.
    """


SizeSpec = Fixed | FromExpr | Terminated | Remaining | Fill


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
        alias: The name the element binds under, spelled ``as:`` in a
            document. ``None`` binds it under the repeated field's own name,
            which is the shorthand and reads fine where the name is plural
            enough to survive it.

    """

    expr: Expr
    alias: str | None = None

    def __post_init__(self) -> None:
        if self.alias is not None and not self.alias.strip():
            msg = "repeat 'as' must name the element; omit it to use the field's name"
            raise SpecError(msg)


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

    Spelled ``dispatch:`` in a document, and named that here so the two agree.
    It was ``on:`` until 0.1.0, which YAML 1.1 reads as the boolean ``True`` —
    so this schema's second-most-common construct had a key its own authoring
    format mangled, and the loader carried a repair for it. The repair worked;
    needing one was the smell, and renaming before the first release cost
    nothing that a rename afterwards would have.

    Attributes:
        dispatch: The expression dispatched on.
        cases: Value to type. Keys are integers or strings.
        default: Type used when no case matches. ``None`` means the region is
            marked ``undecodable`` rather than guessed at, per §2.

    """

    dispatch: Expr
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
    reads rather than a range of its own. Because it cannot move the read
    cursor it is safe under §2.1's rule, which is the basis on which
    ``DESIGN.md`` §11 question 2 was closed in its favour.

    Its value is what lets a wire encoding stop leaking: a length stored in
    32-bit words is converted once and named, rather than multiplied by four
    in every expression that wants bytes.

    Attributes:
        expr: The expression giving the value. Its type is the field's type.

    """

    expr: Expr


@dataclass(frozen=True)
class Pointer:
    """A back-reference: read ``type`` at ``at``, and carry on where you were.

    Real DNS demanded it — an answer record's owner name is usually two bytes
    meaning "the name at offset 12" (RFC 1035 §4.1.4) — and without it the
    answer section of nearly every real response is undecodable
    (``DESIGN.md`` §13.1).

    **It does not break §2.1's cursor rule, and that is why it was chosen over
    a hook.** The spec *names* an offset and the runtime does the seeking, so
    the reading position never moves and coverage stays provable. A hook would
    solve the same problem by handing an author the position, which is the one
    thing §2.1 reserves.

    ``at`` is an expression, so a pointer reads **nothing** where it stands:
    the bytes encoding the reference are read by ordinary fields, whose
    citations already cover them. The shape is :class:`Computed`'s — zero
    width at the cursor, evidence about somewhere else — which is why one
    field never needs to cite two disjoint ranges.

    Offsets are **message-relative**, the only space the construct has: a run
    holds many messages, and a pointer that meant stream-absolute would work
    on a run's first message and silently misread every later one.

    Attributes:
        at: An integer expression giving the offset to read at, measured from
            the start of the message being decoded.
        type: What is there.

    """

    at: Expr
    type: FieldType


@dataclass(frozen=True)
class Select:
    """Ask a question about a repeated field, and get one scalar back.

    The construct that lets a spec choose its own framing. Without it a body
    cannot depend on whether *any* header said ``chunked``, because ``headers``
    is repeated and the expression language has no list type — so
    ``examples/http.yaml`` had to *assume* a framing and call the bytes it then
    misread ``truncated``, declaring a hole in a stream that had none
    (``DESIGN.md`` §13.2).

    **It is aggregation in the model rather than in the grammar**, which is the
    same choice §11.5 made for :class:`Pointer` and for the same reason. An
    ``any(headers, …)`` expression form would need a binding construct in the
    general grammar — a lambda in all but name — and a ``first(headers, …)``
    would have to return *an element*, which :class:`~kober.expr.ExprType` has
    no member for. A select sidesteps both: it yields a scalar whose type is
    its projection's, so the checker types it with machinery that already
    exists, and a later field may reference it like any other value.

    **Totality is structural.** :attr:`default` is required, so "nothing
    matched" always has an answer the author wrote. There is no partial
    function here to argue about, and no need for one.

    It reads no input and moves no position — the repetition is complete before
    it runs — so it stays on the unconstrained side of §2.1's table, exactly as
    :class:`Computed` does.

    **The element may be named.** Without :attr:`alias` the source's own name
    binds it, so ``from: headers`` means *the repetition* on one line and
    ``headers.name`` means *one header* on the next, with nothing marking the
    change. That was deliberate — ``until`` already binds an element under the
    repeated field's name, and two spellings for one idea is how a small
    language stops being small — but it is a rule that can only be explained,
    never made obvious. An explicit ``as: header`` removes the ambiguity
    instead of explaining it, and :class:`Until` takes the same key for the same
    reason, so the two constructs do not diverge.

    Attributes:
        source: Name of the repeated field to ask about, spelled ``from:`` in a
            document. It must be declared earlier in the same unit and must be
            repeated.
        alias: The name one element binds under inside :attr:`where` and
            :attr:`value`, spelled ``as:`` in a document. ``None`` binds it
            under :attr:`source`.
        where: A boolean predicate over one element. The **first** element it
            holds for is the one selected.
        value: The projection of that element, and the field's value.
        default: The value when no element matched. Required. It sees no
            element under either name — nothing matched, so there is none.

    """

    source: str
    where: Expr
    value: Expr
    default: Expr
    alias: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            msg = "select 'from' must name a repeated field"
            raise SpecError(msg)
        if self.alias is not None and not self.alias.strip():
            msg = "select 'as' must name the element; omit it to use the source's name"
            raise SpecError(msg)


@dataclass(frozen=True)
class Concat:
    """The bytes of one field of every element of a repetition, joined in order.

    What a chunked HTTP body is: ``chunks[*].data``, scattered through a
    repetition with a size line and a CRLF between every piece, and wanted as
    one value. The language has no list type and gets none; this is one
    construct with the binding inside it, the answer ``select`` gave to asking
    a question about a repetition (``DESIGN.md`` §3.2).

    **It reads nothing where it stands.** The bytes were read by the
    repetition's own fields, so like :class:`Select` it is zero width at the
    cursor. It cites the *hull* of what it joined: from the first non-empty
    member's first byte to the last one's last. The size lines and CRLFs in
    between are cited twice, once by their own fields and once here, which is
    legal, and they did feed the result: without them there is no
    concatenation. An empty member cites nothing, which is what keeps the
    terminating chunk's size line out of the hull (the transform plan's Stage 1).

    It is a field type, not only something ``transform`` can say, because that
    is what lets one field hold a body however it was framed: a ``switch`` with
    a ``concat`` case and a ``bytes`` case, and a transform that reads it by
    one name.

    Attributes:
        repeated: The repeated field, earlier in the same unit.
        member: The field of each element whose bytes are joined.

    """

    repeated: str
    member: str

    def __post_init__(self) -> None:
        for label, value in (("repeated field", self.repeated), ("member", self.member)):
            if not value.strip():
                msg = f"concat {label} must not be blank"
                raise SpecError(msg)


@dataclass(frozen=True)
class Transform:
    """Bytes already decoded, after a named transform, and optionally what they are.

    ``DESIGN.md`` §11.5's deferred branch, taken: the spec *names* a transform
    and a registry supplies it, so the spec stays data and ``check`` stays
    static. A transform maps bytes to bytes, which is why it is not a row in
    the expression language's function table: it feeds a decode of its own,
    measured from its output's first byte.

    **It reads nothing where it stands.** Its input is a field already decoded,
    so the cursor does not move across it, as it does not across a
    :class:`Select`. What the file says about it is always about input bytes,
    since the output has no offset space the file can name.

    Attributes:
        source: The earlier field, or parameter, whose bytes are transformed.
            Spelled ``from`` in a document.
        name: The transform. Spelled ``with`` in a document.
        limit: The most bytes the output may have. Required: a kilobyte of
            gzip inflates to a gigabyte, and a transform with no bound is not
            total.
        args: The transform's parameters, as expressions, by name.
        type: What the output is, decoded in its own offset space; ``None``
            to keep the output as this field's bytes.
        content_type: The record label for the output, when ``type`` is
            ``None``.

    """

    source: str
    name: str
    limit: int
    args: Mapping[str, Expr] = field(default_factory=dict)
    type: FieldType | None = None
    content_type: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            msg = "transform 'from' must not be blank"
            raise SpecError(msg)
        if not self.name.strip():
            msg = "transform 'with' must not be blank"
            raise SpecError(msg)
        if isinstance(self.limit, bool) or self.limit <= 0:
            msg = f"transform limit must be a positive number of bytes, got {self.limit!r}"
            raise SpecError(msg)
        object.__setattr__(self, "args", MappingProxyType(dict(self.args)))


FieldType = (
    IntType
    | BytesType
    | StringType
    | UnitRef
    | Switch
    | Computed
    | Pointer
    | Select
    | Concat
    | Transform
)


# --- units and specs -------------------------------------------------------


@dataclass(frozen=True)
class Param:
    """A value passed into a unit by whoever references it, or into a whole run.

    A unit's parameters are supplied by the field that references it. A
    document's (:attr:`Spec.params`) are supplied when a decode is set up, and
    are in scope in every unit: what a transform needs that no field holds, a
    key above all.

    Attributes:
        name: Parameter name, referable in expressions.
        type: The type the value must have.
        secret: Whether the value must never be written anywhere: not in a
            record, a region's comment, or a diagnostic. It is hashed into the
            decoder's parameters digest and nothing else. Document parameters
            only.

    """

    name: str
    type: ExprType
    secret: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "parameter name must not be blank"
            raise SpecError(msg)


@dataclass(frozen=True)
class TransformDecl:
    """A transform a spec uses, declared so ``check`` can type its arguments.

    The spec declares the interface and the registry supplies the
    implementation, and the two are checked at different times. Typing
    ``args`` against whatever a process has registered would make a spec valid
    in one process and invalid in another; typing it against this makes it the
    same everywhere, with no registry loaded.

    A core name (:data:`kober.transforms.WELL_KNOWN`) needs no declaration.
    Any other name does, an extended one included: declaring it is how a spec
    says it is not portable, where an author can see it.

    Attributes:
        name: The transform's name, as ``with`` spells it.
        params: Each parameter's name and type. A well-known transform has
            none.

    """

    name: str
    params: Mapping[str, ExprType] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "transform name must not be blank"
            raise SpecError(msg)
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))


@dataclass(frozen=True)
class Foreign:
    """A key from packeteer's dialect that this spec used and kober does not.

    [packeteer](https://github.com/adamkjonsson/packeteer) describes the same
    kind of protocol with a dialect of this format, and has keys kober has no
    use for: dispatch metadata for a tool that *chooses* a decoder, and
    encode-direction and redaction keys for a tool that also writes traffic.

    They are recognised and declined out loud rather than refused as typos.
    Kept in a side list on the :class:`Spec` rather than as attributes on
    :class:`Field` — nothing here reads them, and a diagnostic should not make
    every downstream consumer carry a field for it.

    Attributes:
        key: The key as the document spells it.
        where: Dotted path to the construct carrying it, in the vocabulary
            :func:`kober.check.check` reports in.

    """

    key: str
    where: str


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
        const: A value the decoded field must equal, or ``None``. A magic
            number is the ordinary way a decoder refuses traffic that is not
            its own, and it belongs on the field it constrains rather than in
            a unit-level ``confirm``, which is only evaluated once every field
            has been read against a protocol already known to be wrong.

    """

    name: str | None
    type: FieldType
    condition: Expr | None = None
    repeat: Repeat | None = None
    emit: Emit | None = None
    doc: str | None = None
    const: int | bytes | str | None = None

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
        sources: Where the spec was read from, for the checker's messages.
            **Not compared**: it says where a spec came from, not what it is,
            and two spellings of the same spec must stay equal even though
            their lines differ. See :mod:`kober.source`.
        foreign: Keys the document used that belong to packeteer's dialect of
            this format. Recognised, unused, and reported by
            :func:`kober.check.check` as warnings. Compared, unlike
            :attr:`sources`: they are something the document *said*.
        transforms: The transforms this spec declares, by name
            (:class:`TransformDecl`).
        params: Values supplied when a decode is set up, in scope in every
            unit: a key, say.

    """

    name: str
    version: str
    entry: str
    units: Mapping[str, Unit]
    enums: Mapping[str, EnumDef] = field(default_factory=dict)
    input: InputShape = InputShape.EITHER
    doc: str | None = None
    sources: SourceMap = field(default_factory=SourceMap, compare=False, repr=False)
    foreign: Sequence[Foreign] = ()
    transforms: Mapping[str, TransformDecl] = field(default_factory=dict)
    params: Sequence[Param] = ()

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
        object.__setattr__(self, "foreign", tuple(self.foreign))
        mismatched = [key for key, decl in self.transforms.items() if key != decl.name]
        if mismatched:
            listed = ", ".join(sorted(mismatched))
            msg = f"transform key does not match its name: {listed}"
            raise SpecError(msg)
        object.__setattr__(self, "transforms", MappingProxyType(dict(self.transforms)))
        object.__setattr__(self, "params", tuple(self.params))

    # The loader imports this module, so these import it back lazily. Keeping
    # the constructors here is worth that: `Spec.from_file` is the API
    # `DESIGN.md` §6 promises, and a caller should not have to know which
    # module does the parsing.

    @classmethod
    def from_dict(cls, document: Mapping[str, object], *, source: str | None = None) -> Spec:
        """Build a spec from an already-parsed mapping.

        Args:
            document: The spec document.
            source: The file it was read from, for error messages.

        Returns:
            The spec. It is well formed; run :func:`kober.check.check` to
            learn whether it is valid.

        Raises:
            SpecError: If the document is malformed.

        """
        from kober.loader import from_dict

        return from_dict(document, source=source)

    @classmethod
    def from_json(cls, text: str, *, source: str | None = None) -> Spec:
        """Build a spec from JSON text.

        Args:
            text: The JSON document.
            source: The file it was read from, for error messages.

        Returns:
            The spec.

        Raises:
            SpecError: If the text is not JSON, or the document is malformed.

        """
        from kober.loader import from_json

        return from_json(text, source=source)

    @classmethod
    def from_yaml(cls, text: str, *, source: str | None = None) -> Spec:
        """Build a spec from YAML text, which needs the ``yaml`` extra.

        Args:
            text: The YAML document.
            source: The file it was read from, for error messages.

        Returns:
            The spec.

        Raises:
            SpecError: If PyYAML is missing, or the document is malformed.

        """
        from kober.loader import from_yaml

        return from_yaml(text, source=source)

    @classmethod
    def from_file(cls, path: str | Path) -> Spec:
        """Build a spec from a file, dispatching on its suffix.

        Args:
            path: Path to a ``.json``, ``.yaml``, or ``.yml`` file.

        Returns:
            The spec.

        Raises:
            SpecError: If the suffix is unrecognized, the file cannot be
                read, or the document is malformed.

        """
        from kober.loader import from_file

        return from_file(path)

    def as_decoder(self) -> tuple[str, str]:
        """Return what identifies this spec's decoder to `zpf`.

        The pair every `zpf` writing call wants: ``decoder=spec.as_decoder()``
        on :func:`zpf.decode_stage`, and the same pair behind a ``dec:`` content
        type and a ``role``. ``DESIGN.md`` §6 presents it as the seam for mixing
        spec-driven decoding with hand-written logic in one stage — a caller
        opening its own stage needs this and should not have to know that a
        decoder is named by two of a spec's attributes rather than by some
        third thing.

        Returns:
            The decoder's name and version.

        Example:
            >>> spec.as_decoder()
            ('dns', '1.0')

        """
        return self.name, self.version

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
