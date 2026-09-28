"""The transform names a spec may use, and what each one means.

A ``transform`` field names what turns its source's bytes into its output:
``with: gzip``. This module is what such a name *means*, and it is a fact
about the **format**, not about this implementation. Two rules govern
transforms and they must stay apart (the transform plan's Q7):

- which Python modules kober may import, which is ``CLAUDE.md``'s rule and
  decides what *this backend* can bind;
- which names a spec may use, which is this table's, and which has to hold
  for any backend that reads the same spec.

Deriving the second from the first would make ``lzma`` nameable because
CPython happens to ship it and ``br`` unnameable because it does not, which is
backwards: ``Content-Encoding: br`` is on the wire and ``lzma`` is not.

So a name means a **specification**, by normative reference, and each name is
in one of two tiers:

- **core**: ``gzip``, ``deflate`` and ``deflate-raw``. Every backend binds
  these, so a spec that uses nothing else is portable by construction. A core
  name needs no declaration.
- **extended**: ``br``, ``zstd``, ``bzip2`` and ``xz``. A backend may decline
  one. A spec using one declares it under ``transforms:``, which is how the
  spec says it is not portable, where an author can see it.

The names follow the browser's ``DecompressionStream`` rather than the
libraries': ``deflate`` is the zlib format (RFC 1950), as it is in HTTP's
``Content-Encoding`` too, and raw RFC 1951 is ``deflate-raw``. Those are the
two vocabularies an author copies a name from, and a name that meant something
else here would fail on every body.

Any other name is a spec's own, a cipher say, and is declared with its
parameters under ``transforms:``. What binds a name to code is a separate
question, answered per backend and per process.
"""

from __future__ import annotations

import bz2
import lzma
import sys
import zlib
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from kober.errors import TransformError, UnboundTransformError
from kober.spec import Pointer, Switch, Transform

try:
    # In the standard library from Python 3.14; kober supports 3.11, so what
    # this backend binds depends on the interpreter running it.
    from compression import zstd as _zstd_module
except ImportError:
    _zstd_module = None

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from kober.expr import ExprValue
    from kober.spec import FieldType, Spec


class Tier(Enum):
    """How portable a well-known transform name is."""

    #: Every backend binds it; a spec may use it without declaring it.
    CORE = "core"
    #: A backend may decline it; a spec using it declares it.
    EXTENDED = "extended"


@dataclass(frozen=True)
class WellKnown:
    """One well-known transform name.

    Attributes:
        name: The name, as a spec's ``with`` spells it.
        tier: How portable it is.
        reference: The specification that defines it: what makes the name
            mean the same thing to every backend.
        summary: What it is, in a few words.

    """

    name: str
    tier: Tier
    reference: str
    summary: str


#: Every well-known transform name, by name.
WELL_KNOWN: Mapping[str, WellKnown] = MappingProxyType(
    {
        known.name: known
        for known in (
            WellKnown("gzip", Tier.CORE, "RFC 1952", "the gzip file format"),
            WellKnown(
                "deflate",
                Tier.CORE,
                "RFC 1950",
                "the zlib format: DEFLATE with a header and an Adler-32 checksum",
            ),
            WellKnown("deflate-raw", Tier.CORE, "RFC 1951", "DEFLATE with no header"),
            WellKnown("br", Tier.EXTENDED, "RFC 7932", "Brotli"),
            WellKnown("zstd", Tier.EXTENDED, "RFC 8878", "Zstandard"),
            WellKnown("bzip2", Tier.EXTENDED, "bzip2 1.0.6 file format", "bzip2"),
            WellKnown("xz", Tier.EXTENDED, "The .xz File Format 1.2.1", "xz, LZMA2 in a container"),
        )
    }
)


def is_core(name: str) -> bool:
    """Whether a transform name is in the core tier, usable undeclared.

    Args:
        name: The name, as ``with`` spells it.

    Returns:
        Whether it is a core name.

    """
    known = WELL_KNOWN.get(name)
    return known is not None and known.tier is Tier.CORE


# --- the Python binding -------------------------------------------------------
#
# Everything above is the format's; everything below is this implementation's.
# Which names a process can run is a separate, shorter answer, computed where
# the code runs: `zstd` is in the standard library from Python 3.14, and kober
# supports 3.11.


class Transformer(Protocol):
    """What a transform is bound to: bytes and a limit in, bytes out.

    It must not return more than ``limit`` bytes, and should stop producing
    once it would, so a crafted input costs no more than the bound. Anything it
    raises becomes an ``undecodable`` source; :func:`apply` words it.
    """

    def __call__(self, data: bytes, *, limit: int, **args: ExprValue) -> bytes:
        """Transform ``data``, with the spec's ``args`` by name."""
        ...


class _Decompressor(Protocol):
    """The part of the standard library's decompressor objects used here."""

    eof: bool
    unused_data: bytes

    def decompress(self, data: bytes, max_length: int = ...) -> bytes: ...


#: What a standard-library decompressor raises for data it cannot read. Each
#: codec adds its own; zstd's derives from nothing more specific than
#: `Exception`.
_READ_ERRORS: tuple[type[Exception], ...] = (OSError, EOFError, ValueError, zlib.error)


def _decompressing(
    make: Callable[[], _Decompressor],
    *,
    members: bool,
    errors: tuple[type[Exception], ...] = (),
) -> Transformer:
    """Bind a standard-library decompressor, bounded as it goes.

    Each member is asked for at most one byte past what the limit leaves, so
    output past the limit is detected without producing any more of it: a
    kilobyte that inflates to a gigabyte stops at the limit, in memory the
    limit bounds. ``members`` is whether the format allows several streams one
    after another (gzip, bzip2, xz and zstd do; the deflate formats do not),
    which is what a trailing second stream means rather than trailing garbage.
    """

    def run(data: bytes, *, limit: int) -> bytes:
        out = bytearray()
        remaining = data
        while True:
            engine = make()
            try:
                out += engine.decompress(remaining, limit + 1 - len(out))
            except (*_READ_ERRORS, *errors) as exc:
                msg = "not valid compressed data"
                raise TransformError(msg) from exc
            if len(out) > limit:
                msg = f"output passes its limit of {limit} bytes"
                raise TransformError(msg)
            if not engine.eof:
                msg = "compressed data ends early"
                raise TransformError(msg)
            remaining = engine.unused_data
            if not remaining:
                return bytes(out)
            if not members:
                msg = f"{len(remaining)} byte(s) follow the compressed data"
                raise TransformError(msg)

    return run


def _zstd() -> Transformer | None:
    """Bind ``zstd`` where the standard library has it (Python 3.14 and later)."""
    if _zstd_module is None:
        return None
    return _decompressing(
        _zstd_module.ZstdDecompressor, members=True, errors=(_zstd_module.ZstdError,)
    )


class Registry:
    """What each transform name is bound to, in one process.

    :meth:`standard` is what the standard library can run. A caller adds what
    it cannot: a cipher, which the standard library has none of and ``CLAUDE.md``
    forbids reaching for, or ``br`` from a Brotli package. The module-level
    :func:`register` and :func:`lookup` act on :data:`DEFAULT`, which a decoder
    uses unless handed another.

    Args:
        transforms: Names and what they are bound to, to start from.

    """

    def __init__(self, transforms: Mapping[str, Transformer] | None = None) -> None:
        self._bound: dict[str, Transformer] = dict(transforms or {})

    @classmethod
    def standard(cls) -> Registry:
        """Return a registry holding what this Python's standard library can run.

        The core tier, ``bzip2`` and ``xz`` always; ``zstd`` where the standard
        library has it. ``br`` never, since the standard library has no Brotli.

        Returns:
            A new registry.

        """
        bound: dict[str, Transformer] = {
            "gzip": _decompressing(lambda: zlib.decompressobj(31), members=True),
            "deflate": _decompressing(lambda: zlib.decompressobj(15), members=False),
            "deflate-raw": _decompressing(lambda: zlib.decompressobj(-15), members=False),
            "bzip2": _decompressing(bz2.BZ2Decompressor, members=True),
            "xz": _decompressing(
                lambda: lzma.LZMADecompressor(lzma.FORMAT_XZ),
                members=True,
                errors=(lzma.LZMAError,),
            ),
        }
        zstd = _zstd()
        if zstd is not None:
            bound["zstd"] = zstd
        _SHIPPED.update(bound.values())
        return cls(bound)

    def register(self, name: str, transformer: Transformer, *, replace: bool = False) -> None:
        """Bind a name to a callable.

        Args:
            name: The name, as a spec's ``with`` spells it.
            transformer: What it runs.
            replace: Whether to replace a name already bound. Without it,
                rebinding one is an error, since a second registration by
                accident would change every decode silently.

        Raises:
            ValueError: If the name is bound already and ``replace`` is not set.

        """
        if name in self._bound and not replace:
            msg = f"transform {name!r} is bound already; pass replace=True to rebind it"
            raise ValueError(msg)
        self._bound[name] = transformer

    def lookup(self, name: str) -> Transformer | None:
        """Return what a name is bound to, or ``None``.

        Args:
            name: The name.

        Returns:
            The callable, or ``None`` if nothing is bound to it here.

        """
        return self._bound.get(name)

    def names(self) -> frozenset[str]:
        """Return every name this registry binds: its capability set.

        Returns:
            The names.

        """
        return frozenset(self._bound)

    def bind(self, spec: Spec) -> Mapping[str, Transformer]:
        """Return what every transform a spec uses is bound to, or refuse.

        What a decoder calls when it is set up, so that a transform this process
        cannot run fails before any input is read, once, rather than making
        every message ``undecodable``.

        Args:
            spec: The spec.

        Returns:
            Each name the spec uses, and what it is bound to.

        Raises:
            UnboundTransformError: If any name is bound to nothing, naming
                every one and saying which kind of missing it is.

        """
        return self.bind_names(
            {
                kind.name
                for unit in spec.units.values()
                for item in unit.fields
                for kind in _types_in(item.type)
                if isinstance(kind, Transform)
            }
        )

    def bind_names(self, names: Iterable[str]) -> Mapping[str, Transformer]:
        """Return what each name is bound to, or refuse: :meth:`bind` by name.

        What a generated module calls when it is imported, since it has the
        names its spec uses and not the spec.

        Args:
            names: The transform names.

        Returns:
            Each name, and what it is bound to.

        Raises:
            UnboundTransformError: If any is bound to nothing, naming every one.

        """
        used = sorted(set(names))
        missing = [name for name in used if name not in self._bound]
        if missing:
            msg = "; ".join(_why_unbound(name) for name in missing)
            raise UnboundTransformError(msg)
        return MappingProxyType({name: self._bound[name] for name in used})


def _why_unbound(name: str) -> str:
    """Say why one name is bound to nothing, by what kind of name it is."""
    known = WELL_KNOWN.get(name)
    if known is None:
        return (
            f"transform {name!r} is the spec's own and nothing is registered for it "
            "in this process; register one with kober.transforms.register"
        )
    return (
        f"transform {name!r} is a well-known {known.tier.value} name ({known.reference}) "
        f"that this backend does not bind on Python {sys.version_info.major}."
        f"{sys.version_info.minor}; register an implementation with kober.transforms.register"
    )


def _types_in(kind: FieldType) -> list[FieldType]:
    """Return a type and every type nested in it, a transform's output included."""
    found = [kind]
    if isinstance(kind, Switch):
        for case in (*kind.cases.values(), kind.default):
            if case is not None:
                found.extend(_types_in(case))
    elif isinstance(kind, Pointer) or (isinstance(kind, Transform) and kind.type is not None):
        found.extend(_types_in(kind.type))
    return found


#: The callables :meth:`Registry.standard` binds. :func:`apply` passes their
#: messages on, since kober wrote them; a caller's it does not.
_SHIPPED: set[Transformer] = set()

#: The registry a decoder uses unless handed another.
DEFAULT = Registry.standard()


def register(name: str, transformer: Transformer, *, replace: bool = False) -> None:
    """Bind a name to a callable in :data:`DEFAULT`. See :meth:`Registry.register`.

    Args:
        name: The name, as a spec's ``with`` spells it.
        transformer: What it runs.
        replace: Whether to replace a name already bound.

    """
    DEFAULT.register(name, transformer, replace=replace)


def lookup(name: str) -> Transformer | None:
    """Return what a name is bound to in :data:`DEFAULT`. See :meth:`Registry.lookup`.

    Args:
        name: The name.

    Returns:
        The callable, or ``None``.

    """
    return DEFAULT.lookup(name)


def apply(
    name: str,
    transformer: Transformer,
    data: bytes,
    *,
    limit: int,
    args: Mapping[str, ExprValue] | None = None,
) -> bytes:
    """Run one transform, holding it to its limit and wording every failure.

    The one place a transform runs, for both backends, so the bound and the
    wording cannot differ between them. **Whatever the callable raises becomes
    a** :class:`~kober.errors.TransformError` **in kober's own words.** A shipped
    codec's message is passed on, since kober wrote it. A caller's is not, not
    even its own ``TransformError``'s: a cipher's message is text kober does not
    control, and a region's comment can quote the failure into the file, where
    a key must never appear. Its exception's class name is given instead.

    Args:
        name: The transform's name, which every message starts with.
        transformer: What it is bound to (:meth:`Registry.bind`).
        data: The source's bytes.
        limit: The most bytes the output may have.
        args: The spec's ``args``, evaluated, by name.

    Returns:
        The output.

    Raises:
        TransformError: If the transform failed, or its output passed the
            limit or is not bytes.

    """
    try:
        output = transformer(data, limit=limit, **(args or {}))
    except TransformError as exc:
        if transformer in _SHIPPED:
            msg = f"{name}: {exc}"
            raise TransformError(msg) from exc
        msg = f"{name}: the transform rejected its input"
        raise TransformError(msg) from exc
    except Exception as exc:
        msg = f"{name}: the transform raised {type(exc).__name__}"
        raise TransformError(msg) from exc
    if not isinstance(output, (bytes, bytearray)):
        msg = f"{name}: the transform returned {type(output).__name__}, not bytes"
        raise TransformError(msg)
    if len(output) > limit:
        msg = f"{name}: output passes its limit of {limit} bytes"
        raise TransformError(msg)
    return bytes(output)
