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

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


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
