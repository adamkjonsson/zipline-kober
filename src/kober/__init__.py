"""Decode network protocols from a declarative specification.

Named for Alice Kober, whose structural groundwork made Linear B readable —
working out what a script's structure *is* before anyone could read it, which
is this package's job too.

Nothing is implemented yet — see ``DESIGN.md`` for the intended spec model,
decode semantics, and public API.
"""

from __future__ import annotations

from importlib.metadata import version as _distribution_version

__version__: str = _distribution_version("kober")

__all__ = ["__version__"]
