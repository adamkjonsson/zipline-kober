"""Decode network protocols from a declarative specification.

Nothing is implemented yet — see ``DESIGN.md`` for the intended spec model,
decode semantics, and public API.
"""

from __future__ import annotations

from importlib.metadata import version as _distribution_version

__version__: str = _distribution_version("zipline-decoder")

__all__ = ["__version__"]
