"""Sphinx configuration for the kober documentation."""

from __future__ import annotations

project = "kober"
author = "Adam Jonsson"
project_copyright = "2026, Adam Jonsson"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "myst_parser",
]

myst_heading_anchors = 3

exclude_patterns = ["_build"]

html_theme = "furo"

# Report every cross-reference that does not resolve, so a broken one fails
# the ``-W`` build instead of silently rendering as plain text.
#
# `python-zipline` needs a `missing-reference` hook here to bridge `zpf.Foo`
# onto `zpf.module.Foo`, because its prose cites the top-level re-exports.
# kober does not: its docstrings already cite the defining module
# (`kober.spec.Spec`), so the references resolve where autodoc documents them
# and the hook would be machinery with nothing to do.
nitpicky = True

# The references that cannot resolve here and are not defects:
#
# * standard-library and typing names — linking them needs intersphinx, and
#   that would make every docs build depend on the network;
# * `zpf`'s own names, for the same reason: its documentation is a separate
#   build, and this project cites it constantly;
# * private names used in otherwise public signatures.
nitpick_ignore = [
    ("py:class", "ast.AST"),
    ("py:class", "collections.abc.Iterable"),
    ("py:class", "collections.abc.Iterator"),
    ("py:class", "collections.abc.Mapping"),
    ("py:class", "collections.abc.Sequence"),
    ("py:class", "datetime.datetime"),
    ("py:class", "os.PathLike"),
    ("py:class", "pathlib.Path"),
    ("py:class", "random.Random"),
    ("py:class", "kober.check._Scope"),
    ("py:class", "kober.decoder._Frame"),
    ("py:class", "kober.decoder._Environment"),
]

# Annotations Sphinx's type parser splits on the comma and then fails to look
# up as one name, plus every `zpf` reference, which belongs to another build.
nitpick_ignore_regex = [
    ("py:class", r"tuple\[.*"),
    ("py:.*", r"zpf\..*"),
    ("py:.*", r"^zpf$"),
]

# Keep signatures readable: the model is annotated everywhere, and repeating
# every annotation in the signature line makes the field list harder to scan
# than it makes the signature useful.
autodoc_typehints = "description"
autodoc_member_order = "bysource"
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}
