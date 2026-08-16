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
    # Standard library and typing.
    ("py:class", "ast.AST"),
    ("py:func", "ast.parse"),
    ("py:class", "argparse.ArgumentParser"),
    ("py:class", "collections.abc.Iterable"),
    ("py:class", "collections.abc.Iterator"),
    ("py:class", "collections.abc.Mapping"),
    ("py:class", "collections.abc.Sequence"),
    ("py:class", "datetime"),
    ("py:class", "datetime.datetime"),
    ("py:class", "enum.Enum"),
    ("py:class", "os.PathLike"),
    ("py:class", "Path"),
    ("py:class", "pathlib.Path"),
    ("py:class", "random.Random"),
    ("py:data", "sys.argv"),
    # Private helpers appearing in otherwise public signatures. Listed one by
    # one rather than by pattern, so a new one has to be considered.
    ("py:class", "kober.check._Scope"),
    ("py:class", "kober.decoder._Frame"),
    ("py:class", "kober.decoder._Environment"),
    # Union aliases — `Expr`, `FieldType`, `SizeSpec`, `Repeat`. They are
    # module-level assignments rather than classes, so there is no object for
    # a reference to land on, and autodoc renders them unqualified inside
    # annotations. Documented in prose instead; see api/spec and api/expr.
    ("py:class", "Expr"),
    ("py:class", "ExprValue"),
    ("py:class", "FieldType"),
    ("py:class", "SizeSpec"),
    ("py:class", "Repeat"),
    # Our own exceptions, where an annotation renders them unqualified.
    ("py:class", "EvalError"),
    ("py:class", "ExprError"),
    ("py:class", "KoberError"),
    ("py:class", "SpecError"),
    ("py:class", "TruncatedRead"),
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

# Render `Attributes:` sections as `:ivar:` fields on the class rather than as
# separate attribute entries. Without this every frozen dataclass field is
# documented twice — once from the docstring section, once by autodoc reading
# the annotation — and Sphinx reports each as a duplicate object.
napoleon_use_ivar = True
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}
