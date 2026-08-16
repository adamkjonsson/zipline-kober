# Minimal makefile for Sphinx documentation.
#
# Build the HTML docs with `make html`; output lands in `_build/html`.
# Override the builder to use the project virtualenv, e.g.
#   make html SPHINXBUILD=../.venv/bin/sphinx-build
#
# Warnings are errors: a cross-reference that does not resolve should fail the
# build rather than render as plain text.

SPHINXOPTS    ?= -W --keep-going
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
