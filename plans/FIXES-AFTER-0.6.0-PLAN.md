# Plan: the fixes found after 0.6.0

**State: Stages 0 to 6 done (2026-10-28); Stage 7, the port to
python-zipline 0.8.0, next.** [zipline#168](https://github.com/adamkjonsson/zipline/issues/168),
whose one position past a FIN failed two tests and 80 pipeline checks, was
settled by spec 0.24 and fixed only in python-zipline 0.8.0 (2026-10-30), so
the port joined this milestone (#64; see *Stage 7*). Written 2026-10-28 against `0.6.0` (released
2026-10-20), `zpf` 0.6.0 pinned (`>=0.6.0,<0.7`), packeteer 0.21.0, `zpfwire`
0.5.0. The milestone is GitHub's `0.7.0`, which holds eight open issues, all of
them found *after* `v0.6.0` was tagged. See *The version* for why it is a
minor.

| # | Kind | What | Stage |
| --- | --- | --- | --- |
| [#61](https://github.com/adamkjonsson/zipline-kober/issues/61) | env | `.venv` runs `zpf` from `../python-zipline`, which now reports 0.6.0 while executing **0.7.0** | 0 |
| [#60](https://github.com/adamkjonsson/zipline-kober/issues/60) | test | `zpfcompare.blocks()` ignores `timestamp` and `ts_first` | 1 |
| [#57](https://github.com/adamkjonsson/zipline-kober/issues/57), [#58](https://github.com/adamkjonsson/zipline-kober/issues/58) | bug | a call on a non-name callee is refused as `'Attribute'` (one fix, two reports) | 2 |
| [#59](https://github.com/adamkjonsson/zipline-kober/issues/59) | bug | a mistake inside `params:` / `transforms:` is reported at line 1 | 3 |
| [#51](https://github.com/adamkjonsson/zipline-kober/issues/51) | bug | `check` accepts a repeated `computed`, `select` or `pointer` | 4 |
| [#54](https://github.com/adamkjonsson/zipline-kober/issues/54) | bug + feature | `http.yaml` cannot read a chunk extension; needs a `before()` builtin | 5 |
| [#62](https://github.com/adamkjonsson/zipline-kober/issues/62) | docs + tools | the `--protocol-messages` trap is stale; the pipeline's DNS responses go c2s | 6 |
| [#64](https://github.com/adamkjonsson/zipline-kober/issues/64) | port | move the pin to python-zipline 0.8.0 (spec 0.24, new distribution name) | 7 |

## Why this order

**The environment first, because it decides what every later result means.**
#61 was written when `../python-zipline` held `0.7.0.dev0`; it now holds the
`v0.7.0` tag plus three commits, so today's suite runs against a `zpf` minor
the pin excludes. Nothing measured in this venv — a test pass, a pipeline run,
a baseline — says anything about `zpf` 0.6.0 until that is fixed.

**The comparison second, because it is the instrument for the rest.** Once
#60 lands, a stage that moves a timestamp shows up in the differential tests
and in `tools/pipeline.py --baseline`. Fixing it after the code changes would
leave those changes measured with the old blind spot.

**Then the fixes, cheapest and most local first.** #57/#58 is one function in
`expr.py`; #59 touches the loader and `check` but no decoding; #51 is a new
static refusal in `check`; #54 adds to the language and both backends. #62 is
last because it changes the pipeline's own inputs, and its acceptance is a
`--baseline` diff that should move nothing else — easiest to read once the
other stages are in.

## Stage 0 — an honest venv, and a baseline taken in it (#61)

1. Reinstall `.venv` from `requirements.txt` with `zpf` from the `v0.6.0`
   release, not a path install. Confirm `zpf.__file__` is under
   `site-packages` and `zpf.__version__ == "0.6.0"`.
2. Run the suite. A failure here is a finding: `0.6.0` itself may have been
   validated against a dev `zpf`. Record what was found in this plan.
3. Keep co-development possible in a second venv, `.venv-dev`, with the
   sibling checkout path-installed. Write the convention next to the pin's
   comment in `pyproject.toml` and in `docs/dev/contributing.md`, and in the
   *Virtual environment* section of `CLAUDE.md` (with your sign-off, as it is
   your instruction file).
4. `tools/pipeline.py` prints `zpf.__version__` **and** `zpf.__file__` beside
   the binaries' versions it already prints, so a stale path install is
   visible in the first lines of every run.
5. Take the pipeline baseline on the unchanged `v0.6.0` code, in this venv,
   into `../kober-baselines/v0.6.0`. There is none yet (the last is
   `v0.5.0`), and Stages 1–6 are measured against it.
6. Bump `pyproject.toml` to `0.7.0.dev0`.

Changelog: **Documentation** (the venv convention). Test-only otherwise.

**Done, and what it found.** PyPI's `zpf` 0.1.0 is not an old python-zipline
release but an unrelated, empty project of the same name, so the README's
"PyPI publishes only `0.1.0`" was wrong; `.venv` now installs
`git+https://github.com/adamkjonsson/python-zipline@v0.6.0`, and both install
sections say so. The pin also refuses the checkout's 0.7.0 outright, so
`.venv-dev` installs kober `--no-deps`.

Under the real `zpf` 0.6.0 the suite gave 2,276 passed, 1 skipped, **2
failed**: `test_wireguard_example.py`'s two HTTP-inside tests. They fail the
same way under `zpf` 0.7.0 in `.venv-dev`, so `zpf` is not the cause. The
sibling `zpfwire` is: it is now **0.8.0** (kober 0.6.0 was validated against
0.5.0), and its #60 writes a bare FIN as a zero-length record at the stream's
end, after which the pure ACKs sit **one past it**, since the FIN took a
sequence number. `zpf.check_coverage` then measures each such stream a byte
longer than the bytes it carries, and reports that byte as neither decoded nor
undecoded. The pipeline shows the same on every TCP input: **64 failures, all
this one byte**, 8 inputs × 8 runs, nothing else. Not kober's fault, and to be
reported to python-zipline-wire. The baseline was taken anyway, with these
tools, since later runs use the same ones: `../kober-baselines/v0.6.0`, its
log beside it as `v0.6.0.log` (packeteer 0.21.0, `zpfwire` 0.8.0, `zpf` 0.6.0
from `site-packages`).

Not in scope: `python-zipline-wire`'s venv, which reports `zpf` 0.7.0 — worth
a look before its own review, but it is that project's issue.

## Stage 1 — `blocks()` compares timestamps (#60)

1. Add `block.timestamp` and `block.ts_first` to the record tuple in
   `tests/zpfcompare.py`, as the issue proposes.
2. Run the differential tests and the pipeline against the Stage 0 baseline.
   Under a single `zpf` 0.6.0 both backends should agree; a difference is a
   real drift between interpreter and compiler and becomes its own issue.
3. **Check the test against the bug**: make one backend's record carry a
   wrong `ts` (a local hack, not committed) and watch the differential test
   fail; then remove the hack.
4. Look for any fixture that compares against stored bytes rather than the
   other backend; the issue predicts 12 bytes per affected record.

Changelog: none (test-only), unless the pipeline's comparison counts as
user-visible — it does not; it is a dev tool.

## Stage 2 — name the callee as written (#57, #58)

1. In `_translate_call` (`src/kober/expr.py`), name a non-`Name` callee with
   `ast.unparse(node.func)`: `'a.len'`, `'keys[0]'`, `'(a + b)'`,
   `'lower(tag)'`.
2. For `x.f(...)` where `f` is one of the six functions, say so: *a method
   call is not allowed; write `lower(tag)`* (#58).
3. Make `_describe`'s `type(node).__name__` fallback unreachable, or prove it
   is: list every path into `_describe` (`_translate`, `_lookup`, the call
   path) and what node types can reach each. If one remains, give it words
   rather than a class name. Adding table entries one regression at a time is
   what lost `Subscript` in 0.6.0.
4. Tests: the table from #57 plus the three expressions from #58. Each message
   contains the callee as written and none of `Attribute`, `Subscript`,
   `Constant`, `BinOp`. A fuzz-style test over random refused expressions that
   asserts no AST class name ever appears in a message is cheap and keeps the
   promise `docs/format/expressions.md` makes — by CLAUDE.md's rule it is an
   invariant, so it gets one.
5. Revert, watch fail, restore.

Changelog: **Fixed**, citing both issues. Close #58 as a duplicate of #57 at
release, not before.

## Stage 3 — findings in `params:` and `transforms:` at their own lines (#59)

1. Find where the loader builds the location for a parameter and for a
   transform declaration, and why it takes the document's. Record each entry's
   location from its own mapping; for a scalar short form (`mode: int`),
   from the enclosing `params:` / `transforms:` mapping.
2. Carry those locations into the `SourceMap` (`src/kober/source.py`,
   `loader.py:646`), so `check`'s findings for `t.params.*` and
   `t.transforms.*` resolve the way field paths already do.
3. Tests: each of the five mistakes in the issue, asserting the line, for
   both the loader's `SpecError` and `check`'s errors and warnings. Same for
   JSON input if the JSON loader carries lines at all; if not, say so in the
   test.
4. `docs/format/document.md`: state that only a key on the document itself is
   reported at line 1.
5. Revert, watch fail, restore.

Changelog: **Fixed**.

## Stage 4 — `check` refuses a repetition of a field that reads nothing (#51)

1. In `src/kober/check.py`, refuse `count`, `until` and every other
   repetition kind on a field whose types do not read input where it stands
   (`_reads_input` over `_walk_types_read`), with the message Stage 2 of the
   transform phase uses for `transform` and `concat`: *cannot repeat: it reads
   nothing where it stands*. One rule, so the five constructs cannot drift
   apart again; the existing `transform`/`concat` refusal folds into it.
2. A literal `count: 0` on such a field is refused by the same rule (the
   issue's reasoning). A `count` *expression* that evaluates to 0 at runtime is
   not a static question and stays legal.
3. Confirm no shipped example or doc spec is refused (`test_examples.py`,
   `test_docs.py`).
4. Tests: `computed`, `select`, `pointer` × `count`, `until` and any other
   repetition kind; plus a `select` whose every case is non-reading and one
   where a case reads (accepted). Revert, watch fail, restore.
5. The decoder's runtime guard (`decoder.py:666`) stays: it is now
   unreachable for a checked spec, and still right for `check=False`.

Changelog: **Fixed**. Not *Breaking*: every spec newly refused already failed
on every message with a repetition of at least one element.

## Stage 5 — chunk extensions in `http.yaml`, via `before()` (#54)

1. **The builtin.** `before(s, sep) -> str`: the text before the first
   `sep`, or all of `s` if there is none. Total, typed `(str, str) -> str`.
   Add it where `startswith`/`endswith` (#50) were added: the interpreter and
   type rules in `expr.py`, the compiled backend in `pygen.py`, the list of
   functions in the refusal message, and `docs/format/expressions.md`
   (`test_docs.py` fails until it is documented). An empty `sep` needs a
   decision; `str.partition` refuses it, so refusing it in `check` when it is
   a literal and returning `s` at runtime is the likeliest answer.
2. **The spec.** `examples/http.yaml`'s chunk length becomes
   `to_int(before(size, ';'), 16)`; `size` still reads to CRLF and keeps the
   extension in its text, so the record cites the same bytes as today.
3. **Tests.** Example tests with no extension, one, and several
   (`;a=1;b="x y"`); the stream case from the issue — a first response with an
   extension no longer declines the stream, so **count the start lines**;
   gzip + chunked + extension reaches `content`. The differential test for the
   builtin over both backends. A size line with an extension in
   `fuzzing.py`'s HTTP seeds.
4. **Real traffic.** packeteer's generator writes no extensions (per the
   issue). Check whether 0.21.0 can; if not, a `packeteer protocol` spec or a
   `raw:` message may do it, and if neither can, file it upstream rather than
   leave chunk extensions as example-only coverage.
5. Revert the spec change, watch the stream test fail, restore.

Changelog: **Added** (`before()`), **Fixed** (`http.yaml` and chunk
extensions).

## Stage 6 — the stale trap, and DNS responses that go s2c (#62)

1. Rewrite `tools/dns-messages.json` in the wrapped form, `"direction": "c2s"`
   for the query and `"s2c"` for the response, as
   `examples/wireguard/dns.json` already is.
2. Raise `tools/pipeline.py`'s stated packeteer minimum from 0.18.0 to
   0.20.0.
3. Replace the trap in its three places — `CLAUDE.md` (*Testing*),
   `tools/pipeline.py` (`_generated_dns`), `docs/dev/testing.md` (*One trap*)
   — with the current rule: wrap a section to give it a direction; a bare one
   is sent `c2s`; a bare one with `direction` is refused. Keep the advice to
   count `.target` records.
4. `tools/pipeline.py --baseline ../kober-baselines/v0.6.0`: only the
   DNS-generated outputs move, in participants and directions, not in
   records.

Changelog: **Documentation** (`docs/dev/testing.md`).

## Where it stands

Every stage was checked against its bug: each fix reverted, its tests watched
fail, the fix restored. What each found beyond its issue:

- **Stage 1.** With a backend made to write a wrong `ts`, 383 differential
  tests passed under the old `blocks()` and fail under the new one. No fixture
  compares against stored bytes. The pipeline moved nothing.
- **Stage 2.** `(yield x)`, `(yield from x)` and 3.14's t-strings reached the
  same fallback (`Yield`, `YieldFrom`, `TemplateStr`); `_lookup`'s path cannot,
  since every Python operator is allowed or in `_REFUSED_OPS`. The fallback
  now quotes the source, and a seeded fuzz test asserts no refusal names an
  AST class.
- **Stage 3.** The nearest mapping's line, as #59 suggests, is still wrong for
  a scalar short form that is not its block's first key, so the YAML loader
  records each key's line (`_LinedDict.key_lines`), used for entries of
  `params:` and `transforms:` only. A key on the document still reports line 1,
  as `document.md` says; key lines would let that go too, if wanted.
- **Stage 4.** `test_a_repeated_zero_width_field_is_a_decode_time_finding`
  pinned the old behaviour on purpose, so the family would move together, and
  became the refusal's test. Four tests of the runtime guard now build with
  `check=False`. Not done: a `unit` whose every field reads nothing, repeated,
  passes `check` and fails the same way; rarer, and it needs a fixpoint over
  units.
- **Stage 5.** `before()` is one function in `kober.expr`, which the compiled
  module imports from `kober.runtime`, since `str.partition` raises on an empty
  separator. packeteer's generator writes no extension, but a `raw` message
  does, so the pipeline gained `http_ext` and `http_ext_clean`: 30 transactions
  each, where 0.6.0's spec decoded **no** response and this one decodes all 30
  (26 under unrecovered loss), and the clean one matches the reference reader
  exactly (60 start lines, 80 chunk sizes, 30 trailer lines).
- **Stage 6.** Against `../kober-baselines/v0.6.0`, 96 outputs differ: every
  `http` one in its decoder's `params_digest` alone, since the spec changed;
  the 16 of `dns_gen` (four specs, four runs), whose responses now leave from
  the server, 18 of 18, with the same 35 messages, 1,381 fields and 36 pointers
  followed; and the 16 new `http_ext` ones. 80 checks fail, every one the #168
  position (10 TCP inputs × 8), and nothing else.

`DESIGN.md` §3.3 still says "a closed table of three functions", stale since
0.5.0's `startswith` and `endswith` and now by four.

## Stage 7 — the port to python-zipline 0.8.0 (#64)

Added 2026-10-30. python-zipline 0.8.0 implements spec 0.24, which settled
#168 by reading 1: an extent counts sequence numbers, and a FIN's position is
owed no coverage. No 0.6.x or 0.7.x carries it. `zpfwire` 0.9.0 is already
built on 0.8.0, so against today's siblings kober on `zpf` 0.6.0 fails six
sibling-driven tests with *unsupported version_minor 24*: a 0.7.0 on the old
pin could not read the current tools' output. So the port is part of this
release, not a later 0.8.0.

**Measured before starting**, in a throwaway venv on the `v0.8.0` tag with
this branch's code unchanged: the suite passes, 2,354 and 1 skipped, the
sibling-driven tests and #168's two included; the pipeline holds every check
(419). Against `../kober-baselines/v0.6.0`, every moved output is explained:
the `http` spec digest (Stage 5), `dns_gen`'s directions (Stage 6), `ts_first`
on 5,106 records of the four HTTP inputs (`zpf` 0.7.0, #87, which kober never
shipped on), and `zpfwire`'s version in the sessionized tunnel files. The
Session End extent one larger after a stored final ACK is #168's fix, and
`blocks()` does not compare it. That run is the port's baseline:
`../kober-baselines/plan_0_7_0-zpf080` (log beside it), since `zpf` 0.8
cannot read the `v0.6.0` one.

**Decided (2026-10-30):**

- **The dependency is the release tag**, `python-zipline @
  git+https://github.com/adamkjonsson/python-zipline.git@v0.8.0`, as
  `zpfwire` declares it. Never resolved on an index: `python-zipline` is
  unclaimed on PyPI, so a range by name would install whoever claims it, the
  dependency confusion python-zipline renamed itself to escape (#102). Cost:
  a python-zipline patch reaches kober users only through a kober release,
  and kober and `zpfwire` must name the same tag to share an environment. A
  range again once python-zipline is published under its name.
- **A datagram flagged `copy` is not decoded.** Spec 0.24 makes a copy
  byte-identical to its participant's preceding record, so decoding one tells
  nothing new and counts a message the sender sent once, with no way for a
  reader to see it; on a stream, reassembly already drops a duplicate. The
  driver reads `datagrams(copies=False)` and marks each copy's bytes `skipped`
  with a comment saying it is a capture-point copy. `dns_fuzz` holds 40.

Steps:

1. **The pin.** `pyproject.toml`'s dependency as above, and its comment
   rewritten for the new floor (spec 0.24, the FIN rule, `copy`) and the form.
   `requirements.txt` does not repeat it.
2. **The venvs.** `pip uninstall zpf` in `.venv` and `.venv-dev` before
   installing; `.venv-dev` is broken until then, since `zpf` 0.8 reads its own
   version from `python-zipline`'s metadata. Confirm `zpf.SPEC_VERSION ==
   (0, 24)` and `zpf.__file__` under `site-packages` in `.venv`.
3. **Copies.** `_drive_datagrams` reads `datagrams(copies=False)`, and each
   copy's range is written `skipped` with its comment, in both backends (the
   driver is shared; check the compiled path anyway). Tests: a datagram file
   with a copy, decoded by both, asserting one message and the copy's bytes
   `skipped` with the comment; a copy before confirmation, so a declined
   stream still accounts for it; and a fuzz case, so "no byte both cited and
   undecoded" covers copies. Revert, watch fail, restore.
4. **A stream that ends in a gap.** `chunks()` can now end on a trailing
   `Gap` (a pure ACK after a lost tail). The pipeline passes with it; pin it
   with a test of the driver over such a stream, both backends.
5. **Docs.** The install lines in README, *Contributing* and `CLAUDE.md`, now
   one step (`pip install -e . -r requirements.txt` installs the tag). The
   pin's paragraph in README and *Contributing* (spec 0.24, the new name, why
   a tag). Any page naming spec 0.23 or `zpf` 0.6.
6. **Changelog.** **Changed**, **Breaking**: output is spec 0.24, which
   `zpf` 0.6 and 0.7 refuse, and the dependency is `python-zipline` by tag,
   so an environment needs `pip uninstall zpf` first; a Session End declares
   one more after a stored final ACK; `ts_first` is written on a unit drawn
   from several records; a `copy` datagram is `skipped`, not decoded.
   **Fixed**: kober's output passes `check_coverage` over a closed TCP
   connection (zipline#168).
7. **Checks.** `pressure_test.py` rerun, since it is the source of the
   design's verified claims; any claim it no longer verifies is a finding.
   The pipeline against `../kober-baselines/plan_0_7_0-zpf080`: only
   `dns_fuzz` should move, by its copies.

## Release

1. Full suite, `ruff check`, `sphinx-build -W`, and the deeper pipeline with
   `--baseline ../kober-baselines/plan_0_7_0-zpf080`. Every moved output is
   explained by a stage above.
2. Take the new baseline into `../kober-baselines/v0.7.0`.
3. The release steps in `CLAUDE.md`; close the nine issues and the
   milestone.

## The version

**`0.7.0`.** The milestone was first named `0.6.0`, which was already tagged,
and was renamed on 2026-10-28. `before()` (#54) is new language, which SemVer
puts in a minor. Stage 0 bumps `pyproject.toml` to `0.7.0.dev0`.

Stage 7 moves the pin, from `zpf` 0.6 to python-zipline 0.8.0, which is
always a minor here, and is breaking: kober's output becomes spec 0.24. A
minor is what this release already is, so the port is in it. `zpf` 0.7 is
skipped; kober never shipped on it. (Until 2026-10-30 this section said the
pin would stay at 0.6 and the port be a separate 0.8.0; #168 being fixed only
in python-zipline 0.8.0, and `zpfwire` 0.9.0 moving to it, changed that.)
