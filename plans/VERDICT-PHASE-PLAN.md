# The verdict phase — `0.4.0`

**State: planned.**

> **Written 2026-09-23** against `0.3.0` and the four issues on the
> [`0.4.0` milestone](https://github.com/adamkjonsson/zipline-kober/milestone/3).
> It decides an order, settles what the issues leave open where they interact,
> corrects the issues where probing the code disagreed with them, and records
> what the milestone does not contain. `0.5.0` (byte transforms,
> [`TRANSFORM-PHASE-PLAN.md`](TRANSFORM-PHASE-PLAN.md)) follows it and is not
> touched here.

> The upstream state this was checked against: `../python-zipline` at
> `v0.5.0`, `../packeteer` at `v0.16.0`, `../python-zipline-wire` at
> `v0.4.0-2-g32896b7` (pin `zpf>=0.5.0`). No pin moves in this release.

---

## 1. What this release is

Three of the four issues are about the **verdict** a file states, and one is
about the tool that checks verdicts:

| Issue | What is wrong today | Kind |
| --- | --- | --- |
| [#40](https://github.com/adamkjonsson/zipline-kober/issues/40) | An `emit` on the entry unit is honoured differently by the interpreter's branch, its walk, and the compiler. The two backends write different files for one spec. | bug, both backends |
| [#43](https://github.com/adamkjonsson/zipline-kober/issues/43) | Under `check=False`, a field starved by an earlier `remaining`/`fill` reports `truncated` (hole-class) for a message that arrived whole. | bug, both backends |
| [#32](https://github.com/adamkjonsson/zipline-kober/issues/32) | A stream in the wrong protocol reads as "corrupt messages in this protocol", once per datagram or gap, with a field tree written before the failure. | decode semantics, stage driver |
| [#44](https://github.com/adamkjonsson/zipline-kober/issues/44) | The release checklist requires a pipeline that exists only as prose and a script that was never checked in. | tooling |

**Only #32 changes what kober writes for a spec that passes `check` and sets
no `emit` on its entry unit.** #40 changes output only for specs that set
`emit` on the entry unit, and no shipped spec does. #43 changes output only
for specs that fail `check`. So for `examples/` and every real capture, #40
and #43 must leave the output **byte-identical**, and #32 must change exactly
the streams it declines. §6 makes those two claims the test.

---

## 2. What probing found

Each issue's reproduction was re-run before writing this, with the helpers in
`tests/test_compiled.py`. Where the issue and the code disagree, the code wins
and the plan follows it.

**#40 reproduces exactly as filed.** Over `12 34 56 78` with `emit: field` on
the entry unit, the interpreter writes two field records at every `--emit`
except `none` (where it writes `[0,4) skipped`). The compiler writes one
`dec:t-message` record at `--emit message`. [`emit.py:219`](../src/kober/emit.py)
passes `emit`, not `granularity`, into `_walk`.

**#40's compiler fix is not one line.** The issue proposes seeding
`pygen._granularities` with the entry's own `emit`. That fixes the leaves and
nothing else, because three other places in `pygen.py` also branch on the raw
`--emit` value:

- `render_entry` ([`pygen.py:2459-2554`](../src/kober/pygen.py)) decides
  whether the module writes one message record, walks, or skips.
- `_Function.module` / `threads` ([`pygen.py:1090`](../src/kober/pygen.py))
  decides whether any function carries a sink and a field path at all.
- `_granularity_constants` ([`pygen.py:2890`](../src/kober/pygen.py)) writes
  `EMIT`, which `run_compiled` turns into the participant's adjacency.

With only the seed changed, a module compiled at `--emit message` for an entry
marked `field` would still have `threads == False` and no sink, so it could not
write the field records its seed asks for. §3.1 gives the fix.

**#43 reproduces in both backends, and they agree.** A spec with `remaining`
before a `u16`, and one with a `fill` unit referenced before a trailer, both
run with `check=False` over five bytes:

| granularity | both backends write | tree status |
| --- | --- | --- |
| `message` | `[0,5) truncated`, the complete message declared a hole | `truncated` |
| `field` | every byte cited, no region at all | `truncated` |

So the misdiagnosis is visible in the file only at message granularity. At
field granularity it shows only in the step's return value, which in a byte
stream ends the run.

**#32 costs nothing on any input this project has.** Every stream of the 22
real captures in `../python-zipline-wire/tests/captures/` was run through
`examples/dns.yaml` and `examples/http.yaml`, with the step instrumented to
log each message's verdict. The question was whether any stream has an
`undecodable` before its first OK message **and an OK message after it**,
which is the only case where declining loses a decode:

| spec | first message OK | never OK | OK messages that declining would lose |
| --- | --- | --- | --- |
| `dns.yaml` | 10 | 70 | **0** |
| `http.yaml` | 48 | 32 | **0** |

`packeteer fuzz --seed 1` over `dns_example.pcapng` gives 59 streams, all with
a first message OK, and so **0** lost. On today's inputs #32 changes only
streams that never decode a message: the foreign ones it is aimed at. That
also means the corpus holds **no example of the case #32 is riskiest for**, a
flow in the right protocol whose first message fails and whose later ones do
not. §5 #32 builds that case synthetically.

**The two backends already agree on failure detail text**, which #32's
`comment=` needs. `const` gives `expected 66, read 0` from both, and a switch
with no case gives `no case for 9 and no default` from both. Neither text
names the field, so the comment cannot promise the field path the issue's
example shows (§3.3).

---

## 3. Decisions the issues leave open

### 3.1 #40: resolve the root granularity once, and hand it to everything

The reference's chain is **field → unit → enclosing unit → decoder**, and the
entry unit is the outermost unit. So the granularity of the whole module or
walk is `entry.emit or --emit`. That is exactly what `emit.root_emit()`
already computes for the interpreter, and it is correct today.

- **Interpreter:** in `plan()`, pass `granularity` to `_walk` (the one-line fix
  the issue gives).
- **Compiler:** add `root_granularity(plan, emit) -> Emit`, the `Plan`-side
  twin of `root_emit`, and call it at the top of `render`, `render_decoder`
  and `render_entry`. Everything downstream (the seed, `_Function.module`,
  `render_entry`'s branch, `EMIT`) then receives the resolved value rather
  than the flag. Do this in the three public renderers rather than only in
  `render`, because `render_decoder` and `render_entry` are callable on
  their own and must not disagree with `render`.

What a user will notice: `kober compile --emit none` on a spec whose entry
says `emit: field` now produces a field module, and it exports
`EMIT = "field"`. That is the chain working, not a surprise. It gets one
clause in `--emit`'s help ("the default; a unit's own `emit` overrides it,
the entry unit's included") and in the reference's *Emission granularity*.

### 3.2 #43: convert, keyed on the fields `check` would name

Decide **yes**, with `undecodable`, for the reason `DESIGN.md` §11.5 already
gives for `pointer`: `truncated` claims bytes never existed, and here they
did.

The issue suggests handing the decoder `terminal_units()`. That is the right
source but the wrong granularity. The decoder does not need to know which
*units* are terminal; it needs to know which *fields* are starved. So:

- **One function in `check.py`, `starved_fields(spec) -> dict[tuple[str,
  int], str]`**, keyed `(unit, index)` like `fill_widths`. The value is the
  explanation: `'crc' has no bytes left: 'body' reads to the end of the
  message`. `_check_terminal_field` is refactored to report from it, so the
  error `check` raises and the verdict the decoder gives cannot disagree
  about which fields are affected.
- **Interpreter:** `Decoder.__init__` precomputes it beside `self._fills`,
  regardless of `check`. When a starved field's node comes back `TRUNCATED`,
  replace it with `UNDECODABLE` and the explanation, the same `replace(...)`
  the pointer path uses ([`decoder.py:681`](../src/kober/decoder.py)).
- **Compiler:** wrap a starved field's read in `except TruncatedRead` →
  `raise Undecodable(...)`, the same pattern as the pointer target
  ([`pygen.py:1720`](../src/kober/pygen.py)). Emit it **only** for starved
  fields, so a spec that passes `check` compiles to byte-identical source.
  `tests/compiled_dns.py` regenerated and diffed empty is the proof.
- **A repeated terminal field** (a `remaining` under `repeat`, which `check`
  refuses): the second element is the starved one. Include it: key it as
  the field itself with a flag, and convert a truncation of any element
  after the first. If this turns out awkward in the generated loop, drop it
  and record why after release. It is the least reachable case of a low-priority
  issue.

Rejected: "any truncation after any terminal field in the message". It is
simpler to state, but it would also convert a `fill`'s own trailer truncating
on a genuinely short run, which is a real `truncated`.

### 3.3 #32: what "declining" writes, and what triggers it

The issue's model is adopted: Zeek-style confirmation, entirely in the driver,
with the decoder and `const` untouched. Four points it leaves open:

**(a) The reason: `skipped`, with a comment on every declined region.** This
is the one judgment call the issue names, and the plan leans the issue's way.
`skipped` is literally true of every run after the first, which were never
tried. For the first, `undecodable` would be literal too, but a chained stage
reading `Undecoded` blocks should see *this stream is available to another
decoder*, and one stream should carry one verdict. The comment carries the
evidence either way. **This needs Adam's call before implementation starts**,
because it decides the `DESIGN.md` §3.1 revision and the changelog wording.

The comment is `not {spec name}: {detail} at offset {n}`, e.g.
`not toy: expected 66, read 0 at offset 1`. It uses the spec's `name` (or the
module's `NAME`), the detail both backends already produce identically (§2),
and the offset from `_stopped_at`. It has **no field path**, since neither
backend has one at the step. Adding one would be a separate change to both.
Every declined region carries the comment, not only the first, because a gap
splits the stream into regions and a reader landing on any of them should see
why. `_Writer`'s coalescing merges on `(reason, comment)`.

**(b) Trigger: any `undecodable` before confirmation, as the issue says.** A
narrower trigger (only `const`/`confirm`/`reject`, the identification
constructs) was considered and is not taken. §2 measured the cost of the broad
one as zero, and the narrow one needs a failure classification that neither
backend has. The broad trigger's real risk is iterative decoding: a partial
spec meeting an unknown case in a flow's *first* message now loses the flow's
later datagrams. §2 found no such flow. Record the risk in `DESIGN.md`, and
have the pipeline (#44) print declined-stream counts, so that a future input
where it bites shows up as a number rather than as silence.

**(c) `truncated` before confirmation: keep buffering, decide later.** The
issue says the writer "releases [records] once the step returns OK" and that
`truncated` does not decline. It does not say what happens to a truncated
first message's records. If they are released, a stream that truncates, then
declines, has written records, and the fuzz invariant "no record is ever
written for a declined stream" is false. So: **while unconfirmed, the writer
buffers everything** (records *and* regions, in order) across as many
messages as it takes. The first OK message releases the buffer as-is. A
decline discards the buffered records and rewrites every buffered region
except `gap` to `skipped` with the comment. A stream that ends unconfirmed
without declining (all truncated) is released as-is at `flush()`, which is
today's output.

Cost: memory proportional to the unconfirmed prefix, which is unbounded for a
stream that only ever truncates. Accept it, and say so in the `_Writer`
docstring. A cap would reintroduce the fabricated-records case the issue
exists to remove.

**(d) The step reports its detail.** `_Step` returns `str | None` today. It
becomes a small `_Verdict(reason, detail)` or `None`. For the interpreter
that is `tree.detail`, and for the compiler `str(exc)`. The type is private;
nothing public changes shape.

**Unchanged by (a)–(d):** after confirmation, behaviour is exactly today's.
`undecodable` goes to the end of the run, and the driver resumes at the next
chunk or datagram. Confirmation state is per `decode_stream` /
`decode_stream_compiled` call, so the public per-stream entry points
declining a stream is local to that call. No CLI flag and no API switch turns
it off (§8).

**Changelog:** `Changed`, marked **Breaking:**. No signature moves, but a
consumer that counts `undecodable` bytes for a foreign stream now sees
`skipped`, which is a change in what a file asserts. The note says what to do
instead: read the region's comment.

### 3.4 #44: a script in `tools/`, sharing its comparison with the suite

**A script, not a pytest module.** It shells out to three sibling venvs,
takes minutes, and its output is a report as much as a verdict. A skipped
test is also indistinguishable from a passing one in a green run, which is how
a required step quietly stops happening. So: `tools/pipeline.py`, run as
`.venv/bin/python tools/pipeline.py`, stdlib plus `zpf` and `kober`, with
type hints, ruff clean, and `argparse` flags `--packeteer`, `--wire` (default
`../packeteer`, `../python-zipline-wire`) and `--work DIR` (default a temp
dir, kept on failure).

**One definition of "block for block".** The issue's complaint is that what
the comparison *means* can drift. So `blocks()` and `assert_conformant()` move
out of `tests/test_compiled.py` into a helper module `tests/zpfcompare.py`
(beside `tests/fuzzing.py`, which is the precedent). `test_compiled.py` and
`tools/pipeline.py` both import it; the script adds `tests/` to `sys.path`.
The alternative of a private module in `src/kober` would ship test machinery
in the wheel.

**Inputs are pinned in the script.** They are the seven the 0.3.0 run used
(`docs/dev/testing.md`): fuzzed `dns_example.pcapng` (`--seed 1`), generated
DNS with a compressed `raw:` response, generated chunked HTTP with trailers
at `--mss 200` and 5% loss (`--seed 3`), and `packet_loss`, `http_stream_1`,
`tcp_lossy_ts` and `tcp_reorder_ts`. The DNS messages file the 0.3.0 run wrote
by hand is checked in as `tools/dns-messages.json`, with the query and
compressed response taken from `dns_example.pcapng`, and in the
`{"raw": …}` shape (the trap `testing.md` records). The script prints the
packeteer and zpfwire versions it ran against, since a seed is not a file
across their versions.

**Shape is asserted as relations, not remembered counts.** Absolute counts
move with packeteer's bytes. The relations do not, so the script asserts:

- HTTP: start lines = 2 × requests generated, for streams that confirm;
  chunk-size records > 0; trailer-field records > 0.
- DNS: `.target` records > 0 in both the fuzzed and the generated input.

It prints the absolute counts too, and `testing.md` records them per release
as it does now.

**Per (input, driver, granularity) it checks:** conformance, coverage, and the
interpreter/compiled pair equal under `blocks()` (participant adjacency
included; the undecoded comment included once #32 lands). It prints one line
each, and after #32 a declined-stream count per input. It exits non-zero on
any failure.

**Docs point at the file.** `docs/dev/testing.md` *The deeper pipeline*
keeps its explanation of why the pipeline exists and what each input is for,
and replaces the shell recipes with the command. `README.md` *Fuzzing*,
`docs/dev/contributing.md` *Before a release*, and `CLAUDE.md`'s pointer
("in the README, under Fuzzing") name `tools/pipeline.py`.

---

## 4. Order, and why

```
0.  version → 0.4.0.dev0
1.  #44  tools/pipeline.py; run it on unchanged 0.3.0 code  ← the baseline
2.  #40  entry-unit emit, both backends                      ┐ must leave the
3.  #43  starved fields, both backends                       ┘ pipeline identical
4.  #32  stream confirmation in the driver                   ← the one real change
5.  pipeline again; diff against step 1; release
```

**#44 first, because it produces the baseline.** #32 is the first semantic
change to `stage.py` since the seam bug, and the pipeline is the only thing
that reaches the driver. Landing the tool before anything changes gives a set
of files written by 0.3.0 behaviour to diff every later step against. Built
after #32, it could only say that 0.4.0 agrees with itself.

**#40 and #43 before #32, and each checked against the baseline.** Neither
should move a byte of pipeline output (§1). Running the pipeline after each
turns that into an observation. They are independent of each other and can
swap.

**#32 last**, on top of a differential that already compares comments. After
it, the pipeline diff against step 1 should show exactly the declined streams
and nothing else. §2 predicts that means only the streams that never decoded
a message.

---

## 5. The work, issue by issue

### Step 0 — `0.4.0.dev0`

`pyproject.toml` → `0.4.0.dev0`. Confirm `../python-zipline-wire/.venv` imports
`zpf` 0.5.0, since 0.3.0's §8.6 found sibling metadata stale once already.

### #44 — the pipeline

Files: new `tools/pipeline.py` and `tools/dns-messages.json`; new
`tests/zpfcompare.py` (moved `blocks`, `assert_conformant`); `test_compiled.py`
imports it; `docs/dev/testing.md`, `README.md`, `docs/dev/contributing.md`,
`CLAUDE.md` as §3.4 says.

Check before calling it done: break something the pipeline should catch and
watch it fail. Two cases: make `run_compiled` write one extra undecoded
region, and make the HTTP spec's trailer read two extra bytes (the 0.3.0-era
bug). The first must fail the block comparison, and the second the shape
assertion.

Changelog: `Documentation`. The release checklist now names a script.

### #40 — entry-unit `emit`

Files: [`src/kober/emit.py`](../src/kober/emit.py) (`plan`),
[`src/kober/pygen.py`](../src/kober/pygen.py) (`root_granularity`; `render`,
`render_decoder`, `render_entry`), `cli.py` `--emit` help,
`docs/format/document.md` *Emission granularity*.

Tests, in `test_compiled.py`, each reverted-and-watched:

- The issue's table as one parametrised test: entry `emit: field`, all three
  `--emit`, `writes()` on each. The `none` row catches the `plan()` fault and
  the `message` row catches the `pygen` fault, which gives them separate
  witnesses as the issue asks.
- The mirror: entry `emit: message`, `--emit field` → one message record from
  both.
- `EMIT` on the generated module equals `root_emit()`, and so does the
  participant adjacency, via `blocks()`.
- Add a spec with an entry `emit` to the awkward corpus, so
  `test_every_prefix_writes_the_same_records` covers it from now on.
  Nothing covered it before because every fixture set `emit` on a nested unit.

Changelog: `Fixed`, noting that output changes for a spec with `emit` on its
entry unit, and that a module compiled from such a spec should be regenerated.

### #43 — starved fields

Files: [`src/kober/check.py`](../src/kober/check.py) (`starved_fields`;
`_check_terminal_field` reports from it),
[`src/kober/decoder.py`](../src/kober/decoder.py),
[`src/kober/pygen.py`](../src/kober/pygen.py). `DESIGN.md` §11.5's principle
gains its second application; `docs/format/` *Decode-time failure* gets the
row.

Tests, each reverted-and-watched:

- Both of §2's specs, at both granularities, both backends, `check=False`:
  `undecodable`, the message's bytes named, not `truncated`, with the
  explanation.
- The trailer of a correctly placed `fill` over a genuinely short run still
  says `truncated`. This guards against the rejected broad rule in §3.2.
- `check`'s errors for every existing terminal-rule test are unchanged (the
  refactor moved them, it must not have changed them).
- `tests/compiled_dns.py` regenerated: empty diff.
- **Fuzz** (`test_fuzz.py`, seeded): a spec refused by the terminal rule,
  decoded with `check=False` over mutated inputs, never yields `truncated`
  from a starved field. This is an invariant of the kind `CLAUDE.md` says
  gets a fuzz test.

Changelog: `Fixed`, stating it is reachable only with `check=False`.

### #32 — stream confirmation

Files: [`src/kober/stage.py`](../src/kober/stage.py): `_Verdict`, both steps
return it, `_Writer` gains the unconfirmed buffer and `(reason, comment)`
coalescing, `_drive` holds the confirmed / declined state, and
`_drive_stream` / `_drive_datagrams` skip-without-trying once declined. The
module docstring gains a paragraph on confirmation.

Tests, in `test_stage.py` with `write_transport` / `datagrams`, each
reverted-and-watched, all through **both** drivers with `blocks()` equal:

- The issue's toy spec over a foreign datagram stream: one `skipped` region
  per stream with the comment, no records, at both granularities.
- The same over a byte stream with two gaps: `skipped`, `gap`, `skipped`,
  `gap`, `skipped`, no retry after either gap. Check that with a counting
  step, not from the output.
- **The risky case §2 found no example of:** right protocol, first message
  undecodable, later ones fine. It declines, and the test asserts that and
  names the trade-off in its docstring.
- Confirmed, then undecodable: today's output exactly (resume after the gap
  or at the next datagram).
- Truncated first, then OK: records released, identical to 0.3.0 output.
  Truncated first, then undecodable: declined, and nothing written, which is
  §3.3(c)'s case.
- Message granularity over a foreign stream: no difference but the reason and
  comment.

**Fuzz, stage-level, the first of its kind in the suite.** Seeded random
streams built with `write_transport` and `datagrams`: runs and datagrams
mixing valid, foreign and truncated messages, with gaps. Invariants:

- A declined stream writes no record, and its every byte is `skipped` or
  `gap`.
- A stream that confirms writes, from the confirming message on, exactly
  what 0.3.0's driver would have written. Keep the old driver loop as a
  reference inside the test.
- Conformance and coverage hold.

Docs: `DESIGN.md` §2 (a row in the failure list, a stream whose first message
fails → `skipped` for the whole stream), §3.1 (the "honest `undecodable`
region" sentence, revised per §3.3a), and the risk from §3.3b stated where a
reader of §3.1 will find it. `docs/dev/architecture.md` on the driver.

Changelog: `Changed`, **Breaking:** (§3.3).

---

## 6. Definition of done

- `ruff check` clean, including `tools/`; `.venv/bin/pytest` green;
  `sphinx-build -W` clean.
- `tools/pipeline.py` passes, and its diff against the step-1 baseline is
  **empty after #40 and #43**, and after #32 differs **only** in the streams
  it reports declined.
- `tests/compiled_dns.py` regenerated with an empty diff.
- Every regression test reverted-and-watched; the two pipeline breakages in
  §5 #44 watched to fail.
- `CHANGELOG.md` `Unreleased`: `Changed` (#32, Breaking), `Fixed` (#40, #43),
  `Documentation` (#44).
- `plans/README.md` row updated; this plan's state line updated and a
  "what the plan got right and wrong" section appended after release.

---

## 7. Releasing

1. `tools/pipeline.py`, and record the counts in `docs/dev/testing.md`.
2. The sweep `contributing.md` requires: `README.md`, `DESIGN.md`, `docs/`.
3. `CHANGELOG.md`: `Unreleased` → `[0.4.0] - <date>`, fresh `Unreleased`,
   link definitions.
4. `pyproject.toml`: drop `.dev0`.
5. Tag `v0.4.0`.
6. Close #32, #40, #43, #44 and milestone 3, at release, not at merge.

---

## 8. What the milestone deliberately leaves out

- **A spec key for identification** (`magic: true`, unit-level `identify:`).
  #32 argues against it and the plan agrees. Revisit if §3.3b's risk shows
  up in a pipeline count.
- **A switch to turn confirmation off** (CLI or API). Nothing asks for one,
  and `CLAUDE.md`'s CLI/API parity rule means adding it costs two surfaces.
  If iterative decoding needs it, it is a small additive change later.
- **A field path in the decline comment** (§3.3a). It needs both backends to
  carry one to the step.
- **A cap on the unconfirmed buffer** (§3.3c).
- **Transforms.** That is `0.5.0`.
