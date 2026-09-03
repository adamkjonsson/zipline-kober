# Impact of the spec simplification on kober

> **Assessment, not a plan.** Written 2026-09-03 against
> [SIMPLIFICATION-ANALYSIS.md](https://github.com/adamkjonsson/zipline/blob/main/docs/SIMPLIFICATION-ANALYSIS.md)
> in the spec repository, which ranks five principles of the `0.18` format that
> could be loosened, and beside
> [`python-zipline`'s own assessment](https://github.com/adamkjonsson/python-zipline/blob/main/plans/SIMPLIFICATION-IMPACT.md)
> of the same document. This one asks what each loosening would do to *this*
> project: what it removes, what it costs, and what it changes about the next
> `zpf` bump. It decides nothing; the direction is the spec's to choose.

kober is at `0.1.0.dev0`, unreleased, pinned to `zpf` `0.2.x`, which implements
spec `0.16`. The spec repository is at `0.18`, cut 2026-09-02, and the
simplification would land at `0.19` or later.

---

## 1. Verdict

**The package the analysis recommends — 3.1, 3.2 and 3.3 with the rationale
moved out — costs kober nothing and removes nothing from its source.** Proposal
3.4 is the only one with teeth for this project, and 3.5 is neutral today. The
real gain is fewer format ports; the real decision is which port to take next.

The reason is structural. Everything kober asks of the format lives in one
module, [`stage.py`](../src/kober/stage.py), and it uses a deliberately small
surface:

| kober writes | kober never writes |
| --- | --- |
| records with `cites`, `content_type`, `comment`, `ts` | `origin`, `sequenced_basis`, `SINGLE_CLOCK` |
| Undecoded regions with the four canonical reasons | `output_layer`, hints, `seq_start` |
| a `Seam` carrying a reason and no width | `input_extents`, `reason_class`, `dropped` |

The right-hand column is exactly the option set the analysis deletes. The only
one that appears in a kober output file at all is `input_extents`, which
`zpf.DecodeStage` declares on close without kober's involvement. What kober
reads is narrower still: `chunks()`, `datagrams()`, `is_stream_oriented`,
`Segment.ts`, and `zpf.blocks.UNDECODED_REASONS` for the seam rule. For
verification, the tests and the README's fuzz pipeline use
`zpf.ConformanceChecker`, its `coverage_findings()`, and
`zpf.check_coverage(output, input)`.

That surface is the part of the format the analysis calls the stated goals,
plus the *producer* half of derivation. The *verification* half of derivation,
which is where the weight sits, is something kober consumes rather than
implements.

---

## 2. Per proposal

Ordered as the analysis orders them.

| Proposal | kober code touched | Given up | Gained |
| --- | --- | --- | --- |
| 3.1 pass-through | none | nothing | nothing direct |
| 3.2 sequencing basis | none | nothing | nothing direct |
| 3.3 advisory tier | none | nothing | a simpler fix for python-zipline #63 |
| 3.4 coverage as SHOULD | one assertion in three test helpers | the single-file proof, and the seam check | nothing in code |
| 3.5 single axis | none | a future per-hop tunnel account | a stale sentence in `DESIGN.md` becomes exact |
| Rationale extraction | none | nothing | a shorter spec behind the seam rule |

### 3.1 Pass-through as a distinct derivation kind

kober is a decode stage. Every record it writes carries `spans` through
`cites=`, and it never writes or reads `origin`. The two-hop resolution rule
that 3.1 collapses is about merged and annotated files, which kober neither
produces nor has a reason to read differently. **No impact.**

### 3.2 A producer must justify its sequencing claim

kober never reads hints, `SEQUENCED`, or a basis, and its shape dispatch is on
`is_stream_oriented`, which is a property of whether records carry `seq_start`,
not of sequencing. Whatever the output session's flags are, `zpf.derive_from`
sets them. **No impact.**

### 3.3 Two readers must agree on non-conformant input

kober has no reader of its own beyond `zpf`'s, so the pinned repairs that 3.3
deletes are not code here. But one of them is kober's problem in practice:

- **#63 is the origin floor.**
  [python-zipline#63](https://github.com/adamkjonsson/python-zipline/issues/63),
  filed from this project, is `check_coverage` measuring a real TCP stream as
  2³²−1 bytes. `DESIGN.md` §13.4 records why: a zero-length SYN record sits one
  below the `isn + 1` origin, `chunks()` skips it, and `record_ranges` does not.
  The loosened rule in 3.3 — a record whose `seq_start` precedes the origin
  covers no byte, and a reader ignores its placement — is what `chunks()`
  already does. Under 3.3 the fix is making `record_ranges` agree with
  `chunks()`, which is simpler than `0.17`'s running-maximum placement.
- **The unranked handshake candidate goes further.** Dropping `syn`-flagged
  zero-length records from the format removes #63's trigger entirely: there is
  no empty record for `chunks()` to skip. That is zpfwire's to write and kober's
  to benefit from.

The loss the sibling assessment names — two readers agreeing on a malformed
file — is not kober's to feel, since kober does not have a second reader. The
write-side guard python-zipline plans survives every package and stops the file
existing. **Neutral to positive.**

### 3.4 Coverage as a verifiable MUST

kober's design is built on the coverage guarantee (`DESIGN.md` §2), so this is
the one to be precise about. What 3.4 changes and what it does not:

**The producer side is untouched.** `zpf`'s auto-fill, the `Seam`, and kober's
hole-class seam rule (`DESIGN.md` §5) all stay: they are how the output honours
the guarantee by construction, and a SHOULD does not tell a producer to stop.
`reason_class` leaves, but kober writes only the four canonical reasons, and 3.4
keeps those implying a class, so `UNDECODED_REASONS` and the seam rule that
reads it are unchanged. `dropped` leaves, and kober never writes it: a message
it cannot parse is `undecodable`, which is the right word under both versions.

**kober's own verification survives.** Every `assert_conformant` helper in the
tests, and the README's fuzz pipeline, checks the *pair* with
`check_coverage(output, input)`, and kober always has the input in hand because
it is a stage. Only the single-file `coverage_findings()` assertion goes. The
invariants in [`test_fuzz.py`](../tests/test_fuzz.py) — never raises, never
claims more than given, never both cited and undecoded, every reason
classified — are emitter-level and do not depend on the spec at all.

**What kober gives up is a claim to its consumers.** Today a kober output file
proves on its own that nothing was dropped. Under 3.4 that becomes a promise
the producer keeps, and anyone holding only the output cannot check it.
`zpf validate FILE` without `--input` stops being able to say it.

**The seam check is the concrete loss.** kober's one shipped nonconformance,
recorded in `DESIGN.md` §13.5, was a `truncated` region between two whole
messages with no Discontinuity. At `0.16` no checker could see that — §5 says
so in as many words — which is why fuzzing found it. The `0.18` seam predicate
makes exactly that case decidable from one file: a hole-class region between
the input ranges of two adjacent output records requires a Discontinuity, and a
checker may raise from the file alone. Under 3.4 that predicate is deleted, and
under python-zipline's proposed middle path too. kober has never run against a
checker that has it, and would never get one. Fuzzing stays the only net for
that bug class.

**Position.** kober's interest is served by the middle path python-zipline
raised: keep the coverage MUST, delete only the single-file verification
apparatus. kober verifies pairs already, so under that version it loses nothing
except the seam predicate, which it loses under every version. If the spec
prefers the clean SHOULD, kober can accept it; the cost is the consumer-facing
claim, not anything kober does.

### 3.5 Provenance and layer as independent axes

kober passes no `output_layer`, so the default `DECODED` applies, and it never
passes hints. `DESIGN.md` §3 says a decoded input is always packet-oriented.
Under the `0.15` axes that is imprecise — a `zpf`-sourced *transport* stream
from a sessionization stage can be byte-oriented — but the driver dispatches on
the stream rather than on the sentence, so nothing breaks, and under 3.5 the
sentence becomes exactly true again.

The loss the analysis and the sibling assessment name — the per-hop account
inside a tunnel chain, and a reassembler's `params_digest` — belongs to
zpfwire, which opposes 3.5. kober's deferred transform hook (`DESIGN.md` §11.5)
emits decoded records citing the outer stream and feeds a sub-decode with its
own offset space; it does not need the tunnel model and would be unaffected.
**Neutral; defer to zpfwire's position.**

### Rationale extraction

kober's docs cite the spec by concept, not by anchor, so nothing here breaks.
The gain is for a contributor reading what `stage.py` owes: the seam rule
currently rests on a 130-line duty in the Discontinuity section, and the
project's own error history (§13.5) was about reading that duty too narrowly.

---

## 3. The decision kober actually has

Every spec minor is a `zpf` minor, and every `zpf` minor is a kober minor with
no upgrade path — `CHANGELOG.md` states the rule. kober has taken one port so
far, `0.9` to `0.16` through `zpf` `0.2.0`, and it was a break in both
directions. So the question that matters here is not which proposals to support
but how many ports to take, and python-zipline's assessment ends on exactly that
choice for `v0.3.0`.

| Path | kober's sequence | Cost to kober |
| --- | --- | --- |
| **Port now** | `0.16` → `0.18` → `0.19` | Re-run the capture and fuzz pipeline against two formats; rework docs twice. The `0.18` content that touches kober is `role`, which is opt-in, and `dropped`, which kober never writes. |
| **Wait** | `0.16` → `0.16` on `zpf` `0.3` (API only) → `0.19` | `role` arrives later. `DESIGN.md` §4.1 already holds the field path at one emit site for that switch, and §11.4 already plans to ship `0.1.0` on `comment=`. |

kober takes the `zpf` `0.3` API break either way, since
[#59](https://github.com/adamkjonsson/python-zipline/issues/59) reshapes
`record()` regardless of format. What differs is the number of *format* hops.
**From kober's side, wait is the cheaper path**: nothing kober needs to ship
`0.1.0` is in `0.17` or `0.18`, and every churn item since `0.14` fell inside the
clusters the analysis removes.

---

## 4. What changes in kober if the package lands

Small, and almost all of it wording:

- **Tests.** The three `assert_conformant` helpers
  ([`test_stage.py`](../tests/test_stage.py),
  [`test_emit_conformance.py`](../tests/test_emit_conformance.py),
  [`test_compiled.py`](../tests/test_compiled.py)) drop the
  `coverage_findings() == []` line if that method leaves, and keep
  `check_coverage(output, input)`.
- **`DESIGN.md`.** §1's table lists "extents" under output scaffolding and
  "coverage guarantee" as auto-fill on close; §2 opens on the guarantee. Both
  move from "the file proves" to "the producer promises and the pair check
  confirms". §3's packet-oriented note becomes exact under 3.5.
- **[`architecture.md`](../docs/dev/architecture.md)** "Every byte is cited or
  named, never both" and the README's fuzzing section, same shift.
- **`CLAUDE.md`** testing section, which says the fuzz pipeline is checked with
  `ConformanceChecker` and `check_coverage`; the second survives, the first
  stops proving coverage.
- **Nothing in `src/kober/`.** The surface `stage.py` uses is the part the
  analysis does not propose to touch.
