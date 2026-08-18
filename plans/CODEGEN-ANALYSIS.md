# Analysis: generating a Python module from a spec

**Not a plan. An analysis, requested before deciding.** Written against the
codebase at the end of the documentation phase.

The proposal: instead of interpreting a spec at decode time, **compile it into
a Python module** with a typed API that a consumer imports and uses alongside
`zpf`.

## What we have now

`kober` is an interpreter. {class}`Decoder` walks the frozen `Spec` model over a
cursor, dispatching per field, and builds a generic {class}`Node` tree. The
emitter then walks that tree to decide what to write.

## Measurements

Everything below is measured on `examples/dns.yaml` against a real 29-byte DNS
query, on this machine. They are the numbers the argument rests on.

| | µs/message | throughput | vs today |
| --- | --- | --- | --- |
| Interpreter, builds a `Node` tree | 97.0 | 0.30 MB/s | — |
| Straight-line code, but still building `Node`s | 7.4 *(only 6 nodes)* | 3.9 MB/s | — |
| Straight-line code, typed objects, no generic tree | **1.7** | **16.8 MB/s** | **56×** |

Profiling the interpreter says where it goes. The largest single entry is
`Node.__init__` — **120,000 calls for 3,000 messages**, forty nodes per
message — followed by `isinstance` dispatch at 579,000 calls.

### The finding that matters

**Most of the win is not from compiling the spec. It is from not building a
generic tree.**

The middle row above is the evidence: straight-line code that still allocates
`Node` objects costs 7.4 µs for *six* nodes, where the full decode allocates
about forty. A generated decoder that still produced a `Node` tree would
recover perhaps a quarter of the gap.

That reframes the proposal in a useful way. **The typed API and the speed are
the same benefit**, not two benefits that happen to arrive together: the typed
objects *are* what replaces the tree, and the tree is where the time goes.

### One cheap win, available today, unrelated to codegen

`Node` is a frozen dataclass, and `frozen` is expensive — every field
assignment goes through `object.__setattr__`:

| | ns per object |
| --- | --- |
| `@dataclass(frozen=True)` — today | 1046 |
| `@dataclass(frozen=True, slots=True)` | 1008 |
| `@dataclass(slots=True)` | 286 |
| plain class with `__slots__` | 286 |

Dropping `frozen` measures **1.5× end to end** (97 → 66 µs). It is a one-line
change and it costs a real property: immutability was deliberate, and
`test_node.py` asserts it. Worth deciding on its own merits rather than folding
into this — it does not change the codegen argument, since 1.5× and 56× are not
alternatives to each other.

## Pros

**A typed, completable API.** The stated goal, and the strongest argument.
Today a consumer writes `tree.find("questions").children[0].find("qtype").value`
and gets `Any`. Generated code gives `msg.questions[0].qtype` with a real type,
IDE completion, and an error at import time rather than `None` at runtime.

**56× on the measured ceiling.** At today's 0.30 MB/s a 1 GB capture takes
about 55 minutes; at 16.8 MB/s it takes about a minute. That is the difference
between a tool you run on a sample and one you run on a corpus.

**No runtime dependency on kober or the YAML.** A generated module ships on its
own. That is what "versatile" mostly means in practice — a protocol decoder
becomes a distributable artifact rather than something that needs this project
installed and a spec file present.

**Errors move to build time.** `check` runs when generating, so an invalid spec
fails a build rather than a decode.

**Generated code is inspectable.** You can read the decoder for a protocol, set
a breakpoint in it, and see exactly what it does — which is not true of an
interpreter whose behaviour is spread across `decoder.py`.

**The interpreter becomes a reference implementation.** Differential testing —
interpreter and generated code must agree on every input — is a genuinely
strong property, and it is only available if both exist.

## Cons, and the hard part

**The coverage bookkeeping is the crux, not the code generation.** This is the
one I would want settled before starting.

`Node` carries `off_start`/`off_end`/`status` for every field, and `emit.py`
reads exactly that to decide what to cite and what to mark. Typed objects that
carry only *values* cannot feed the emitter. So either:

- generated objects carry offsets and statuses too — in which case much of the
  56× goes back, because that bookkeeping is most of what the tree costs; or
- emission is restructured so the generated decoder emits records **directly**,
  never materialising a tree at all.

The second is the one that keeps the speed, and it is a redesign of the emitter
rather than an addition to it. It is also not obviously worse: `plan()` is pure
today and could stay pure over a different input shape.

**Two implementations must agree.** Unless the interpreter is retired — and it
should not be, since `kober try`, the REPL path, and differential testing all
want it. The equivalence test makes disagreement visible rather than
impossible.

**§2.1's cursor rule weakens from structural to enforced.** Today nothing
author-supplied can move the read cursor *because there is no author-supplied
code*. Generated code moves the cursor directly, so the invariant becomes "the
generator only emits correct patterns" — a property of one program rather than
an impossibility. Still defensible, and `DESIGN.md` §2.1 would need restating
rather than merely extending.

**Generating Python from a data file is a new security posture.** Field names,
enum labels, and `doc:` strings all flow toward source text. The generator must
never interpolate them: identifiers validated against a whitelist, everything
else emitted as constants. Today "a spec cannot run code" is partly a security
property, and this is where it would be lost if done carelessly.

**Fuzzing moves up a level.** The current fuzz tests assert invariants over one
engine. With codegen they must hold for *generated decoders*, so the suite has
to generate and then fuzz — specs × inputs rather than inputs.

**A build step.** Iterating on a spec gains a compile. Mitigated by keeping the
interpreter for `kober try`, which is what it is good at.

## Size of the job

Calibration: the decoder phase — engine, cursor, tree, emitter, driver, and
their tests — is **3,700 lines**, and ran as five stages.

| Piece | Estimate | Notes |
| --- | --- | --- |
| Generator core: spec → Python source | 700–900 | Comparable to `decoder.py`, since it re-expresses the same semantics |
| Expressions → Python source | 200–300 | The AST exists; `unparse` is close. Scope binding (`parent`/`root` → attribute access) is the new part |
| Typed model emission | 150–250 | A dataclass per unit, with slots and annotations |
| Identifiers and collisions | 100–150 | Spec names are author-chosen and need not be valid Python |
| Runtime shims | 100–200 | Generated code can reuse `Cursor`; reads are not the bottleneck |
| **Emission / coverage integration** | **200–400** | The hard part above |
| `kober generate` CLI verb | ~80 | |
| Tests | 800–1200 | Differential equivalence, conformance over generated output, fuzz across generated decoders |

**Total ≈ 2,300–3,500 lines** — a phase comparable to the decoder phase,
perhaps slightly smaller. Not because it is easier, but because the semantics
are already settled and tested: this is a re-expression of decisions already
made, not a set of new ones. The genuinely new decisions are the coverage
question and the API's shape.

## A cheaper option, honestly assessed

**Generate only a typed binding layer** — dataclasses plus a `from_node()`
mapper — and keep the interpreter decoding. About 300–500 lines.

It buys the completable API and none of the speed, since the tree is still
built and then converted. Given that the measurements show the API and the
speed are the same win, this gets the smaller half of the benefit for a quarter
of the work. Worth knowing about; not what I would choose.

## Recommendation

**Worth doing, keeping both, and settling the emission question first.**

The proposal is right for a better reason than throughput. A generic `Node`
tree is a decoder's *internal* representation leaking into its public API, and
that is what makes the current integration story awkward — the speed cost is
the same design flaw measured a different way.

Sequencing I would suggest:

1. **Decide the emission design before writing a generator.** Does generated
   code emit records directly, or carry offsets and reuse `plan()`? This
   determines whether the result is 56× or 4×, and it is a decision about
   `emit.py`, not about code generation.
2. Generate the typed model and the decoder together — they are one artifact.
3. Keep the interpreter, and add the differential test early. It is the cheapest
   insurance available and it only exists if both do.
4. Re-state §2.1 in terms of what the *generator* guarantees, rather than
   leaving a document claiming an impossibility that no longer holds.
