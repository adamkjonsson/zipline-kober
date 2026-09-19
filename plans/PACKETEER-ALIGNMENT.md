# What kober can take from packeteer's dialect

**State: discharged, on both sides.** Every item below has happened. §3.1–3.3
landed in kober `0.2.0` (2026-09-10): source locations on findings, `const` on a
field, and foreign keys recorded and declined by name. §5.1–5.3 landed in
packeteer `0.13.0` the same day: it renamed `on:` to `dispatch:`
(packeteer#143), took the three shorthands, `endian` inheritance and `fill`
(#141, #142, #146), rewrote its examples in the short form, and vendored
kober's `dns.yaml` and `http.yaml` with a test asserting the outcome of each —
the test §5.3 asks for, from its side. kober's side of §5.3 is
`tests/test_packeteer.py`, which since 2026-09-19 loads *and decodes* both of
packeteer's examples as `0.16.0` ships them, including the switch-dispatched
one that §5.1 said was blocked. What still does not transfer is now the mirror
image of §2 — kober constructs packeteer declines by name — and is recorded in
`docs/format/document.md` rather than here. The text below is left as written.

> **Assessment, not a plan.** Written 2026-09-09 against
> [packeteer](https://github.com/adamkjonsson/packeteer) `0.12.0` and kober
> `0.1.0`. Both projects describe application protocols with a YAML dialect,
> and packeteer's reference calls its dialect a **superset of kober's**. This
> asks one question in one direction: what is in packeteer that kober should
> have. The reverse transfer — kober's `0.1.0` shorthands moving to packeteer —
> is packeteer's to schedule, and §5 records only what it must not carry with
> it. Nothing here is decided.

---

## 1. Verdict

**Three things are worth copying, and one of them is worth more than the other
two together.** In order:

| | What | Why |
| --- | --- | --- |
| §3.1 | **Source locations on errors** | kober names the construct, packeteer names the line. Highest-value diagnostic kober is missing. |
| §3.2 | **`const` on a field** | The ordinary way a decoder refuses traffic that is not its own. kober needs two places to say it. |
| §3.3 | **Recording a foreign construct rather than refusing it** | The mechanism that makes one dialect out of two, rather than two that overlap. |

Everything else packeteer adds is encode-direction or dispatch metadata, and
kober should *recognise* it without implementing it (§4).

**The finding that frames all of it:** the shared dialect is currently a stated
intention and not a fact. Neither project loads the other's shipped examples.

---

## 2. The superset claim, tested

packeteer's `docs/protocols/format.md` says the dialect is a superset of
kober's and that "a kober spec therefore loads here", while noting the claim is
"a strong intention rather than a guarantee" because no test suite is shared.
It is currently false in **both** directions.

| Direction | First blocker |
| --- | --- |
| packeteer → kober | `spec: unknown key(s) 'over', 'ports'` |
| kober → packeteer | `dns.yaml:27: units.message.fields[0]: a field has no key 'bits'` |

Loading each project's examples with the other's loader finds four independent
blocker classes going into kober:

1. `over` and `ports` at the top level.
2. `const`, `derive` and `sensitive` at field level.
3. The switch dispatch key (§5.1).
4. Everything after those, unexamined, because the load stops.

and, going the other way, kober's `0.1.0` shorthands — `bits:`, the lifted kind
key, bare scalars — none of which packeteer implements (§5.2).

**This is worth stating in both references.** A claim of compatibility that no
test enforces and that no example satisfies is worse than no claim, because a
reader plans around it.

---

## 3. What to copy

### 3.1 Source locations on errors

The single largest gap, and the least arguable. The same class of fault, in the
two projects:

```
kober:     spec: unknown key(s) 'over', 'ports'; allowed here: doc, entry, ...
packeteer: dns.yaml:27: units.message.fields[0]: a field has no key 'bits'; ...
```

One of them tells the author where to look. For a format whose entire surface
is hand-written YAML, that is the diagnostic that matters most, and kober does
not have it: [`errors.py`](../src/kober/errors.py)'s `SpecError` carries a
message, `ExprError` adds a dotted `where`, and
[`check.py`](../src/kober/check.py)'s `Finding` carries `where` and nothing
else. No line, no file.

**The mechanism packeteer uses**, in `protospec/loader.py` and
`protospec/spec.py`:

- A `Location` record of `path`, `line` and `source`, with `child(step)` to
  descend and `at_line(n)` to attach a line. The dotted path is what kober's
  `where` already is, so it is an extension rather than a replacement.
- A `SafeLoader` subclass whose mapping constructor records
  `node.start_mark.line + 1` on every mapping it builds.
- `_LinedDict`, a `dict` subclass with a `line` slot, so **the line travels on
  the object** rather than in a side table keyed by `id()`. packeteer's
  docstring gives the reason, and it is a good one: a side table either leaks,
  by holding every mapping alive so its id stays valid, or reports the wrong
  line once an id is reused.
- JSON degrades correctly: its parser reports no positions, so `line` is
  `None` and the path carries the message alone.

Roughly forty lines. It lands in two places in kober — the loader's raised
`SpecError`, and the checker's returned `Finding` — and the second is the one
that matters more, since `check` reports every fault at once and a list of
faults without lines is a list of things to go hunting for.

### 3.2 `const` on a field

```yaml
- {name: magic, bits: 16, const: 0x5345}
```

A value the decoder checks. kober's nearest equivalent is a unit-level
`confirm`, which costs two places:

```yaml
fields:
  - {name: magic, bits: 16}
  # ...
confirm: "magic == 0x5345"
```

Three differences, all in `const`'s favour for this use:

- **It is one place.** The constant sits on the field it constrains.
- **It fires at the field.** `confirm` and `reject` are evaluated once the
  unit's fields are decoded, so a wrong magic number is discovered after the
  whole unit has been read against the wrong protocol.
- **It is declarative**, so `check` can verify the constant fits the field's
  declared width. packeteer does exactly that, and that check should come with
  the key.

The motivation packeteer gives is its own — a port claim is a weak signal, so a
magic number is what keeps another protocol's traffic an opaque payload rather
than a mangled message. **kober's version of the same need is stronger**, not
weaker: the stage driver decodes message after message across a run, so a wrong
guess on the second message should end that message rather than corrupt every
one behind it.

**Adapt the failure, not the key.** In packeteer a disagreeing constant raises.
In kober it must make the region `undecodable`, which is the existing
vocabulary for *tried and could not*, and never raise. `confirm` and `reject`
stay for the conditions that span more than one field.

### 3.3 Recording a foreign construct rather than refusing it

This is the one that makes the dialect shared, and it is a mechanism rather
than a key.

packeteer reads the kober constructs it cannot implement — `pointer`, `select`,
`computed`, delimiter-framed sizes, `until` and `to_end` repeats, unit
parameters, and the three expression functions — collects them as `Unsupported`
records carrying a location, and reports them through the checker as **"not
supported yet"**, naming the construct. They are read and understood, and then
declined out loud.

kober has no mirror. `_reject_unknown` gives packeteer's five keys the same
treatment as a typo, which is exactly what packeteer decided not to do.

**Copy the mechanism, not the verdict.** kober's answer for each key differs:

| Key | kober's answer |
| --- | --- |
| `const` | Implement it (§3.2). |
| `over`, `ports` | Recognised, unused. kober is pointed at a spec explicitly and has no port dispatch. |
| `derive`, `sensitive` | Recognised, unused. Encode-direction and redaction; kober only decodes. |

A recognised-but-unused key should be a **warning** naming packeteer, not an
error, because ignoring it changes no decode. That keeps kober's strictness
intact — an unknown key is still an error, and the point of that rule is that a
misspelled key must not load and do nothing — while making a spec written for
the sibling project load and decode here.

---

## 4. What not to copy

- **`derive`.** The encode-direction dual of kober's `computed`. kober decodes
  only, and until it has an encoder there is nothing for it to mean.
- **`sensitive`.** kober has no `sanitise` verb and writes decoded records into
  `zpf`. Redaction there is a different layer's problem.
- **`over` and `ports`.** Dispatch metadata for a tool that decides which
  decoder to hand a packet to. kober is handed the spec.
- **The whole-byte constraint on sub-byte runs.** packeteer requires
  consecutive sub-byte fields to add up to whole bytes. kober deliberately does
  not, and cites the containing byte instead; that permissiveness is load-bearing
  for its coverage model.
- **`input: datagram` as the default.** kober's default is `either`, and
  packeteer's stricter default exists because it refuses `stream` outright.

---

## 5. Divergences to settle before the transfer

### 5.1 The switch dispatch key is a live disagreement

Not a lag. kober renamed `on:` to `dispatch:` in `0.1.0` and **deleted** the
boolean repair, because YAML 1.1 reads an unquoted `on:` as `true`. packeteer
still requires `on:`, and its `_restore_on_key` docstring and changelog both say
the repair "matches kober's", which stopped being true at kober's `0.1.0`.

It blocks both directions on its own, and it is the only item where the two
projects mean different things by the same construct. **Settle this first**;
every other alignment step is cheap beside a key with two meanings.

kober's error for it is the model of how to move: it names the old spelling,
the new one, and the reason, in both the bare and quoted forms.

### 5.2 The shorthand lag is the transfer itself

packeteer implements none of kober's `0.1.0` shorthands, so its examples and
its reference are written entirely in the long form. When the shorthands
transfer, packeteer inherits the problem [#21](https://github.com/adamkjonsson/zipline-kober/issues/21)
records here: a reference written in a dialect its own examples do not use.
Worth saying out loud before it happens rather than after.

### 5.3 The compatibility claim needs a test or a caveat

packeteer's reference already admits the claim is not enforced. The cheap fix,
if either project wants the claim to mean anything, is a test in each that
loads the *other's* shipped examples and asserts the expected outcome — loaded,
or declined by name under §3.3. That is a handful of lines and it is the only
thing that would have caught §2.

---

## 6. What this is worth

§3.1 is worth doing whatever happens to the alignment, because it is a
diagnostic gap in kober measured against nothing but kober's own authors.

§3.2 is worth doing on its own merits too; `const` earns its place in a
decode-only language.

§3.3 is the only item that exists *because* of packeteer, and it is the one
that decides whether "the same dialect" is a sentence in two references or a
property of two loaders.
