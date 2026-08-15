# Phase plan: real captures

**State: live.** Written after the decoder phase landed
([`DECODER-PHASE-PLAN.md`](DECODER-PHASE-PLAN.md)), against `DESIGN.md`
revision 5 and `zpf` 0.2.0.

## Why this phase

Everything kober has been verified against so far is a fixture written by the
same hand that wrote the code. That tests the implementation against *its
author's reading* of the format and of the protocols — which is exactly the
reading most likely to be wrong in the same direction twice.

A real capture tests the **design**: whether the spec language can express a
protocol nobody simplified first, whether framing survives contact, whether the
model's silences are the right ones. It is the same move the pressure test made
against `zpf`, one level up, and this project's framing already commits to it —
*a load test, where a gap is a finding rather than a constraint to route
around.*

It also produces something already promised elsewhere. Upstream
[#58](https://github.com/adamkjonsson/python-zipline/issues/58) deferred the
question of whether per-field records suit a payload format at all, wanting
*real files from a real decoder* as evidence. We now have the decoder and
nobody has brought it that evidence.

## What is available

`python-zipline-wire` is checked out beside this project and converts captures
to `.zpf`, so no new plumbing is needed:

```bash
../python-zipline-wire/.venv/bin/zpfwire convert CAPTURE -o OUT.zpf
```

Its `tests/captures/` holds fourteen captures. Three are the targets here:

| Capture | Shape | Why |
| --- | --- | --- |
| `dns_example.pcapng` | UDP, 4 query/response pairs | `DATAGRAM` shape, self-contained messages, and a protocol whose vocabulary we nearly have already |
| `http_example.pcapng` | TCP, 3138 bytes | `STREAM` shape: real framing, headers, a body |
| `packet_loss.pcap` | TCP, 193 packets, 71 KB | Real `Gap`s, which so far exist only in a hand-built two-record fixture |

## Already found, before any spec was written

**DNS name compression, and the spec language cannot express it.** The first
real response in `dns_example.pcapng`:

```
0000  18 3e 81 80 00 01 00 01 00 00 00 00 1c 62 72 6f
0010  77 73 65 72 2d 69 6e 74 61 6b 65 2d 75 73 35 2d
0020  64 61 74 61 64 6f 67 68 71 03 63 6f 6d 00 00 01
0030  00 01 c0 0c 00 01 00 01 00 00 00 9f 00 04 22 95
      ~~~~~ ^^^^^
```

The answer record's name is `c0 0c` — two bytes meaning *the name at offset
0x0c*, which is where the question's name already sits. RFC 1035 §4.1.4, and
near-universal in real responses.

Three things about this are worth separating, because they are different
problems:

1. **A name is a union**: either a run of length-prefixed labels ending in a
   zero byte, *or* a two-byte pointer. `Switch` can dispatch on the top two
   bits, so this part is expressible.
2. **Following a pointer means reading at an absolute earlier offset** and then
   returning. Nothing in §3 can express that, and §2.1's cursor rule says the
   runtime owns the position — deliberately, because a construct that moves the
   cursor arbitrarily is exactly what makes coverage unprovable.
3. **The pointed-at bytes are already cited** by whatever decoded them the
   first time. Citing them again is fine (overlapping spans are **[verified]**
   legal), so the coverage guarantee is not what blocks this — only the
   language is.

So DNS is decodable up to the answer section and then stops. That is a real
boundary of the design, found on the first real packet. Options were:

- **Accept the boundary.** Decode the header and question, mark the answer
  section `undecodable`. Honest, conformant, and useless for the thing people
  actually want out of DNS.
- **A `Pointer` construct** — a declarative "read this type at that offset"
  that the *runtime* executes, keeping the cursor rule intact (the spec names
  an offset; it does not move anything). Solves a whole family of formats, not
  just DNS: back-references appear across binary protocols.
- **A hook** (§11.5), which is the escape hatch already sketched and would need
  the hook API this project has deferred.

### Decided: the `Pointer` construct

Chosen. It is the option that keeps §2.1 intact rather than working around it:
the spec *names* an offset and the runtime does the seeking, so nothing
author-supplied moves the cursor and coverage stays provable. It also earns its
keep beyond DNS — back-references are a recurring shape in binary formats, and
a hook would solve the same problem while giving up the static analysis.

Not yet built. What it will need, so the size is on the record:

- **Model** — a `Pointer` field type carrying the offset expression and the
  type to read there, and a decision on whose offset space the expression means
  (message-relative is what DNS wants; the run's is what the cursor holds).
- **Checker** — the pointed-at type checks like any other; the offset
  expression must be an integer. Termination is the new hazard: a pointer
  chain can loop, and DNS pointers legitimately chain, so a bound is needed
  the way `MAX_DEPTH` bounds unit nesting.
- **Engine** — read at the offset and return, leaving the cursor where it was.
  A second `Cursor` over the same buffer is the obvious shape and keeps the
  invariant literal: the reading cursor never moves.
- **Emitter** — the pointed-at bytes are cited again, which is already legal
  (**[verified]** overlapping spans), so nothing changes there.
- **Coverage** — a subtlety worth naming: if a region is *only* ever reached
  through a pointer, it is cited without ever having been walked. That is
  fine, but it means the "leaves tile the input" property the emitter tests
  rely on stops holding, and the tests that assert it need to say so.

Sequenced after the remaining stages, since HTTP and packet loss are already
planned and neither needs it.

## Stages

Sized loosely: this is exploratory, so "what breaks" is the deliverable and
each stage may end early with a finding instead of a spec.

### Stage 1 — DNS over UDP — **done**

Write `examples/dns.yaml` against the real capture, as far as the language
goes. Confirm the compression boundary precisely, decode at both granularities,
check conformance and coverage. Extract the fixture DNS spec out of the three
test files while doing it — the phase plan's acceptance criteria asked for a
committed example and got one only in tests.

### Stage 2 — HTTP over TCP — **done**

`examples/http.yaml` decodes the real request and response from
`http_example.pcapng`: start line and every header, conformance and coverage
clean at both granularities. `Terminated` on `\r\n` and `until` on an empty
line express HTTP's line framing exactly, and the blank line that ends the
headers is kept as an element rather than dropped — it is input, and every byte
has to be accounted for.

**The finding is the one this stage predicted, and it is sharper than
expected: framing derived from a text value is not expressible.** The capture's
response is `Transfer-Encoding: chunked` with a gzip body, so both of HTTP's
body-framing mechanisms appear in one exchange:

- `Content-Length: 1922` — a **decimal string**. Using it as a size needs
  string-to-integer conversion.
- `Transfer-Encoding: chunked` — each chunk is a **hexadecimal string** size,
  and whether that framing applies at all depends on matching a header value
  case-insensitively.

The expression language has none of that: no string-to-integer, no substring,
no case folding, no search. It compares strings for equality and that is all.
So the body is claimed as `remaining` — correct for a capture holding one
message per direction, wrong the moment a connection carries two.

This is the same shape as the DNS finding one level up. DNS needed the cursor
to *move*; HTTP needs values to be *computed from text*. Neither is about
coverage, and neither is expressible today.

It maps straight onto §11.5's three options. A handful of total string
builtins — `to_int(s, base)`, `starts_with`, `lower` — would close it, and is
the "richer expressions" option rather than the hook option. Worth noting the
parser is already a whitelist, so adding calls is a bounded change; worth
noting too that this is the first case where something real needed it, which is
the bar §11.5 set.

### Stage 3 — packet loss

`packet_loss.pcap` for real `Gap` handling: gap regions, seams, and messages
that do not span holes, at 71 KB rather than the hand-built 12 bytes.

### Stage 4 — write up

Findings to `DESIGN.md` and upstream where they belong, and real field-
granularity files to #58 as the evidence it asked for.

## What counts as what

- A **kober bug** — the design says it should work and it does not. Fix.
- A **design finding** — the language cannot express something real. Record it,
  and decide deliberately whether to grow the language, per §2.1's rule about
  what may move the cursor.
- A **`zpf` finding** — file upstream, as three times before.
- A **capture artefact** — the sample is unusual and the protocol is fine.
  Note and move on.

## Acceptance

1. `examples/` holds specs that check clean and decode their captures.
2. Conformance and coverage clean on every output, from real input.
3. Every boundary hit is written down with its evidence, and each has a
   recommendation.
4. #58 has real files.
