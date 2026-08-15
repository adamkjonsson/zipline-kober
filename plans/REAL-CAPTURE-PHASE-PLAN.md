# Phase plan: real captures

**State: done.** All four stages landed on `real_captures`. Written after the decoder phase landed
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

### Stage 3 — packet loss — **done**

`packet_loss.pcap` gives 7 segments and **6 real gaps** across 71 KB. Decoded
line by line (the payload is synthetic filler text, so a line-oriented spec is
what frames it) it produces 2386 records with:

- 6 `reason="gap"` regions, one per hole, at the reassembler's own offsets;
- 6 `stream-gap` Discontinuities, one per hole, **widths absent**;
- 7 `truncated` regions — the partial line at the end of each segment, which
  is what a hole does to a line-oriented stream;
- `ConformanceChecker` clean at both granularities.

No message spans a hole and every byte is accounted for. This is the seam and
gap path at scale, and it holds.

#### Finding: `check_coverage` measures a real TCP stream as 2³²−1 bytes

`zpf.check_coverage` reports four violations against this output, and all four
are false. It measures the input stream as **4294967295** bytes — 2³²−1 — where
the data ends at 74931, and then reports everything past that as uncovered.

The mechanism, confirmed rather than inferred:

```
pid=0 isn=4287897474 records=9 zero-length=1
    zero-length record seq_start=4287897474   (seq_start - isn = 0)
    record_ranges (first 4): ((4294967295, 4294967295), (0, 1193), (1193, 7422), ...)
    stream_extent = 4294967295
```

A TCP SYN consumes a sequence number, so a stream's data starts at ``isn + 1``
and `record_ranges` computes an offset as ``seq_start - (isn + 1)``. The SYN
itself sits at ``seq_start == isn``, so its offset is **−1**, which wraps to
2³²−1 in the modular arithmetic. `stream_extent` takes the maximum end over all
ranges, so that one empty record sets the extent for the whole stream.

The inconsistency is inside `zpf`, between two functions reading the same
blocks: :meth:`StreamView.chunks` documents that "zero-length (pure-ACK)
records contribute no bytes and are skipped", and does skip them.
`record_ranges` does not. One says the stream is 74931 bytes; the other says it
is 4294967295.

The consequence is larger than this capture. `zpfwire` writes the handshake as
zero-length records, so **any realistic TCP capture that includes its SYN makes
`check_coverage` report false violations** — and `check_coverage` is the tool a
decode stage is meant to prove itself with. Our own tests never hit it because
every hand-built fixture starts at ``isn + 1`` and has no SYN.

Not a kober bug: the output is conformant, its declared extent (74931) matches
the data, and the diagnostics are about measuring the *input*. Filed as
[#63](https://github.com/adamkjonsson/python-zipline/issues/63).

### Stage 4 — write up — **done**

`DESIGN.md` is at **revision 6**: a new §13 holds the findings, the status line
finally says what is built, §3.2 carries `Pointer` as decided-not-built, §3.3
records the expression-language gap, and §11 question 5 gets the conclusion
that both real gaps were closable declaratively. Upstream got
[#62](https://github.com/adamkjonsson/python-zipline/issues/62) and
[#63](https://github.com/adamkjonsson/python-zipline/issues/63).

**#58 has its evidence** ([comment](https://github.com/adamkjonsson/python-zipline/issues/58#issuecomment-5304645319)). It deferred "are per-field records the
right level for a payload format" pending real files from a real decoder. The
measurement is done and the answer is *it depends on the protocol*, which is
more useful than a yes or no:

| Capture | Input | Message granularity | Field granularity |
| --- | --- | --- | --- |
| DNS, 4 query/response pairs | 2116 B (676 B payload) | 8 records, 2608 B | 176 records, 22988 B — **8.8×** |
| HTTP, one exchange | 4324 B (3138 B payload) | 2 records, 4488 B | 26 records, 7764 B — **1.7×** |

The cost tracks **fields per byte**, not payload size. DNS is bitfield-dense —
nine flags in two bytes, names as one record per label — and pays 8.8× for it,
about 3.8 bytes of payload per record. HTTP is a handful of long text fields
and pays 1.7×. So "useful or noise" is not a property of the format; it is a
property of what is being decoded, and a reader of the file cannot tell which
they are getting without knowing the protocol.

Said upstream plainly, because it argues against a single answer to #58 and for
whatever mechanism it settles on being *optional* per spec — which `Emit`
already is.

The comment also carries a second gap the issue had not accounted for. Of the
176 DNS records, **all 176** are distinguishable only by `comment`, so the
naming problem is total rather than partial; and `prim:`'s closed vocabulary
means a field's *width* is lost too — a `u4` is written `prim:u8` and `cites`
rounds to the containing byte. A `label` option alone would close the first and
not the second.

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
