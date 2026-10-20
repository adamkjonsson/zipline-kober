# Review: the WireGuard example as a guide to writing your own transform

Reviewed at kober `2225371`: `examples/wireguard/README.md`,
`wg_transforms.py`, `wireguard.yaml`, `example.json`, and
`docs/guides/your-own-code.md`.

The question was whether a reader about to implement a transform of their own
(a VPN, HTTPS, or something similar) can follow it.

**In short:** for a VPN whose packets each carry what is needed to open them
(WireGuard, ESP, an OpenVPN data channel), yes, mostly, especially through the
guide. For HTTPS, no. The reader learns only at the very end that TLS does not
fit, and is not told what to do instead.

## What works well

- **The core idea is clear.** *The spec declares, your code supplies* is stated
  in both documents, and everything else follows from it.
- **The code side is small and copyable.** `wg_transforms.py` is about 90 lines:
  one function from `(data, *, limit, **args)` to bytes, and one `register`
  call, well commented. A reader can take its shape directly.
- **The README's *Adapting this to your own protocol* table** says, file by
  file, what to replace, keep or delete. That is exactly what someone copying
  the folder needs.
- **The guide's *Which steps your protocol needs* table** sorts protocols into
  three shapes, with examples of each: a keyed tunnel, an unkeyed tunnel, and a
  transformed field such as `Content-Encoding: gzip`. It is the right first
  question, and `examples/packbits/` shows the second shape built from the
  template.
- **The safety points are made well:** a transform's exception text never
  reaches the output (so a key cannot leak through it), and a cipher is checked
  against outside test vectors and a second implementation (Wireshark), not
  only against a round trip through itself.

## What would trip up a new implementer

Most important first.

### 1. Whether a protocol fits comes last, not first

Everything hinges on one rule: **a transform keeps no state between messages.**
That rule decides whether HTTPS, QUIC, or any protocol whose nonce or counter is
not on the wire can be done at all.

- The guide states it in its final section, *What a spec cannot do here*
  (lines 267–279 of 279). TLS 1.3 gets one sentence there: *the same line rules
  out TLS 1.3's per-connection nonce counter*.
- The README never mentions TLS, and it opens by inviting *a cipher, a
  compression scheme, anything that turns bytes into other bytes*.

So an HTTPS reader could work through most of the eight steps before finding
out that their protocol cannot work.

**Suggested:** a short fit check near the top of both documents.

- **Fits:** each message carries everything needed to open it, such as a key
  index and a counter or nonce. WireGuard, ESP, OpenVPN and DTLS do.
- **Does not fit:** the counter is implicit or derived from earlier messages
  (TLS, QUIC), or opening a message needs a handshake to have been followed.
- **What to do instead** when it does not fit: for example, decrypt in a
  separate tool or stage and hand kober the plaintext, or wait for the
  extension point `DESIGN.md` §11.5 describes. Whatever the intended answer is,
  say it.

### 2. No path for real captures

The keys always come from `wg_seal.py`, which generated the traffic. A reader
with a real capture needs to know where keys come from in practice, and how to
turn them into the `--param` key-log format:

- WireGuard: the endpoint's own key extraction;
- ESP: `ip xfrm state`;
- TLS, if it ever fits: `SSLKEYLOGFILE`.

Wireshark key logs appear only as something the example *writes*
(`--tunnel-arg wireshark_keylog=…`), not as something a reader might start from.

### 3. Two audiences are mixed together

Much of the README is for someone adding an example to **kober's own
repository**: `example.json` written "key for key" against
`tests/examplekit.py`, `tools/pipeline.py`, the truth-file and tunnel-module
conventions, and the tests that *hold a fuzzed decode to every shipped spec's
promises*. It sits beside the material for someone writing a transform in
**their own project**, and comes before the *generate, decode, go inside*
walkthrough.

**Suggested:** split the README into *Using kober with your own transform* and
*Adding an example to this repository*. Each reader then reads only what
applies.

### 4. Terms are used before they are explained

The adaptation table assumes the reader knows `fails_as`, `limit` and
`emit: none`. `limit` in particular, the bound on how many bytes a transform may
produce, is never explained in the README. The section that explains the rest,
*How the pieces meet*, comes later in the file.

**Suggested:** move *How the pieces meet* near the top, or link the guide's
step 1 from the adaptation table.

### 5. Small things

- *The one case where the name says more than happened* is cryptic. It means a
  packet that decrypted correctly but was not an IP packet is still labelled
  `decrypt-failed`. Saying that plainly would help.
- A stray line break in *No key is / ever written*.
- The note that `--content-type dec:ip-packet` *goes away once kober labels
  them `net:ip` … which needs `zpf` 0.6* will be stale once `zpf` 0.6.0 is
  tagged.
