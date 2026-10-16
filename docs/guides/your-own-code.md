# Bringing your own code: a WireGuard tunnel

Some protocols carry bytes a spec can frame but cannot read. A tunnel encrypts
its traffic, a body is compressed, a payload is encoded by an algorithm with
state of its own. kober decodes them anyway, by a division of labour:
**the spec declares, your code supplies.** The spec says where the bytes are,
what the transform is called, what it takes, and what its failure means; your
code turns the bytes into other bytes. kober ships no cryptography and never
will, so this is also how every cipher reaches a decode.

[`examples/wireguard/`](https://github.com/adamkjonsson/zipline-kober/tree/main/examples/wireguard)
does it for WireGuard, completely: a spec, a cipher, a handshake, a module that
generates sealed traffic, and tests that check the decode against what was
sealed. This page walks through it in the order you would build your own.

| File | Your protocol's equivalent |
| --- | --- |
| `wireguard.yaml` | The spec: framing, the transform it declares, its parameters. |
| `wg_transforms.py` | The transform: a function, and one call that registers it. |
| `wg_crypto.py` | The algorithm, in a file of its own, because two things share it. |
| `wg_handshake.py`, `wg_seal.py` | What generates traffic you know the answer to. |

The folder is meant to be copied: its README says, file by file, what to
replace, keep or delete, and the conventions a new example keeps.

## Which steps your protocol needs

The eight steps below are WireGuard's, and WireGuard needs all of them. Most
protocols need fewer. Three shapes cover most of what a transform is for:

| Your protocol | Like | Steps it needs |
| --- | --- | --- |
| **A tunnel whose messages need a key**: each datagram one sealed packet, opened with key material the run supplies | WireGuard, ESP, an OpenVPN data channel | All eight. |
| **A tunnel without keys**: each datagram one packet, compressed or encoded by an algorithm of its own | A compressed or obfuscated tunnel; [`examples/packbits/`](https://github.com/adamkjonsson/zipline-kober/tree/main/examples/packbits) | All but 2: nothing to supply when a decode is set up, so no `params:`, no key log, and no failure for a missing key. If the algorithm checks nothing, as a codec seldom does, the protocol needs a check of its own, or a corrupted datagram decodes to a wrong packet that nothing can tell from a right one: PackBits' carries a CRC-32. |
| **A transformed field inside a protocol**: a body, a payload, a blob, opened in place | HTTP's `Content-Encoding: gzip` | 1, 3, 4 and 7. There is no tunnel module (5): generate the messages with their fields already encoded, as `tools/gzip_http.py` does for the pipeline. And the output can be decoded where it stands, with a `type:` on the transform, rather than in a stage after it (8). |

Two shortcuts before writing any code:

- **A codec kober already knows needs no code at all.** `gzip`, `deflate` and
  `deflate-raw` are core: name one in `with:` and step 3 is done. `bzip2`, `xz`
  and `zstd` are bound from the standard library where it has them, once the
  spec declares them under `transforms:` with no parameters
  ([transform names](../format/types.md#transform)).
- **Step 6 is never optional.** If the algorithm is your code, check it against
  something that is not: a specification's own examples, or another
  implementation. If it is a library's, the library is the outside check, and
  what is left to check is the framing around it.

## 1. Declare the transform

A transform field reads bytes already decoded, never the position, and names
what turns them into something else:

```yaml
transforms:
  wg-transport:
    params: {key: bytes, counter: int}
    fails_as: decrypt-failed

units:
  transport:
    fields:
      - {name: receiver, bits: 32, emit: none}
      - {name: counter, bits: 64, emit: none}
      - {name: sealed, bytes: {size: {remaining: true}}}
      - name: packet
        transform:
          from: sealed
          with: wg-transport
          limit: 65535
          args: {key: "keys[receiver]", counter: counter}
          content_type: "dec:ip-packet"
```

- **`transforms:` is the interface**, a name and the types of its arguments.
  `kober check` types every use against it with nothing registered, so a spec is
  valid or not the same way on every machine; see
  [`transform`](../format/types.md#transform).
- **`limit` is required**: the most bytes the output may have. A transform
  without a bound is not total.
- **`fails_as` names a failure** where its bytes are marked, in place of
  `undecodable`, so a reader can tell a wrong key from bytes that made no
  sense. It must be a reason of the format's `bytes` class: a failed transform's
  bytes did exist.
- **The output speaks for its source.** The record for `packet` cites the
  datagram it came from, `receiver` and `counter` included, so marking those
  `emit: none` leaves one record per datagram for the next stage to read.

## 2. Supply what a run needs

A key cannot be in a spec that is checked in, so it is a parameter, supplied
when a decode is set up. WireGuard needs a different key per session and per
direction, and every message says which by its receiver index, so the
parameter is a table:

```yaml
params:
  keys: {type: {map: [int, bytes]}, secret: true}
```

`keys[receiver]` reads one entry of it ([an entry of a map
parameter](../format/expressions.md#an-entry-of-a-map-parameter)). One table
covers both directions, every rekey and every peer, which is how WireGuard finds
a session itself. A receiver with no entry fails that message's transform,
named by its key and never by a value, and the next message decodes.

From the command line a map is a JSON file of keys and values, each written as
`--param` writes it:

```json
{"287454020": "hex:a1a1a1…", "572662306": "hex:b1b1b1…"}
```

`secret: true` keeps a value out of every record, region and message. It goes
into the output's `params_digest` only as part of the hash, so a file says which
key log wrote it, and a run with another reads as another configuration.

## 3. Write the transform

A transform is a function from the source's bytes, `limit` and the declared
arguments to the bytes it produces, and one call registers it. Abridged; the
file itself also checks the key's length, the counter and the limit first:

```python
from wg_crypto import open_sealed, transport_nonce
from kober.transforms import register

def wg_transport(data: bytes, *, limit: int, key: bytes, counter: int) -> bytes:
    plaintext = open_sealed(key, transport_nonce(counter), data)
    return plaintext[: ip_length(plaintext)] if plaintext else plaintext

register("wg-transport", wg_transport)
```

```console
kober run examples/wireguard/wireguard.yaml wg.zpf -o packets.zpf --emit field \
    --load-transforms examples/wireguard/wg_transforms.py \
    --param keys=file:keys.json
```

- **Whatever it raises is a failed transform**, never a failed decode. kober
  reports only the exception's class, never its text, because a cipher's error
  message can hold a key.
- **Do what the protocol's own receiver does.** WireGuard pads a packet to 16
  bytes before sealing it, and a receiver cuts it where its IP header says it
  ends; so does this transform, and it refuses what is not an IP packet, as
  WireGuard drops it.
- **A module loaded by path can import the modules beside it**, so the
  algorithm can live in a file of its own. The next section is why it should.
- From Python, {func}`kober.transforms.register` does the same, or a
  {class}`kober.transforms.Registry` of your own passed to the decoder.

## 4. Tell apart what decodes differently, before opening it

A WireGuard keepalive is a transport message that seals nothing: its 16 bytes
are its tag alone. It opens to no packet, so labelling it like one would be
false. The spec tells the two apart by size, and opens both (abridged: each
branch's `args` are the ones in step 1):

```yaml
- name: packet
  switch:
    dispatch: "len(sealed)"
    cases:
      16: {transform: {from: sealed, with: wg-transport, limit: 1, args: …,
                       content_type: "dec:wireguard-keepalive"}}
    default: {transform: {from: sealed, with: wg-transport, limit: 65535, args: …,
                          content_type: "dec:ip-packet"}}
```

Decide by what the framing already says, and keep every branch going through
your code, so that what is checked is checked on every message: a corrupted
keepalive is `decrypt-failed` like any other. Writing no record for an empty
output was weighed and refused, because the keepalive's bytes were decoded, and
with nothing citing them the file would have to name them as something they
were not.

## 5. Generate traffic you know the answer to

A decoder tested only on what its author wrote down is tested against its
author's reading. [packeteer](https://github.com/adamkjonsson/packeteer) 0.18.0
generates traffic, and hands each packet it sends to a tunnel module of yours,
which returns the datagrams that carry it:

```python
def make_wrapper(args: dict[str, str]) -> WireGuard: ...

class WireGuard:
    def wrap(self, inner: bytes, direction: str, timestamp: float) -> list[tuple[str, bytes]]:
        ...  # a handshake first when one is due, then the packet, sealed
```

```console
packeteer stream --protocol udp --payload dns --protocol-messages examples/wireguard/dns.json \
    --client-ip 10.8.0.2 --server-ip 10.8.0.1 --server-port 53 --packets 40 \
    --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 51820 \
    --tunnel-module examples/wireguard/wg_seal.py \
    --tunnel-arg keylog=keys.json --tunnel-arg truth=truth.jsonl \
    --tunnel-packet-loss 0.1 --tunnel-corruption 0.1 --tunnel-reorder 0.2 \
    --seed 7 --pcap wg.pcap
```

- **It is called once per packet actually sent, in wire order**, after the
  traffic's own impairments. A retransmission is sealed again with a fresh
  counter, and a lost packet never, so a module that counts or rekeys is right
  without trying.
- **The tunnel's impairments happen after sealing**, so a corrupted datagram's
  tag fails, as on a real link. They are separate flags (`--tunnel-*`) from the
  traffic's own.
- **Write down what you sealed.** `wg_seal.py` writes the key log kober reads,
  and `truth.jsonl`, a line per packet: what went in, and the datagram it
  became. That file is what a decode is checked against.
- **Seed everything.** A seeded run reproduces the capture and the key log byte
  for byte.

## 6. Check your code against something that is not your code

The module that seals and the transform that opens share `wg_crypto.py`. That is
the point of keeping it in one file, and it is also the risk: a fault in it
seals and opens consistently, and every round trip passes. So the example's
tests check it against what is not this code:

- **The specification's own vectors.** RFC 8439's and RFC 7748's test vectors
  are extracted from the RFCs' text by a script rather than typed, and the
  cipher must reproduce each.
- **An independent implementation.** `wg_seal.py` can also write the keys
  Wireshark needs (`--tunnel-arg wireshark_keylog=…`), and
  `tshark -o wg.keylog_file:…` must open every packet, byte for byte.

That second check has shown its worth: swapping the two transport keys inside
the shared handshake passes every other test, kober's decode included, and
fails that one. Find the equivalent for your protocol, a reference decoder or a
published capture with its keys, before trusting a round trip.

## 7. Check the decode against what was sealed

The rule is exact: **a sealed packet whose datagram reached the wire unchanged
opens, once per arrival, and every other transport datagram is one
`decrypt-failed` region.** Loss, reordering and duplication all fall out of that
one comparison. Two things it has to allow for:

- **Compare as multisets.** `zpfwire` writes each direction as a stream of its
  own, and kober decodes one after the other, so the decode's order is not the
  wire's.
- **A corrupted datagram fails its UDP checksum too**, as on a real link.
  `zpfwire` keeps it by default and kober names it `decrypt-failed`;
  `zpfwire convert --checksum drop` drops it, and it reads as a loss instead.

## 8. Go inside

What a tunnel carries is traffic of its own. `zpfwire` 0.5.0 turns the
decrypted packets back into the conversations they were, and any spec decodes
those:

```console
zpfwire convert packets.zpf -o inner.zpf --content-type dec:ip-packet
kober run examples/dns.yaml inner.zpf -o dns.zpf
```

Every record cites what it was read from, all the way down: a DNS answer in
`dns.zpf` cites the conversation in `inner.zpf`, which cites the packets in
`packets.zpf`, which cite the datagrams of the capture. A packet the inner connection lost and resent arrives whole, since it
was sealed like any other; a datagram the tunnel lost is a segment the inner
connection never knew to resend, so the conversation has a gap there, named and
never decoded past.

## What a spec cannot do here

A transform keeps nothing between messages, and two things in WireGuard need
exactly that:

- **The handshake stays structure.** Opening it takes Noise IK's state, which
  runs from one message to the next. The transport keys come from the key log
  instead.
- **A replay decodes again.** WireGuard's replay window is state too.

The same line rules out TLS 1.3's per-connection nonce counter and compression
with a dictionary carried between messages. It is a deliberate line, and
`DESIGN.md` §11.5 says where it sits and why.
