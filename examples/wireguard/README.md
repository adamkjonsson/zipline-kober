# WireGuard: a protocol that needs your own code

kober decodes a protocol from a spec, but some protocols cannot be decoded by a
spec alone. WireGuard encrypts its traffic, and kober ships no cryptography and
never will: a cipher is always the code of whoever runs the spec. This example
shows how the two fit together, and it is meant to be copied for a protocol of
your own, a cipher or a compression scheme, as long as it fits the one rule
below.

This README has two parts. The first is for using kober with a transform of
your own, in your own project. The second, [*Adding an example to this
repository*](#adding-an-example-to-this-repository), is for contributing one
to kober itself.

## Does your protocol fit?

**A transform keeps nothing from one message to the next.** It sees one
message's bytes, and what the spec hands it from that message's fields and the
run's parameters. So a protocol fits when **each message carries what opens
it**: which key (an index, an SPI), and the nonce or counter, on the wire.

- **Fits:** WireGuard, whose transport messages carry their receiver index and
  counter. ESP without extended sequence numbers. DTLS 1.2, whose records carry
  their epoch and sequence number. An OpenVPN data channel, whose packets carry
  their packet ID. Each with its keys supplied when the decode is set up.
- **Does not fit:** TLS, of any version, where the record sequence number is
  never sent. QUIC, whose packet numbers are shortened and protected, and need
  earlier packets to reconstruct. DTLS 1.3, for the same reason. ESP with
  extended sequence numbers, whose high 32 bits are never sent. Compression
  with a dictionary carried from message to message.

If yours does not fit, the step that keeps state has to happen outside a
spec. Write it as a stage of your own with python-zipline's `zpf.decode_stage`:
it reads the capture's streams, keeps whatever the protocol needs, and writes
the plaintext as records that cite the ciphertext they came from. kober then
decodes what is inside with an ordinary spec, and every record still cites the
capture. Or decrypt with a tool that follows the connection, such as Wireshark
with `SSLKEYLOGFILE` for TLS, and decode its output, which loses the citation
back to the capture. Do not wait for kober to keep the state: a transform kept
for a whole stream is named as a possible extension (`DESIGN.md` §11.5), and
deferred, with no date.

## The files

| File | What it is |
| --- | --- |
| [`wireguard.yaml`](wireguard.yaml) | The spec. The handshake decodes as structure; a transport message is opened with a transform the spec names, `wg-transport`, and declares. |
| [`wg_transforms.py`](wg_transforms.py) | Registers `wg-transport` with kober. Everything kober needs from your code is in this file. |
| [`wg_crypto.py`](wg_crypto.py) | ChaCha20-Poly1305 (RFC 8439) and X25519 (RFC 7748), standard library only. Shared by both sides, which is why it is a file of its own. |
| [`wg_handshake.py`](wg_handshake.py) | WireGuard's handshake, Noise IK, both peers' sides of it. |
| [`wg_keylog.py`](wg_keylog.py) | Turns the keys a real WireGuard endpoint can be made to log, and a capture, into the key log kober reads. |
| [`wg_seal.py`](wg_seal.py) | A tunnel module for `packeteer stream`: it seals the traffic packeteer generates, with a real handshake, and writes the key log and what it sealed. |
| [`dns.json`](dns.json) | A DNS query and its answer, the traffic the commands below send through the tunnel, one each way. |
| [`example.json`](example.json) | The example, described for this repository's tests and pipeline (the second part). |

## How the pieces meet

- **The spec declares, your code supplies.** `wireguard.yaml` declares the
  transform under `transforms:`, with what it takes (`key: bytes,
  counter: int`) and what its failure is called. `kober check` types every use
  of it from that alone, with nothing registered.
- **A `transform:` field reads bytes already decoded**, `from: sealed`, and its
  output stands in their place. `limit` is required: the most bytes the output
  may have, so a decode stays bounded whatever your code does.
- **`fails_as` names a failure**, `decrypt-failed`, so a reader can tell a
  wrong key from bytes that made no sense (`undecodable`).
- **`emit: none` on the fields the output speaks for.** The packet's record
  cites the whole message, receiver and counter included, so those write no
  records of their own, and a second stage reads one record per datagram.
- **The key is chosen per message**, `keys[receiver]`: an entry of a map
  parameter, indexed by a field. One table covers both directions, every rekey
  and every peer, which is how WireGuard itself finds a session.
- **`--load-transforms` runs your module**, which calls
  `kober.transforms.register`. A module loaded by path can import the modules
  beside it, as `wg_transforms.py` imports `wg_crypto.py`.
- **What your code raises is a failed transform**, never a failed decode, and
  only its exception's class is reported: its text, which could hold a key,
  never reaches the file.

The guide, [Bringing your own code](../../docs/guides/your-own-code.md), walks
through each of these in the order you would build them.

## Copying it for your own protocol

Most of this folder is WireGuard's own cryptography, which your protocol will
not reuse; the pattern is in the smaller files.

| File | What to do |
| --- | --- |
| `wireguard.yaml` | **Replace**, keeping the pattern above: a `transforms:` declaration, a `transform:` field with a `limit`, `fails_as`, `emit: none` on what the output speaks for, and `params:` only if a run needs something a spec cannot hold ([step 1](../../docs/guides/your-own-code.md#1-declare-the-transform)). |
| `wg_transforms.py` | **Replace the body, keep the shape**: one function from `(data, *, limit, **args)` to bytes, doing what your protocol's own receiver does, and one `register` call. Raise on anything wrong. |
| `wg_crypto.py` | **Replace** with your algorithm, in a file of its own whenever two things use it (the transform, and what generates traffic). |
| `wg_handshake.py`, `wg_keylog.py` | **Delete**, unless your protocol agrees keys in messages of its own and you need keys from a real endpoint. kober decodes a handshake as structure only (see *What it does not do*). |
| `wg_seal.py` | **Replace** if you want generated traffic you know the answer to (see *Generating traffic*); **delete** if you only decode real captures. |
| `dns.json` | **Keep or replace**: the traffic sent through the tunnel. Any packeteer payload works. |

Which of these your protocol needs depends on its shape, which the guide
covers in *Which steps your protocol needs*. [`examples/packbits/`](../packbits/README.md)
was written from this table, for the shape with no keys: start there if yours
has none.

## Decoding a real capture

kober reads `.zpf` files, and
[`zpfwire`](https://github.com/adamkjonsson/python-zipline-wire) turns a pcap
into one. What a real capture needs besides is the keys, and a WireGuard
endpoint never writes its transport keys down: it derives them in each
handshake and drops them when the session ends. What it can be made to log is
the keys it derives them from. On Linux, wireguard-tools'
[`contrib/extract-handshakes`](https://github.com/WireGuard/wireguard-tools/tree/master/contrib/extract-handshakes)
logs them from the kernel, for every handshake the endpoint takes part in, in
the format Wireshark reads. `wg_keylog.py` replays each handshake in the
capture with them, and writes the key log kober reads:

```console
zpfwire convert wg.pcap -o wg.zpf
python examples/wireguard/wg_keylog.py wg.zpf --wireshark-keylog handshakes.log -o keys.json
kober run examples/wireguard/wireguard.yaml wg.zpf -o packets.zpf --emit field \
    --load-transforms examples/wireguard/wg_transforms.py \
    --param keys=file:keys.json
```

One endpoint's log opens both directions, whichever end it was, and a
pre-shared key in the log is used where the peers have one. A derivation is
only taken when the capture confirms it, and a handshake the log cannot open is
reported by its index. A session whose handshake happened before the capture
started cannot be opened from it.

`keys.json` is each session's key in each direction, by the receiver index a
transport message carries, written as `--param` writes bytes:

```json
{"287454020": "hex:a1a1a1…", "572662306": "hex:b1b1b1…"}
```

For another protocol, the key log is whatever maps the field that picks a key
to the key. ESP's is the security associations, `ip xfrm state` on Linux: one
key per SPI, so `keys[spi]`.

## Generating traffic you know the answer to

A decode of a real capture can only be checked against what you believe it
holds. [packeteer](https://github.com/adamkjonsson/packeteer) 0.18.0 or later
generates traffic whose every packet is known: it hands each packet it sends
to `wg_seal.py`, which returns the WireGuard datagrams that carry it, and
writes down what it sealed:

```console
packeteer stream --protocol udp --payload dns --protocol-messages examples/wireguard/dns.json \
    --client-ip 10.8.0.2 --server-ip 10.8.0.1 --server-port 53 --packets 40 \
    --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 51820 \
    --tunnel-module examples/wireguard/wg_seal.py \
    --tunnel-arg keylog=keys.json --tunnel-arg truth=truth.jsonl \
    --tunnel-arg rekey_after=10 \
    --tunnel-packet-loss 0.1 --tunnel-corruption 0.1 --tunnel-reorder 0.2 \
    --seed 7 --pcap wg.pcap
```

The client is the initiator, and every `rekey_after` packets a new handshake
starts a new session. The inner traffic keeps its own impairments
(`--packet-loss`, `--retransmit-lost`), separate from what the tunnel's
datagrams suffer (`--tunnel-*`), and `wg_seal.py` is called once per packet
actually sent, so a retransmission is sealed again with a new counter. A
seeded run reproduces the capture and the key log byte for byte.

- `keys.json` is the key log kober reads, as above: `wg_seal.py` ran the
  handshake, so it has the keys a real endpoint would not write down.
- `truth.jsonl` has one line per sealed packet: its session, direction,
  receiver, counter, plaintext and the datagram it became. A decode can be
  checked against it exactly. Compare as a set: each direction is a stream of
  its own once converted, so a decode lists one direction's packets before the
  other's.
- `--tunnel-arg wireshark_keylog=wireshark.keys` also writes the keys Wireshark
  needs, in the format `extract-handshakes` writes, so a WireGuard
  implementation that is not this one can open the same capture
  (`tshark -r wg.pcap -o wg.keylog_file:wireshark.keys`), and `wg_keylog.py`
  can be run on it as on a real endpoint's log.
- `--tunnel-arg initiator_key=hex:…` and `responder_key=hex:…` set the static
  private keys; otherwise every key and index comes from `--tunnel-arg seed`.

Decode it with the commands in *Decoding a real capture*, the `kober run`
line alone, since `wg_seal.py` wrote `keys.json` already.

## What the decode says

`packets.zpf` has one `dec:ip-packet` record per transport message, citing the
datagram it came from, for the next stage to read: the IP packet, without the
padding WireGuard sealed it with, cut where its own header says it ends, as a
WireGuard receiver cuts it. A keepalive, which seals nothing, is an empty
record labelled `dec:wireguard-keepalive`, so a reader looking for packets
passes it over and every byte is still accounted for. The spec tells the two
apart by size before opening either, `len(sealed) == 16`, and opens both, so a
keepalive's tag is checked too.

A message that does not open, because it was corrupted or its receiver is not
in the key log, is one `decrypt-failed` region, and the next message is
decoded as usual. A message that decrypts to something that is not an IP
packet is `decrypt-failed` too, though it did decrypt: WireGuard drops such a
packet, and so does the transform. No key is ever written, and the decoder
descriptor's `params_digest` says which key log produced the file.

A datagram the tunnel corrupted also fails its UDP checksum, as it would on a
real link. `zpfwire` keeps it by default, and kober names it `decrypt-failed`;
with `zpfwire convert --checksum drop` it is dropped instead, and reads as a
loss.

## The traffic inside

`packets.zpf` holds packets, one per transport message. `zpfwire` 0.5.0 or
later turns them back into the conversations they carried, UDP split into
flows and TCP reassembled as it would be from a capture, and kober decodes
those with any spec:

```console
zpfwire convert packets.zpf -o inner.zpf --content-type dec:ip-packet
kober run examples/dns.yaml inner.zpf -o dns.zpf
```

`--content-type dec:ip-packet` says which records are packets. Every record in
`inner.zpf` cites the decrypted packets it came from, and those cite the
datagrams, so a DNS answer three stages down still says which bytes of the
capture it was read from. `zpfwire pcap packets.zpf -o inner.pcap
--content-type dec:ip-packet` writes the decrypted packets as a capture
instead, for Wireshark.

Losses inside and outside the tunnel are different things, and the files say
so. A segment the inner connection lost and retransmitted (`--packet-loss
--retransmit-lost`) arrives whole, since `wg_seal.py` sealed the retransmission
like any packet. A sealed datagram the tunnel lost (`--tunnel-packet-loss`) is
a segment the inner connection never knew to resend, so `inner.zpf` has a gap
there, and what kober decodes after it is named, never guessed.

## What it does not do

- **Open the handshake.** Its encrypted fields stay bytes: Noise IK's state
  runs from one message to the next, and a transform keeps nothing between
  messages. The transport keys come from a key log instead, which
  `wg_keylog.py` derives from a real endpoint's keys, and `wg_seal.py` from
  the handshakes it ran.
- **Detect a replay.** A duplicated message opens again. WireGuard's replay
  window is state across messages too.

## How the example checks itself

The sealing side and the opening side share `wg_crypto.py`, so a fault in it
would seal and open consistently, and a round trip would pass. So
`tests/test_wireguard_example.py` checks it against what is not this code:
RFC 8439's and RFC 7748's own test vectors, extracted from the RFCs' text, and
Wireshark, which opens a capture `wg_seal.py` sealed and must find, byte for
byte, every packet that went in. Swapping the two transport keys inside the
handshake passes every other test and fails that one. `wg_keylog.py` is
checked the same way round: from the log Wireshark opens the capture with,
either endpoint's half of it alone, it must derive exactly the keys
`wg_seal.py` sealed with.

None of this is hardened against timing attacks, and none of it is meant to
protect anything.

## Adding an example to this repository

Everything above is for using kober with your own transform. This part is for
adding an example to kober's own `examples/`, where its tests and the deeper
pipeline (`tools/pipeline.py`) run it.

| File | What to do |
| --- | --- |
| `example.json` | **Rewrite**, key for key; the keys are `Example`'s attributes in `tests/examplekit.py`, and a key it does not know is refused. With it, the deeper pipeline runs your spec over every input and generates your `inputs` through your tunnel module, checking each exactly; nothing in `tools/pipeline.py` changes. |
| `README.md` | **Rewrite**, keeping the order: does it fit, the files, how the pieces meet, decode, generate, go inside, and what it cannot do. |
| `tests/test_wireguard_example.py` | **Copy the shape**, outside this folder. `Example.load("<yours>")` reads your `example.json`, and with it the kit does what every example's tests need: load your modules by path, read your key log as `--param` does, check a decode against your truth file exactly, run the whole chain where packeteer and `zpfwire` are checked out beside it, hold a fuzzed decode to every shipped spec's promises, and run `kober run` as the README does. What is left is your own: your algorithm against outside known answers, and against another implementation where there is one, and your spec over messages built in the test. |

Code in this repository uses the standard library only, and so does an
example's.

### Conventions

What the example's tests and `tools/pipeline.py` rely on, and a new example
should provide in the same form:

- **The key log**, when the spec takes a map parameter: a JSON object, each key
  the map's key written as `--param` writes it (an `int` in decimal, a `str` as
  it is) and each value `hex:…`. It is exactly what `--param NAME=file:PATH`
  reads, so whatever writes it, kober reads it unchanged. A protocol with no
  keys writes none.
- **The truth file**, `truth.jsonl`: one JSON object per sealed packet, in the
  order sealed, with at least `inner` (the packet that went in, as hex),
  `outer` (the datagram it became, as hex) and `direction` (`c2s` or `s2c`).
  What a decode is checked against is computed from those three; anything else
  on the line, such as WireGuard's `session` and `counter`, is for a reader.
- **The tunnel module**: `make_wrapper(args)` returning an object whose
  `wrap(inner, direction, timestamp)` returns `(direction, bytes)` pairs, as
  packeteer's `--tunnel-module` requires. `args` are the `--tunnel-arg` pairs,
  and the example takes `truth`, `keylog` (if it has keys) and `seed`, and
  derives everything random from the seed so a run reproduces.
- **The description**, `example.json`: what the tests and the pipeline read
  about the example, rather than knowing it by name. Its `traffic` is the
  traffic inside as datagrams, each payload one message its `inside` spec
  decodes, so what decodes inside is checked exactly.
