# WireGuard: a protocol that needs your own code

kober decodes a protocol from a spec, but some protocols cannot be decoded by a
spec alone. WireGuard encrypts its traffic, and kober ships no cryptography and
never will: a cipher is always the code of whoever runs the spec. This example
shows how the two fit together, and it is meant to be copied for a protocol of
your own: a cipher, a compression scheme, anything that turns bytes into other
bytes.

| File | What it is |
| --- | --- |
| [`wireguard.yaml`](wireguard.yaml) | The spec. The handshake decodes as structure; a transport message is opened with a transform the spec names, `wg-transport`, and declares. |
| [`wg_transforms.py`](wg_transforms.py) | Registers `wg-transport` with kober. Everything kober needs from your code is in this file. |
| [`wg_crypto.py`](wg_crypto.py) | ChaCha20-Poly1305 (RFC 8439) and X25519 (RFC 7748), standard library only. Shared by both sides, which is why it is a file of its own. |
| [`wg_handshake.py`](wg_handshake.py) | WireGuard's handshake, Noise IK, both peers' sides of it. |
| [`wg_seal.py`](wg_seal.py) | A tunnel module for `packeteer stream`: it seals the traffic packeteer generates, with a real handshake, and writes the key log and what it sealed. |

## Generating traffic

[packeteer](https://github.com/adamkjonsson/packeteer) 0.18.0 or later
generates the traffic inside the tunnel and hands each packet it sends to
`wg_seal.py`, which returns the WireGuard datagrams that carry it:

```console
packeteer stream --protocol udp --payload dns --protocol-messages dns.json \
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

- `keys.json` is the key log kober reads, below.
- `truth.jsonl` has one line per sealed packet: its session, direction,
  receiver, counter, plaintext and the datagram it became. A decode can be
  checked against it exactly, which `tests/test_wireguard_example.py` does.
  Compare as a set: each direction is a stream of its own once converted, so
  a decode lists one direction's packets before the other's.
- `--tunnel-arg wireshark_keylog=wireshark.keys` also writes the keys Wireshark
  needs, so a WireGuard implementation that is not this one can open the same
  capture: `tshark -r wg.pcap -o wg.keylog_file:wireshark.keys`.
- `--tunnel-arg initiator_key=hex:…` and `responder_key=hex:…` set the static
  private keys; otherwise every key and index comes from `--tunnel-arg seed`.

## Decoding a capture

kober reads `.zpf` files. A pcap becomes one with
[`zpfwire`](https://github.com/adamkjonsson/python-zipline-wire):

```console
zpfwire convert wg.pcap -o wg.zpf
kober run examples/wireguard/wireguard.yaml wg.zpf -o packets.zpf --emit field \
    --load-transforms examples/wireguard/wg_transforms.py \
    --param keys=file:keys.json
```

`keys.json` is a key log: each session's key in each direction, by the receiver
index a transport message carries. Values are written as `--param` writes
bytes:

```json
{"287454020": "hex:a1a1a1…", "572662306": "hex:b1b1b1…"}
```

A datagram the tunnel corrupted also fails its UDP checksum, as it would on a
real link. `zpfwire` keeps it by default, and kober names it `decrypt-failed`;
with `zpfwire convert --checksum drop` it is dropped instead, and reads as a
loss.

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
decoded as usual. So is one that opens to something that is not an IP packet,
which WireGuard drops as well: the one case where the name says more than
happened. No key is
ever written, and the decoder descriptor's `params_digest` says which key log
produced the file.

## How the pieces meet

- **The spec declares, your code supplies.** `wireguard.yaml` says the
  transform exists, what it takes (`key: bytes, counter: int`) and what its
  failure is called (`fails_as: decrypt-failed`). `kober check` types every use
  of it from that alone, with nothing registered.
- **The key is chosen per message**, `keys[receiver]`: an entry of a map
  parameter, indexed by a field. One table covers both directions, every rekey
  and every peer, which is how WireGuard itself finds a session.
- **`--load-transforms` runs your module**, which calls
  `kober.transforms.register`. A module loaded by path can import the modules
  beside it, as `wg_transforms.py` imports `wg_crypto.py`.
- **What your code raises is a failed transform**, never a failed decode, and
  only its exception's class is reported: its text, which could hold a key,
  never reaches the file.

## What it does not do

- **Open the handshake.** Its encrypted fields stay bytes: Noise IK's state
  runs from one message to the next, and a transform keeps nothing between
  messages. The transport keys come from the key log instead, which
  `wg_seal.py` derives by running the handshake.
- **Detect a replay.** A duplicated message opens again. WireGuard's replay
  window is state across messages too.

## How the example checks itself

The sealing side and the opening side share `wg_crypto.py`, so a fault in it
would seal and open consistently, and a round trip would pass. So
`tests/test_wireguard_example.py` checks it against what is not this code:
RFC 8439's and RFC 7748's own test vectors, extracted from the RFCs' text, and
Wireshark, which opens a capture `wg_seal.py` sealed and must find, byte for
byte, every packet that went in. Swapping the two transport keys inside the
handshake passes every other test and fails that one.

None of this is hardened against timing attacks, and none of it is meant to
protect anything.
