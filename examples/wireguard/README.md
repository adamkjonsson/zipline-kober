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
| [`wg_crypto.py`](wg_crypto.py) | ChaCha20-Poly1305 (RFC 8439), standard library only. Shared with the code that generates traffic, which is why it is a file of its own. |

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

`packets.zpf` has one `dec:ip-packet` record per transport message, citing the
datagram it came from, for the next stage to read. A message that does not
open, because it was corrupted or its receiver is not in the key log, is one
`decrypt-failed` region, and the next message is decoded as usual. No key is
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
  messages. The transport keys come from the key log instead.
- **Strip the padding.** WireGuard pads a packet to 16 bytes before sealing it,
  and the record holds it padded; the IP header says where the packet ends.
- **Detect a replay.** A duplicated message opens again. WireGuard's replay
  window is state across messages too.

`wg_crypto.py` is checked against RFC 8439's own test vectors in
`tests/test_wireguard_example.py`, so a fault in it cannot hide behind a round
trip with itself. It is not hardened against timing attacks, and is not meant to
protect anything.
