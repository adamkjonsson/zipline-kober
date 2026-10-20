# PackBits: a tunnel that needs your own codec, and no keys

The smallest example of a protocol kober cannot decode from a spec alone. It is
made up: a tunnel whose every datagram carries one IP packet, compressed with
PackBits, the run-length scheme of Apple's Macintosh toolbox and TIFF. The
standard library has no PackBits, so the code that unpacks it is yours.

It is the second example of [bringing your own code](../../docs/guides/your-own-code.md),
after [WireGuard](../wireguard/README.md), and it was written from WireGuard's
*Adapting this to your own protocol* to show the shape that needs least: no
keys, no handshake, no parameters, one transform.

| File | What it is |
| --- | --- |
| [`packbits.yaml`](packbits.yaml) | The spec: a version, the packet's length and CRC-32, and the packed packet, which a transform the spec declares, `packbits`, unpacks. |
| [`pb_transforms.py`](pb_transforms.py) | Registers `packbits` with kober: unpack to the declared length, check the CRC. |
| [`pb_codec.py`](pb_codec.py) | PackBits, both ways (TIFF 6.0 §9, Apple TN1023). Shared by both sides, which is why it is a file of its own. |
| [`pb_tunnel.py`](pb_tunnel.py) | A tunnel module for `packeteer stream`: it packs the traffic packeteer generates, one datagram per packet, and writes what it packed. |
| [`dns.json`](dns.json) | A DNS query and its answer, the traffic the commands below send through the tunnel. |
| [`example.json`](example.json) | The example, described for its tests and for `tools/pipeline.py`. |

Its tests are [`tests/test_packbits_example.py`](../../tests/test_packbits_example.py).

## What you need

kober with its YAML extra (`pip install 'kober[yaml]'`),
[`zpfwire`](https://github.com/adamkjonsson/python-zipline-wire) 0.5.0 or
later, and, to generate traffic,
[packeteer](https://github.com/adamkjonsson/packeteer) 0.18.0 or later.

## The protocol

```
version   1 byte    1
length    2 bytes   the packet's length, unpacked
crc       4 bytes   CRC-32 of the packet, unpacked
packed    the rest
```

Each field is there for a reason a protocol of your own may share:

- **`length`, because PackBits cannot say where its packed bytes end.** TN1023:
  unpacking "requires the length of the unpacked data". The transform unpacks
  exactly that much, from exactly all of `packed`, and anything else fails.
- **`crc`, because PackBits checks nothing.** A corrupted byte in a literal run
  unpacks to a wrong packet of the right length, and without a check that
  packet would be decoded as if it were real. With one, the transform fails and
  the datagram is `unpack-failed`, as a cipher's tag makes WireGuard's
  `decrypt-failed`. If your protocol has no integrity check of its own, a
  decode of a corrupted datagram can be wrong, and nothing can tell.

PackBits does not pay for itself on this traffic: DNS has few runs, and the
datagrams come out about 9% larger than the packets in them. The example is
about the shape, not the ratio.

## Generating traffic

[packeteer](https://github.com/adamkjonsson/packeteer) 0.18.0 or later
generates the traffic inside the tunnel and hands each packet to `pb_tunnel.py`:

```console
packeteer stream --protocol udp --payload dns --protocol-messages examples/packbits/dns.json \
    --client-ip 10.8.0.2 --server-ip 10.8.0.1 --server-port 53 --packets 40 \
    --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 9999 \
    --tunnel-module examples/packbits/pb_tunnel.py --tunnel-arg truth=truth.jsonl \
    --tunnel-packet-loss 0.1 --tunnel-corruption 0.15 --seed 7 --pcap pb.pcap
```

`truth.jsonl` is the example's one convention to keep (the WireGuard README's
*Conventions*): a line per packet, with `inner`, `outer` and `direction`. There
is no key log. Nothing here is random, so packeteer's seed alone makes a run
reproduce, and the same packet always packs to the same datagram, which a
check of the decode has to allow for (it does, in `tests/examplekit.py`).

## Decoding it

```console
zpfwire convert pb.pcap -o pb.zpf
kober run examples/packbits/packbits.yaml pb.zpf -o packets.zpf --emit field \
    --load-transforms examples/packbits/pb_transforms.py
```

No `--param`: everything the transform needs, the datagram says. Each packet
is one record, `packbits.packet`, labelled `net:ip` and citing the datagram
it came from; a corrupted datagram is one `unpack-failed` region, and the next
one decodes. `net:ip` promises exactly one IP packet and nothing checks it
downstream, so the transform does: what unpacks with the right length and CRC
but is not one IP packet is `unpack-failed` too, as a tunnel's receiver would
drop it.

## The traffic inside

As for WireGuard, `zpfwire` 0.5.0 turns the packets back into the conversation
they carried, and any spec decodes it:

```console
zpfwire convert packets.zpf -o inner.zpf
kober run examples/dns.yaml inner.zpf -o dns.zpf
```

## How the example checks itself

- **The codec against what is not this code.** TN1023's worked example, packed
  and unpacked, and TIFF 6.0 §9's rules one at a time, both extracted from the
  documents' own text. A fault made the same way on both sides, such as a
  replicate count off by one in both `pack` and `unpack`, passes every round
  trip and the whole chain, and fails those.
- **The decode against what was packed**, exactly, through packeteer and
  `zpfwire` and back, under loss, corruption, reordering and duplication: the
  shared kit's oracle.
- **The pipeline**, from `example.json`: `pb_clean` and `pb_impaired`, through
  both drivers, with the tunnel and the DNS inside checked exactly.
