# packeteer's shipped specs, copied

`sensor.yaml` and `rpc.yaml` exactly as
[packeteer](https://github.com/adamkjonsson/packeteer) **0.16.0** ships them,
in `examples/protocols/`.

**Copies, not a path into a sibling checkout.** The test suite cannot depend on
one being present, and a test that read the live files would measure a moving
target — which is the failure `plans/PACKETEER-ALIGNMENT.md` §5.3 records: both
projects claimed one dialect and neither had a test that would notice when the
claim stopped being true.

Re-copy them when packeteer releases, and update the version above. A diff here
is the two dialects moving apart, which is the thing worth seeing — and the
version above is the only drift detector there is. A test that asserts a copy
is *refused* cannot fail when the other project moves, since the copy does not
move with it; the `rpc.yaml` test learnt that by staying green for nine days
after packeteer 0.13.0 had made it wrong.
