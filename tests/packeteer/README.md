# packeteer's shipped specs, copied

`sensor.yaml` and `rpc.yaml` exactly as
[packeteer](https://github.com/adamkjonsson/packeteer) **0.12.0** ships them,
in `examples/protocols/`.

**Copies, not a path into a sibling checkout.** The test suite cannot depend on
one being present, and a test that read the live files would measure a moving
target — which is the failure `plans/PACKETEER-ALIGNMENT.md` §5.3 records: both
projects claimed one dialect and neither had a test that would notice when the
claim stopped being true.

Re-copy them when packeteer releases, and update the version above. A diff here
is the two dialects moving apart, which is the thing worth seeing.
