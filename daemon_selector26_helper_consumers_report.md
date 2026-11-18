# fairplayd selector 26 shared-helper consumers

On the selector 26 continuation with constructor status `0x8b3dc651` and context bit 7 clear, `fairplayd` uses six returns from `0x100444dfc` to populate and transform private stack storage before requesting another allocation. A null return from that 128 B allocation frees the earlier 120 B and 8 B objects in that order. The outer path then releases its service and iterator. Both class profiles follow this sequence. [Postprocessing entry](daemon_selector26_postprocess_report.md) [Original-byte audit](triage_evidence/audit_daemon_selector26_helper_consumers.py) [Compressed evidence](triage_evidence/daemon_selector26_helper_consumers_audit.json.zst)

Addresses are unslid in the pinned arm64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. A is the caller-owned argument at the core's FP−0xa0 B. B is the core's SP+0xa60 B during the common serialization prefix. R is the outer record at F+0xc8 B, where F is the outer SP. Each of the six calls reuses A and resolves through original slot `0x1010a01b0`, key IA and diversity `0x9a7c`. The callee writes its 64-bit output at A+8 B at `0x10044a3bc`. The replay substitutes a fresh opaque word at that exact output field on each return. [Callee body and argument audit](daemon_scalar_field_population_report.md)

## Common data flow

| Operation | Source location | Destination or next consumer |
| --- | --- | --- |
| First call and result load | `0x100a2146c`, `0x100a21478` | `X8 = u64[A+8 B]`. `0x100a214b0` dispatches through slot `0x1010827b0` to `0x100688230`. |
| First byte loop | `0x100688238` | Eight successive stores to B+0…7 B. The loop writes one byte derived from each successive byte of the first result. A bit-vector equivalence check covers every 64-bit value. |
| Second call and byte loop | `0x100646bbc`, `0x100646bcc`, `0x10087a0a8` | Reads the replacement word at A+8 B and writes B+8…15 B. |
| Intermediate copy and transform | `0x10094ba40` through `0x10094bbc4` | Reads B+15…0 B in descending order and writes B+47…32 B. |
| Third through sixth calls | `0x10094bc5c`, `0x100930840`, `0x100641dbc`, `0x100640144` | The byte stores at `0x1009c356c`, `0x100951340`, `0x10092c52c`, and `0x100962ef0` write B+0…7 B, B+8…15 B, B+16…23 B, and B+24…31 B, respectively. The third and fourth loops replace the first two loops' destination bytes. |
| 32 B transformation | `0x100908874`, `0x100908890` | Reads B+31…0 B and writes B+79…48 B, both in descending order. |
| Next allocation gate | `0x100a5f394`, `0x100a5f40c` | Clears a separate 24 B local range, then calls `_malloc(128)`. The common prefix reaches this allocation for all opaque output values under the recorded premises. There is no Mach or IOKit call in this prefix. |

## Allocation branches and interface handoff

| Modeled allocator results | Established behavior | Evidence limit |
| --- | --- | --- |
| 128 B allocation returns null | `_free` at `0x100a86f0c` frees the 120 B object. `_free` at `0x100a2fe70` frees the 8 B object. The core writes `0x74c29d85` at R+8 B, the adapter output is zero, and the outer continuation rejoins at `0x1002c99a0` with SP=F. Service release `0x1001dcab8` precedes iterator release `0x100205980`. The Avp profile resumes the primary FairPlayIOKit lookup. The primary profile proceeds to status publication. | The rights and API results are replay fixtures. The earlier RAX capture observes primary-side deallocation following an open failure. |
| 128 B allocation succeeds and 112 B allocation at `0x1009447b4` returns null | The branch reaches an 8 B load at `0x10064ff10`. | The loaded value has no reaching definition in the replay. Subsequent cleanup is unknown. |
| First six subsequent allocations succeed | Requests are 128, 112, 16, 16, 32, and 14 B at `0x100a5f40c`, `0x1009447b4`, `0x1006bfff8`, `0x100645b00`, `0x100948dd0`, and `0x100a2fc00`. The 112 B object is freed at `0x1006bcce4` before the first 16 B request. There are eight additional calls to the same shared helper, four each at `0x10064881c` and `0x10092425c`. | The replay reaches a 2 B load at `0x10094326c` whose complete source value is unknown. The successful return and any subsequent IOKit message are unverified. |

The initializer artifact records 8 B pointer publications at `0x1003b42d4` and `0x1003b43c4` and allocation coverage of 58 and 101 B. It records the number of captured bytes for each allocation. An exact byte snapshot of either allocation at the selector 26 helper invocation is unavailable in this artifact. Fourteen symbolic outputs in the longer profile cover the caller's result field without asserting that every combination can occur in the initialized process. [Initializer artifact](triage_evidence/arcade_subscription_initialization_profile.json.zst) [Shared state context](arcade_subscription_report.md) [RAX capture](zut_trace_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The two earlier allocations are nonnull and disjoint, the original branch selects postprocessing, and the stack guard succeeds. All six profiles depend on these conditions. | Correlate the context bit, the two original allocator returns, and restored SP in the same invocation. |
| A2 | Each modeled helper return writes opaque data at A+8 B, preserves the caller's nonvolatile register state, and leaves all other modeled caller locations usable. Call ordering and serialization depend on the verified result location and the scoped memory model. | Check the complete helper store footprint against the live caller regions and compare the reaching definitions at the first downstream loads. |
| A3 | Allocator success uses disjoint pointers and models no implicit heap initialization. A load without a fully modeled source halts the trace. | Recover the source stores or capture the load and producing writes in the same lifecycle. A reconstructed value must match both width and timing. |
| A4 | Chained fixup resolution identifies logical branches in the pinned image. | Compare chained pointer words, diversity, and actual authenticated targets in the same build. |

Six profiles cover two classes and three allocation branches. The audit preserves 2,779 instruction spans and verifies 188 chained fixup records. For I instruction visits, L recorded loads and M modeled byte writes, replay bookkeeping uses O(I·L+M) time and O(I+L+M) space, with one bounded 64-bit equivalence query per profile. QG1–QG7 cover factual scope, explicit premises, the three branch outcomes, byte widths, trace bounds, image provenance, and the open evidence below.

| Impact | Open evidence |
| --- | --- |
| High | Resolve the reaching definitions at the two load boundaries and follow the successful return to any subsequent interface call. |
| High | Correlate a successful selector 26 exchange and the resulting service and iterator lifecycle in a native capture. |
| Medium | Relate the process-wide helper state at initialization to its state at the selector 26 call sites. |
