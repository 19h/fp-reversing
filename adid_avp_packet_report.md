# CoreADI adid: Avp packet representations, typed records and returned-count control

The original full callback constructs a 144-byte Avp method-100 request with four outer records and five nested records in an 80-byte span. Its byte representations can now be followed through the original stores and copies. In the retained environment controls, time and random inputs change only the four bytes at packet offsets 94..97; the intervening protected computation remains unknown.

The returned byte count controls a second interface. A modeled 144-byte response enters the typed-record parser. Every tested shorter response instead reaches a second method-100 call with a source-built 320-byte packet over the same cached connection. All twelve retained 320-byte packets are identical, despite different first-response contents. The second call is left opaque. Neither packet is assigned a successful protected-operation meaning, and native Avp/FairPlayIOKit pairing remains unknown.

Six full-width arithmetic proofs, 32 retained complete callbacks, one additional byte-audit callback and nine fresh callback runs support this increment. All 147,690 assertions pass. These are source-derived and bounded private-model findings; no native target, framework, Mach, driver, target-file or synchronization API executes. The full investigation remains active.

## Identity, assumptions and falsification probes

Source: `/System/Library/PrivateFrameworks/CoreADI.framework/adid`, selected arm64e slice, preferred base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. Addresses are unslid addresses in this exact slice. Original binaries, IDBs and supplied inputs remain preserved.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| P1: pinned original bytes/fixups identify the inspected image | All addresses, instructions and local contracts | Fresh original instruction/range/window and independent `dyld_info` readbacks. Another image requires new mappings; actual native image selection/integrity remains unknown. |
| P2: frozen private API/PAC/vector/atomic models delimit the experiment | Callback, driver-call and response witnesses | Eight fresh retained-case replays plus one additional complete byte-audit callback. Hardware PAC, native API behavior and concurrency remain unproved. |
| P3: restored peer/context and declared credential/filesystem/environment prerequisites admit these local requests | Complete callback-to-Avp paths | Entry `0x100029fc8`, command `0x76e89210`, successful VMM value 1 and explicit time/random/small-allocation models; no internal PC/frame/context override. Native admission and effective identity remain unknown. |
| P4: watched addresses can hold multiple allocations and representations | Byte provenance, before/after ledgers and final snapshots | Verify 52,695 original watched writes and 14 declared API effects in captured order, including preimages and final snapshots. An address observation is not a native object type or one continuous lifetime. |
| P5: exact structural parsing describes the retained bytes | Four outer/five nested records and the 320-byte hierarchy | Independent bounded parser checks every header/extent/tag/scalar width. Structurally valid bytes do not establish an accepted driver response or complete protocol language. |
| P6: controlled time/random changes expose finite source dependence | Four-byte influence at offsets 94..97 | Six alternate time bit patterns and three alternate random values; original staging and subsequent state stores/reads retained. Complete algorithm, meaning, entropy and dependence outside these cases remain unknown. |
| P7: explicit API-return bytes are external inputs to original response processing | Size controls, error payloads and follow-up request | Identity, prefix, raw byte, scalar and header/nested-tag controls; no original instruction or context is changed. None is asserted to be a genuine driver response. |
| P8: the observed parser control and encoded-count comparison constants apply locally | Key/scalar/tag reductions and 144-byte branch | Six full-domain proofs plus source operands/targets and independent typed-field checks. The count predicate observes low32 of size64, not all 64 bits. |
| P9: declared response sizes obey the supplied first-call capacity | Bounded copies and tested size transitions | First call has capacity 144 bytes; models reject larger output. High-bit count aliases, over-capacity providers, arbitrary overlap, ownership and native consequences remain untested. |
| P10: the second call's bytes and connection are observations at an opaque boundary | 320-byte hierarchy, cache reuse and architectural lead | All twelve second calls retain exact bytes, caller records and original method/API sites; one open per callback. Subsequent reply, hardware transformation, application meaning and native port/right identity remain unknown. |

Artifacts: [packet profiles](triage_evidence/adid_avp_packet_profiles.json), [source contracts/windows/proofs](triage_evidence/adid_avp_packet_contracts.json), [producer](triage_evidence/probe_adid_avp_packets.py), [recoverer](triage_evidence/recover_adid_avp_packets.py), [validator](triage_evidence/validate_adid_avp_packet_delivery.py), [checks/count audits/320-byte packets](triage_evidence/adid_avp_packet_checks.json), [additional byte-audit callback](triage_evidence/adid_avp_packet_byte_audit.json), [quality gates](triage_evidence/adid_avp_packet_quality_gates.json), and [prior-artifact preservation](triage_evidence/adid_avp_packet_preservation.json). The [command-dispatch report](adid_command_dispatch_report.md) establishes the full request predecessor; the [caller report](adid_iokit_caller_report.md) retains the general caller-record, copy, size and status scope.

## Representation and control sequence [P1-P4,P7-P10]

```text
original complete XPC callback + command 0x76e89210
  -> VMM exact1 -> explicit time/random -> original small-state computation
  -> typed serialization, 144 bytes
  -> reverse physical byte transform 0x10024b53c      XOR 0xe8
  -> forward copy 0x10025fc38                       XOR 0xe8
  -> Avp method100 0x100058a1c, shared144-byte buffer
  -> explicit first API response, size64 N <= 144
  -> original caller copies N bytes and publishes encoded count32
  -> count comparison 0x10024e1d4
       +-- low32(N) == 144
       |    -> forward physical byte transform 0x10024bb90  XOR 0xe8
       |    -> reverse parser-input copy 0x10025fd24        XOR 0xe8
       |    -> typed-record parser -> retained payload error
       +-- tested low32(N) < 144
            -> original protected continuation/packet construction
            -> Avp method100, shared320-byte buffer, same cached connection
            -> opaque boundary; no second response supplied
```

In the retained 144-byte response cases, the two XOR transforms cancel before typed parsing. The original API buffer is first copied unchanged to the caller destination by the separately established caller helper. These are distinct stores/copies and memory epochs; final bytes at a reused address alone do not identify the earlier packet.

| Phase | Source site | Retained address/extent |
| --- | --- | --- |
| Pre-call physical representation | Reverse byte store `0x10024b53c` | Staging `0x7e0105c0`, 144 bytes |
| Final first method input | Forward byte store `0x10025fc38` | Shared method buffer `0x7e000530`, 144 bytes |
| API input/output | `0x100058a1c` | Connection `0x5804`, selector 100, output-size64 at `0x7a02d9b8` initially 144 |
| First response copied to caller | Reverse copy store `0x100058c88` | Destination `0x7e010420`, N bytes |
| Received physical representation, N=144 | Forward byte store `0x10024bb90` | Staging `0x7e0005d0`, 144 bytes |
| First typed-parser input, N=144 | Reverse byte store `0x10025fd24` | `0x7e0104c0`, 144 bytes |
| Second method input | Same API site `0x100058a1c` | Shared buffer `0x7e0004f0`, 320 bytes; size64 initially 320 |

These addresses and numeric connection names belong to private fixtures. Source call sites, relative layouts and byte arithmetic are evidence; native Mach rights, port objects, mappings and endpoint identities remain unknown.

## Compact byte and typed-record contracts [P1,P4,P5,P8]

For a byte b, both original physical-transform branches reduce exactly to XOR `0xe8`:

```text
forward8(b) = b - ((b << 1) AND 0xd0) - 0x18       modulo 2^8
reverse8(b) = b + (0x2f OR NOT(b << 1)) - 0x17     modulo 2^8
            = b XOR 0xe8
```

The [byte proof](triage_evidence/adid_avp_packet_byte8.smt2) covers all 256 inputs and the paired inverse. Two 144-byte response experiments additionally pass all 256 byte values through the original forward physical-transform code. Their arbitrary bytes are parser-error controls, not accepted responses. Copy direction/extent is checked for the retained disjoint buffers; the arithmetic proof is not a whole-function overlap/lifetime proof.

The inspected typed-record header is ten bytes: raw key BE32, tag BE16, payload byte count BE32. Original gathers and internal encodings reduce as follows:

| Source block/store | Local value |
| --- | --- |
| `0x100260c9c..0x100260cc4` | Payload length = raw BE32 at header+6 |
| `0x100260d38..0x100260d90`, control `0xd5b` | Internal key32 = raw key + `0x46d726`, modulo 2^32 |
| `0x100260dd8..0x100260e40` | Normalized tag16 = `(raw tag XOR 0x5a47)+0x10`, modulo 2^16 |
| `0x100260ed4..0x100260f28` | Internal scalar32 = raw BE32 payload + `0x46d726`, modulo 2^32 |
| `0x100262000..0x100262090` | Internal scalar64 = raw BE64 payload XOR `0xf048dd51c8511450` |

| Raw tag | Normalized tag | Local payload kind |
| --- | --- | --- |
| `0x50db` | `0x0aac` | Byte span |
| `0x8485` | `0xded2` | Eight-byte scalar |
| `0x9777` | `0xcd40` | Four-byte scalar |

The [word32](triage_evidence/adid_avp_packet_word32.smt2), [tag16](triage_evidence/adid_avp_packet_tag16.smt2) and [scalar64](triage_evidence/adid_avp_packet_scalar64.smt2) proofs cover their entire respective domains. The normalized-tag comparison selects exactly these three raw tags at the inspected block. This is local tag dispatch, not an accepted whole-record language or application schema. Shared tags with other FairPlay components do not establish identical scalar encodings or operation meanings.

The original payload-extent comparison at `0x100260d14` also has a conditional exact reduction. With cursor p, raw payload length L and capacity C represented as zero-extended u32 values, and the captured relation `X9_before = 0x366c08f7bb6af577 + p`, its unsigned 64-bit comparison is equivalent to:

```text
p + 10 bytes + L <= C
```

The [extent proof](triage_evidence/adid_avp_packet_extent64.smt2) covers all three u32 domains under that stated cursor relation. This proves the local payload check; header availability, cursor production, whole-parser acceptance and memory validity remain separate requirements.

## Exact first request layout [P3,P5,P6]

Baseline explicit inputs: time result 1,700,000,000 s; `_arc4random_uniform(0x7fffffff)` result `0x12345678` (305,419,896); successful VMM query/value 1. Original imported malloc calls request 12 and 1 bytes. The private allocator uses owned addresses and a bounded 4,096-byte/three-allocation policy; it calls no host allocator.

| Absolute offset (bytes) | Raw key | Tag | Payload extent (bytes) | Baseline payload |
| --- | --- | --- | --- | --- |
| 0 | `0x6125a127` | `0x8485` | 8 | `051ef018eda04201` |
| 18 | `0x7976211a` | `0x9777` | 4 | `00000000` |
| 32 | `0xfd2821c7` | `0x50db` | 80 | Five structurally parsed records below |
| 122 | `0x00000000` | `0x50db` | 12 | Twelve zero bytes |

| Absolute nested offset (bytes) | Raw key | Tag | Payload extent (bytes) | Baseline payload |
| --- | --- | --- | --- | --- |
| 42 | `0x197aefe2` | `0x9777` | 4 | `7a021901` |
| 56 | `0x70bf3591` | `0x9777` | 4 | `00000001` |
| 70 | `0x8d0a2514` | `0x9777` | 4 | `2ab0e071` |
| 84 | `0xf6964e3e` | `0x9777` | 4 | `4825a3e7` |
| 98 | `0x00000000` | `0x50db` | 14 | Fourteen zero bytes |

The layout sums exactly to 144 bytes; the nested span sums exactly to 80 bytes. The independently checked scalar widths are 4 and 8 bytes. No key above is assigned a command/status/account/cryptographic meaning from its numeric value or shape alone.

Original time staging at `0x10014648c..0x1001464cc` stores eight little-endian bytes in a local slot; random staging at `0x1001465d4..0x100146600` stores four little-endian bytes. The 12-/1-byte allocated states undergo additional source reads/writes, including repeated blocks in `0x100149xxx`/`0x10014bxxx`. Their complete compact semantics are unknown. They are not labeled a hash, cipher, nonce, certificate or authentication result.

Time controls use raw result bit patterns 0, 1, 2, `0xffffffff`, `0x100000000`, and `0xffffffffffffffff`; random controls use 0, 1 and `0x7ffffffe`. All remain within the declared model, with the random values below the original upper bound. Compared with the baseline method input, only offsets 94..97 differ in these nine alternate cases. This establishes finite dependence of the nested `0xf6964e3e` payload on those inputs; it is not a proof of exclusive dependence for all environments or inputs.

## Returned count, parser entry and follow-up [P7-P10]

Fresh original-store observations identify count initialization at `0x10016839c`: the caller's four-byte slot at fixture `0x7a030954` receives encoded zero `0x46d726` before the first API call. On positive-size success, helper store `0x100058cf8` writes `low32(N)+0x46d726`. A zero-size success leaves the initialized slot unchanged. Thus the earlier fragment-level unknown caller initialization is resolved for this complete callback path.

At `0x10024e1d4`, the original caller compares that encoded count with `0x46d7b6` (144+`0x46d726`). Equal dispatch at `0x10024e1f8` reaches `0x10024e1fc`; unequal dispatch reaches `0x10024e244`. Fresh operands and original branch targets are retained in the checks artifact.

The [returned-count proof](triage_evidence/adid_avp_packet_return_count64.smt2) establishes that this comparison is equivalent to `low32(N)==144` over the complete 64-bit domain. It does not establish `N==144` for arbitrary 64-bit API outputs. The retained response model restricts N to 0..144, where equality has the ordinary exact-size interpretation. Copying, size64 and published count32 remain separate ABI scopes.

| Declared first response | Size (bytes) | Retained continuation |
| --- | --- | --- |
| Identity buffer | 144 | Typed parser; completed `ffff5805` (-43003) |
| Identity prefixes | 0, 1, 9, 10, 18, 32, 122, 143 | Second original method-100 call with 320-byte input |
| Ten zero bytes | 10 | Same 320-byte boundary |
| Bytes 144..255 | 112 | Same 320-byte boundary |
| Single `0x7976211a` scalar record, value 0 or 1 | 14 | Same 320-byte boundary |
| Bytes 0..143 | 144 | Parser extent failure; completed `ffff5802` (-43006) |
| Bytes 144..255 followed by 32 zeros | 144 | Same parser-error payload; completes byte-domain audit |
| Outer scalar at offset 28 changed to 1, `0x8b3dc651`, or `0xffffffff` | 144 | Completed `ffff5805` |
| First raw key changed to zero | 144 | Completed `ffff5805` |
| First raw tag changed to zero, or first payload length changed to `0xffffffff` | 144 | Completed `ffff5802` |
| First nested raw tag changed to zero | 144 | Completed `ffff5802` |
| Nested four-byte payload at offset 94 changed to zero | 144 | Completed `ffff5805` |

The first nested-tag control also demonstrates original processing beyond the outer span's structural framing. Error meanings beyond the numeric values and observed source paths remain unknown. The shorter responses do not reach the first response parser-copy path in these cases; their contents must not be interpreted as parser-rejection evidence. The second method call receives no modeled response and emits no completed XPC reply before the stop.

## Source-built 320-byte follow-up hierarchy [P5,P10]

All twelve follow-up buffers have SHA-256 `fb8563f814c1534bf411f71cba2ee7ce87e5fb8aeb4b5e1016e258b9fca7eda8`. The connection remains fixture `0x5804`, obtained through one type-0 open/cache `0x1002dd290`. The second method call uses the same source emission site `0x100058a1c`, selector 100, shared input/output pointer and eight-byte output-size cell, now initialized to 320.

The structural hierarchy below uses absolute packet offsets. Scalar payloads occupy four or eight bytes; span lengths exclude their ten-byte headers.

```text
320-byte method input
  0    key6125a127  scalar64 [8]
  18   key7976211a  scalar32 [4]
  32   keyfd2821c7  span [256]
       42   key197aefe2  scalar32 [4]
       56   key70bf3591  scalar32 [4]
       70   key8d0a2514  scalar32 [4]
       84   key351bdea7  span [176]
            94   key7976211a  scalar32 [4]
            108  keyfd2821c7  span [128]
                 118  keyfa834112  scalar32 [4]
                 132  keyf6964e3e  scalar32 [4]
                 146  keyf8910ace  opaque span [16]
                 172  keyf547819e  opaque span [32]
                 214  keyf8819aec  scalar32 [4]
                 228  key00000000  zero span [8]
            246  key00000000  zero span [14]
       270  keyf6964e3e  scalar32 [4]
       284  key00000000  zero span [4]
  298  key00000000  zero span [12]
```

The first three inner scalar payloads are `7a021901`, `00000001`, and `e2b109ab`. The third differs from the corresponding first-request payload `2ab0e071`. The 16-byte and 32-byte spans are exactly retained in the checks/profiles. Their meanings, producers' complete algorithms, accepted response and subsequent operation remain unknown. Equal bytes across these twelve declared fixtures do not establish invariance across native state or environments.

## Incoming/outgoing interfaces and evidence limits

The incoming path remains the original `com.apple.adid` callback `0x100029fc8` with the previously recovered peer/audit/context gates. Outgoing IOKit method emission is `0x100058a1c` for both packet sizes. Successful acquisition uses `_IOServiceOpen` at `0x10002b854`; service and iterator release sites remain `0x10002b8ac`/`0x10002b940`. Completed first-response controls request XPC data/reply at `0x1000aa9fc`/`0x1000aaa70`.

No new raw Mach send site, incoming receive right, outgoing send right or native port-object identity is established. Avp selector 100 and the primary FairPlayIOKit selector-26 descriptor interface remain distinct. The actual Avp driver implementation, effective entitlements, primary-kext transfer, daemon RPC relationship and deeper hardware/firmware behavior remain unknown.

## Reproduction and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_avp_packets.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_avp_packets.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_avp_packet_delivery.py
```

The retained 32 callbacks comprise ten opaque first-call cases, ten completed response controls and twelve opaque second-call cases. The additional byte-audit callback completes a parser-error reply. Together they retain 10,707,812 original instruction visits, 33,461 distinct original instructions and 19 complete compiler ranges. Verification checks 52,695 original watched writes, 14 explicit API memory effects, 98 typed scalar/header snapshots, six fresh solver results and ten original source windows. The profiles additionally retain 44,646 watched reads. Nine fresh callbacks cover 2,504,233 hooks; eight reproduce retained instruction/event/write/read/final-epoch evidence exactly, and the ninth supplies the remaining received-byte values. The watched-read total is not a separate proof of every read's semantic provenance.

Source recovery costs O(B+F+P+R) time/space for original bytes, fixups, proof/window data and record bytes, excluding solver internals. Each of six SMT queries has a 30 s timeout. Callback production costs O(C*(B+F+K)) time/space with C cases and K capped at 800,000 hooks per case. Verification costs O(B+F+V+W+R) time/space plus the nine bounded callback runs, where V is retained visits and W is watched events. These are analysis-workflow bounds, not native-runtime bounds.

| Gate | Stated increment |
| --- | --- |
| QG1 | Descriptive binary/interface findings; no normative content required |
| QG2 | P1-P10 list assumptions, dependent results and falsification probes |
| QG3 | Packet representations, exact retained framing, count/response controls and follow-up API boundary covered; broad native goal remains incomplete |
| QG4 | Full-width local arithmetic, explicit byte extents/time units and bounded algorithms |
| QG5 | Address reuse, physical/typed/wire representations, count32/size64, short-size control versus parser admission, synthetic responses and opaque fields separated |
| QG6 | Fresh original source/fixups, independent parser/byte/ledger checks, six proofs, nine callbacks, complete byte domain and preserved inputs |
| QG7 | Impact-labeled continuation below; open native/protocol requirements remain open |

## Bounded continuation

| Impact | Further evidence | Closure criterion |
| --- | --- | --- |
| High | Actual Avp user client and method-100 implementation | Matching image/type-0 method table and original request/response transformation; correlate primary FairPlayIOKit or deeper daemon/kernel transfers |
| High | Complete 144-/320-byte response grammar and callers | Recover required keys, values, size/count contracts and successful original consumer paths; identify actual client/library producers |
| High | 320-byte continuation and opaque 16-/32-byte values | Trace source producers, consumers, response checks, complete ownership and any hardware/firmware boundary without assigning meanings from lengths alone |
| High | Native IPC/credential/endpoint pairing | Effective peer/task entitlements, real libxpc/IOKit Mach emission and incoming/outgoing right/object identities |
| Medium | Compact 12-/1-byte state computation | Recover the repeated source transforms, constants, input staging and four-byte result semantics; validate varied original behavior independently |
| Medium | Count width and provider-conformance boundary | Complete size64/count32/capacity guards, initialization, aliasing and lifetime; distinguish low32 comparison from complete size acceptance |
| Medium | All fourteen command schemas and record publication | Complete command-body admission/outputs, valid constructor blob, natural collection lifecycle and persistence feedback |
| Medium | Cache/retry/resource ownership | Complete close/reset/reentry/error/concurrency paths and native references across both method calls |
| Low | Remaining typed fields and zero-key spans | Establish field roles and additional consumers; preserve raw key and structural interpretation until corroborated |
