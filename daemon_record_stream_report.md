# Daemon record-stream termination and retained CoreFP serializer lineage

The output helper recovered in [the list-output report](daemon_list_output_report.md) emits a trailing record that matches the daemon XPC reader's variable-record stop case. Separately, all 12 retained Arcade send profiles associate the helper's final allocation with the exact bytes supplied to the CoreFP XPC `data` setter and send boundary. These establish a conditional format contract and historical private-model data lineage. Native delivery between these endpoints, and a native FairPlayIOKit exchange, remain unknown.

The primary inputs are the original thin daemon and retained profiles in `/Users/___/Downloads/zut` and `triage_evidence`. No legacy probe/generator or target code was executed in this increment. Static file reads, disassembly, original fixup comparison and SMT solving were performed. Reference data sufficed; no additional IDA access was required.

| Evidence | Identity or verification |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh instruction capture | 15 fragments, 663 instructions, 2652 B; 12 branch bindings, two import bindings, 14 original pointer records |
| Prior daemon bytes recaptured | 104 ranges, 56252 B, from four source ledgers; kernel ranges in the Arcade ledger are outside this daemon-only recapture |
| Retained execution evidence | 12 original private-model send profiles; four other stop classes excluded from this lineage claim; original profile files remain unchanged |
| Static verification | 147 instruction/profile assertion groups; nine UNSAT component queries, including five rerun prior queries; 32 translated instruction sites, 27 SSA definitions; eight altered-evidence controls rejected |
| Native execution | Unknown; neither a target execution nor a new emulation was performed |

Primary artifacts: [fresh source and frozen-profile summaries](triage_evidence/daemon_record_stream_source.json), [queries, translations and checks](triage_evidence/daemon_record_stream_checks.json), [capture script](triage_evidence/recover_daemon_record_stream.py), [validator](triage_evidence/validate_daemon_record_stream.py), [preservation ledger](triage_evidence/daemon_record_stream_delivery.json), [quality gates](triage_evidence/daemon_record_stream_quality_gates.json). The historical [Arcade report](arcade_subscription_report.md) and [original profiles](triage_evidence/arcade_subscription_profiles.json) retain the complete model assumptions and packet bytes. Their earlier finite sizing claim is extended below by a conditional algebraic result, not replaced by a native claim.

## Writer-to-reader contract [RS1-RS4, RS8]

All offsets and extents below are in bytes. The wire header is `H:BE32, T:BE16, P:BE32`, followed by P payload bytes. H is a numeric record identifier; application field names remain unknown. T is the wire discriminator. The stored discriminator is `u16(T XOR 0x11c3)` and the signed decision uses `s16(stored+3)`.

| Stage | Original site or exact contract |
| --- | --- |
| Writer trailing header | `0x1009178e4`; at D+Tbody: `00 00 00 00 50 DB BE32(P)` |
| Writer padding | `0x1006d6a30`; P zero bytes after the 10 B header |
| Writer extent | `P=16-((Tbody+10) AND 15)`; `L=Tbody+10+P`; admitted `0<=Tbody<=0xffffffe5` |
| Reader iteration | `0x100b22fe4 -> 0x100ad9f78 -> 0x100ba9504 -> 0x100a6c060`; nonempty source, at least 10 B, fitted record extent |
| Reader header and tag | `0x100cc0944 -> 0x100d31e14 -> 0x100aa9478 -> 0x100cb31bc`; `0x50db -> 0x4118 -> 0x411b`, selecting variable-record leaf |
| H decision | `0x100a85d74`; compare recovered H encoding against `0xabffbeef`; H=0 selects index `0x3b5c`, H!=0 selects `0x3b60` |
| H=0 continuation | `0x100c8f210`; raw local marker `0x8b3dc651`, Q loaded from frame+`0x700`; next index `0x5f5a` |
| Q publication | `0x100c044e4`; store Q as 8 B through pointer loaded from frame+`0x568`; next index `0x893a`, target `0x100c4dc4c` |
| H!=0 continuation | `0x100ab3e34`; constructor-argument route, including the case P=0 |

For a reader positioned at `c=Tbody` in a buffer of extent `N=L`, `N-c=10+P` is 11-26 B, `e=c+10+P=N`, and the record fits without a 64-bit sum wrap. The writer guarantees `1<=P<=16`, `16<=L<=0xfffffff0`, and `L mod 16=0`. L fits u32, so the earlier distinction between a full 64-bit supplied length and its low-32-bit copy extent vanishes for this particular writer extent. It remains relevant to other producers.

The three translated stop/publication blocks do not load payload bytes. They save the payload pointer and fitted end, select the H=0 branch, and publish Q. No padding-content, canonical-padding-count or alignment test occurs in these selected blocks. Earlier record fitting is still required. This is a local control/data dependency result: it does not establish application acceptance of arbitrary tails, authorization, later consumers, or a successful public result. The raw marker is a private frame value.

Reaching `c=Tbody` requires the preceding body to parse and its earlier constructor/iteration steps to succeed. The writer's address-dependent byte transformation and the producer-side inverse remain separate obligations. The common grammar alone does not identify a transport direction between this writer and this XPC reader.

```text
conditional writer output
  body[Tbody] | H=0,T=50db,P | zeros[P]
                ^ c=Tbody              ^ N=L
                |
reader bounds + tag dispatch + H=0
                |
                +--> local marker; publish accumulated Q

actual writer-to-this-reader transport: unknown
```

## Historical Arcade allocation-to-XPC lineage [RS1, RS5]

The existing [Arcade subscription analysis](arcade_subscription_report.md) establishes a kernel-collection process-path producer, an anonymous registered daemon endpoint and MIG request 61471. That is a separate interface from the unresolved FairPlayIOKit selector-26/RPC-502 pairing. This increment recaptures the daemon source and inspects the existing successful send-boundary profiles; it does not repeat kernel execution or the old private runs.

| Interface | Site or observation |
| --- | --- |
| Selected serializer caller | `0x100847960`; retained authenticated-branch event at `0x100847994` targets `0x1006bc13c`, modifier `0x6e32`, with authentication bypassed |
| Allocator call | `0x1006c318c`; three modeled `_malloc` calls per retained send profile |
| Trailer and publication | Original PCs `0x1009178e4` and `0x10068f630` are present in every retained send profile |
| Selected helper return | Retained event `0x10066efc8 -> 0x10090f880`, modifier `0x5677`, authentication bypassed |
| XPC dictionary create | `0x10077e508` |
| XPC `data` setter | `0x10077e5c4`; original slot `0x1010a0850`, IA modifier `0x485b`, `_xpc_dictionary_set_data` |
| Synchronous send boundary | `0x10077e614`; original slot `0x1010a04d0`, IA modifier `0x2e76`, `_xpc_connection_send_message_with_reply_sync` |
| Connection setup, prior source | `0x10040fdb0`, `com.apple.fpsd.arcadeservice`; resume `0x10040fea8`; full setup provenance remains in the Arcade report |

The original binding bytes and modifiers are corroborated here. Binding identity alone is not a fresh proof of every mutable-state-dependent bank-address expression at each call. The retained private import events identify the invoked setter/send models under their recorded state.

For each of the 12 profiles, the third allocator result equals setter argument X2; its requested extent equals setter X3 and the recorded data size. The setter dictionary equals send argument X1. The setter's complete byte string equals the send model's dictionary `data` byte string. These comparisons establish the retained model's buffer/extent/dictionary/byte lineage. Private allocation addresses and opaque XPC handles are neither native addresses nor Mach port names.

The unique-PC lists establish membership, not dynamic order or execution counts. The selected PAC-bypass events establish their own recorded branch targets. The original continuation constraints make phase `0x1593` compatible with the selected helper route; an incoming W22 register snapshot is not supplied by this evidence. Native phase production remains unknown.

```text
kernel process-path producer
  -> anonymous daemon endpoint / MIG61471    [prior original-source evidence]
  -> typed nested records
  -> serializer: modeled allocations 1,2,3
  -> final allocation pointer + explicit extent
  -> dictionary["data"] at 0x10077e5c4
  -> CoreFP synchronous send at 0x10077e614  [retained model stops here]
  -> native receiver / response             [unknown in this increment]
```

## Nested sizing and packet structure [RS5-RS6]

Let n be the path extent including its terminal NUL. The retained packet has an outer 14 B scalar record and a 10 B nested-span header. The inner body contains a 14 B scalar, a `10+n` B path record, and a 14 B scalar. Thus `Ti=38+n`, `Pi=16-(n AND 15)`, `Li=Ti+10+Pi=64+16*floor(n/16)`. The outer body is `To=24+Li`; `Po=14`, and `Lo=To+10+Po=112+16*floor(n/16)`.

| Recorded labels | n (B) | Allocations 1,2,3 (B) | Inner trailer offset (B) | Pi (B) | Outer trailer offset (B) |
| --- | --- | --- | --- | --- | --- |
| default; count0/count1/count57/countmax; opaque0/opaquemax | 57 | 16,112,160 | 95 | 7 | 136 |
| path_empty | 1 | 16,64,112 | 39 | 15 | 88 |
| path_one | 2 | 16,64,112 | 40 | 14 | 88 |
| path15 | 16 | 16,80,128 | 54 | 16 | 104 |
| path16 | 17 | 16,80,128 | 55 | 15 | 104 |
| path1023 | 1024 | 16,1088,1136 | 1062 | 16 | 1112 |

Offsets are relative to their respective inner or outer packet, not a shared base. Every outer trailer has Po=14. Each complete packet and both trailers were checked against the retained bytes, including the NUL-terminated path and zero contents. Packet SHA-256 values are recorded per profile.

| Level | H | Wire T | Payload |
| --- | --- | --- | --- |
| Outer | `7976211a` | `9777` | 4 B, raw `00000000` |
| Outer | `fd2821c7` | `50db` | Li B, nested packet |
| Inner | `7e852555` | `9777` | 4 B, raw `2cfbf0b8` |
| Inner | `1fe19f28` | `50db` | n B, path including NUL |
| Inner | `f6964e3e` | `9777` | 4 B, raw `04f2abb5` |
| Inner/outer terminators | `00000000` | `50db` | Pi/14 zero bytes |

The algebraic sizing query covers every integer n from 1 through 1024 B under this grammar and the conditional writer contract. It does not establish that every native request reaches this grammar, that every path is available, or that an external service accepts it. The four excluded profile stops are preserved verbatim in the source summary; they contribute no successful send-lineage claim.

## Assumption register and falsification probes

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RS1 | Recorded thin-image identity and original unslid addresses; all source results | Require exact source SHA-256, instruction bytes and original fixup membership; a build mismatch invalidates address transfer |
| RS2 | Stable finite acyclic list, valid disjoint owners and normal allocation ABI; full writer coverage | Static producer/owner/lifetime evidence could invalidate these premises; conditional size arithmetic alone does not prove them |
| RS3 | Reader has inherited phase, cursor and valid fitted span; stop compatibility | Establish incoming frame/phase and preceding iteration; a different phase or failed earlier record blocks the claimed path |
| RS4 | Wire H/type conversion follows the recovered header decoder | Rerun original header/discriminator queries after byte recapture; altered conversion or tag invalidates the H=0 connection |
| RS5 | Retained models report their own modeled calls/bytes accurately; historical lineage only | Check source identity, allocator/setter/send equalities and PAC-bypass flags; authenticated native execution is a separate missing observation |
| RS6 | Specified nested grammar and n=1..1024 B; universal conditional sizing | A different record, length convention or omitted terminator invalidates Ti/To; query proves only these stated premises |
| RS7 | Identical grammar does not by itself identify a native communicating pair | Require source-level caller/receiver linkage plus connection/endpoint identity; absent evidence leaves transport join unknown |
| RS8 | Frame/output pointers permit the indicated stores; local Q publication | Establish original owner and frame lifetimes; aliasing/invalid pointers invalidate operational publication despite scalar identities |

## Bounded extensions and unresolved interfaces

| Impact | Finding or opportunity | Boundary |
| --- | --- | --- |
| High | Separate kernel MIG61471 -> Arcade/CoreFP path from FairPlayIOKit selector26/RPC502/700 | A shared serializer cannot close the missing native kext-to-daemon pairing |
| High | Establish original producer encoding and owner lifetimes before treating helper bytes as a general serialized object | Byte transformation, mutable list state and phase production remain conditional |
| Medium | Use numeric keys, tags, extents and trailer grammar to compare an identified receiver's original parser | Shared format is supporting evidence; it cannot establish port or peer identity |
| Medium | Distinguish writer canonical padding from reader early termination | The selected stop blocks have a weaker local content dependency; no malformed target requests were constructed or sent |
| Low | Nested aligned paths require a full 16 B inner padding span | The formula explains retained allocation boundaries; it is not a native memory-use measurement |

Further evidence needed to close the principal interface is a build-matched original caller/receiver association, including endpoint acquisition, port-right transfer and dispatch, followed by the corresponding owner/status return path. This increment adds no new Mach port name or transfer claim. Original emissions and current gaps remain in [the Mach report](mach_ports_report.md) and [cross-layer ABI report](interface_abi_report.md).

## Reproduction and quality gates

Run from the extraction directory, using the supplied interpreter and no legacy probe scripts:

```text
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_record_stream.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_record_stream.py
```

Extraction is O(image bytes + fixup count + retained bytes + recorded PC count) time and space. Frozen packet decoding is O(packet bytes) time and space with fixed two-level nesting. Translation is O(selected instructions); SMT solving has separate solver complexity and an explicit per-query timeout. These are static analytical operations, not target emulation. No physical measurements or dimensioned computations beyond byte extents occur; BE and u16/u32/u64 operations are explicit.

QG1: No normative conclusion is required. QG2: RS1-RS8 identify dependencies and falsification probes. QG3: Routine roles, data flow, control flow, source APIs and transport limits are covered for this increment; broad investigation remains active. QG4: Byte dimensions, endianness, modular widths and the conditional 1024-value size domain are explicit. QG5: Shared grammar, historical private occurrence, arbitrary-H branch algebra and native execution are kept separate; no whole-message acceptance inference is made. QG6: Original bytes/fixups and preserved profile ledgers provide primary provenance; scalar queries and source dependencies are retained. QG7: Impact-bounded extensions identify the remaining caller/receiver, ownership and phase obligations.

All gates apply to the stated increment. Native peer identity, authentication, authorization, hardware PAC, delivery, reply policy and the complete daemon-kext exchange remain unknown. The active goal is incomplete.
