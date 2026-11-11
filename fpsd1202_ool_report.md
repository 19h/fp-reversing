# FPSD1202 control endpoint, session-state selector and OOL ABI

Request1202 first compares its received local Mach name with the name extracted from the CF object stored for `com.apple.fpsd`. The other-name path scans session markers and selects `0x4577df4d`; the earlier post-1200 marker4b session is skipped. Its MIG stub accepts one OOL byte descriptor, requests input deallocation after the application returns, clears the consumed address/count fields, and constructs either a simple36-byte error or complex72-byte reply. Original application paths, declared application-return controls and stop boundaries are separated below. Native transport, authorization, ownership and successful application processing remain unknown. [FO1-FO8]

This continues the [FPSD1201 report](fpsd1201_session_report.md). The broad daemon/kext/deeper-interface goal remains active.

The subsequent [selected-session report](fpsd1202_session_report.md) continues the declared marker4d case through the CF-name comparison, operation1/2 fork, diagnostic SHA-1/AES path, counter stores and original replies. It supersedes this report's stop boundary only for those explicit later profiles; native valid state and daemon/kext completion remain unknown.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FO1 | The pinned thin daemon and matching IDA bytes identify the implementation. All addresses and source predicates depend on this identity. | Rehash the thin image,37 source spans,170 original format12 rebases and10 bindings; distinguish the IDB input hash from the thin-image hash. |
| FO2 | The frozen successful FPSD1200 snapshot supplies startup owners/globals and the session pool. Original request paths depend on that explicit composition. | Pin the exact payload, successful predecessor receipt and dependency hashes; independently reconstruct the eight startup owners, global overlays and pool. The predecessor prefix is not freshly replayed here. |
| FO3 | One registration-produced CF field is separately composed at header+40. The control-endpoint interpretation depends on its recorded service/destination and object/name construction. | Check the exact `services_success` original store, final header bytes and CF constructor pair. The private name is `0x1003`; the historical trace's `0x1403` is a different observation. Complete registration/startup temporal continuity is unknown. |
| FO4 | Receive-side header names, descriptor fields, three words, inline16 bytes and OOL mapping are declared inputs. Local ABI/path results depend on them. | Vary the word, local name, slot index, descriptor envelope and registration cell. Native receive conversion, client pairing and sender rights remain unknown. |
| FO5 | CF name extraction, locks, once, stack probing, PAC and deallocation use explicit private models. Original application status is not injected in the source cases. | Independently recompute every ABI argument/result/clobber, complete CPU frame, source read/write journal and final RAM byte. No native API or unmap is executed. |
| FO6 | Two stub controls explicitly replace the whole application call with declared outputs/status. Their reply contracts are conditional, not observed application success. | Verify all eleven application arguments, exact output stores, caller clobbers, original return/deallocation ordering and both reply forms. Keep these controls separate from original application paths. |
| FO7 | Complete source CPU frames establish the name and marker phases. The marker4d case is a declared field control. | Independently lift both original scalar expressions; solve all-u32 counterexample queries; check the selector table words and original pool reads. Stop before supplying a session CF-name result. A source-produced marker4d state is still unknown. |
| FO8 | Fifteen bounded profiles and their exact stops define this increment. | Check source, controlled and guard cases separately; preserve unknown OOL processing, output ownership, later cleanup, successful operation and daemon/kext/deeper continuation. |

## Primary provenance [FO1-FO3,FO8]

| Object | Identity / extent |
| --- | --- |
| Thin arm64e daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Live IDA input metadata | SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`;37 fresh source-span hashes match |
| New source catalog |3140 distinct four-byte instructions /12560 bytes |
| Frozen session | `queue7_success` in [lifetime checks](triage_evidence/fpsd1200_lifetime_checks.json.zst); exact decoded payload and successful fresh-replay receipt pinned |
| Frozen registration | `services_success` in [registration profiles](triage_evidence/daemon_registration_profiles.json.zst); one original8-byte publication and its constructor pair are joined |
| Primary SDK | Five hashed headers; arm64e compile-only assertions for Mach/NDR extents, packed request/reply offsets, enum/error values, CF name and deallocator signatures |
| IDA knowledge search | No fact matched the two tail-store locators; no semantic conclusion comes from memory |

Evidence: [producer](triage_evidence/recover_fpsd1202_ool.py), [source/profiles/proofs](triage_evidence/fpsd1202_ool_checks.json.zst), [IDA/SDK attestation](triage_evidence/fpsd1202_ool_ida_readback.json.zst), [independent auditor](triage_evidence/audit_fpsd1202_ool.py), [fresh receipt](triage_evidence/fpsd1202_ool_audit.json.zst) and [publication verifier](triage_evidence/verify_fpsd1202_ool_publication.py). New IDA scripts read bytes, functions and references without requesting edits. No decompiler operation is used in this increment.

## Incoming request and application ABI [FO1,FO4-FO6]

The family demultiplexer `0x100004b80` selects request1202 stub `0x1000047a4`; its descriptor advertises maximum reply72 bytes. The stub requires the complex bit, descriptor count1 and reported message size84. Violations return MIG_BAD_ARGUMENTS=-304. Descriptor type+39 must be MACH_MSG_OOL_DESCRIPTOR=1, and descriptor size+40 must equal repeated count+80; either failure returns MIG_TYPE_ERROR=-300. These are source-defined local guards, not a complete backing-storage, sender-right or authorization theorem.

| Received request offset, bytes | Width | Meaning in this stub |
| --- | --- | --- |
|0..23|24 bytes|Mach header; remote/reply name+8, received local name+12, ID1202 at+20|
|24|u32|Descriptor count1|
|28|u64|Received OOL address|
|36..39|4 bytes|OOL descriptor flags/padding/type; type1 is tested at+39|
|40|u32|OOL byte size|
|44..51|8 bytes|NDR record|
|52 /56 /60|Three u32|Application words A / B / C|
|64..79|16 bytes|Inline input, forwarded by pointer|
|80|u32|Repeated OOL count|

No audit trailer is copied by this stub. NDR and the three application words are not semantically validated here. Native authorization and the actual client builder remain separate obligations.

At original call `0x100004844`, wrapper `0x1000060b4` receives:

| Argument | Exact source / role |
| --- | --- |
| W0 | Received local name from request+12 |
| W1 / W2 / W3 | Words A / B / C from request+52/+56/+60 |
| X4 | Pointer to inline16 at request+64 |
| X5 | OOL address from request+28 |
| W6 | OOL count from request+40, zero-extended into X6 |
| X7 | Pointer to reply+52,16-byte output cell |
| Stack+0 / argument8 | Pointer to reply+28, OOL-address output cell |
| Stack+8 / argument9 | Pointer to reply+68, OOL-count output cell |
| Stack+16 / argument10 | Pointer to a4-byte deallocate-flag scratch cell |

The original wrapper stages this64-byte payload at `0x100006204..0x100006224`:

| Payload offset | Width | Staged value |
| --- | --- | --- |
|0 /4 /8 /12|Four u32|Received local name / A / C / B|
|16 /24|Two u64|Inline16 pointer / OOL address|
|32|u32|OOL count|
|36|4 bytes|No semantic field assigned; the listed stores do not initialize it|
|40|u64|Inline16-output pointer|
|48|u64|Initial OOL-address output value, copied from the caller's output cell|
|56 /60|Two u32|Initial OOL-count / deallocate values|

Original call `0x100006398` reaches shared dispatcher `0x10065ffd8`. `(carrier_phase XOR 0x6cf4) XOR carrier_tag` equals operation label `0x8799a4f1`. On return, original instructions consume the returned frame delta, copy payload+48/+56/+60 back to their caller cells at `0x1000063b4..0x1000063c0`, and XOR-decode status with `0x8b3dc651` at `0x1000063e4`. The16-byte input/output semantics and the three word meanings remain unknown.

## Named control endpoint and marker4d consumer [FO2-FO5,FO7]

The [registration report](daemon_registration_report.md) maps `com.apple.fpsd` to header `0x1010c4cd8`+40=`0x1010c4d00`. The frozen private registration publishes CF reference `0x5000000200` through original store `0x100315354`; its CF constructor received private Mach name `0x1003`. These values are separate from the historical trace's name and from the session reference `0x77001000` / private raw name `0x6800`.

Original request1202 instructions load the context pointer from SP+0x448 at `0x100501d28`, then load its CF field+40 at `0x100501d2c`. Call `0x100501d48` requests `CFMachPortGetPort` for that reference. Complete frames check W28 as the received local name. The following all-u32 identity holds modulo2^32:

```text
v = (n XOR 0x80000010) - ((n << 1) AND 0xffffffdf) + p
  = 0x80000010 - n + p

(v == 0x80000010) <=> (n == p)
```

The retained query and independent instruction lift are UNSAT. With control name `0x1003`, the four word-A values0/1/2/3 return original status5 without reading the session pool or OOL bytes. Word2 takes94 additional original visits; no complete application-word classification is established.

With received name `0x6800`, the original path instead requests the once/lock contracts and scans50 slot markers. `0x10052184c` reads slot+876 with stride896. Fresh CPU frames establish the local selector phases:

```text
k = 0x4577df4d
s = ((m - k) OR (k - m)) >> 31     [logical shift, u32]
index = ((1 AND NOT s) * 0x6f) XOR 0x3abc
      = 0x3ad3 if m == k, otherwise 0x3abc
```

| Original table word | Branch |
| --- | --- |
| `0x101057588`, index0x3ad3 | Marker match -> `0x1004a07b4` |
| `0x1010574d0`, index0x3abc | Other marker -> `0x1005bec24` |

The original frozen slot marker4b does not match, so all50 markers are visited and original status5 is returned. In the declared marker4d control, original `0x1004a07d4` reads the selected slot+0 CF reference and call `0x1004a0834` requests its name. The run stops before that CF operation receives any modeled result. No tail field is read or written in this bounded selection interval.

```text
received local name
       |
       +-- equals registered com.apple.fpsd name
       |       -> checked word paths -> original status5
       |
       +-- differs
               -> once / lock -> scan marker == 0x4577df4d
                    |                        |
                 no match                 match control
                    |                        |
                  status5             selected slot+0 CF ref
                                             |
                                      stop before CF name API
```

| Consumer / producer | Established marker relation |
| --- | --- |
| Request1201 | Selects4b; its checked failure passes through4c and ends at49 |
| Request1202 session selector | Selects4d in the freshly checked local predicate |
| Candidate `0x1009b7d24` / `0x1009b7d2c` | Earlier census records marker4d and tail+880 publication in one source block; base/value producers and a successful-operation join remain unknown |

Marker names abbreviate `0x4577dfXX`. This relation supplies a state-consumer lead for the earlier tail publisher. It does not establish that the declared marker control is a source-produced state, that the tail object belongs to that slot, or that request1201 successfully creates it.

## Deallocation and outgoing reply emission [FO1,FO4-FO6,FO8]

| Original location | Data/control effect |
| --- | --- |
| `0x100004848` | Preserves application return status in W19 |
| `0x10000484c..0x100004854` | Loads original received OOL address/count and calls the deallocator |
| `0x100e2ab40`, binding `0x1010b1d38` | Veneer resolves to `libSystem/_mig_deallocate` |
| `0x100004858`, `0x10000485c` | Clears request OOL address+28 and count+40 after the returning deallocator call |
| `0x100004860` | Tests saved application status after deallocation and clearing |
| `0x100004864..0x100004874` | Nonzero application status -> reply+32; NDR at+24; simple36-byte reply remains selected |
| `0x1000048cc`, `0x1000048d4` | Zero-status continuation copies deallocate low byte to reply+36 and count scratch+68 to descriptor size+40 |
| `0x1000048e4`, `0x1000048f4`, `0x1000048fc` | Writes NDR at+44, complex bit/size72 and descriptor count1 |
| `0x100004b90`, `0x100004b9c`, `0x100004ba0` | Family demultiplexer emits initial bits/size, reply destination/local-name fields and reply ID1302 |

The SDK declares `mig_deallocate(vm_address_t,vm_size_t)` as returning void; both parameters are64 bits on this ABI. The original stub loads the received descriptor count through W1, zero-extending its u32 byte size. It does not treat an API return register as a deallocation status. Its local address/count clearing follows both the original status5 paths and the two declared application returns0/8. Structural guard rejections return before this application/deallocation interval and preserve those request fields in the checked cases. Outer message-destruction policy remains unknown here.

| Reply form | Exact emitted fields in the checked cases |
| --- | --- |
| Simple error,36 bytes | Header `(bits=0x12,size=36,remote=0x6400,local=0,reserved=0,id=1302)`; NDR+24; signed32 status+32 |
| Conditional complex success,72 bytes | Header `(bits=0x80000012,size=72,remote=0x6400,local=0,reserved=0,id=1302)`; body count1 at+24; OOL address+28; deallocate+36, virtual-copy1 at+37, padding0 at+38, OOL type1 at+39; size+40; NDR+44; inline16 output+52; repeated count+68 |

The complex reply has no simple-error RetCode field at+32: those bytes lie inside its OOL address. The stub's byte load at `0x100004808` followed by the original word store initializes descriptor padding to0. In the declared success control, the application supplies address `0x7300b000`, count24, deallocate1 and inline bytes80..8f. Those are declared opaque outputs, not an allocated native owner or successful original application result.

The remote/reply name comes from received request+8; the family writes it at reply+8 through `0x100004b9c`, with local name0. There is no port-right descriptor in either reply form; the complex descriptor carries memory. These runs execute no actual Mach send or receive, OOL copyout/unmap, CF operation or IOKit call. The deallocator model records an API request and leaves the private mapping intact; its bytes remaining readable do not establish native reclamation behavior.

## Finite cases and independent validation [FO1-FO8]

| Profile | Original visits | Terminal observation | Pool reads | Input deallocation request |
| --- | ---: | --- | ---: | --- |
| source_word0 |2296|Original status5, simple36|0|Yes|
| source_word1 |2296|Original status5, simple36|0|Yes|
| source_word2 |2390|Original status5, simple36|0|Yes|
| source_word3 |2296|Original status5, simple36|0|Yes|
| source_session_name |4332|Original status5, simple36|50|Yes|
| source_marker4d |2544|Before selected-session CF-name request|2|No, interval unfinished|
| source_moved_session |2296|Original status5, simple36|0|Yes|
| source_no_registration |2133|Before NULL control-CF-name request|0|No, interval unfinished|
| stub_success |100|Declared application0 -> original complex72|0|Yes|
| stub_error |91|Declared application8 -> original simple36|0|Yes|
| guard_simple |37|Original -304, simple36|0|No|
| guard_descriptor_count |40|Original -304, simple36|0|No|
| guard_size |43|Original -304, simple36|0|No|
| guard_descriptor_type |46|Original -300, simple36|0|No|
| guard_repeated_count |50|Original -300, simple36|0|No|

No profile reads the16 OOL body bytes or changes the session pool after its declared entry. The moved-slot control swaps the populated slot to index1; the matched control-endpoint path still does not read that pool. The marker4d control changes only the recorded marker field before entry; its two pool reads are the selected marker and stored CF reference. The two stop boundaries have no completed application reply/status claim.

| Independent audit | Checked extent |
| --- | --- |
| Original source |20990 instruction visits;4583 reads;2642 writes |
| ABI contracts |29 explicit external API contracts and2 declared application-return contracts |
| Complete CPU frames |294, including172 ABI checkpoints; GP31, SP, NZCV and32 Q registers |
| Final inherited mutable RAM |36618240 bytes across15 cases |
| Additional final state |983040 pool bytes,983040 mask bytes and983040 private-mapping bytes |
| Source/fixups |37 fresh IDA spans;170 original format12 rebases;10 bindings |
| Local scalar proofs |Two retained UNSAT queries and two independently instruction-lifted UNSAT queries; name/marker phases checked in full source CPU frames |
| Frozen prefixes |Session payload/receipt/dependencies and registration artifacts pinned; neither earlier prefix is freshly replayed in this increment |

The auditor does not import the new producer. It independently reconstructs the composition, wire, declared entry, CF/deallocator/application contracts, CPU/read/write journals, complete final RAM and exact field joins. The lifter admits only the inspected straight-line W-register instructions; variable shifts use their low five bits. Publication verification pins the successful fresh receipt and exact owned delta; it does not itself replay instructions.

```sh
env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/audit_fpsd1202_ool.py

env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_fpsd1202_ool_publication.py
```

Replay takes O(V+J+H*R+I) time and O(J+H*R+I) space for original visits V, journals J, snapshot count H, mutable bytes R and image I; SMT costs are separate. Wire lengths and byte extents are explicit, with u32 modular arithmetic and u64 API/address widths. Substantial JSON is Zstandard ultra22 archived with exact decompression comparison. Path checks inspect decoded metadata and typed RAM, including the application controls.

## Bounded continuation opportunities [FO2-FO8]

| Impact | Discriminating next evidence |
| --- | --- |
| High | Recover the actual producer of a marker4d session, including `0x1009b7d24`/`0x1009b7d2c`, its tail+880 owner and the original operation that creates it. |
| High | Continue the selected-session name comparison and later request1202 consumers from a source-produced state, establishing any provider, IOKit user-client and deeper-facility call/data joins. |
| High | Recover the matching client request1202 builder and meaningful word/inline/OOL formats. Current source failures do not establish successful processing or the meaning of status5. |
| High | Establish output OOL allocation/ownership and native copyout/deallocation/destruction, including outer cleanup on guard rejection. An emitted address or API request is insufficient. |
| Medium | Recover the control-name branch's full application-word classification and status producer. The checked word2 divergence is a concrete source lead. |
| Medium | Replace the separate registration/session overlays with a freshly checkpointed continuous source path and independently establish actual native endpoint/name lifetimes. |

**QG1** passes: factual source, ABI and bounded state analysis. **QG2** passes: FO1-FO8 list assumptions, dependencies and falsification probes. **QG3** passes for this increment; the full interface goal remains active. **QG4** passes: exact bytes, widths, counts, source arithmetic and SDK compilation are reproducible. **QG5** passes within scope: control CF reference versus raw name, declared marker versus source-produced state, original application return versus controlled stub return, memory descriptor versus port descriptor, and API request versus native effect remain distinct. **QG6** passes: original image/fixups, fresh read-only IDA bytes, primary SDK, independently replayed state/journals, independent source lifting and pinned predecessor provenance support the claims. **QG7** passes: remaining questions have explicit impact labels.
