# fairplayd: record extension, container publication and the next byte-bank frontier

The continued conditional constructor reaches the eight-byte parent store at `0x100901498`: J+0x68 receives S+`0x4aba552460e435c6` modulo 2^64. At that point S points to U, and U points to a fully defined 224 B buffer. The source first zeroes S+0x30, fifteen recorded instruction visits before publication. This establishes a local construction and publication path under explicit allocation-return, owner, caller and root premises. The corresponding native initializer epoch, external caller and daemon-kext transaction remain unknown. [RE1-RE6; RE-A1-RE-A6]

The NULL result for the first 97 B request instead retires the incoming 77 B buffer and U, clears S+0 and stops before the S+0x30 initializer and parent publisher. The normal policy supplies five fresh, initially undefined buffers of 97, 125, 145, 185 and 224 B. No new root, descriptor-node or payload bytes are supplied. Later allocation failures are outside this increment. [RE2-RE5; RE-A2-RE-A4]

| Evidence | Primary provenance and scope |
| --- | --- |
| RE1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; RE3 retains original instruction words and authenticated fixup metadata. |
| RE2 | [Descriptor growth](daemon_descriptor_growth_report.md), [descriptor polynomial](daemon_descriptor_polynomial_report.md), [feedback callers](daemon_feedback_callers_report.md) and [container construction](daemon_state_container_construction_report.md): inherited admissions, codecs and owner/caller premises. RE3 pins the growth checks and replay receipts. |
| RE3 | [Extractor](triage_evidence/recover_daemon_record_extension.py), [checks](triage_evidence/daemon_record_extension_checks.json.zst): complete 304-parent cross product, two new ABI patterns, NULL-97 and fresh-only continuation policies. |
| RE4 | [Independent replayer](triage_evidence/replay_daemon_record_extension.py), [receipt](triage_evidence/daemon_record_extension_replay.json.zst): original-source replay, pointer custody, complete admissions, object/copy/publication census and five nonvacuous local source obligations. |
| RE5 | [Publication verifier](triage_evidence/verify_daemon_record_extension_publication.py): current-source receipt binding, fresh original words, representative semantics, five fresh SMT obligations, exact manifest delta, three original-input hashes and decoded path hygiene. Full numeric replay and complete admissions are recorded by RE4 and are not repeated during publication. |
| RE6 | [Child-loop contract](daemon_child_loop_report.md), [ABI report](interface_abi_report.md) and [Mach-port report](mach_ports_report.md): prior tag/status/control and transport boundaries. This increment does not establish a new port or native transaction. |

Decoded receipt SHA-256 values are `9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7` (RE3) and `7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d` (RE4).

## Objects and source interfaces

Addresses and pointer arithmetic are u64 modulo 2^64. Extent fields use u32 modulo 2^32. B denotes bytes. Addresses below identify private analysis fixtures, not native addresses or observed allocator returns. [RE1-RE4; RE-A1-RE-A4]

| Object / field | Fixture address or offset | Width / extent | Established role |
| --- | --- | --- | --- |
| J | `0x6500115b20` | 552 B | Parent context; current publisher changes only J+0x68. |
| S | `0x6600040000` | 64 B | Container; S+0 contains raw U; S+0x30 is zeroed late. |
| U | `0x6600060000` | 48 B | Storage object; U+8 is the raw active-buffer pointer. |
| U+0x10, U+0x14 | U-relative | 4 B each | At each pre-free checkpoint, `u32(raw+0xef133bef)` equals the new allocation extent. |
| Incoming buffer | `0x6600080000` | 77 B | Earlier growth-success owner, retired after copying and source overwrite. |
| Final buffer | `0x66000d0000` | 224 B | Last fresh owner in this policy; all bytes defined by source before parent publication. |
| Saved parent destination | SP+0x6608 | 8 B | Loaded at `0x100901494`; value is J+0x68. All eight bytes lack a writer in the final interval; earlier caller custody remains inherited. |
| New missing root | SP+0x390 | 8 B | Entirely undefined at `0x10084fdcc`; no definition is introduced. |

```text
J+0x68 -- stored value S+K -- subtract K --> S
                                            |
                                         S+0: raw U
                                            |
                                         U+8: raw buffer
                                            |
                                         224 B defined

K = 0x4aba552460e435c6
```

| Source call site | Imported binding | Original authenticated slot | IA diversity | Continued effect premise |
| --- | --- | --- | --- | --- |
| `0x100d640ac` | `libSystem/_malloc` | `0x10109ff58` | `0x6aa4` | First request NULL or fresh; subsequent requests fresh only. |
| `0x100a8e84c` | `libSystem/_free` | `0x10109ff30` | `0x46a2` | Normal-path retirement of the exact old-buffer owner and byte invalidation. |
| `0x1003174d0` | `libSystem/_free` | `0x10109ff30` | `0x46a2` | NULL-97 cleanup retires the incoming 77 B buffer. |
| `0x100336dec` | `libSystem/_free` | `0x10109ff30` | `0x46a2` | NULL-97 cleanup retires U. |

Pointer provenance follows original authenticated slot loads and exact 64-bit register/store/reload transfers. ABI clobbers and overlapping invalidation destroy tags; equal numeric values do not create provenance. These are logical authenticated transfers, without hardware PAC or native imported calls. [RE1-RE5; RE-A1-RE-A4]

## Growth and owner transitions

| Old extent | New request | Fresh fixture pointer | Copied bytes | Undefined new tail at pre-free checkpoint |
| --- | --- | --- | --- | --- |
| 77 B | 97 B | `0x6600090000` | 77 B | 20 B |
| 97 B | 125 B | `0x66000a0000` | 97 B | 28 B |
| 125 B | 145 B | `0x66000b0000` | 125 B | 20 B |
| 145 B | 185 B | `0x66000c0000` | 145 B | 40 B |
| 185 B | 224 B | `0x66000d0000` | 185 B | 39 B |

For each row, the source copy body at `0x100b5c9b4`/`0x100b5c9b8` reads and writes exactly one byte at descending indices old_extent-1 through zero. Each copied byte equals the admitted incoming old-buffer byte. Only after the last copy does the source overwrite every old-buffer byte. U+8 and both encoded extent fields select the new owner before the pending free; the new tail is still undefined at that checkpoint. The declared free return removes the exact old owner and invalidates its bytes. Later source writes define the tail before the next full-buffer copy; all 224 final bytes are defined before publication. Source overwrite is established; an intended confidentiality or erasure guarantee is unknown. [RE1-RE4; RE-A2-RE-A4]

Per normal representative, copied volume is 77+97+125+145+185=629 B. Requested fresh volume is 97+125+145+185+224=776 B across five successive requests. These totals are source/model byte counts, not native peak memory, timing or complete constructor bounds. [RE3-RE4; RE-A2-RE-A4]

```text
pending malloc(97)
  NULL -> free(77) -> free(U) -> S+0 = 0 -> stop 0x10074abc8
  fresh
    -> copy 77; overwrite old 77; retire old owner
    -> malloc 125 -> copy 97; overwrite; retire
    -> malloc 145 -> copy 125; overwrite; retire
    -> malloc 185 -> copy 145; overwrite; retire
    -> malloc 224 -> copy 185; overwrite; retire
    -> define final tail
    -> zero S+0x30
    -> publish encoded S at J+0x68
    -> further writes and nested itgr invocation
    -> stop on undefined SP+0x390 pointer
```

Every new API return uses one of two declared volatile GP/Q/NZCV patterns while preserving that parent's X18-X29 and low 64 bits of Q8-Q15. The errno fixture's four bytes are invalidated at each return. Fresh allocations start entirely undefined, have distinct owners and never alias admitted storage. The 40-event and 65,536 B fresh-extent limits are analytical observation guards; neither is reached and neither is a target bound. Existing 104 B root and 12 B terminal-node premises remain conditional inherited definitions. [RE2-RE4; RE-A2-RE-A4]

## Publication and incomplete continuation

In each normal representative's last interval, source visit 87,169 at `0x1006b2304` stores eight zero bytes at S+0x30. The preceding source constant is `0xb545aadb9f1bca6a`, equal to -K+0x30 modulo 2^64. With X20=S+K, the effective destination is exactly S+0x30. All eight bytes were undefined in the incoming conditional parent; the normal source initializes them before parent publication. NULL-97 does not reach this writer. This distinguishes a conditional model's missing field definition from evidence of a native uninitialized-memory defect. [RE1-RE4; RE-A1-RE-A4]

| Recorded visit in final interval | PC | Source effect |
| --- | --- | --- |
| 87,169 | `0x1006b2304` | `STR XZR,[X8]`: S+0x30 becomes zero. |
| 87,183 | `0x100901494` | `LDR X11,[SP,#0x6608]`: destination `0x6500115b88` = J+0x68. |
| 87,184 | `0x100901498` | `STR X20,[X11]`: bytes `c6 35 e8 60 8a 55 ba 4a`, encoded S=`0x4aba558a60e835c6`. |
| 355,620 | `0x1005015e8` | Nested invocation with raw tag `0x69746772` (`itgr` in big-endian ASCII). |
| Boundary | `0x10084fdcc` | `LDR X1,[SP,#0x390]` requires eight undefined bytes at `0x6800060490`. |

At publication, the snapshot contains 61/64 defined S bytes, 40/48 defined U bytes and 224/224 defined active-buffer bytes. Undefined offsets are S+0x3d through S+0x3f, U+0x1c through U+0x1f and U+0x2c through U+0x2f; their roles are unknown. The preceding raw J+0x68 value is K, which decodes to NULL under this codec. The encoded pointer decodes by u64 subtraction: `0x4aba558a60e835c6-K=0x6600040000`. There are 74 later source store events overlapping that same 224 B buffer before the frontier. The pointer store therefore precedes additional work within the selected path. Completion, cross-thread visibility and synchronization are unknown. [RE3-RE5; RE-A2-RE-A5]

The later `itgr` invocation has raw first word `0x8b3dc650` and raw count word `0x8b3dc645`. Neither the shared postprocessing gate `0x1006d140c` nor its further-work target `0x100705fb8` occurs in this interval. This invocation does not establish completion of the prior clear-mask/itgr route. The literal and count alone do not establish an integrity algorithm or public schema. [RE3-RE4, RE6; RE-A5-RE-A6]

The next static block would derive X1 from SP+0x390 and a low-nibble offset, read a byte through it, and use additional pointer banks SP+0x3a0 and SP+0x398 before a byte store at `0x10084fe0c`. Current X0 is final_buffer+184 B. Execution stops before the first missing pointer load; those subsequent reads and that store are static source shape, not admitted execution. The initializer and lifetime of all three banks remain unknown. [RE1, RE3-RE4; RE-A3-RE-A6]

## Validation, assumptions and bounded continuation

The checked cross product is 304 inherited parents x two new ABI patterns x two first-malloc policies = 1,216 terminal exports, grouped into four admitted classes of 544, 64, 544 and 64 members. The four representatives contain 26 intervals, 2,530,408 original instruction visits, 451,330 reads, 123,934 writes, 108,268 logical edges and 652 internal source calls. RE4 independently replays selected GP/Q/NZCV, memory and control effects and recomputes every member's demands and terminal export. Missing/changed demanded bytes, changed SP and missing owners are rejection controls; a changed unused saved X18 is a preservation control. The local ADC extension also checks 60 integer carry/wrap cases across 32- and 64-bit widths, without changing NZCV; CCMN checks 960 integer condition/fallback/carry/overflow cases across both widths. [RE3-RE5; RE-A1-RE-A4]

Independent comparison checks 80,973,888 GP/SP values, 80,973,888 Q values and 2,530,434 NZCV frames, plus 2,287,010 read bytes and 538,540 write bytes. Original authenticated-pointer custody covers 107,608 transfers. The 52 fresh ABI-recipe checks, eight demanded-byte rejection controls, four changed-SP controls, four missing-owner controls and four saved-X18 preservation controls pass. [RE4-RE5]

Five nonvacuous UNSAT obligations establish the generic byte-copy step, encoded extent update, zero-extended allocation count, encoded-S publication and S+0x30 initializer. Complete prior admission corpora are receipt dependencies rather than rerun here. Extraction/replay complexity is O(visits*frame_state + admissions*demands + proof_DAG) time and O(receipts + parent_maps + largest_interval + proof_DAG) space, excluding solver search; individual queries have a 30 s timeout. Archives use zstd with decoded round-trip verification. [RE3-RE5]

Existing reference data suffice for this increment. The IDA instance-discovery attempt returned a supervisor unavailable error; no database query or mutation followed. No native target API, allocator/free, IPC, hardware authentication or daemon-kext pairing is executed or established. New port names, rights and emission sites are unknown in this private constructor increment; the prior port report remains the transport evidence boundary. [RE3-RE6; RE-A1-RE-A6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RE-A1: Pinned image, original fixups and retained parent receipts apply | Original PCs, imports, codecs and local equations | Rehash artifacts and dependencies; compare original words/fixups; reconstruct source obligations. |
| RE-A2: Earlier conditional admissions and the declared new ABI/allocation policies apply | Four classes, growth sequence, NULL cleanup and J publication | Recompute all 1,216 admissions and terminal exports; alter demanded bytes/SP/owners; test later NULL returns separately. No native epoch follows. |
| RE-A3: Sequential separated byte memory and exact owner retirement apply | Copy order, old-buffer overwrite, field custody and missing-bank frontier | Validate each read/write and owner span; invalidate retired bytes; falsify with aliasing, missing definitions or native lifetime evidence. |
| RE-A4: Logical authenticated-pointer transfers model the selected control flow | Imported bindings, saved continuations and normal/cleanup transitions | Require original pointer-load custody and exact transfers; kill clobbered tags; independently establish native PAC and scheduling if needed. |
| RE-A5: A local pointer publication does not imply constructor completion or concurrent visibility | Post-publication continuation and itgr interpretation | Follow the actual remaining source work and source-bank definitions; require synchronization/consumer evidence for visibility. |
| RE-A6: Private tags and object fields do not identify an external transaction or public schema | Daemon/kext linkage and higher-level record semantics | Join native caller epochs and matched Mach/IOKit buffers to kext consumers; corroborate independent tag consumers and field readers. |

| Impact | Bounded next evidence | Present limitation / falsification target |
| --- | --- | --- |
| High | Recover last-writer and caller-epoch custody for SP+0x390, SP+0x398 and SP+0x3a0 | The first pointer is wholly undefined; no new bank bytes are supplied. |
| High | Join J+0x68 publisher, its native consumer and the earlier initializer epoch | This conditional construction path reaches the publisher; a native transaction identity is unknown. |
| High | Correlate daemon Mach/IOKit request/reply buffers with kext entry and completion | No new port, right transfer, emission site or paired transaction is established. |
| Medium | Exercise NULL at 125, 145, 185 and 224 B requests and alternate storage modes | Only the first new failure and a fresh-only success policy are covered. |
| Medium | Follow the current itgr invocation through byte-bank admission and postprocessing | The shared gate and further-work target have no current execution witness. |

**QG1**: factual data/control-flow and ABI analysis. **QG2**: RE-A1-RE-A6 specify dependencies and falsification probes. **QG3**: the allocation/publication increment is covered; the full interface investigation remains active. **QG4**: byte units, widths, modular arithmetic, counts and algorithmic bounds are explicit. **QG5**: NULL cleanup, late initialization, local publication, later writes and incomplete itgr processing are distinguished. **QG6**: source hashes, pinned receipts, independent replay and fresh publication checks establish provenance. **QG7**: impact-labeled adjacent interfaces and unknowns are enumerated.

## Record-bank follow-up

The [record-bank increment](daemon_record_banks_report.md) resolves nominal source producers for the three missing bank fields and proves the local descending masked-byte copy. It leaves all twenty-four field bytes undefined in the 608 retained normal exports and reports conditional output predictions without new target intervals or native epoch claims.

## Record-input provenance follow-up

The [record-input provenance increment](daemon_record_input_origin_report.md) traces K+0xc4b0 back through the formatter at 0x100aaa324 to five-word serialization and a separate middle-sixteen-byte transform. Twenty actual formatter stores survive to the retained stop in both normal classes. The current missing banks and any later native execution remain unresolved.

## Complete state-format follow-up

[The state-format report](daemon_state_splice_report.md) composes the five encoded words, serializer, recovered AES wrapper and twenty-byte formatter. Decode each word with XOR 0xf4f92df7, serialize big-endian, encrypt decoded bytes 2..17 under the recovered AES-128 key, preserve both two-byte edges, then XOR all 20 bytes with 0x98. Four source queries, fresh epoch/custody checks and 196 complete format controls qualify this conditional 160-bit permutation. Upstream message identity, native admission, the later undefined bank fields and daemon-kext pairing remain open.
