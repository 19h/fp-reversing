# Daemon post-seed cleanup, full twist and first encoded output byte

The completed warm initializer reaches conditional internal arena cleanup, releases its gate, transforms all 624 state words, selects and tempers word 0, then writes one encoded byte into the caller's private output workspace. This is the first source-established output use on the current payload-dependent route. Cleanup requires one additional 8 B neighbor-header premise from the previously used constructor snapshot; strict controls stop before that missing read. Native caller/constructor epoch identity, output-buffer ownership and daemon-kext transport pairing remain unknown. [PO1-PO6; PO-A1-PO-A10]

```text
completed initializer -> reacquired gate
  -> readiness==1 AND runtime flag!=0
  -> saved payload!=NULL -> encoded extent passes signed test
  -> overwrite P[63..10]; reverse 88 B reservation accounting
  -> missing neighbor header: strict execution stops
     +8 B source-defined constructor-snapshot premise
       -> restore marker; overwrite 86 B near arena head
       -> gate=0x5d96
       -> twist 227+396+1 words
       -> reset index; select G[0]; publish index/counter
       -> temper selected word
       -> address/cache/text-dependent byte store at output+31
       -> stop before 0x100bf6d40
          later output bytes / transport identity: unknown
```

| Evidence | Primary artifact and boundary |
| --- | --- |
| PO1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_postseed_output.py) retains source regions, fixups, complete packed intervals and the exhaustive runtime-pointer bank decoder. |
| PO2 | [Second mixing pass](daemon_second_mix_report.md) and its [checks](triage_evidence/daemon_second_mix_checks.json.zst): two complete entry boundaries before `0x100a3881c`, including source-known state/key/payload, private phase fields and gate. |
| PO3 | [Current checks](triage_evidence/daemon_postseed_output_checks.json.zst): 26 executed intervals and two separate zero-instruction missing-field controls; exactly one extra 8 B field per conditional continuation, zero new imported returns. |
| PO4 | [Independent auditor](triage_evidence/audit_daemon_postseed_output.py) and [audit receipts](triage_evidence/daemon_postseed_output_audit.json.zst): full source/state replay, compact complete-twist and byte-encoder models, eleven nonvacuous original-source obligations. |
| PO5 | [Arena split](daemon_arena_split_report.md), [constructor snapshot](triage_evidence/daemon_context_lock_snapshot.json.zst) and [constructor success](triage_evidence/daemon_context_lock_success.json.zst): source-defined neighbor bytes and 4418 subsequent constructor visits without overlapping writes; separate caller epoch remains explicit. |
| PO6 | [Publication verifier](triage_evidence/verify_daemon_postseed_output_publication.py): source/dependency pins, packed-payload hygiene, exact manifest delta, preserved inputs, fresh proof-DAG comparison and retained query rechecks. |

## Readiness, runtime control and cleanup admission

Entry is `0x100a3881c`, with incoming phase W10=`0xcbb6`. Source reads readiness byte `0x1010c5798` at `0x100a38830` and runtime flag u32 `0x1010b6cb8` at `0x100a388a4`. Both are inherited caller definitions: readiness=1 and flag=1. The runtime flag's native writer remains unknown. The decoder combines two u32 control words at `0x1010c4f48` and `0x1010c4670`, then uses two source byte banks. Exhaustive evaluation of all 256 low-byte inputs gives a constant XOR output `0x14`; therefore pool index=`0x565+0x14`=`0x579`, slot=`0x1010a4528`. Its decoded scalar `0x1088e003f` minus `0x07829387` gives the runtime flag pointer. This establishes pointer selection independently of the actual control-word values. [PO1-PO4; PO-A1-PO-A3]

Under the inherited phase, source `CCMP`/`CSET` selects cleanup exactly when readiness==1 and runtime flag!=0. All other readiness8/flag32 combinations select gate release. These are source partitions; only the admitted concrete route is resumed here. Saved P=`0x650011521c` is loaded from SP+`0x190`; the next block tests it for NULL. The extent block reads P-16 and tests signed64(encoded_extent+`0x2178739ec47edc16`) > -1. Actual encoded extent is M-88, M=`0x5e878c613b8123ea`, and the sum is `0x7fffffffffffffa8`, so cleanup proceeds. W0=`0x54` is an opaque phase/control value here; it is not established as an allocation extent. [PO1-PO4]

| Source transfer | Condition under established phase | Index | Fixup slot | Target | IA modifier |
| --- | --- | --- | --- | --- | --- |
| `0x100a388d0` | readiness==1 AND flag!=0 | `0xcbc1` | `0x10109fcf8` | `0x100c21ab8` | `0xa0a7` |
| `0x100a388d0` | Other readiness/flag inputs | `0xcbb6` | `0x10109fca0` | `0x100bde5d8` | `0xa0a7` |
| `0x100c21aec` | P!=0 | `0x5ae9` | `0x101067638` | `0x100abb0c0` | `0x50e9` |
| `0x100c21aec` | P==0 | `0x5aeb` | `0x101067648` | `0x100bde5d8` | `0x50e9` |
| `0x100abb11c` | signed adjusted extent >=0 | `0x75f8` | `0x101074eb0` | `0x100cb2ef0` | `0xd437` |
| `0x100abb11c` | signed adjusted extent <0 | `0x24f4` | `0x10104c690` | `0x100bde5d8` | `0xd437` |

## Exact internal cleanup effects and snapshot boundary

The strict cleanup prefix executes 1048 instructions and ends before `0x100a77ef8 LDR X11,[X11]`, demanding 8 B at `0x6500115264`=old marker+8. Both original strict paths and the two restored controls leave this read unexecuted. Completed generator state remains unchanged throughout cleanup. [PO2-PO4]

| Operation | Source store | Exact effect per case |
| --- | --- | --- |
| Descending payload overwrite | `0x1009f2984` | 54 one-byte writes, P+63 down through P+10; first 10 payload bytes unchanged |
| Reservation-accounting reversal | `0x100c19b9c` | u64 at `0x1010b5f18`: subtract 88 modulo2^64; bytes `cf8301081f07a41a` -> `778301081f07a41a` |
| Arena-head extent restoration | `0x100a6ee4c` | H+8, H=`0x6500100000`: add 88; M+86532 -> M+86620 |
| Additional neighbor premise | Before `0x100a77ef8` | 8 B at old marker+8: `3e1b813b618c875e`=M-2220 |
| Old marker restoration | `0x100c0cec8` | u64 at `0x650011525c`: M -> M+86620 |
| Descending arena-head overwrite | `0x100b7c0d0` | 86 one-byte writes, H+`0x179` down through H+`0x124` |
| Gate release | `0x100bde608` | u32 at `0x1010b5de0`: `0xa94ef` -> `0x5d96` |

For the first overwrite loop, source counter n decrements before the store and x increments afterward. The stored byte is low8((low32(x) XOR a XOR b)*u32(low32(x)+17)), where a=W15 and b=W10 are the current source operands. Actual destination indices are 63..10. The second loop uses low8((low32(x) XOR `0xba`)*u32(low32(x)+17)), with the same decrement-before-store/increment-after-store order. Their source equations are proved for arbitrary operands; full replay establishes concrete counters, phases, values and footprints. These are patterned overwrites of distinct spans, not complete payload clearing. No native free API executes. [PO1,PO3-PO4; PO-A4-PO-A6]

The extra field has eight defined bytes in the same constructor snapshot used for the earlier metadata subset. Every one of 4418 later constructor-source instructions is byte-checked, and no later constructor write overlaps that field. The current cleanup prefix also has no definition there: its byte map is explicitly missing all eight bytes. Supplying only that field permits 1820 further source instructions to the release block. This establishes a conditional metadata-compatible path; it does not establish a continuous native constructor-to-caller epoch or valid ownership. Header/accounting restoration is a local internal bookkeeping contract. [PO3-PO5; PO-A4]

## Full 624-word twist and extraction

The released gate precedes the actual state consumer. Source `0x100bde620` selects index`0x1782`, slot`0x101045b00`, target`0x100a6cd1c`, IA`0x504c`. That block loads G[0], sets byte offset 0 and points X1 at the inherited source-known two-word table `[0,0x9908b0df]` at `0x680005ff68`. G=`0x1010c784c` contains624 little-endian u32 words, exactly2496 B. [PO1-PO4; PO-A2,PO-A7]

For each update, with all words modulo2^32:

```text
y = (G[i] & 0x80000000) | (G[(i+1)%624] & 0x7fffffff)
G[i] = G[(i+397)%624] XOR (y >> 1)
       XOR ((y & 1) ? 0x9908b0df : 0)
```

Updates run in place. Thus the second phase uses already updated far words G[0..395]; the last update uses already updated G[0] and G[396]. The original source masks the next word with`0x7ffffffe` before the right shift and separately uses its parity for the table read, which is equivalent to the equation above. Complete phase-boundary arrays and every written word agree with the compact model. [PO1,PO3-PO4]

| Phase | Destinations | Update store | Table read | Exit index / slot / target | IA modifier |
| --- | --- | --- | --- | --- | --- |
| First | i=0..226,227 words | `0x100a5e93c` | `0x100a5e930` | `0x56c9` / `0x101065538` / `0x100a8d294` | `0x996d` |
| Second | i=227..622,396 words | `0x100b312a4` | `0x100b31298` | `0xaa52` / `0x10108f180` / `0x100a2f5e4` | `0x1d4a` |
| Last | i=623,1 word | `0x100a2f634` | `0x100a2f628` | index>623: `0x6d1a` / `0x1010707c0` / `0x100b2296c` | `0x1a9f` |
| Last, alternative | Same word; alternate index control | Same | Same | index<=623: `0x6d0e` / `0x101070760` / `0x100a3c074` | `0x1a9f` |

Actual private extraction index SP+`0x1ec` is624. Source`0x100b22974` resets it to0. Selection loads G[0] at`0x100a3c080`, stores private index1 at`0x100a3c07c` and global index1 at`0x100a3c088` to`0x1010c67dc`. The distinct generation counter `0x1010c8258` is read at`0x100a3c090`; it is inherited0 in both cases. [PO1-PO4]

The source builds a40 B private comparison record at`0x680005ff70` and calls`0x100427514` from`0x100a3c13c`, IA`0x46a2`. Independent record decoding gives unsigned5119 < counter0, false. The leaf result selects index`0x16a1`, slot`0x1010453f8`, target`0x100b7c410`, IA`0x4868`. This counter block loads saved index`0x6058`, slot`0x10106a1b0`, target`0x100a7ccac`, IA`0xa835`; source`0x100a7ccb4` publishes counter1. The true comparison path and general counter lifecycle are outside this concrete continuation. [PO1,PO3-PO4]

Source tempering under the inherited phase is:

```text
t = raw XOR (raw >> 11)
t = t XOR ((t << 7) & 0x9d2c5680)
t = t XOR ((t << 15) & 0xefc60000)
word = t XOR (t >> 18)
```

The equation is proved for every raw u32 word. Source `0x100a7cd18` selects byte encoder`0x100a0c988`, index`0x26d1`, slot`0x10104d578`, IA`0xf9f2`. [PO1,PO3-PO4]

| Parent case | Selected raw G[0] | Tempered word | Complete twisted-array SHA-256 | First encoded byte |
| --- | --- | --- | --- | --- |
| 0 | `0x1a101e27` | `0xb43d632b` | `61ae3df854b76ca03a54fdf199bcbc85296ae49e252428a2a6c45e962f749a45` | `0x73` |
| 1 | `0x6d64a612` | `0x5d2f5fcd` | `3c5748c167ff874a8092d2842984a7d590f890bf7f60986789d98b88001f91a6` | `0x95` |

## Address-dependent output encoding and zero-byte retry

The output base saved at SP+`0xa0` is`0x680006c590`. Remaining count32 and shift0 select destination a=output+31=`0x680006c5af`. None of its32 output bytes was defined before this interval. The encoder reads a cached u32 at`0x6500115e34`=`0xa0018891`; two global cells decode a text base`0x100822058` and mask`0xfff0c01200007fff`. All cache pointers, words and globals are inherited definitions, not new fixture bytes. Their native initialization/ownership remains unproved. [PO2-PO4; PO-A2,PO-A8]

Under current phase`0xbc66`, the source byte transform is:

```text
a       = output + remaining - 1
r       = u32(cached_word + low32(a))
textA   = byte[text_base + (u32(r + 0x0ba3ccc8) & mask64)]
textB   = byte[text_base + (u32(r + 0x0ba3ccca) & mask64)]
candidate8 = low8((word >> (shift & 31)) XOR u32(31*low32(a)) XOR textA XOR textB)
stored8 = candidate8 XOR 0xd7
byte[a] = stored8
remaining = u32(remaining - (stored8 != 0))
shift = u32(shift + 8)
```

The address dependence uses low32(a), not merely the output index. Actual r=`0xa0084e40`; source text loads at`0x100a0ca30` and`0x100a0ca54` read`0x06` from`0x100823b60` and`0xb8` from`0x100823b62`. The only output write is`0x100a0ca74`. Candidate bytes`0xa4`/`0x42` encode to`0x73`/`0x95`, so both paths decrement32->31 and advance shift0->8. The counter does not advance for stored zero, leaving that destination for a subsequent attempt. General stream completion/termination is not established by this first-byte result. [PO1,PO3-PO4]

Source`0x100a0caa0` transfers to`0x100bf6d40`, index`0xbc66`, slot`0x101098220`, IA`0xf601`. Execution stops before its first instruction. Exactly one of the32 output bytes is source-defined;31 remain unknown. This is a private generated-byte encoder, distinct from the older512 B arena-XOR consumer in the [separate PRNG-output report](daemon_prng_output_report.md). Similar state equations do not identify their output buffers, streams or native callers. [PO1-PO4; PO-A9]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| PO-A1: Pinned source/fixups identify this specimen | Block semantics and targets | Rehash image, all visited opcodes, source bank bytes and used fixups; logical authentication does not execute hardware PAC. |
| PO-A2: Two frozen parent boundaries apply | Caller phase/state/key/cache/output pointer | Exact GP/Q/SP/NZCV/known-byte/owner joins; preserve inherited API/controller premises and native epoch uncertainty. |
| PO-A3: Readiness and runtime flag retain their inherited definitions | Actual cleanup admission | All-readiness8/flag32 original-source partition, exhaustive256-input pointer decode; native flag writer remains unknown. |
| PO-A4: One extra snapshot neighbor field applies conditionally | Marker restoration and downstream route | Verify known mask,4418 later constructor instructions/no overlap, exact8 B join; two no-field controls stop before the read. |
| PO-A5: Internal metadata arithmetic describes this local arena | Reservation reversal and marker effects | Verify exact ledger/header writes and initial/final values; native lifetime or free semantics remain unknown. |
| PO-A6: Scalar/vector lift implements original instructions | Independent execution/effects | Compare every scalar/vector/flag state, known read byte, write byte and authenticated source transfer; prove both overwrite equations. |
| PO-A7: In-place twist phases/table match their inherited definitions | Complete624-word transformation | Compare all1248 updates across two cases and complete phase arrays; prove arbitrary-word equations/table addresses for all three phases. |
| PO-A8: Cache/text/global definitions apply to this caller | Actual encoded byte | Verify exact cached word, original text bytes, decoded mask/base, address arithmetic and single output write; native cache writer/ownership remains open. |
| PO-A9: Current private output has no established transport identity | Cross-layer interpretation | Retain exact output address/known mask and stop; require later def-use joins to Mach/IOKit buffers. |
| PO-A10: Sequential state has no concurrent external mutation | Observed gate and counter effects | Preserve source order and exact pointers; native synchronization, competing writers and publication guarantees remain unknown. |

## Verification and bounded continuation

There are28 intervals,31424 original instruction visits,5750 reads,1852 writes,1572 logical edges and two internal calls. Per case,13 executed intervals contain15712 visits; one separate missing-field control contains zero. Independent replay checks1006464 scalar register values,1006464 vector register values,31452 flag states,30614 read bytes,7706 write bytes and1570 authenticated source edges. The model checks1248 twist updates,3744 complete phase-boundary words,7488 unchanged cleanup-state words,108 payload overwrite bytes and172 arena-head overwrite bytes. Parity choices total628 odd and620 even. [PO3-PO4]

Eleven nonvacuous original-source UNSAT obligations cover readiness/flag partition, NULL pointer partition, signed extent partition, each overwrite equation/counter step, each of three twist equations/table addresses, extraction-index reset partition, tempering and stored-zero counter/transfer behavior. Source-byte equations use fixed-width bit vectors; branch/loop execution and concrete memory extents are separately established by complete replay. Bank decoding is exhaustive over256 byte inputs. Publication reconstructs proof DAGs modulo commutative operand order and reruns retained queries. [PO1,PO4,PO6]

Word arithmetic is modulo2^32, pointer/header arithmetic is64-bit, table/state words are4 B, and all extents/counts are exact. No dimensional physical quantity is inferred. Twist time is O(N), N=624, with O(N) state and O(1) loop counters. Cleanup takes O(54+86) writes per case. Receipt extraction/replay costs scale with decoded receipts, source visits and byte effects; JSON decoding retains the collection and largest interval. Each solver query is limited to30 s. No native API/IPC, allocation/free, concurrent target execution, hardware PAC or IDB mutation executes. [PO1-PO6]

| Impact | Next evidence | Architectural purpose and boundary |
| --- | --- | --- |
| High | Continue before`0x100bf6d40` | Establish retry/word-refill control, all32 output bytes and eventual destination consumption |
| High | Join output pointer into concrete Mach/IOKit argument/buffer definitions | Convert local state-to-byte flow into a transport contract, if source supports it |
| High | Establish constructor/controller/cache writer epochs | Separate compatible metadata from native caller/ownership continuity |
| Medium | Extend generation-counter threshold branches | Current5119<0 comparison is false; rollover and full generator lifecycle remain open |
| Medium | Census gate/state/cache competing writers | Sequential release-before-twist does not establish native exclusion or visibility |
| Low | Add navigation labels for cleanup/twist/temper/byte-encode blocks | Preserve exact source addresses and unknown whole-function boundaries |

No new incoming/outgoing Mach port, right disposition, emission site, UserClient selector or native daemon-kext exchange is established. Existing [Mach-port](mach_ports_report.md) and [ABI](interface_abi_report.md) reports retain the transport mappings. This increment supplies a complete local initialization-to-first-output dependency and a concrete subsequent consumer boundary. The full interface goal remains active. [PO1-PO6]

**QG1** passes: factual source/interface analysis. **QG2** passes: PO-A1-PO-A10 register dependencies and probes. **QG3** passes for this cleanup/twist/first-byte increment; the broader interface goal is incomplete. **QG4** passes: exact bit widths, modulo arithmetic, extents, counts and complexity. **QG5** passes: strict and snapshot paths, two overwrite spans, private output and native transport remain distinct. **QG6** passes after pinned source, full independent replay, source equations, preserved inputs and publication verification. **QG7** passes: bounded continuation addresses output completion, transport def-use, epochs, counter thresholds and competing writers.

Decoded checks SHA-256:`6466a4b4d732b9f65d45e419d8516a25a951390db5017a29a352e512281cea6b`. Decoded audit SHA-256:`a0b681b43750070af2f4d76bd4c16739de3b216461eebca5db5f55749a404fde`.
