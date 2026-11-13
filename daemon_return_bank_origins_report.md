# Return-bank origins, generation-counter lifecycle and comparison ABI

Current cache-codec increment: The [cache-codec continuation](daemon_return_cache_codec_report.md) preserves this report's unknown-pointer boundary. A separate path adds two initializer-compatible cache-root cells, executes the original pointer loads and byte-generation/readback loop, and stops at an unknown pointer/count predicate. It does not close the initializer-to-caller lifetime join.

The large-frame initializer writes the two bank roots missing from the selected post-IOKit error fixtures. Its strict source paths preserve those cells through distinct argument-read, audit-import and early-return boundaries. A separate caller continuation, explicitly conditional on those two bank values, resolves the later pointer to generation counter `0x1010c8258`, executes one complete 624-word state-update pass and increments the counter before stopping at another unspecified pointer. It also reuses the old root-record storage for two comparison ABIs. The initializer-to-caller control/lifetime join remains unproved; the previously published unknown-bank stop is preserved. [BR1-BR9]

```text
strict initializer 0x10061a2d0
  -> source writes F+0x600 and F+0x5f8
  -> opaque argument record: stop before unknown read
  -> declared RPC502 record: stop before audit import
  -> unsupported operation: restore frame, stop before RETAB

             initializer-to-caller control/lifetime gap

prior post-error caller stop + two additional bank-cell premises
  -> decode generation-counter pointer
  -> reuse root record for equality comparison with zero
  -> one in-place 624-word MT19937 recurrence
  -> reuse record for unsigned comparison: 5119 < counter
  -> publish counter+1 in the retained cases
  -> load unspecified pointer from S+0x878
  -> STOP before LDRSW at 0x100792b28
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BR-A1 | The pinned daemon and retained receipts identify this source build and epochs. All source claims depend on them. | Rehash source/dependencies; compare retained words, bank bytes, pool word and original fixups. Native build/task/provider pairing remains unknown. |
| BR-A2 | Strict upstream execution has valid declared protected record, stack, TLS, controller and cache-helper inputs. Its writable image backing is a private model. Upstream reachability depends on these premises. | Exercise four placements/controller/cursor/backing configurations, fast/walking probes and three record/operation variants. Only listed private fixtures and source writes define bytes; native startup and PID values are not inferred. |
| BR-A3 | The later caller separately receives the two initializer-compatible u64 bank-cell values. Every later caller result depends on this additional contract. | Retain the preceding eight unspecified-pointer boundaries unchanged; record both cells' prior unknown origins and exact added effects. Require an uninterrupted same-frame source path and preservation audit before claiming the missing control/lifetime join. |
| BR-A4 | Inherited private objects, API/output/free-return effects and ABI preservation rules still apply. Conditional caller execution depends on them. | Restore preceding journals; independently replay the selected post-block/result/error-return prefixes; vary physical unknown/clobber backing and reject access to the logically retired 32 B allocation. No native API/free occurs. |
| BR-A5 | The retained 624-word state and counter are source-defined private state in these epochs. Recurrence/counter observations depend on those values. | Verify every first state read, temporal consistency, all 624 ordered writes and the in-place recurrence. Retain per-epoch/mode counters; original-file zero-fill alone does not establish runtime values. |
| BR-A6 | Local source proofs use the explicit readable-cell contracts and modular u32/u64 arithmetic. Universal identities depend on that scope. | Rebuild nine nonvacuous UNSAT queries, including bank read bounds, CLZ zero/high-bit behavior and both signed/unsigned comparison modes. Universal slice results do not prove whole-path reachability for arbitrary native states. |
| BR-A7 | Unspecified private bytes retain their origins. Unknown-frontier and strict-prefix claims depend on this distinction. | Replay two independent physical patterns. Ignore only unused original stack-probe touch values; stop before dereferencing the new unknown pointer. Its upstream origin and external controllability remain unknown. |
| BR-A8 | Current IDA routing metadata is not daemon corroboration. Live-readback limitations depend on the observed tool context. | Preserve the read-only routing receipt. A requested image-hash prefix did not resolve and the default database identified a different image; that failure does not prove the daemon database is closed or absent elsewhere. Original daemon evidence remains the analysis source. |

## Source initializer and remaining continuity gap

The [shared-root report](daemon_shared_roots_report.md) and [builder-owner report](daemon_builder_owner_join_report.md) already retain initializer writer evidence. This increment re-executes the original entry and extends its source paths, rather than assigning bank meaning from matching offsets alone. Let E be initializer entry SP and F=`E-0x10dd0` the large-frame SP. [BR2-BR4,BR7]

| Cell | Original writer | Source-produced u64 | New lifetime coverage |
| --- | --- | --- | --- |
| F+`0x600` | `0x1004c2838`, `STR X2,[SP,#0x600]` | `0x100e99a00` | Exactly one overlapping write; value preserved through each retained upstream boundary. |
| F+`0x5f8` | `0x1004c343c`, `STR X22,[SP,#0x5f8]` | `0x100f4e390` | Same strict lifetime checks. |

The twelve upstream profiles use four inherited environments and three variants. The source tag remains `0x6cf4`. The declared RPC502 variant supplies a separate 120 B private argument record with a readable empty filename, zero scalar/audit fields, disjoint fixed-record destinations and zero local OOL-result fields. It does not construct or deliver a native Mach request. [BR3-BR4,BR7]

| Variant, four environments each | Operation | Boundary and established behavior |
| --- | --- | --- |
| Original opaque downstream record | `0xbc84919b` | Stop before `0x1007fc58c`, the 16 B load from downstream record+8. No value is assigned to those bytes. |
| Separately declared private RPC502 argument record | `0xbc84919b` | Source performs both audit-token copies and stops before `_audit_token_to_au32` at `0x1007fc754`; the import and output PID are unexecuted. |
| Unsupported-operation control | `0x80000000` | Source publishes encoded `0x74c29dee` at protected record+`0x18`, restores entry SP/X19-X29 and stops before original RETAB `0x100528e20`. Native return authentication is unexecuted. |

The unsupported-operation word decodes through XOR `0x8b3dc651` to `0xffff5bbf`. These prefixes do not execute the later IOKit caller. Conversely, the later error fixtures begin in separately declared caller frames S with the two bank cells still unspecified. No initializer bytes are silently grafted into those published states. The new conditional traces record exactly two additional cell effects and preserve this gap as an explicit false completion flag. [BR2-BR4,BR7-BR9]

## Exact bank consumer and mutable counter

Under the additional bank contract, original instructions `0x1004f6508..0x1004f6524` implement the byte map below for arbitrary incoming W8. Both bank-read addresses remain inside their respective 256 B spans. The complete original-source lift proves the result for all u32 inputs, and the receipt separately enumerates all 256 byte inputs. [BR3-BR6]

```text
L = bytes at 0x100e99a00; R = bytes at 0x100f4e390
i = low8(W8)
j = L[i] XOR 0x78
low8(W8 XOR R[j]) = 0xa1
```

| Decoder stage | Exact original value |
| --- | --- |
| Bank result | `0xa1` |
| Pool index | `0xe07+0xa1 = 0xea8` |
| Pool slot | `0x1010a1960 + 8*0xea8 = 0x1010a8ea0` |
| Slot u64 | `0x000000011c106a42` |
| Original source bias | `0xffffffffe4fc1816`, from MOV/MOVK at `0x1004f6530`/`...6534` |
| Decoded address | `u64(slot_word+bias) = 0x1010c8258` |
| Pointer publication | `0x1004f653c` writes S+`0x920` |
| Counter read | `0x1004f6540` loads u32 through that pointer, zero-extending into X14 |

The bias is lifted from original instructions, including their high bits. The selected address lies in writable `__DATA,__common`, a Mach-O zero-fill section; file bytes do not supply its runtime value. The [PRNG report](daemon_prng_output_report.md) independently identifies this generation-counter cell beside the 624-word state at `0x1010c784c` and extraction index at `0x1010c67dc`. The current traces consume their retained source-defined epoch values. [BR1-BR3,BR5-BR7]

The later load from S+`0x8d0` is defined in these caller states; it is not an unresolved frontier. Continuing past it reaches comparison, state processing and counter publication. No arithmetic or pointer value is supplied for the later unknown cell at S+`0x878`. [BR4,BR7]

## Reused record and two comparison contracts

Let Q=`S+0x10cb8`. It is the same address that held the preceding IOKit root record. The new continuation gives it different field meanings in successive source epochs. A single permanent structure type would conflate these contracts. [BR2-BR4,BR7]

| Source epoch / PC | Q-relative effect | Established meaning |
| --- | --- | --- |
| Prior root publication | Q+8, u32 | Encoded IOKit/API error word, consumed by the preceding caller gate. |
| `0x1004f658c` | Q+8, u64 overwrite | Encoded A operand for the next comparison; the earlier error-word storage is reused. |
| Call `0x1004f6610` -> `0x10041a5e0` | Source-built 48 B comparison record | Decoded mode=0, A=counter, B=0; all retained positive counters choose the false result. |
| `0x10041a668` | Q+`0x10`, u32 | Encoded result `0x16f2`; source then consumes it as a table selection. |
| Call `0x10078703c` -> `0x100427514` | Another record at Q, accessed extent 36 B | Decoded mode=0, A=5119, B=counter; all retained counters choose unsigned less-than false. |
| `0x1004275ac` | Q+`0x0c`, u32 | Encoded result `0x179e`; it is separate from both the prior root error and the first comparison result. |

The first leaf's full codec is already established in the [context-transfer report](daemon_context_transfer_report.md). This increment verifies its actual record producer, operands and result after the error-path continuation. The second leaf is captured completely: 40 original instructions / 160 B, no stack frame or nested call, X0 retained, one four-byte write at Q+`0x0c`, and final RET. Its call uses diversity `0x46a2`, also seen elsewhere on free imports; this actual target is an internal comparison leaf. Diversity alone does not identify a callee. [BR3-BR7]

For the second leaf, define the original u64 modular key and its low word:

```text
K(Q) = (((((Q << 1) OR 0x5a2dd95b7f1fcb68) - Q
           + 0xd2e9135240701a4c) XOR 0x2c6f16a258bd37d6)
           * 0xba209ef7) mod 2^64
k = low32(K)
```

| Offset | Width | Source decoding / role |
| --- | --- | --- |
| +`0x00` | u64 | A=`u64(raw+K)` |
| +`0x08` | u32 | mode=`raw XOR k`; bit0 selects signed comparison |
| +`0x0c` | u32 | Output, overwritten by the leaf |
| +`0x10` | u32 | true choice=`raw XOR k` |
| +`0x14` | u32 | false choice=`u32(raw+k)` |
| +`0x18` | u64 | B=`raw XOR K` |
| +`0x20` | u32 | mask=`raw XOR k` |

The exact result is `mask XOR (choose ? true_choice : false_choice)`, where `choose=(mode&1) ? s64(A)<s64(B) : u64(A)<u64(B)`. A nonvacuous source theorem covers arbitrary u64 operands/address and arbitrary u32 mode/mask/choices under the readable-cell contract. The 36 B accessed extent does not establish a larger allocation or public C prototype. Native pointer validity, signing and timing behavior remain outside this proof. [BR3,BR5-BR7]

## State recurrence and counter publication

Every conditional caller case writes exactly 624 consecutive u32 words at `0x1010c784c..0x1010c8208`. The independent audit reconstructs all initial bytes from source reads, checks temporal read/write consistency, and verifies every ordered write against this in-place recurrence. Here M is the evolving array; later iterations may read words already updated earlier in the same pass. [BR4,BR7]

```text
for j = 0..623:
    next = M[(j+1) mod 624]
    y = (M[j] AND 0x80000000) OR (next AND 0x7fffffff)
    M[j] = M[(j+397) mod 624] XOR (y >> 1)
           XOR ((next AND 1) ? 0x9908b0df : 0)
```

This matches the MT19937 state recurrence previously identified in other daemon clones. The observed write sites are `0x1005301bc` for 227 words, `0x1008183d4` for 396 words and `0x10079e698` for the final word. This is finite complete-pass evidence for the retained states, not a universal proof of the entire generator or native entropy quality. [BR4,BR7]

| Epoch | Mode | Counter read at `0x1004f6540` | Counter stored at `0x1004dc344` |
| --- | --- | --- | --- |
| 0 | Prefix | `0x83` | `0x84` |
| 0 | Extended | `0x87` | `0x88` |
| 1 | Prefix | `0x84` | `0x85` |
| 1 | Extended | `0x88` | `0x89` |

Both error controls agree within each parent context. The source also executes CLZ at `0x1007d35f8`; the extractor now supports it, with an all-u32 proof of the leading-zero count including CLZ(0)=32. Independent A64 replay checks its actual effects. No counter-zero, threshold-crossing or reseed path is claimed from these finite cases. [BR3-BR7]

## New frontier and bounded writer census

The last executed instruction is `0x100792b24`, loading eight unspecified bytes from S+`0x878` into X17. Execution stops before `0x100792b28`, `LDRSW X17,[X17]`, without committing any effect of that instruction. The pending pointer retains eight original byte origins; varying its physical backing does not make it a defined source pointer. The following `0x100792b2c` load through X19 is also unexecuted. The upstream writer, pointer validity and external controllability of either dependency remain unknown. [BR3-BR4,BR7]

The original `__text` contains 14,849,960 B / 3,712,490 aligned instruction words, SHA256 `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e`. An exact encoding census finds the following candidate stores; the receipt retains every PC. These are literal-offset candidates across different functions and stack epochs, not 93 established writers of the current two cells. [BR1,BR3-BR4]

| Literal SP offset | STR Wn / WZR sites | STR Xn / XZR sites |
| --- | --- | --- |
| `0x600` | 27 | 19 |
| `0x5f8` | 32 | 15 |

The census excludes pair, unscaled and vector stores, computed or aliased bases, and partial overlaps at other offsets. It does not establish SP equivalence, reaching definitions or absence of another writer. Only the twelve strict upstream paths establish the particular bank values and lifetimes reported here. [BR3-BR4]

## Provenance and reproducible validation

| ID | Primary evidence and role |
| --- | --- |
| BR1 | Original thin daemon, SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original Mach-O bytes, sections and fixups. All PCs are preferred virtual addresses. |
| BR2 | [Preceding error-return report](daemon_iokit_error_return_report.md) and parent logical checks SHA256 `191d641b67e9200cb7f906a0b96f3c89715cfeb1936a910cb4febdbfa9b6cc83`. Its unknown-bank boundary remains unchanged. |
| BR3 | [Source extractor](triage_evidence/recover_daemon_return_bank_origins.py): original instruction lifts, strict initializer execution, bank decoder, exact encoding census and source obligations. |
| BR4 | [Source checks](triage_evidence/daemon_return_bank_origins_checks.json.zst): twelve upstream traces, eight separate conditional caller traces, precise premises, fixups, source regions and dependency hashes. |
| BR5 | Nine freshly rebuilt and persisted source obligations in BR4. The bank theorem exhausts all 256 low-byte partitions while retaining the upper 56 input bits symbolically; every original bad predicate simplifies to false, including read bounds. |
| BR6 | Original bank bytes, pool bytes, bias instructions and complete comparison leaf retained in BR4. No runtime counter value is inferred from file zero-fill. |
| BR7 | [Independent auditor](triage_evidence/audit_daemon_return_bank_origins.py) and [audit receipt](triage_evidence/daemon_return_bank_origins_audit.json.zst): original A64 replay under two backing patterns, actual record decoding, temporal byte checks and separate recurrence oracle. |
| BR8 | [Read-only IDA routing receipt](triage_evidence/daemon_return_bank_origins_IDA_context.json). The default database identifies `appletouch.ko`, metapc; requested daemon image-hash prefix does not resolve. There is no contemporaneous daemon byte readback or database mutation, and no claim about all open mesh databases. |
| BR9 | [Publication verifier](triage_evidence/verify_daemon_return_bank_origins_publication.py): exact owned delta, manifest/input preservation, fresh source checks, receipt pins and raw/typed/decoded-payload path hygiene. |

Eight conditional cases retain 124,064 new source visits, 25,528 reads and 5,192 writes. Twelve upstream cases retain 21,396 visits. The independent replay repeats them under two physical patterns: 248,128 caller visits and 42,792 upstream visits, plus 40,032 separately replayed prefix visits. All 4,992 source state-word updates receive independent recurrence checks; replay additionally checks actual CPU effects twice. Both source comparison-result fields and the first root-result overwrite are verified. Nine source queries are UNSAT under their stated contracts. [BR3-BR7]

The recurrence costs O(N) time and O(N) state for N=624, with 2,496 B of word state. The fixed-width leaf is O(1). The exact text census is O(T) time for T aligned words, with O(number of matches) output. Extraction/replay scale with source visits, restored bytes and recorded effects; each solver query has a 30 s limit. These counts describe offline software observations. No native Mach, IOKit, free, pointer authentication or hardware operation is executed. [BR3-BR7]

## Bounded next investigations

| Impact | Remaining question | Concrete evidence needed |
| --- | --- | --- |
| High | Same-frame initializer-to-IOKit-caller continuity | Uninterrupted original source path with both bank cells' reaching definitions and all overlapping writes; equal offsets alone are insufficient. |
| High | New pointer dependencies | Original producer and lifetime of S+`0x878`, then the following X19 dependency; preserve unknown-byte origins until defined. |
| High | Actual daemon-kext exchange | Matched native build, task, connection/provider, selector, buffers, return status and time ordering; offline counter/state execution does not supply this join. |
| Medium | Counter zero/reset behavior | Source-produced zero/threshold states and complete branch consumers, including other writers to the counter/index/state. |
| Medium | Other bank-store candidates | Frame/SP epoch analysis and exact reaching definitions for the 93 literal-offset sites; broaden to aliased and overlapping writes. |
| Low | Record typing and PAC diversity | Apply epoch-specific record types; classify actual targets and complete leaves independently of diversity values. |

## Scoped quality gates

**QG1** passes: factual source/interface analysis requires no normative content. **QG2** passes: BR-A1..BR-A8 identify assumptions, dependent results and falsification probes. **QG3** passes for this increment's routine roles, data/control flow, interfaces and port-emission accounting; the full investigation remains active. There is no new Mach port or emission site in these intervals.

**QG4** passes: widths, wrapping, 36 B versus 48 B records, 624*4=2,496 B state, instruction/byte counts and complexity are explicit. **QG5** passes within the stated scope: conditional bank effects, storage reuse, source-defined counters and unknown pointers are distinguished; the missing lifetime join and native pairing remain unknown. **QG6** passes with original bytes/fixups, source obligations, retained premises and independent A64/recurrence evidence; current IDA routing provides no daemon byte corroboration. **QG7** passes with the bounded impact-ranked questions above. Publication verification records the exact owned delta and original-input preservation. [BR1-BR9]
