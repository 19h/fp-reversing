# FPSecureTunnel allocation and local initialization

The original FairPlayIOKit instructions establish a conditional 120 B `site.FPSecureTunnel` allocation request in `_PRnut72j9`, its scratch publication, a six-byte header copy, and the subsequent byte initialization layout. The allocation descriptor and the previously recovered free descriptor are byte-identical at distinct addresses. This establishes matching typed requests; native allocation identity, ownership, entry insertion and daemon transaction correlation remain unknown.

The associated C identifies `_PRnut72j9` at `0xfffffe000a635208` but displays only its initial dispatcher fragment. Original compiler function starts bound the containing function at `0xfffffe000a666930`: 50,634 instruction words, SHA256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`. Its complete semantics are not established. This increment captures 434 instructions in 17 spans and nine terminal transfers; ten source obligations cover 349 distinct instructions. Unproved captured context is not counted as semantic coverage.

## Primary evidence and reproducibility

| Artifact | Provenance / role |
| --- | --- |
| Normalized FairPlayIOKit | SHA256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection | SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; original bytes, function starts, symbols and verified chained-fixup membership |
| Associated C | SHA256 `dfb28b99b293db95a78a5d2dd20f6fcf1a95f1a53245b99a090370e7a3327f08`, line 199131 supplies the obfuscated name; instruction semantics come from bytes |
| [Extraction](triage_evidence/recover_secure_tunnel_allocation.py) / [checks](triage_evidence/secure_tunnel_allocation_checks.json.zst) | Decoded checks SHA256 `447c0147f900d5da40c67b314f3e41c82a34ded9045699e4e7b761b96e0e81fe` |
| [Audit](triage_evidence/audit_secure_tunnel_allocation.py) / [receipt](triage_evidence/secure_tunnel_allocation_audit.json.zst) | Decoded audit SHA256 `58bbb935c0cbb2fb4121f69a43b3887ac5a3d04982922874dcf5728da1111d8c` |
| [Publication verifier](triage_evidence/verify_secure_tunnel_allocation_publication.py) | Fresh extraction/audit, canonical SMT comparison and resolution, decoded path scrub, input preservation and manifest custody |
| [Predecessor reclamation](userclient_hash_table_reclamation_report.md) | Existing entry+16 consumption and conditional typed free; predecessor checks SHA256 `831f3e6b1a7283f2b1b6a87df5a99a1bb627f3552e0c72da0c65d7e88b6757c0` |

No target API executes and no IDB is changed. Existing original/normalized binary evidence suffices for this increment; no new IDA evidence is claimed.

## Binding and emission locations

Let `TABLE=0xfffffe0008472f20`, `POOL=0xfffffe0008471f00`, `C=X2` denote the current scratch-record base, `S=X4` the current source-record base and `P` the opaque allocator return. These are local register roles; their business meaning and complete provenance remain unknown.

| Claim | Original location | Established contract |
| --- | --- | --- |
| ST1 | `0xfffffe000a635490`, `0xfffffe000a6354ac` | Save bank roots to SP+0x930/SP+0x928 from POOL+0xf50/POOL+0xf20, subtracting four from each pointer |
| ST2 | `0xfffffe000a65a540`, `0xfffffe000a65a550`, `0xfffffe000a65a55c` | Load the allocator pointer, load descriptor+4 then subtract four, and issue `BLRAA X9,X17` with X0=descriptor and IA modifier 0xd0c8 |
| ST3 | `0xfffffe000a65a588`, `0xfffffe000a65a5b0` | Store P at C+0x148 before testing P; branch according to the null selector |
| ST4 | `0xfffffe000a65a5c4`, `0xfffffe000a65a600` | Test C+0x6d0 and copy its first six bytes into P when the corresponding local header-copy block is selected |
| ST5 | `0xfffffe000a65a740`, `0xfffffe000a65a750` | Separate default-header block writes u32 value 7 and two zero bytes to its header candidate and to P; complete fallback continuation is unresolved |
| ST6 | `0xfffffe000a65a7d4` through `0xfffffe000a65a974` | Load P from C+0x148; fill bytes +0x08..+0x67, set statuses/flag, publish aliases C+0x6e8 and C+0x48 |
| ST7 | `0xfffffe000a65a978` through `0xfffffe000a65abd0` | Overlay two source byte ranges and a u32 scalar; retain 48 fill bytes and set the final local flag to 1 |
| ST8 | `0xfffffe000c4ba154` through `0xfffffe000c4ba16c` | Exact symbol `_IOMallocTypeImpl`; flags at descriptor+0x28 select W1, then branch to `0xfffffe000bcfeb8c` |

The bank identity is exhaustive: for every byte `x`, `x XOR R[L[x] XOR 0x93] = 0xec`. Actual L/R bytes reside at `0xfffffe000792fdc0` / `0xfffffe00079392f0`. Original root fixups are `0xfffffe0008472e50 -> 0xfffffe000792fdc4` and `0xfffffe0008472e20 -> 0xfffffe00079392f4` before the four-byte adjustments.

| Selector | Index | Original slot | Decoded target |
| --- | --- | --- | --- |
| 0xec+0xe27 | 0xf13 | `0xfffffe000847a7b8` | `0xfffffe000c4ba154`; authenticated original pointer, diversity 0xd0c8 |
| 0xec-0x58 | 0x94 | `0xfffffe00084723a0` | `0xfffffe000847c124`; caller subtracts four to obtain `0xfffffe000847c120` |

Both selectors were independently checked over all 256 byte inputs, followed by 256 replays of the original load/select instructions. An additional nonvacuous symbolic obligation covers every u32 selector input using the explicitly certified finite bank-composition lemma. Matching PAC modifiers alone are not caller evidence.

## Descriptor comparison and deeper allocator interface

| Field | Allocation descriptor | Existing free descriptor |
| --- | --- | --- |
| Address | `0xfffffe000847c120` | `0xfffffe000847bf60` |
| Name-pointer slot (+0x10) | `0xfffffe000847c130` | `0xfffffe000847bf70` |
| Name target | `0xfffffe00079436c0`: `site.FPSecureTunnel` | Same |
| Signature-pointer slot (+0x20) | `0xfffffe000847c140` | `0xfffffe000847bf80` |
| Signature target | `0xfffffe000793bde0`: empty string | Same |
| Flags u32 (+0x28) | 0x6c | 0x6c |
| Size u32 (+0x2c) | 120 B | 120 B |
| Original and normalized 64 B | Equal to the other descriptor | Equal to the other descriptor |

The original name/signature fixups have verified membership in pointer-format-8 chains. Their original words are respectively `0x2000000093f6c0` and `0x60000000937de0`. The allocator slot's original word is `0x8010d0c8054b6154`; the descriptor+4 slot's word is `0x10000001478124`.

The adapter reads flags, tests bit 0x10, sets W1 to 0x8004 if that bit is zero and to 4 otherwise, and tail-branches with X0 preserved. For flags0x6c, bit0x10 is zero, so W1=0x8004. The deeper allocator implementation is outside this increment. Descriptor equality does not establish that a particular later free receives this particular return P.

## Conditional control flow

The following path is conditional on entering the allocation preparation block with W22=0xb80, preserved TABLE/bank roots, valid disjoint storage and ordinary authenticated transfers. The initial reachability of that state is unknown. Preparation computes W20=0x9f3 and W19=0x8c, and clears the cell whose address is saved at SP+0x60. The captured root producer makes that cell C+0x3f8 when its C value is the current C.

| Condition / local token | Index | Target / consequence |
| --- | --- | --- |
| Allocator P!=0 | 0xb80 | `0xfffffe000a65a5b4`, save P in X19 and test the header pointer |
| Allocator P==0 | 0xb97 | `0xfffffe000a65e4bc`; null continuation not analyzed here |
| Header pointer C+0x6d0 !=0 with W20=0x9f3 | 0xa1a | `0xfffffe000a65a5f0`, copy u32 at +0 and bytes +4/+5 |
| Header pointer C+0x6d0 ==0 with W20=0x9f3 | 0x9f3 | `0xfffffe000a65a64c`, separate default-header allocation context |
| Header-copy continuation | 0x8c3 | `0xfffffe000a65a7c8`, initialization block |
| Default-header copy block, W20=0x93 | 0x794 | `0xfffffe000a65ef50`; continuation unresolved |

The captured second call at `0xfffffe000a65a6c8` uses a different selector context. Its target, descriptor, allocation size and complete return-to-initialization path are unknown here. The default-header block's exact six-byte stores are proved independently of that call. A direct fallback-to-initialization edge is not asserted.

```text
conditional allocation state
  -> typed allocation request -> P -> C+0x148
       P!=0 -> existing header!=0 -> six-byte copy -> initialization
       P==0 -> unresolved continuation
       existing header==0 -> separate allocation / fallback continuation

initialization -> C+0x48 and C+0x6e8 contain P
               -> source-byte overlays -> 120 B local layout

entry+16 producer -> later cleanup/free identity: unknown
daemon transaction -> this dispatcher state: unknown
```

## Byte layout and source influence

The first initialization span writes byte0xc7 across +0x08..+0x67, zeros byte+0x68 and writes u32 status0x31ae0066 at +0x6c,+0x70,+0x74. It also writes that status to S+0x270 and publishes P at C+0x6e8 and C+0x48. The following overlay span yields this final local layout:

| Object offsets (inclusive) | Width | Value / source after overlay |
| --- | --- | --- |
| +0x00..+0x03 | 4 B | Existing header's u32, or 7 in the separate default-header block |
| +0x04..+0x05 | 2 B | Existing header's two bytes, or zero in the separate default-header block |
| +0x06..+0x07 | 2 B | Untouched by the recovered header/layout stores |
| +0x08..+0x17 | 16 B | Byte-for-byte S+0x710..S+0x71f |
| +0x18..+0x37 | 32 B | Byte-for-byte S+0x26..S+0x45 |
| +0x38..+0x67 | 48 B | 0xc7 in every byte |
| +0x68 | 1 B | 1 |
| +0x69..+0x6b | 3 B | Untouched by the recovered header/layout stores |
| +0x6c..+0x6f | 4 B | u32 0x31ae0066 |
| +0x70..+0x73 | 4 B | u32 0x31ae0066 |
| +0x74..+0x77 | 4 B | u32 from S+0x2b4, transferred through W10 |

The two byte arrays are copied in reverse instruction order but preserve their byte order in the destination. Their first-byte source pointers are produced at `0xfffffe000a635ef4` (S+0x710 -> SP+0x630) and `0xfffffe000a635c74` (S+0x26 -> SP+0x628). Their correlation to the current S requires the saved roots and source identity to remain stable across the dispatcher. The audit proves the local affine producers and the complete copy mapping separately under that explicit composition premise.

Exactly 115 of the 120 object bytes are written by the header-plus-layout sequence; five retain their prior values. The two layout spans alone contain 210 object-byte store instances at 197 distinct instruction locations because fill bytes and the final scalar/flag are overwritten. No field is named as a cryptographic key, identity or port without further evidence. Caller influence over S, header contents and the copied scalar remains unknown.

## IPC and architectural scope

This increment adds a kext-to-kernel typed-allocation touch point and kext-local record aliases. It establishes no new incoming or outgoing Mach endpoint and no `mach_msg` emission. The new local fields are opaque bytes, u32 scalars and pointers; a numerical value alone does not establish a Mach port name. Existing endpoint and userclient contracts remain in [the Mach-port report](mach_ports_report.md) and [interface ABI report](interface_abi_report.md).

The matching descriptor names narrow the allocation/free investigation, but a same-object join still requires the path from C+0x148/C+0x48/C+0x6e8 into table entry+16, the associated occupied-entry key and a coherent serialization/lifetime epoch. None is supplied by descriptor equality.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| ST-A1: Pinned original/normalized image and actual pointer chains | ST1-ST8 provenance | Fresh byte extraction, whole-container hash, exact symbol and original chained-fixup checks; altered byte/size/target inputs rejected |
| ST-A2: W22=0xb80 at the selected allocation preparation state | Conditional null/header routing | Prove W20/W19 derivation and both null branches; recover incoming dispatcher transitions before claiming native reachability |
| ST-A3: Saved bank roots and TABLE have the recovered values | ST1-ST3 binding | Original affine root stores, 512 bank checks, 256 original-instruction replays, all-u32 symbolic selector obligation; other PAC-equal routines remain distinct |
| ST-A4: Valid, disjoint, nonwrapping storage outside the loaded image | Header, padding and byte layout | Nonvacuous separation/extent premises for object120 B, source/context2048 B, frame4224 B and header6 B; aliasing executions are outside the claim |
| ST-A5: Current scratch/source roots retain their values between selected blocks | Source-range and alias composition | Exact local root producers and full 120-byte obligation; inspect intervening calls/writes and source ownership before extending the composition |
| ST-A6: Ordinary authenticated transfers and opaque allocator results | Request/return interpretation | Original modifier/fixup, explicit null result, preserved descriptor argument; native PAC and actual allocation are unexecuted |
| ST-A7: Local fallback stores do not imply the complete fallback path | ST5 and default header values | Proved six-byte stores and distinct continuation0x794; resolve second allocation and continuation before joining paths |
| ST-A8: Matching typed descriptors do not identify the same object | Allocation/free relation and daemon interaction | Recover entry+16 producers, key insertion, synchronized epochs and correlated daemon/userclient records; present identity remains unknown |

## Bounded continuation

| Impact | Evidence target | Expected contribution |
| --- | --- | --- |
| High | C+0x148/C+0x48/C+0x6e8 to occupied-entry+16 stores | Close the allocation-to-table payload chain and compare with the already proved cleanup free |
| High | Entry-key and UIDList node+4 producers | Establish raw key domain, source influence and insertion/counter invariant |
| High | Dispatcher entry conditions and context/table serialization | Establish reachability and which observations belong to one lifetime epoch |
| Medium | Default-header allocation at `0xfffffe000a65a6c8` and continuation `0xfffffe000a65ef50` | Close the alternate six-byte header route without assuming its allocator type or convergence |
| Medium | Daemon/userclient transaction correlation | Bind this local object construction to existing incoming/outgoing IPC contracts |
| Low | Other FPSecureTunnel descriptors/callers and the five retained bytes | Determine whether additional initialization or consumers assign those bytes a defined role |

## Quality gates

- **QG1**: Technical claims only; no normative judgment is required.
- **QG2**: ST-A1-ST-A8 list dependencies and falsification probes.
- **QG3**: Allocation binding, original emission location, deeper adapter, scratch publication, header alternatives, byte layout, IPC scope and continuation are covered for this increment; the overall investigation remains active.
- **QG4**: Addresses and pointers are u64; selectors/status/scalar are u32; byte extents and inclusive ranges are explicit. All arithmetic is exact and modular; no rounding term applies. Extraction/model construction is O(B+I+256R+query DAG) time/space, excluding SMT search; each query has a 30 s limit.
- **QG5**: Distinct descriptors, matching type versus object identity, initial versus final bytes, five untouched bytes, null continuation, partial fallback path and unproved dispatcher reachability are explicit.
- **QG6**: Fresh original bytes/fixups/symbols, ten nonvacuous UNSAT obligations, 256 original-instruction selector cases, 512 finite bank checks and three extraction-custody rejection controls provide reproducible evidence. Captured context is distinguished from proved source coverage.
- **QG7**: Ranked continuation covers insertion, keys, synchronization, fallback, daemon correlation and retained bytes without claiming those results.

## Conditional tunnel-to-table insertion follow-up

[The insertion report](secure_tunnel_table_insertion_report.md) establishes the conditional tunnel-alias transfer to entry+16, the source-marker XOR key, a status-only lookup gate, the exact occupied-entry record and the subsequent raw-marker writeback to tunnel+0x6c. Fifteen nonvacuous source/storage obligations and eight predecessor obligations pass; 388 selected instructions, 354 intervening def-use instructions and 512 bank inputs are checked. Successful lookup may select a candidate or an existing match because this caller omits the found-byte output. Native reachability, allocation identity, ownership, serialization, UIDList producer correspondence and daemon transaction correlation remain unknown. No new Mach-port emission site is established.

## UIDList search and publication follow-up

[The UIDList publication report](userclient_uidlist_publication_report.md) recovers the separate node+0 discriminator and node+4 tunnel marker, exact search/successor gates, typed 16 B allocation and ordered node-fill/context-head stores. Candidate tunnel+0x6c flows into node+4 under the recorded frame/object premises, joining the insertion and cleanup key codecs conditionally. Seventeen new obligations, six predecessor obligations, 232 selected instructions and 512 bank cases pass. Existing-match resource/status completion, discriminator/input identity, native reachability, ownership, serialization and daemon correlation remain unknown; no new Mach endpoint is established.

## Existing UIDList marker replacement follow-up

[The replacement report](userclient_uidlist_replacement_report.md) establishes the selected nonnull shared-holder path from an existing discriminator match through two old-marker lookup records, prior entry+16 payload capture, tombstone/reclamation requests, conditional 120 B typed payload free and status-gated node+4 replacement. Thirty-four nonvacuous obligations, 18 predecessor obligations, 734 selected instructions and 1792 bank inputs pass. Zero saved payload skips free and reaches the same marker-update join; raw success and found outputs remain separate. Null-holder construction, complete incoming reachability, native ownership/deallocation, serialization and daemon correlation remain unknown. No new Mach-port emission site is established.
