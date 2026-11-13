# Arena context sealing, global descriptor and lock-creation interfaces

Follow-up: The [context unseal report](daemon_context_unseal_report.md) recovers the matching selected reader at 0x10048192c, the reference-codec relationship and the complete 552-byte inverse in constructor-compatible states. It restores the raw context and lock field before rewriting cell 0x1010c9298. Producer and caller epochs, native ownership and lock validity remain separate.

The arena-lock caller leads to a global descriptor at `G=0x1010C8218`. Its selected successful path creates a lock, allocates960 bytes, initializes twenty48-byte records, then reaches the previously recovered primary/secondary lock-creation pair and workspace-fill call. The arena lock token itself has a representation boundary: a second codec seals552 context bytes and, for the retained seed, moves the token from raw offset+8 to encoded offset+248. These are process-local construction and synchronization interfaces; no additional daemon-level Mach or IOKit call site is reached in the retained paths; imported internals are unexamined.

Thirteen conditional source paths,52 independent A64 replays covering175,372 visits,18 source proof pairs and46 isolated552-byte codec cases pass. Four live IDB raw ranges match640 original bytes; automatic function analysis remains partial. Native allocation/init behavior, the full encoded global-reference codec, consumer reachability and transport use remain unknown. The full investigation remains active.

Primary evidence: [pre-creator snapshot](triage_evidence/daemon_context_lock_snapshot.json), [twelve outcome paths](triage_evidence/daemon_context_lock_profiles.json), [extended success path](triage_evidence/daemon_context_lock_success.json), [source contracts](triage_evidence/daemon_context_lock_contracts.json), [proofs](triage_evidence/daemon_context_lock_proofs.json), [52 A64 replays](triage_evidence/daemon_context_lock_replays.json), [552-byte sealing contracts](triage_evidence/daemon_context_seal_contracts.json), [isolated codec checks](triage_evidence/daemon_context_seal_checks.json), [independent checks](triage_evidence/daemon_context_lock_checks.json), [IDB function information](triage_evidence/daemon_context_lock_live_ida.json), [IDB byte readback](triage_evidence/daemon_context_lock_ida_bytes.json), [preservation](triage_evidence/daemon_context_lock_preservation.json), and [scoped gates](triage_evidence/daemon_context_lock_quality_gates.json).

## Assumption register

| ID | Assumption / dependent result | Stress test or falsification probe |
|---|---|---|
| KL1 | Addresses refer to the retained thin arm64e source, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. All source claims depend on this identity. | Rehash source and compare1182 distinct opcodes, retained spans and fixup fields; compare the bounded IDB raw ranges independently. |
| KL2 | Entry is the sealed prior reference state, case17. Earlier entropy/time/arena fixtures and the stable canary remain conditional. | Snapshot capture independently replays all160048 preceding visits; native state/inputs can select different paths. |
| KL3 | `F=0x640000B520`, arena owner `H=0x6500100000` of90000 bytes, and logical image addresses are private fixtures. | Check all effective addresses and owner extents; vary placements in a future composed path. They are not native addresses. |
| KL4 | malloc returns NULL or a distinct declared token, at successive0x1000-byte spacings from0x6600001000. Allocated extents are200 or960 bytes. | Verify exact allocation arguments, disjoint owners and source bounds. Native allocation/lifetime are unknown. |
| KL5 | Imported calls return under the declared integer/AdvSIMD ABI. Caller-clobbered GPR/SIMD bits and NZCV are arbitrary; X18 platform context is held fixed. | Four physical patterns exercise arbitrary bits; source has no X18/W18 access. Preserve X19-X29, SP and low64 ofV8-V15; reject unknown-dependent source control/arithmetic. |
| KL6 | Every200-byte initializer object is unspecified after pthread_rwlock_init, for either status. | Invalidate all200 source-defined bytes after the modeled call. Verify header clearing before the call and absence of later object-byte reads in these paths. Native writes outside this model remain unknown. |
| KL7 | Initializer return categories are represented by0,12,16,22,FFFFFFFF; malloc NULL is separate. | Compose the frozen all-u32 creator-status proof with new all-u32 caller gates. Finite paths are not exhaustive native execution. |
| KL8 | Logical authenticated calls/returns preserve selected targets and return tokens. Native PAC success is unknown. | Check original opcodes, selected slots/modifiers, logical X30 and frame restoration; native authentication needs a separate runtime observation. |
| KL9 | The helper record is eight-byte-aligned in this path. | Verify actual `R=F+0xAF8`; the frozen callee prekey premise requires alignment. The new second-caller prekey identity itself is unrestricted. |
| KL10 |552-byte codec uses observed index/multiplier constants, selected text and address-derived seed. | Arbitrary-bit source vector/remainder proofs, varied isolated A64 inputs, guards and complete inverse checks. Native runtime text/slide differences remain unknown. |
| KL11 | Raw and encoded context representations have different field locations. | Reconstruct before/after byte arrays and permutation; inverse recovers the raw lock token at+8 from encoded+248 for this seed. Do not carry raw field labels across sealing. |
| KL12 | Saved pool-index annotations are candidate premises for two additional readers. | Verify original rebase/bias and IDB bytes; resolve each incoming state/bank selection before claiming actual consumer reachability or a lock operation. |
| KL13 | An address outside the declared owners stops the failure-path model before the read. | Preserve the actual address and producer chain. Native address validity and native failure behavior are unknown. No fixture pointer is substituted to continue. |
| KL14 | Publication order alone does not establish reader synchronization or completion. | Follow actual readiness predicates, locks and readers across the capacity/pointer/record writes. Native interleavings remain unknown. |
| KL15 | Live IDB data are bounded range evidence. Automatic analysis and semantic labels are incomplete. | Compare all raw640 bytes; treat the three partial-byte macro display rows separately from underlying A64 opcodes. No IDB edits are performed. |
| KL16 | Continuation ends at the retained read/return/allocation/fill boundaries. | Continue from those states and resolve later interfaces; this increment does not complete the broader daemon/kext investigation. |

## Control and ownership sequence

```text
arena lock destination H+0x15B28
  |
  +-- creator0x10043A240: malloc200 / pthread_rwlock_init
  +-- seal arena context552B; encode global reference0x1010C9298
  |
  +-- first result != encoded zero --> common continuation
  |                                  --> stop before out-of-owner read
  |
  +-- first result == encoded zero
        |
        +-- creator -> global lock cell G=0x1010C8218
        +-- nonzero result --> status publication / callback epilogue
        +-- zero result
              |
              +-- G+8 =0
              +-- malloc960 -> G+16, including NULL
              +-- NULL --> status publication / callback epilogue
              +-- nonnull: G+8 =20, initialize20 *48B
                    |
                    +-- creator -> primary0x1010C8240
                    +-- creator -> secondary0x1010C5748
                    +-- state09 path -> workspace preparation
                    +-- stop before0x10030631C ->0x10046FAF8
```

This is a source-selected rejoin with the [earlier lifecycle](daemon_rwlock_lifecycle_report.md) and [initialization frame](daemon_frame_entry_report.md) interfaces. A rejoin does not establish an unconditional cycle, native startup completion, or subsequent IOKit execution [KL2-KL8,KL16]. The extended success journal preserves all3959 visits of the preceding three-allocation path exactly before extending it.

| Creator call | Destination | New allocation on the extended path | Relationship |
|---|---|---|---|
| 0x100492644 | H+0x15B28 | 0x6600001000 /200 bytes | Raw arena-context lock field, subsequently sealed |
| 0x1003AE608 | 0x1010C8218 | 0x6600002000 /200 bytes | Lock member of the new global descriptor |
| 0x1002DAC48 | 0x1010C8240 | 0x6600004000 /200 bytes | Previously recovered primary synchronization cell |
| 0x1002DAD48 | 0x1010C5748 | 0x6600005000 /200 bytes | Previously recovered secondary cell |

The intervening third allocation is the960-byte array at0x6600003000. Pointer publication through each creator destination occurs at `0x1002097DC` only after initializer return0. Later context-codec writes to the arena field are transformations, not additional lock-pointer publications. No free/destroy occurs in the retained creator/construction sequence; previous pointer ownership and native reclamation remain unknown.

## Creator record and result gates

The private creator record has minimum accessed extent20 bytes, separate from the24-byte byte-output record that previously occupied the same stack region:

| Offset from R | Width | Creator-phase meaning |
|---|---:|---|
| +0 |4 bytes| Encoded control |
| +4 |4 bytes| Unread by this contract |
| +8 |8 bytes| Address of output pointer cell |
| +16 |4 bytes| Encoded result output |

With `k=low32(R) XOR 0xDC40790B`, decoded control is `u32(raw_control+k*0x5973A279)=0xAED7`. The helper stores encoded results rather than requiring a C return value to carry status. New source `0x1003AE510..0x1003AE53C` proves the second caller's k identity for all32-bit address values; actual helper composition retains its eight-byte-alignment premise [KL9].

| Outcome | Encoded result | Decoded signed32 after XOR0x8B3DC651 |
|---|---|---:|
| Initializer0 |0x8B3DC651|0|
| malloc NULL or initializer12 |0x74C29D85|-42028|
| Initializer16 |0x74C29D82|-42029|
| Other nonzero initializer |0x74C29D83|-42030|

The [frozen creator proofs](triage_evidence/daemon_rwlock_lifecycle_proofs.json) cover the complete u32 initializer domain. New caller gates test the encoded result word atR+16:

| Gate | Source branch | Failure index / target | Zero-result index / target |
|---|---|---|---|
| Arena lock |0x10049267C|0x55FC ->0x1002F08C0|0x6248 ->0x100320AD0|
| Global lock |0x1003AE63C|0x924A ->0x1002FFBF4|0x9257 ->0x10038EB04|
|960-byte return |0x10038EB94|NULL:0x9285 ->0x1002FFBF4|nonnull:0x92A7 ->0x100393D18|

All-u32/u64 source proofs establish these indices under their source-observed phases. Original fixup words establish the targets. The first gate and second gate inspect memory results, not residual X0. The callback epilogue can retain a last API return in X0; a semantic callback return status is not inferred from it.

## Global descriptor, array and publication timeline

| G-relative offset | Width | Established construction role |
|---|---:|---|
| +0 |8 bytes| Pointer to200-byte pthread rwlock object after successful creation |
| +8 |4 bytes| Configured slot count:0 before allocation,20 on successful array construction |
| +12 |4 bytes| Not assigned a semantic role by these source writes |
| +16 |8 bytes| malloc result for960-byte array, including NULL |

The successful source sequence is exact:

| Order | Source PC | Effect |
|---:|---|---|
|1|0x1002097DC|Publish initialized-lock token through G|
|2|0x10038EB08|Write0 toG+8|
|3|0x10038EB5C|Request malloc(0x3C0), IA modifier0x6AA4, original slot0x10109FF58|
|4|0x10038EB60|Publish returned pointer toG+16 before the NULL test|
|5|0x100393D34|Write20 toG+8|
|6|0x100407464..0x100407470|Initialize every byte of twenty48-byte slots|
|7|0x100407494|Select the paired lock-creation continuation0x1002DAB28|

The initialized record layout is:

| Record offset | Width | Initial value |
|---|---:|---|
| +0,+8,+16 |8 bytes each|0|
| +24 |8 bytes|0xE3B88695C0D52DBC|
| +32 |4 bytes|0x9008B011|
| +36,+40,+44 |4 bytes each|0x0095BDDB|

These are literal fields/sentinels; record purpose, occupancy semantics and native type name remain unknown. `20*48=960` bytes. Four STP instructions per record yield80 source instruction visits and160 memory-store events. Every allocated byte becomes source-defined, independently of initial allocation contents [KL4-KL6].

The source loop uses obfuscated counter `I0=0x7A3A710C`, stride48 and bias `-0x16EAF53240`. Its compact form is `record[j]=buffer+48*j` forj=0..19: `48*(I0+j)-0x16EAF53240=48*j`. The two counter increments sum to1 modulo2^64. Exit index0x1DEC selects0x1002DAB28; continuation index0x1DD7 selects0x100407458. Source proofs cover the fields, addresses, bounds and exit.

The slot count20 is visible before the first slot store. A nonnull buffer pointer and configured count therefore precede complete record initialization. The two candidate readers do not establish the synchronization needed to interpret this publication order natively [KL12,KL14].

## 552-byte context sealing and lock-token location

The arena block at `C=H+0x15B20=0x6500115B20` has an accessed seal extent `0x228=552` bytes, containing69 u64 words. It ends at0x6500115D48,36 bytes before the cached512-byte table at0x6500115D6C. It is a different range from the earlier2184-byte block in the [callback-revisit report](daemon_callback_revisit_report.md).

The source at0x1003C3FB8 reads the cached table's u32 at byte offset200, XORs0xEB36C1CA, then chains eight u32 self-text reads:

```text
t0 = cached_u32_at_offset200 XOR0xEB36C1CA =0x4B37495B
repeat8 times:
    t = u32(t XOR read_u32(A + (t &0x7FFF)))
fold =0xC41C69CD
seed = u32(low32(C)*0xEB36C1CA) XOR fold =0x78396E8D
```

All104 word reads across13 paths match original image bytes. `A=0x100822058` is the previously selected self-text window. The source decodes the full64-bit mask/address globals here; unaligned u32 reads retain the preceding section-margin premise. The native mapped code image remains unknown [KL2,KL10].

The source body `0x1003C41DC..0x1003C4324` reduces to:

```text
for i in0..551:
    m = low8(seed XOR u32((i+seed)*(i-seed)))
    byte[i] = u8((byte[i] XOR m)*0x93)
for i in68 down to1:
    j = u32((u32(seed+i) XOR seed)*0x01000193) % i
    swap_u64(word[i],word[j])
```

The vector body covers544 bytes in34 iterations; the tail covers8 bytes in two four-byte iterations. The word loop performs68 swaps withj<i. The byte multiplier inverse is0x9B modulo256. Reverse the swaps in increasingi order, multiply bytes by0x9B, then XOR the same mask. Both directions take O(n) time and O(1) auxiliary in-place storage; the independent fixture uses O(n) comparison storage.

For the retained seed, the permutation places input word1 at output word31:

```text
raw context C+0x08: allocator's lock pointer
        |
        +-- byte transform, then word permutation
        v
sealed context C+0xF8: encoded lock token
```

The independent checker recomputes this mapping and checks the encoded eight bytes against the raw token's byte transform in all13 contexts. Inverting the complete block recovers the original pointer. The value atC+8 after sealing is another permuted word and is identical across these success/failure cases; it is not the raw lock field in this phase. Encoded+0xF8 is seed-specific, not a fixed native structure offset [KL10,KL11].

The initializer's200-byte object contents remain entirely unspecified after its modeled call. Encoding the pointer stored in the552-byte context does not inspect or establish native lock-object contents. The isolated source fixture varies the unused high64 bits ofQ15; only its ABI-preserved low64 half supplies the tail's four16-bit0x93 multipliers.

## Global reference representation and failure frontiers

The context-reference cell0x1010C9298 was published as rawC at0x1002EF978 in the preceding source journal. During the present continuation, source0x1003C43B4 replaces it with0xE5F6A0000600F0C1. Both retained first-lock outcome branches execute the sealing/reference transformation before their later continuation. The result gate itself is tested earlier at0x100492658..0x10049267C; the control diagram groups the retained outcome states through the common work.

The final publication core `0x1003C439C..0x1003C43B8` has a source-local all-u64 identity. LetA andCfac be the incoming low64 halves ofQ0 andQ13, B the packed word atF+0x630, andDxor the packed word atF+0x628:

```text
lane0 = u32(low32(A) + low32(B)*low32(Cfac))
lane1 = u32(high32(A) + high32(B)*high32(Cfac))
global_reference = Dxor XOR concat_u64(lane1,lane0)
```

The preceding byte-packing/permutation and its full inverse remain to reduce. This theorem does not establish a complete raw-pointer decoder for0x1010C9298.

Five first-lock failure paths continue through source0x10039CB84, which reloads that global word, and0x10039CB88, which writes it toF+0x358. At0x1003868D8, `LDUR X10,[X10,#-0x10]` would read address0xE5F6A0000600F0B1. The model stops before the read because this address has no declared backing/owner. Original A64 replays verify every committed preceding instruction and the pre-read register state. Native address validity, representation prerequisites and native fault behavior are unknown [KL2,KL8,KL13].

At these five frontiers, callback status cell0x1010B6360 still contains0x8B3DC651, its earlier encoded-zero value. Later error publication is not established. On the six completed logical epilogue paths, the cell contains the creator/allocation error category:0x74C29D85,0x74C29D82 or0x74C29D83. The epilogue restores the saved frame, reachesSP=F+0xBE0, and stops before RETAB to the inherited private return token0x22222222220A. No native return target or semantic status inX0 is inferred.

## Candidate descriptor readers and live IDB provenance

Saved `fp_annotate.py` comments propose pool index0x6BB at two sites. Its original slot0x1010A4F38 decodes to0x12B6848B3; adding bias0xFFFFFFFFD5A43965 givesG=0x1010C8218. This validates the rebase/bias arithmetic. The dynamic index selection remains a candidate premise rather than a complete incoming-state proof [KL12].

| Candidate | Exact conditional field use | Unresolved part |
|---|---|---|
|0x100A63754 ->0x100A63764|After pool/bias resolution, loadG+16; combine pointer-is-zero with an incoming flag bit|Incoming pool/bank state, enclosing operation and actual reachability|
|0x10021ED4C ->0x10021ED7C|After pool/bias resolution, loadG+0; copy it into a private record atFP-0xF8 before an indirect call at0x10021EE18|Selected callee/type, incoming record phase and reachability; no lock primitive is identified from this alone|

The live database named `fairplayd`, target6b117c693e3b, reports the candidate blocks at0x10021ECF4..0x10021EE94 and0x100A636EC..0x100A6379C. Its automatic function-analysis enrichment processed only a bounded prefix and left indirect calls unresolved. These block boundaries and existing comments do not establish original source-function ownership.

Four raw160-byte IDB ranges match640 original bytes. The display contains139 rows, including three macro rows whose logical sizes exceed their returned byte strings. The checker validates each returned prefix against original bytes and uses the complete raw ranges for full byte agreement. It does not count those rows as139 independently decoded A64 instructions. No IDB annotation, function-boundary or type edit is performed [KL15].

## ABI and verification scope

The imported calls use arbitrary caller-clobbered X1-X17, all caller-volatile SIMD bits, unspecified high32 of an int return and unspecified NZCV. X19-X29, SP and low64 ofV8-V15 are preserved. These register classes follow the primary [Arm AAPCS64 sections6.1.1-6.1.2](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst); [Apple's platform ABI](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms) reservesX18. The1182 source opcodes in this increment do not accessX18/W18. Integer/AdvSIMD source is modeled here; native library internals and other architectural state are unknown [KL5,KL6,KL8].

A [post-call scratch-stack check](triage_evidence/daemon_context_stack_scratch_checks.json) taints every private byte below each imported call's SP, then clears taint only on source writes. Across13 paths and47 calls, all subsequent reads of surviving lower-stack contents address the explicitly stable eight-byte guard fixture. No other retained read depends on pre-call scratch contents. The guard remains the declared KL2 fixture; native stack/guard placement is unknown.

The13 paths retain38040 arbitrary API-origin bytes. No new source load consumes an undefined byte in these continuations. Initializer outputs invalidate200 bytes per object, while the960-byte slot array becomes entirely source-defined. These are explicit memory-definedness contracts, not assertions about native heap contents.

The independent checker rehashes dependencies, verifies51 original fixups, rechecks all36 SMT files, reconstructs field/publication epochs, confirms52 A64 runs and performs two fresh full continuations covering7424 source visits. It also checks13 retained seal/inverse contracts,33 varied isolated codec cases,104 self-text reads and two fresh isolated codec runs. Four nonempty theorem premises have satisfiable witnesses. The source proofs lift110 original instructions across their bounded blocks.

## Bounded continuation opportunities

| Impact | Next bounded investigation | Expected discrimination |
|---|---|---|
|High|Continue from0x10030631C with the actual updated globals/objects.|Determine whether workspace preparation reuses or rebuilds context and locate the next external interface. A prior sealed entry state is insufficient for this new rejoin.|
|High|Reduce the complete0x1010C9298 reference encoding and find its matching decoder.|Establish raw-reference validity windows and the remaining failure-path prerequisites.|
|High|Resolve both candidate reader pool selections and0x10021EE18.|Connect the new global descriptor to actual locking, record operations, and eventual Mach/IOKit callers.|
|High|Trace48-byte slot consumers and552-byte context consumers into established transport records.|Establish actual data dependencies; record size alone does not identify an IPC structure.|
|Medium|Trace readiness and synchronization across pointer/count/slot publication.|Determine which intermediate descriptor states readers can observe. Native concurrency is unknown.|
|Medium|Follow ownership when primary/secondary cells replace their prior values.|Identify destroy/free/reference-lifetime contracts; source-local absence of cleanup is not native lifetime proof.|
|Medium|Vary arena placement, selected self-text window and allocator tokens in full compositions.|Separate reference-state behavior from address/environment-dependent representation.|
|Low|Refresh broader IDB reader coverage and source-function ownership.|Bound candidate completeness without promoting comments or split chunks to semantic proof.|

## Scoped quality gates

| Gate | Result / evidence |
|---|---|
|QG1|Pass: factual binary/interface analysis.|
|QG2|Pass: KL1-KL16 retain assumptions, dependencies and falsification probes.|
|QG3|Pass for this increment: creator/record gates, descriptor/array ABI, representation changes, outcome boundaries and synchronization rejoin covered; full objective active.|
|QG4|Pass: u8/u32/u64 wrapping, half-open owner extents,200/552/960-byte distinctions,20*48=960,34*16+2*4=552 and69*8=552 explicit.|
|QG5|Pass within scope: raw/encoded fields, source stores/API opacity, record phases, partial publication, logical return token, incomplete readers and macro display bytes distinguished.|
|QG6|Pass within scope: original source/fixups,18 proof pairs,52 A64 paths,46 isolated codec cases, fresh checks and640 live IDB raw bytes; native effects remain unknown.|
|QG7|Pass: impact-labeled continuation table retains the full daemon/kext/deeper interface objective.|

The [preservation check](triage_evidence/daemon_context_lock_preservation.json) verifies3237 preceding artifacts:3231 remain byte-identical and only the five aggregate/status reports plus manifest publisher change. Original supplied inputs and the thin source remain unchanged.
