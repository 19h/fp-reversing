# Daemon clock fields, entropy record and first state-mixing demand

The source following `gettimeofday` at `0x100b4db4c` reads the output fields without checking the integer return. It packs a 16 B private record as `[third random word, microseconds, low32(seconds), second random word]`. The two later random calls occur at `0x100b4dba8` and `0x100b4dbf8`. Under separately declared outputs and returns, the source completes the record, updates generator-state word1 and traverses two decoded comparison records. Every retained defined-output control then reaches a pending u32 read at address `0x4`. That read is not executed. These are conditional source facts; native reachability, clock outcomes, object validity and daemon-kext linkage remain unknown. [CR1-CR5]

```text
pending gettimeofday(out,NULL)
  + declared return, no output definition
  -> STOP before first undefined seconds read

  + separate sec64/usec32 definitions; padding remains undefined
  -> record+4 = usec32; record+8 = low32(sec64)
  -> pending second arc4random -> record+12 = random2
  -> pending third arc4random  -> record+0  = random3
  -> one original state-word mixing update
  -> unsigned 623 < 2: false -> unsigned 1 > 3: false
  -> source-saved zero pointer + index1 * 4
  -> STOP before LDR W15,[X10], X10=0x4
```

| Evidence | Primary artifact and scope |
| --- | --- |
| CR1 | Original thin-image SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_clock_record.py) retains source regions, visited opcodes, complete states, memory effects, fixups and parent pointer provenance. |
| CR2 | Frozen [context-state checks](triage_evidence/daemon_context_state_publish_checks.json.zst), decoded SHA-256 `a0c631dcec58e837f66de9a1222f9789d8058b98d89b79c685393a5fcbbfa74e`; all eight entropy boundaries are continued without a new caller/root or image-state substitution. |
| CR3 | [New checks](triage_evidence/daemon_clock_record_checks.json.zst): forty clock controls and sixty-four paired-random controls; explicit output fields, imported returns, complete GP/Q/NZCV states and strict read cuts. |
| CR4 | [Independent auditor](triage_evidence/audit_daemon_clock_record.py) and [audit receipts](triage_evidence/daemon_clock_record_audit.json.zst): scalar/AdvSIMD replay, byte/state joins, eight nonvacuous UNSAT obligations, decoded comparison inputs and compile-only current arm64e SDK evidence. |
| CR5 | [Publication verifier](triage_evidence/verify_daemon_clock_record_publication.py): pinned source and dependencies, original-input preservation, exact manifest delta, compression and raw/typed/decoded path hygiene. |
| CR6 | Earlier [seed-material report](daemon_seed_material_report.md) and [generator-output report](daemon_prng_output_report.md): separate material representation and complete shared comparison-leaf contracts; their caller contexts are not transferred here. |

## Clock and private-record interfaces

Let T be SP at the pending clock call, Q=T+0x220 and out=Q+0x10. The retained component has T=`0x680005fce0`, Q=`0x680005ff00` and out=`0x680005ff10`. These are source-model placements, not native addresses. Current arm64e compile-only evidence establishes a 16 B `struct timeval`, alignment8 B, seconds at offset0 with width8 B and microseconds at offset8 with width4 B. The final4 B are padding. No padding byte is supplied, read or written in this increment. [CR2-CR4]

| Source | Read or write | Established operation |
| --- | --- | --- |
| `0x100b4db50` | Read out+0, 8 B | Load seconds word immediately after the clock call |
| `0x100b4db54` | Read out+8, 4 B | Load microseconds word |
| `0x100b4db58` | Write Q+4 and Q+8, 4 B each | Store microseconds, then low32 seconds |
| `0x100b4dba8` | Pending `arc4random`, IA `0x2692` | Zero-argument API, second random return in this seed lineage |
| `0x100b4dbac` | Write Q+12, 4 B | Store low32 random2; unspecified upper X0 bits are discarded |
| `0x100b4dbf8` | Pending `arc4random`, IA `0x2692` | Zero-argument API, third random return in this lineage |
| `0x100b4dc00` | Write Q+0, 4 B | Store low32 random3 |

The 22-instruction route from the clock return to random2 uses the two field loads and two record writes above. It does not test X0/W0. Eight status-only pairs keep the supplied fields equal and vary the declared low32 status between0 and `0xffffffff`; visited opcodes, source reads/writes and logical edges remain identical. This establishes local return-value independence over these complete routes, while the first three instructions also have an arbitrary-field/status source proof. It does not establish any failure-output guarantee for a native clock implementation. [CR3-CR4]

| Clock control, repeated for each of eight parent boundaries | Declared low32 status | Separate fields `(seconds, microseconds)` | Result |
| --- | --- | --- | --- |
| Failure without output | `0xffffffff` | Both undefined | Stop before the first8 B seconds read; zero source visits |
| Zero time | 0 | `(0,0)` | Reach random2 |
| Seconds above u32 | 0 | `(4294967297,999999)` | Store seconds low32=1 |
| Negative seconds | 0 | `(-1,123456)` | Store seconds low32=`0xffffffff` |
| Nonzero-status defined-field control | `0xffffffff` | `(0,0)` | Same source route/effects as zero-time control |

The final row supplies status and fields as independent sensitivity premises. It is not a native failure observation. All supplied microseconds values lie in `[0,1000000)`; `1 us = 10^-6 s`. Seconds fields retain their64-bit input representation until the original32-bit store. No seconds-to-microseconds conversion occurs here. Undefined clock output remains undefined regardless of the physical backing pattern. [CR3-CR4]

Each of the32 defined-field controls is continued with random2/random3 pairs `(0,0xffffffff)` and `(0x89abcdef,0x76543210)`, giving64 child controls. The final Q record is checked byte for byte as four little-endian u32 values:

```text
Q+0x00 random3
Q+0x04 microseconds
Q+0x08 low32(seconds)
Q+0x0c random2
```

This field order matches the earlier seed-material path, whose corresponding words were XOR-encoded by `0x5cf7672b` and whose clock/random calls use different source sites. The current record is raw. Shared order, state base and comparison leaves provide a concrete structural correspondence; complete routine equivalence, shared native epoch and downstream wire use remain unknown. [CR3-CR4,CR6]

## First state update and comparison-driven control

The generator state base remains G=`0x1010c784c`, with624 u32 words already seeded in the parent report. Source `0x1009c46dc..0x1009c4710` performs one first-pass mixing step before the read cut. For the retained i=1,j=0:

```text
G[1] = u32((old_G[1] XOR
            u32((old_G[0] XOR (old_G[0] >> 30)) * 1664525))
           + random3)
i = 2
```

The exact store is `0x1009c470c -> 0x1010c7850`, width4 B. It is the only image-state write in the child continuation. All64 concrete results match the independent equation, and an arbitrary-u32 source obligation proves the equation and index increment. The inherited624-word initialization and this one step do not establish a completed mixed state on this caller route. [CR2-CR4]

Both internal calls reuse a private40-byte region R=FP-0x90=T+0x290. The first complete leaf reads36 B and writes R+0xc; the second reads a40 B accessed extent and writes R+0. Their field meanings differ across record epochs. The previous contents are not one simultaneous ABI structure. Native C object size and IPC serialization are unknown. [CR3-CR4,CR6]

| Call site -> leaf | Decoded inputs | Selected result and continuation |
| --- | --- | --- |
| `0x1009c4808 -> 0x100427514`, IA `0x46a2` | mode0, unsigned A=623, B=2 | Predicate false; result index `0x17ba`, slot `0x101045cc0`, target `0x100a894b0` |
| `0x100b6bb74 -> 0x100444d6c`, IA `0xa499` | mode1, unsigned A=1, B=3 | Predicate false; result index `0x1752`, slot `0x101045980`, target `0x100a075e0` |

The independent audit reconstructs each record at its actual call visit, applies the earlier leaf's address-key and field decoding, checks the source result store and verifies the original continuation fixup. It checks128 caller/leaf contracts. These helpers return control-selection words through memory rather than an established OS status or Mach port. Complete opcode replay also checks their scratch registers, flags and effects. [CR3-CR4,CR6]

## Computed read and zero-pointer provenance

The parent source executes `0x100b73fa0 MOV X16,#0`, then `0x100a8c054 STR X16,[SP,#0x190]`. Four parent success paths each retain that exact store, with no intervening X16/W16 writer. The saved pointer cell remains zero across the entropy seed, clock and later random returns. No new zero value is substituted in this increment. [CR2-CR4]

At `0x100a075e4`, source computes `4*low32(X27)` as a64-bit offset; X27=1 on the retained route. It loads the saved zero pointer at `0x100a075e8` and adds the offset at `0x100a075ec`. The demand at `0x100a0769c` is `LDR W15,[X10]` with X10=4, a pending access to `[0x4,0x8)`. No declared owner or original-image span covers that range. All64 defined-output children stop before this instruction; no read, synthetic mapping or replacement pointer is supplied. [CR1-CR4]

The arithmetic formula is proved for arbitrary saved u64 base and arbitrary u64 index:

```text
address = u64(base + 4 * zero_extend_u32(low32(index)))
```

This determines the read demand under the retained component state. Its native reachability, intended pointer role, alternate admission paths and native outcome remain unknown. Remaining evidence concerns the zero-pointer setup and path admission. The earlier seed-material caller has a separately established nonzero arena-interior pointer; transferring it here would break current source provenance. [CR2-CR4,CR6]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| CR-A1: Pinned thin source and logical fixups identify the specimen | Every operation and target | Check source SHA-256, each visited opcode and used original fixup; hardware PAC remains unexecuted. |
| CR-A2: Eight frozen entropy boundaries apply | Clock/random continuation and pointer demand | Exact parent state, GP/Q/SP/NZCV, memory and owner joins; prior constructor/caller epoch premises remain inherited. Native admission is unknown. |
| CR-A3: Imported returns and ABI preservation apply | Continuations after each pending call | Check all return-register joins, X18-X29, low64 Q8-Q15 and SP; carry both parent clobber fixtures and unspecified upper return bits. |
| CR-A4: Only explicitly supplied clock fields become defined | Field consumers and failure boundary | Write8 B seconds and4 B microseconds separately; preserve4 B unknown padding; the no-output control stops before the first load. |
| CR-A5: Clock fields/status and later random words are separate input controls | Packing and sensitivity | Retain five clock profiles, status-only pairs and two random pairs; add arbitrary-field/word source proofs. No native outcome or distribution is inferred. |
| CR-A6: Scalar/AdvSIMD replay and address-key decoding match original semantics | Control contracts and data equations | Independently check full GP/Q/NZCV and byte effects, each comparison record and original continuation target; unsupported behavior fails closed. |
| CR-A7: The source zero-pointer cell remains the same memory epoch | Computed address4 | Check four zero-producer/store chains, absent intervening X16 writes and unchanged saved bytes through all64 children. Do not replace the saved zero. |
| CR-A8: Current arm64e SDK is a layout/prototype comparison | Clock/random API interpretation | Compile only and pin header hashes; historical SDK/runtime identity and library side effects remain unknown. |
| CR-A9: Strict undefined-output and computed-read cuts bound the increment | Remaining caller, context and transport behavior | Preserve both actual frontiers; successful unlock/reseal, native clock outcome, filesystem use and daemon-kext delivery remain unknown. |

The forty clock controls are five profiles for each of eight parent entropy boundaries. Those parents cover four successful second-allocation controls under two declared initial random returns; they do not represent all constructor profiles or native callers. The sixty-four random children are32 defined-field parents times two paired return controls. Status, seconds, microseconds, entropy, pointer provenance and the earlier constructor-compatible metadata remain separately labeled premises. [CR2-CR4]

## Verification and bounded continuation

Receipts retain168 intervals,19,392 original instruction visits,3872 read events,1280 write events,512 logical edges and128 internal call records. Independent replay checks625,920 GP/SP values,625,920 full Q-register values,19,560 NZCV states,21,056 read bytes and6144 written bytes. It checks384 authenticated-branch origins/modifiers,40 clock-return joins,128 random-return joins,128 comparison contracts and64 full16-byte compositions. Eight undefined-output controls execute zero source instructions after the return. [CR3-CR5]

Eight nonvacuous UNSAT obligations establish arbitrary-field time packing, preservation of full X0 by the first field consumers, low32-only random2 storage, low32-only random3 storage and index reset, unconditional X16 zeroing, full-u64 saved-zero storage, the arbitrary-base/index address equation, and the arbitrary-word first state-mixing step. Parent zero-pointer liveness is independently checked over the retained source instructions. Complete native routine semantics and whole-state mixing on this caller path remain unknown. [CR4-CR5]

Extraction and replay use O(parent receipt bytes + cases*(visits+effects)) time and storage, excluding solver work. The new record construction, first update and complete comparison leaves each use O(1) source time and auxiliary state; the retained generator array occupies624*4=2496 B. Each solver query has a30 s limit. Address arithmetic is modulo2^64, word arithmetic modulo2^32; byte extents and event counts are exact under the stated premises. No native target API, IPC operation, allocation/free, hardware PAC or IDB mutation executes. [CR1-CR5]

| Impact | Next evidence | Purpose and present boundary |
| --- | --- | --- |
| High | Recover all admissions and alternate definitions of the saved SP+0x190 pointer | Explain why this retained path saves zero and later demands address4; native admission is unknown. |
| High | Correlate the current raw material path with the earlier encoded material caller | Recover shared algorithm and distinct optional-input/owner contracts without transferring an incompatible arena pointer. |
| High | Follow successful context release/reseal and actual material consumers | Establish context lifetime and any source dependency reaching filesystem, Mach or IOKit interfaces. |
| Medium | Extend time-output guarantees with specimen-matched implementation or observations | Current compile-only ABI checks and conditional failure controls do not establish native failure writes or errno effects. |
| Medium | Recover other state-word writers and reader synchronization | The single new mixing store and shared2496 B region do not prove native exclusion, epoch coherence or final generator state. |
| Low | Associate recovered selectors and data with existing port/method maps | This increment establishes no new Mach name, right transfer, send/receive or daemon-kext transaction. |

**QG1** passes: factual source and ABI analysis. **QG2** passes: CR-A1-CR-A9 give dependencies and falsification probes. **QG3** passes for this increment: clock fields/status, random-word packing, first mixing update, comparison callers and strict pointer demand are covered; the full goal remains active. **QG4** passes: widths, units, modulo arithmetic, extents, counts and complexity are explicit. **QG5** passes: source versus native, raw versus encoded material, memory epochs, undefined bytes and unexecuted demand remain distinct. **QG6** passes after source, independent replay, comparison, solver, SDK, receipt and publication checks. **QG7** passes: the impact-ranked continuation bounds the unresolved architectural and native interfaces.

Decoded checks SHA-256: `0636a892fbba8b6ab2bd3637b7f6049aa5127ae68b5a32d7081b3786b34e97dd`. Decoded audit SHA-256: `b5b5c334300d8dc73a262435b5ebdc3821bd5520085320818a3a80630e08e264`.
