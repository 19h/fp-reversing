# Auxiliary 104-byte initialization and existing-table admission

The pending daemon `malloc(104)` at `0x10054b43c` feeds an initializer at `0x1007fccd8`. A separately declared nonnull pointer return receives 93 source-defined bytes in 15 writes, with 11 bytes left undefined. Only after those writes does `0x1007fcdfc` store the full pointer at caller base J+`0x1e0`. A NULL return skips the initializer and leaves that caller field unchanged. Both paths test a different existing field, J+`0x100`, and the carried nonzero value enters a table-record decoder. [AS1-AS4; AS-A1-AS-A5]

The decoder reconstructs table base `0x6500115274`. Original execution stops before its first undefined 8-byte table read at `0x1008660f0`; no table byte is supplied. The following source loop specifies swaps over 273 entries of 8 B, but no swap executes in these retained paths. The generated 32 B at J+`0x34` remains unchanged and is neither read nor written by this increment. Native ownership, coherent constructor/caller epochs, later auxiliary-object use and daemon-kext transport remain unknown. [AS2-AS6; AS-A5-AS-A8]

```text
pending malloc(104), original call 0x10054b43c
  + declared pointer64 return and ordinary ABI clobber fixture
  |
  +-- NULL ------> skip initializer, preserve J+0x1e0
  |
  +-- nonnull --> initialize 93 B; leave 11 B undefined
                  -> source store pointer64 at J+0x1e0
                         |
             common test: raw u64[J+0x100] != 0 ?
                +-- false -> STOP before alternate target 0x100867168
                |            (separate zero-word control)
                +-- true --> cached word + eight source-text lookups
                             -> decode private 16 B record
                             -> table base 0x6500115274
                             -> STOP before undefined table[1] read
                                  static suffix: 272 swaps, 273 entries
```

| Evidence | Primary artifact and scope |
| --- | --- |
| AS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_auxiliary_state.py) retains source regions, logical fixups and complete packed execution intervals. |
| AS2 | [Generated-stream report](daemon_generated_stream_report.md), [checks](triage_evidence/daemon_generated_stream_checks.json.zst) and [audit](triage_evidence/daemon_generated_stream_audit.json.zst): two exact pending-allocation states, existing J fields, private byte definitions and distinct completion/adjustment cells, whose roles are established in the later [payload-reactivation report](daemon_payload_reactivation_report.md). |
| AS3 | [Current checks](triage_evidence/daemon_auxiliary_state_checks.json.zst): both parent states crossed with two ABI clobber patterns, NULL/nonnull returns and carried/zero existing-table words; 16 intervals. |
| AS4 | [Independent auditor](triage_evidence/audit_daemon_auxiliary_state.py) and [audit receipts](triage_evidence/daemon_auxiliary_state_audit.json.zst): full GP/Q/flags/byte replay, strict owner joins, complete field comparison, compact decoder comparison and eight nonvacuous obligations. |
| AS5 | [Context-state report](daemon_context_state_publish_report.md) and [context-unseal report](daemon_context_unseal_report.md): prior context/cache lineage and constructor-compatible premises; repeated scalar constants do not establish a common native type. |
| AS6 | [Publication verifier](triage_evidence/verify_daemon_auxiliary_state_publication.py): source/dependency pins, exact case product, rebuilt proof expressions, preserved original inputs, manifest delta and raw/typed/decoded/unpacked path hygiene. |

## Allocation and branch contracts

Entry `0x10054b440` compares the full returned X0 with zero. Under the exact inherited phases W19=`0x8371`, W21=`0x4b15`, W22=`0x4a95`, it computes index `0x4a95 XOR (is_NULL*0x180)`. The source proof covers every pointer64 bit pattern at those phases. The nonnull fixture B=`0x6600005000` introduces an exactly 104 B owner with zero initially defined bytes; the page mapping does not initialize any byte. No native allocation executes. [AS1-AS4; AS-A2-AS-A4]

| Emission site | Condition | Index / original fixup slot | Target / IA modifier |
| --- | --- | --- | --- |
| `0x10054b464` | X0!=0 | `0x4a95` / `0x10105f398` | Initializer `0x1007fccd8` / `0x18f4` |
| Same | X0==0 | `0x4b15` / `0x10105f798` | Common admission `0x10050e008` / `0x18f4` |
| `0x1007fce0c` | After initializer and pointer store | `0x4b15` / `0x10105f798` | Common admission `0x10050e008` / `0x18f4` |
| `0x10050e04c` | Raw u64[J+0x100]!=0 | `0x838b` / `0x10107bb48` | Decoder `0x100865de0` / `0xa1fc` |
| Same | Raw u64[J+0x100]==0 | `0x8371` / `0x10107ba78` | Alternate target `0x100867168` / `0xa1fc` |

Admission first stores the address J+`0x100` in SP+`0xa6e0` and then loads its word at `0x10050e024`. Actual carried bytes are `2e4c2bee000003c5`, u64 `0xc5030000ee2b4c2e`; they are not a raw canonical table pointer. Separate controls replace only these 8 B with zero and stop before the alternate target's first instruction. They establish the raw zero-word branch and supply no alternate-path outputs. The new allocation and this older table field have independent null predicates. [AS1-AS4; AS-A5-AS-A6]

All return joins preserve the inherited SP, X18..X29 and low 64 bits of Q8..Q15. Two explicitly declared caller-register/SIMD/flag patterns are crossed with each parent state and allocation result. These are local return premises, not observations of a native imported call. [AS3-AS4; AS-A3]

## Source-defined auxiliary layout

The initializer does not read B. It writes the following fields and then publishes B at J+`0x1e0`=`0x6500115d00`. Each successful case has exactly 15 byte-effect records totaling 93 B; paired stores account for separate records at the same PC. Each byte is written once. The pointer store follows every initializer write in source order, with no memory-ordering or inter-thread visibility claim. [AS1,AS3-AS4]

| B offset | Width | Exact initialized value | Original writer |
| --- | --- | --- | --- |
| `0x00`, `0x04` | 4 B each | `0x8b3dc651` | `0x1007fcd08` paired store |
| `0x08` | 8 B | `0xe3b88695c0d52dbc` | `0x1007fcd00` |
| `0x10` | 8 B | 0 | Same paired store |
| `0x18` | 4 B | `0x8b3dc651` | `0x1007fcd04` |
| `0x1c` | 4 B | Undefined; no write | None |
| `0x20` | 8 B | 0 | `0x1007fcd0c` |
| `0x28` | 4 B | 0 | `0x1007fcd10` |
| `0x2c` | 4 B | Undefined; no write | None |
| `0x30` | 8 B | `0xe3b88695c0d52dbc` | `0x1007fcd20` |
| `0x38` | 8 B | Same constant | `0x1007fcd14` |
| `0x40` | 8 B | 0 | Same paired store |
| `0x48` | 8 B | `0x7fb71248f0ba4179` | `0x1007fcd94` |
| `0x50` | 8 B | `0x02bdebf673344e2b` | `0x1007fcdf4` |
| `0x58` | 8 B | 0 | Same paired store |
| `0x60` | 4 B | `0x8b3dc651` | `0x1007fcdf8` |
| `0x64` | 1 B | 1 | `0x1007fcd1c` |
| `0x65` | 3 B | Undefined; no write | None |

The accounting is 93+4+4+3=104 B. The initialized extent ends at exclusive B+`0x65`; the allocation ends at exclusive B+`0x68`. None of the 11 gap bytes is promoted from mapped backing memory into a source definition. NULL cases perform no B write and no J+`0x1e0` store; their existing pointer bytes remain unchanged. [AS3-AS4; AS-A4]

The constants `0x8b3dc651` and `0xe3b88695c0d52dbc` occur in other recovered representations, including the parent context. Their presence here establishes scalar defaults. A field-specific status, count, pointer sentinel, canonical C type or cryptographic role is unknown without consumers. In particular, this daemon allocation is separate from the [kernel AES parameter allocation](versioned_aes_parameters_report.md), which also requests 104 B. Matching size does not establish shared layout or transport. [AS1,AS4-AS5]

## Cached-word data flow

The initializer loads the cached index through saved SP+`0x878` -> `0x1010c67d4`, and cached-array base through SP+`0x858` -> `0x1010c8268`. Carried index=255 and base=`0x6500115d6c`. The first source uses the sign-extended index AND `0xfffffffffdae14b8`; the second uses AND `0xffffffff9171abc8`. Both data reads lie in the inherited cache definition, rather than B or J+`0x34`. [AS1-AS5]

| Source load | Cache offset / address | Raw source u64 | B destination |
| --- | --- | --- | --- |
| `0x1007fcd44` | `0xb8` / `0x6500115e24` | `0x54761be04d56e570` | B+`0x48` |
| `0x1007fcda8` | `0xc8` / `0x6500115e34` | `0xeec93239a0018891` | B+`0x50` |

For each word r, let t=(r AND m) XOR c1. The stored value is u64(((r AND `0x7fffffffffffffff`) XOR c2 XOR t)-t). The first mask incorporates the source phase X19=`0x8371`. A source obligation covers arbitrary source words, cached index/base and destination pointer under explicit disjoint, nonwrapping memory-input spans; actual owner/read extents satisfy those premises. [AS1,AS4; AS-A4-AS-A5]

| Output | m | c1 | c2 |
| --- | --- | --- | --- |
| B+`0x48` | `0x1eb684772ee1201f` | `0x9436845702010016` | `0x2bc109a8bdeca409` |
| B+`0x50` | `0x4d6e4499c38fc7bc` | `0x810a0410008a0104` | `0x6c74d9cfd335c6ba` |

These equations establish two cached-word transforms and their destination fields. They do not identify the source words as keys, addresses, handles or port rights. No source read or write overlaps J+`0x34`..J+`0x53`, and its 32 generated bytes are checked unchanged in every case. The current increment therefore adds no consumer of the generated stream. [AS3-AS4]

## Existing-table record and unexecuted swap suffix

At `0x100865de0`, the decoder reloads the same cache roots. It reads u32 `0xb6f0c062` at cache+`0x94`=`0x6500115e00`, XORs `0x41da4f94`, and performs eight source-text u32 lookups. The mask from `0x1010c6800` and text root from `0x1010ca2a8` retain their inherited definitions; the actual lookup addresses and source bytes are recorded individually. The resulting control32 is `0x487b0e7b`. The compact decoder independently reproduces the original scalar/AdvSIMD/byte-operation result for all eight carried-word cases. [AS1-AS4; AS-A5-AS-A7]

The source forms a private 16 B record at `0x680006b798`: zero at offset0, carried encoded64 at offset8. With F=`0x01000193`, p=u32(control32*`0x41da4f94`)=`0x705a541c`, its two affine offsets are u32(p*p XOR p)=`0xcf08370c` and u32((p OR 1)*p XOR p)=`0x5ff6e330`. The record codec combines XOR, two u32 affine inverse steps with inverse multiplier `0x359c449b`, and a reversible 8-byte permutation. Its current modulo-derived byte indices for divisors3,5,6,7 are0,4,4,0. The comparison checks the exact final record word and X12=`0x6500115274`; it does not claim an arbitrary-input theorem for the complete SIMD decoder. [AS1,AS3-AS4]

At the boundary, X11=1, W13=0, W9=`0x4546796b`, X12=table base and X14=table base+8. No bytes in the prospective 273*8=2184 B table span are source-known, and no table read/write has executed. The requested first read is `[0x650011527c,0x6500115284)`, 8 B, at `0x1008660f0`. The broad inherited arena owner permits the address range but supplies no data. The reconstructed base has low three bits4: it is4 B aligned, not8 B aligned. No alignment correction is applied, and a native array type/alignment contract remains unknown. [AS3-AS4; AS-A4-AS-A7]

The following 13 source instructions contain the three-XOR swap and loop control; the loop increments i and compares it with `0x111`=273. Together with the preceding original quotient/subtraction operations, its conditional contract is:

```text
K = u32(low32(decoded_table_base)*0x41da4f94) XOR control32
for i = 1 through 272:
    n = u32((u32(K+i) XOR K)*0x01000193)
    j = n - floor(n/i)*i             # unsigned; 0 <= j < i
    swap_u64(table[i], table[j])     # three XOR operations
```

The source proof retains the exact W-register quotient/subtraction expression, including AArch64's zero-divisor result in its algebraic model; the loop's actual divisor premise is1..272. A separate unsigned-remainder obligation proves j<i under unsigned division semantics. All swapped slot pairs are therefore distinct. Another original-source obligation proves the three-XOR sequence swaps arbitrary 64-bit words at two distinct 8-byte cells. These are static contracts of the suffix; neither its reads nor its writes execute in the current receipts. [AS1,AS4; AS-A7]

Its addressed span would be `[table,table+2184)`=`[0x6500115274,0x6500115afc)`, ending 36 B before J. Each iteration contains four u64 reads (`0x1008660f0`, `0x1008660f4`, `0x100866100`, `0x10086610c`) and three u64 writes (`0x1008660fc`, `0x100866108`, `0x100866114`). The 272 iterations would therefore issue1088 reads and816 writes, totaling8704 read B and6528 write B, if fully admitted. These are source-loop counts, not executed evidence. The interval performs zero such accesses. [AS1,AS3-AS4]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| AS-A1: Pinned source and logical fixups identify this specimen | Every instruction and branch target | Rehash the image, all visited opcodes and all four selected slots; retain authentication modifiers. |
| AS-A2: The two frozen parent states apply | Pending allocation, J/cache/private fields | Exact parent-to-entry GP/Q/SP/NZCV, defined-byte and owner joins; add no main-path data. |
| AS-A3: Declared pointer return and ordinary ABI preservation apply | NULL/nonnull allocation continuations | Cross both parent states with both clobber patterns and both pointer results; native import effects remain unexecuted. |
| AS-A4: New B owner and inherited owners describe local accessible spans | 93 defined B bytes, 11 undefined gaps and table boundary | New B starts with no definitions; check disjoint owner addition, no B reads, all initializer writes and first undefined table read. Native allocation/lifetime remains unknown. |
| AS-A5: Cache roots, index and contents retain inherited definitions | B+0x48/+0x50 transforms and table decoder | Check exact source loads, signed masks, all eight text lookups and arbitrary-word equations with explicit disjoint-memory premises. Native cache writers/epochs remain unknown. |
| AS-A6: Zeroing only J+0x100 defines the separate controls | Raw zero-word admission branch | Verify precisely one 8 B effect and identical remaining state; stop before alternate target without additional bytes. |
| AS-A7: Source arithmetic and modeled scalar/AdvSIMD operations apply | Decoder comparison and conditional table-loop contract | Independent full-state replay; exact source quotient proof, remainder bound and arbitrary-data distinct-slot swap; no unknown table load is executed. |
| AS-A8: The retained source order has no concurrent mutation | Pointer-after-initialization order and preserved generated bytes | Verify every effect and no overlap with the 32 B stream; no native synchronization, visibility or external transport follows. |

## Verification, scope and continuation

The 16-case product is2 parent states *2 ABI patterns *2 pointer returns *2 table-word variants. Eight carried-word paths have224 visits for NULL allocation or302 for nonnull. Eight zero-word controls have28 or106 visits. Total2640 source visits,496 read events,400 write events,40 logical authenticated edges and zero internal calls. The pending import is represented solely by the explicit return/owner event. [AS3-AS4]

Independent replay checks84992 scalar register values,84992 vector register values,2656 flag states,2408 read B and1464 write B. The compact checks cover16 exact return joins, eight pointer publications,744 newly initialized B bytes and88 undefined-gap byte checks. Every case preserves32 generated bytes without access,512 byte comparisons in total. Eight table decodes check64 source-text lookups and eight stopped 8 B requests. Eight nonvacuous obligations cover pointer-null selection, fixed fields, arbitrary cache-word transforms under explicit disjointness, raw pointer publication, table-word selection, original quotient/subtraction, unsigned remainder bounds and arbitrary-data XOR swapping. The initially combined remainder query timed out; the retained set separates source arithmetic from its unsigned range lemma and every retained query passes. [AS3-AS4,AS6]

All u32 calculations wrap modulo2^32; scalar fields and pointer arithmetic are64-bit with modulo2^64 arithmetic; byte permutations use8-bit values. B extent=104 B, defined bytes=93 B, unknown bytes=11 B. The table span is273*8 B=2184 B. These are exact counts and bit-vector extents, not physical measurements. Initializer and record decoding have fixed O(1) cost; the conditional table loop costs O(T) time and O(1) auxiliary storage for T=273 entries. Receipt generation/replay costs O(receipt bytes+source visits+byte effects) time and storage; query complexity is separate, with30 s/query limits. [AS1-AS4]

The parent generator writes completion status through `0x6800070db8`, while its adapter reads the distinct inherited adjustment cell at `0x6800060010`. The later [payload-reactivation report](daemon_payload_reactivation_report.md) traces the temporary adjustment cell's original initialization/restoration and establishes that no alias or status-copy edge is required between these channels. This allocation continuation does not establish a coherent native epoch. J's existing modeled owners and B's declared104 B owner remain separate. No new Mach port name/right, message-emission site, IOKit selector or native daemon-kext exchange is established. [AS2-AS6]

| Impact | Next evidence | Architectural consequence and evidence boundary |
| --- | --- | --- |
| High | Recover the original producer of J+0x100 and all273 table entries | Admit or falsify the exact reconstructed pointer, including low bits4, and table epoch before executing its first read |
| High | Recover consumers of J+0x1e0 and B fields | Establish auxiliary semantics, gap handling and local lifetime |
| High | Join a consumer of generated J+0x34 bytes to a concrete transport buffer | Current initialization does not access those bytes; daemon-kext linkage remains unknown |
| High | Recover an actual native caller epoch | Separate completion/adjustment roles do not establish native caller validity |
| Medium | Continue the original raw-zero table branch from its stopped target | Qualify the table-absent case without borrowing unknown private bytes |
| Medium | Compare repeated field codecs with actual consumers | Reused constants are evidence candidates; shared type identity remains unknown |
| Low | Annotate initializer/admission/decoder navigation blocks | Exact block addresses are established; complete original function boundaries remain unknown |

**QG1** passes: factual source/interface analysis. **QG2** passes: AS-A1-AS-A8 register dependencies and falsification probes. **QG3** passes for the allocation/initializer/table-admission increment; the broader interface investigation remains incomplete. **QG4** passes: widths, extents, exact arithmetic, operation counts and complexity are explicit. **QG5** passes: uninitialized gaps, allocation/table null predicates, static suffix and executed paths remain separate; native caller epoch gaps persist explicitly. **QG6** passes after pinned-source replay, eight retained nonvacuous obligations, preserved-input and publication checks. **QG7** passes: bounded continuation covers table producers, auxiliary consumers, generated-byte transport, status epochs and representation comparison.

Decoded checks SHA-256: `320da14726a35e4c32f34708d03b34479923d8b0fbff7234fe9edd9069ffa2a4`. Decoded audit SHA-256: `8092b66fffa6c6801cb43fbcbb0313a3a96fb8e9149412ca675415c3e1348a3d`.

Follow-up: The [payload-reactivation report](daemon_payload_reactivation_report.md) identifies the original constructor of the 2184 B table payload. Transferring only those bytes under an explicit separate-epoch premise permits four retained paths to unseal the payload, generate a four-byte scalar, update its header, clear 30 slot fields, reseal it and reach a pending malloc(74). It also establishes separate completion-status and adjustment channels. Native ownership, caller pairing and transport remain unknown.
