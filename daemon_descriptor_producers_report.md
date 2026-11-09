# Mode471C record, cursor adapter and stack-probe ABI

Caller `0x10039C894` produces a 24-byte accessed record with decoded mode `0x471C`, a pointer at+8 and an auxiliary word at+20. It calls adapter `0x100ABCA64`, which constructs a cursor and calls entry `0x100A59BB4`. The original NULL-pointer path completes and writes raw result `0x74C29D88` at record+16. The non-NULL path reads eight opaque bytes, computes a compact word view, and reaches the known rwlock creator for destination cell `0x1010C67C0`, then its `malloc(200)` import. This destination is distinct from descriptor G=`0x1010C8218`.

These are continuous source paths from a declared caller entry; there are no fixture PC transitions. Entry `0x100A59BB4` was found as the compiler interval enclosing the earlier reader B, but **none of these paths reaches reader B at `0x100A636EC`**. Its native incoming phase and frame/bank producers remain unknown. The full daemon/kext/deeper-interface investigation remains active.

The installed cache resolves the daemon's `___chkstk_darwin` import through libcompiler_rt to libsystem_pthread's `____chkstk_darwin`. Its original 108-byte implementation supplies the special ABI needed here: it preserves X0/X1 and SP, saves/restores X10/X11 in 16 bytes below SP, and may change X9 and NZCV. This replaces the previous special-preservation unknown with source- and replay-backed evidence for this cache version, conditional on normal return and valid memory.

Evidence: [original source/cache capture](triage_evidence/daemon_descriptor_producers_source.json), [48 continuous prefixes](triage_evidence/daemon_descriptor_producers_profiles.json), [four arbitrary-byte continuations](triage_evidence/daemon_descriptor_producers_copies.json), [contracts](triage_evidence/daemon_descriptor_producers_contracts.json), [23 proof pairs](triage_evidence/daemon_descriptor_producers_proofs.json), [64 independent A64 replays](triage_evidence/daemon_descriptor_producers_replays.json), [independent checks and 32 helper cases](triage_evidence/daemon_descriptor_producers_checks.json), [entry IDB bytes](triage_evidence/daemon_descriptor_producers_live_ida.json), [caller/body IDB bytes](triage_evidence/daemon_descriptor_producers_more_ida.json), [IDB incoming references](triage_evidence/daemon_descriptor_producers_xrefs_ida.json), [preservation](triage_evidence/daemon_descriptor_producers_preservation.json), and [scoped quality gates](triage_evidence/daemon_descriptor_producers_quality_gates.json). Prior context is in the [descriptor-reader report](daemon_descriptor_readers_report.md), [rwlock lifecycle report](daemon_rwlock_lifecycle_report.md), and [callback adapter report](daemon_callback_revisit_report.md).

## Assumption register

| ID | Assumption and dependent conclusions | Stress test or falsification probe |
|---|---|---|
| DP1 | Daemon addresses identify thin arm64e SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. | Rehash source; compare 11 spans, 62 original fixups, every replayed opcode and six bounded IDB windows. Identical VAs in another image do not establish identity. |
| DP2 | Execution begins at selected caller `0x10039C894` with declared bank/table/controller context, a private stack and an upstream pointer/counter cell. Native reachability of that entry is unknown. | Check all effective addresses, records and continuous edges; vary two placements, three u64 counter seeds, two controller pairs and NULL/non-NULL pointer. |
| DP3 | Caller SP/FP geometry and a 1,048,576-byte private owner are fixtures. Native stack ownership is unknown. | Verify all stack reads/writes and actual nested SP values; no fixture PC transition connects clips or changes a selected phase. |
| DP4 | Installed-cache implementation is applicable to this composition. Native loader/version compatibility with the retained daemon is unknown. | Verify cache/dylib UUIDs, original reexport terminals and original helper bytes; rehash three consumed cache files. This is not an audit of every cache file. |
| DP5 | Authenticated calls/branches/returns are logical target/return-token operations. Native PAC success is unknown. | Compare original authenticated slots, modifiers, target registers, return sites and frame restoration. |
| DP6 | TPIDRRO_EL0 and its two readable u64 words at-48/-40 are private environmental fixtures; stack-probe addresses are mapped. | Exercise fast/walk paths, 32 additional size/pattern cases and exact touch addresses. Native thread-field names, page faults and guard handling are unknown. |
| DP7 | Writable image state starts from original file bytes, logical fixups and declared overrides; file-unbacked image pages are explicit zero fixtures. Native evolved global state is unknown. | Retain all initial overrides and source writes; vary controller pairs. Source self-modification, concurrency and other native publishers are outside this fixture. |
| DP8 | The non-NULL pointer has an eight-byte private owner whose initial contents are unspecified. | Preserve all eight byte identities, validate the exact word transform, and replay zero/FF/address-dependent backing patterns. The nearby malloc(8) literal producer is a provenance candidate, not a proved continuous allocation-to-use path. |
| DP9 | Undefined stack and payload bytes remain arbitrary, including through copies and arithmetic. They are not replaced by zero or fabricated source definitions. | Retain 36 origins per continuation, exact symbolic expressions and zero SSA substitutions; stop before unknown-dependent addresses/control or imported allocation. Native prior initialization remains unknown. |
| DP10 | Input mode/auxiliary values are source-produced `0x471C`/`0x2BE18A5D` under the caller record key. The new creator record is eight-byte aligned. | Full-width source proofs establish the caller fields, entry decode and selected gates; verify actual alignment and a nonempty creator-prekey premise. No minimum weaker alignment is claimed. |
| DP11 | Imported addresses are private logical tokens with original import-table and pointer addends. | Independently decode all consumed words, including `_kCFAllocatorDefault` addend `0x6AE8388F`; compare source reads after relocation and debiasing. Imported object contents and native resolutions are unknown. |
| DP12 | Raw result is established independently of an error-name interpretation. Applying the previously recovered XOR convention is a separate mathematical interpretation. | Verify the source store at+16. XOR with `0x8B3DC651` yields signed32 -42023; a symbolic error name and this caller's eventual native interpretation are unknown. |
| DP13 | The NULL cursor completion relies on the selected path and normal stack-probe/callee return. | Prove u64 cursor cancellation and low16 delta identity; replay the full NULL epilogue and caller SP adjustment for 24 cases. Native faults remain outside the result. |
| DP14 | Literal call/store censuses are bounded syntactic evidence, not complete caller or writer graphs. | Reproduce exact aligned patterns; retain four discriminator-colliding slots for each call modifier. Computed modifiers, other registers, paired/unscaled stores, aliases and SP changes remain outside the census. |
| DP15 | Sparse LC_FUNCTION_STARTS intervals do not establish semantic ownership or native incoming phases. | Follow actual selected edges, which cross physical compiler intervals. Retain reader B's reachability as unknown even though an enclosing entry now has a concrete caller. |
| DP16 | IDB analysis is partial; macro display rows can omit underlying bytes. | Compare 1,024 raw bytes and 211 displayed rows separately; identify seven partial-byte macro rows. No IDB modification occurs. |
| DP17 | Inspected boundary instructions differ from executed instructions. | Count 1,169 distinct retired daemon opcodes and one additional unretired allocator-call opcode; do not add the terminal call to source visits or executed imported calls. |
| DP18 | The new lock request rejoins the previously verified creator contract; native allocation, initialization, publication and lifetime remain unknown. | Verify decoded control AED7, destination `0x1010C67C0`, source-selected creator and allocator arguments. Continue outcome-specific creator/caller effects without conflating this cell with G. |

## Continuous control and memory contracts

```text
declared entry at0x10039C894
  |
  +-- source record: mode471C / pointer / auxiliary2BE18A5D
  |
  +--0x10039C92C -> adapter0x100ABCA64
        +-- generate counter / reserve16..256 bytes
        +-- local cursor = incoming counter -160
        +--0x100ABCC98 -> entry0x100A59BB4
              +--0x100A59BE4 -> original installed-cache stack probe
              +-- cursor +=160 / decode record
              |
              +-- pointer NULL
              |     +-- write result0x74C29D88 at record+16
              |     +-- return through both source epilogues
              |     +-- wrapper delta0 / caller SP adjustment0
              |
              +-- pointer non-NULL
                    +-- preserve undefined local copies
                    +-- read and transform eight opaque bytes
                    +--0x1009729D0 -> creator0x10043A240
                          +-- destination cell0x1010C67C0
                          +-- stop before imported malloc(200)

earlier reader B0x100A636EC: not reached; incoming phase remains unknown
```

| Interface / object | Established extent or width | Source evidence |
|---|---:|---|
| Main input record R=caller_FP-0x100 | At least 24 bytes | Caller stores and entry reads/result store below. This is an accessed extent, not `sizeof`. |
| Pointer carried at record+8 | u64 | NULL branch or eight-byte input owner; semantic object type unknown. |
| Opaque input behind that pointer | 8 bytes read | Byte0..byte7 at `0x1009D01AC..0x1009D0288`. |
| Upstream counter/cursor cell | u64 | Caller copies its value into caller_SP+0x2480; wrapper overwrites that slot with a byte delta. |
| Callee cursor passed through X1 | u64 in/out | Adapter sets it to counter-160; callee advances it by160 before dispatch. |
| Adapter fixed frame | 64 bytes | 48-byte saves plus16-byte local reservation. |
| Adapter variable reservation | 16..256 bytes, multiple of16 | High-nibble expression below; not the input object's extent. |
| Callee frame | 57,168 bytes | 96-byte saves plus57,072 local bytes. |
| Stack-probe scratch | 16 bytes immediately below incoming SP | Saved X10/X11; SP itself does not change. |
| New creator record | At least20 accessed bytes | Encoded control+0, destination-cell address+8, eventual creator result+16. Its result is not produced before this increment's allocator boundary. |

The 160-byte cursor step is separate from the eight-byte input owner and the variable stack reservation. A shared accounting pattern does not establish interchangeable record formats or semantic object types.

## Source-produced record and branch gates

Let r=low32(R) and `K=u32((r XOR0xDC40790B)*0x5973A279)`.

| Record offset | Width | Producer / consumer contract |
|---|---:|---|
| +0 | u32 | Caller writes `0x471C XOR K`; entry decodes mode471C. |
| +4 | 4 bytes | Unread/source-undefined fixture padding; no field semantics established. |
| +8 | u64 | Caller writes its saved pointer; entry loads X2. |
| +16 | u32 | NULL path writes raw result `0x74C29D88`. It remains undefined in the non-NULL prefix. |
| +20 | u32 | Caller writes `u32(K+0x2BE18A5D)`; body subtracts K before signed comparison. |

The entry's original 64-bit prekey reduces to `R XOR0x0EFBAC0EDC40790B`; multiplying by `0x5973A279` yields the caller's K in the low32 bits. The prekey and multiply are separately proved composition cuts, followed by source record decode. The input-record identity does not require the new creator's alignment premise.

| Source gate | Established index and target |
|---|---|
| First branch, `0x100A59DFC` | `mode XOR (pointer!=0 ?0x2C:0)`. Mode471C selects index471C ->`0x10095F074` for NULL, index4730 ->`0x100A09C5C` otherwise; modifier BB7D. |
| Non-NULL next branch, `0x100A09C6C` | `471C-1663=30B9` ->`0x1006583B0`; modifier9689. |
| First signed auxiliary gate, `0x100658408` | Decoded auxiliary2BE18A5D is not signed-less than EEDD0B20, giving index8B54 ->`0x100A2C7E0`. |
| Second signed gate, `0x100A2C82C` | Threshold reduces to2BE18A5D. Equality selects index8200 ->`0x100A22288`; a signed-smaller auxiliary would select8202. |

All bare gate values above are hexadecimal. These are internal mode/table indices, not Mach message identifiers, IOKit selectors or proof of external controllability.

The NULL result is an exact source-written raw word. `u32(0x74C29D88 XOR0x8B3DC651)=0xFFFF5BD9`, whose signed32 interpretation is `4294925273-4294967296=-42023`. An original error symbol and the subsequent caller's status interpretation remain unknown.

## Cursor adapter and stack accounting

For incoming u64 counter C, adapter `0x100ABCA64` computes:

```text
L       = u64(C*0x2EBD +1)
reserve =16*((L >>60)+1)        #16..256 bytes
local_cursor =u64(C-160)
callee(record, &local_cursor)  #callee first adds160
output_delta =16*low16(u32(local_cursor)-u32(C))
```

The source reads only the low32 cursor word when forming the return delta, then retains only the low16 difference and shifts it by4. The output is an eight-byte value in `[0,0xFFFF0]`, aligned to16. On the NULL path the callee's advance cancels the adapter bias modulo2^64, so output_delta=0. The caller loads that delta at `0x10039C934` and adds it to SP at `0x10039C938..0x10039C93C`; all24 selected NULL cases restore the caller SP exactly.

Nested peak reservations relative to caller SP are `64+reserve+96+57072`, giving57,248..57,488 bytes. These source-derived arithmetic extents require valid native stack ownership for actual execution. The private owner in the fixtures covers them.

This adapter differs from the earlier callback adapter `0x100ADD594`: that report establishes multiplier2EC5 and cursor bias-176, whereas this one uses2EBD and-160. Their similar stack/accounting pattern does not make their input records or callee entries equivalent.

## Installed stack-probe implementation

| Link / implementation | Original evidence |
|---|---|
| Daemon call at`0x100A59BE4` | Bind slot`0x1010B1E28`, symbol`___chkstk_darwin`, original format12/IA/address-diversity1/diversity0. X17 holds the full slot address. W9=0xDEF0=57,072. |
| `/usr/lib/libSystem.B.dylib` | Original LC_REEXPORT_DYLIB includes libcompiler_rt. |
| `/usr/lib/system/libcompiler_rt.dylib` | Export terminal for`___chkstk_darwin` has reexport flag8, ordinal4 and alias`____chkstk_darwin`; its fourth dependency is libsystem_pthread. |
| `/usr/lib/system/libsystem_pthread.dylib` | Original export`____chkstk_darwin` ->`0x180587CD4..0x180587D40`,108 bytes; dylib UUID`d5e656b3-84b5-368d-a6e7-ccc1a736fb75`. |

The helper first stores X10/X11 at `[SP-16]`/`[SP-8]`, reads TPIDRRO_EL0, then reads two u64 thread-context words at-48 and-40. Their original native structure field names are unknown here. Unsigned SP/range tests select either a fast return or stack touching; a limit-failure path first reads `[second_word-8]`, which can fault natively. That fault path was not executed against a native process.

The walk subtracts4096-byte chunks and performs eight-byte loads at the selected stack addresses, followed by a tail load. At the source caller's size57072, it touches13 full-page positions plus the tail at incoming_SP-57072, and leaves X9=3824. The fast path leaves X9 unchanged. Both normal-return paths reload X10/X11 from their saved scratch and return with SP unchanged. No original helper instruction writes another GPR or SIMD register; NZCV is modified.

Thirty-two isolated original-helper cases cover sizes0,1,16,4095,4096,4097,8192,57072, fast/walk paths and two backing patterns. At exactly4096, the selected walk performs two loads from the same address: the full-page load and zero-size tail load. This is a source-verified boundary behavior, not a native fault or performance claim. All cases preserve X0/X1, SP, all GPRs except X9, and all SIMD registers.

Three consumed cache files are fully rehashed in the checker; library/export/cache UUIDs and exact helper bytes are retained. Native loader binding, compatibility with another OS/cache version and fault-free return remain explicit assumptions. No host helper invocation occurs.

## Opaque data, compact word view and distinct lock destination

The first non-NULL prefix stops before reading an undefined four-byte local at `0x100A222A4`. The continuation restores the exact CPU/memory boundary and retains the four copied local fields, totaling28 independent stack-byte origins. It also retains eight input-byte origins. The resulting36 origins per context remain distinct through copies and arithmetic; no source definition or zero is substituted for them.

Let p0..p7 be the eight bytes read through the input pointer. Source packing forms `U=BE64(p0..p7) XOR0x9898989898989898`. The following apparent subtraction/mask/add sequence is:

```text
u64(U -((U <<1)&0xC7710D2B81AA5B78)+0xE3B88695C0D52DBC)
    =U XOR0xE3B88695C0D52DBC
```

This identity is proved for every u64 U and independently checked against each retained expression. Thus the complete stored word is `BE64(input8) XOR0x9898989898989898 XOR0xE3B88695C0D52DBC`. It is stored at callee_SP+0x2A70. At `0x1009F0168..0x1009F016C` the source reads it and XORs the source-derived mask0xE3B88695C0D52DBC; `0x100975790` stores the resulting `BE64(input8) XOR0x9898989898989898` at+0x3630. This corrects the earlier copy description; see the [registry lookup report](daemon_registry_lookup_report.md). A semantic token type, cryptographic purpose or external wire meaning is unknown. The undefined local copies do not establish a native uninitialized-memory defect: native preceding writes and allocation-to-use continuity remain unknown.

All retained continuation addresses and control choices remain concrete despite those arbitrary-byte expressions. The continuations reach:

| Site / field | Established source value |
|---|---|
| New creator caller | `0x1009729D0` ->`0x10043A240`, modifier8C6D. |
| Creator record | R2=callee_FP-0xB0=callee_SP+0xDE90; minimum20 accessed bytes. |
| Encoded control atR2+0 | `u32(0xAED7-((low32(R2) XOR0xDC40790B)*0x5973A279))`. |
| Destination-cell address atR2+8 | `0x1010C67C0`, source-produced by a separate pool/bias resolution. |
| Creator result atR2+16 | Unknown before the imported allocator; no result is fabricated. |
| First imported allocator boundary | `0x10019385C`, original `_malloc` slot`0x10109FF58`, X0=200, modifier6AA4. The call is not executed. |

The creator is the same previously recovered allocation/rwlock-initialization implementation. Its successful publication to this new cell is conditional on its allocator/initializer outcomes; this increment neither executes those native APIs nor proves lock lifetime. In particular, `0x1010C67C0` is not G=`0x1010C8218`, the previously recovered primary cell`0x1010C8240`, or a Mach port.

## Table, relocation and architectural boundaries

Twelve selected-target rules use seven distinct byte-bank/key identities, each checked over all256 inputs. The contracts retain the complete left/right/key/additive/base/bias/slot mapping; selected significant mappings are:

| Role | Original selected slot | Effective target |
|---|---|---|
| Caller to adapter | `0x1010A0860` | `0x100ABCA64`, modifierCA54 |
| Adapter to entry | `0x1010A0FC0` | `0x100A59BB4`, modifier1803 |
| Adapter counter publication | Pool-selected biased pointer | `0x1010C4DB0` |
| Entry controller pair | Pool-selected biased pointers | `0x1010C4E18`, `0x1010C4670` |
| New creator destination | Pool-selected biased pointer | `0x1010C67C0` |
| Entry to creator | Bank81/additiveCC85 | `0x10043A240`, modifier8C6D |
| Literal malloc8 producer candidate | Bank78/additiveCB6C | `_malloc`, requested size8 at`0x100397184` |

The exact literal call census contains three `MOV X17,#1803;BLRAA X8,X17` sites and16 analogous CA54 sites. Each modifier also occurs on four original target slots. The resolved local call edges above rely on original bank/slot evidence, not discriminator equality. The unsigned-immediate `STR Xn,[SP,#2328]` census has three sites across __text; only`0x100397190` lies in the enclosing caller interval, immediately after malloc8. Other store forms, aliases and native frame/flow continuity remain unproved.

Original relocation checking found `_kCFAllocatorDefault` at`0x1010A7E18` with import-table addend`0x6AE8388F` and inline addend0. The new loader initially omitted that addend; verification caught the mismatch, the loader was corrected, and all dependent profiles, expressions and replays were regenerated. The corrected path is authoritative. Existing sealed verifiers were not changed: their zero-addend checks remain appropriate to their own consumed slots. The new contracts separately verify this nonzero case against the original import table and dyld annotation.

No new daemon-level Mach send/receive, right disposition, IOKit connection or external-method emission occurs in the retained paths. Executed calls are source-local adapters/creator blocks and the original cache stack probe in a private guest. The imported allocator is an unexecuted terminal boundary. Imported internals, later caller continuations and reader B's eventual interfaces remain unknown.

## Validation and reproduction

| Check | Verified coverage |
|---|---|
| Continuous prefixes | 48 cases:2 pointer categories *2 probe paths *3 counter seeds *2 placements *2 controller pairs;21,096 source visits. Twenty-four NULL cases return through the original epilogues and stack adjustment. |
| Arbitrary-byte continuations | Four contexts,711 source instructions each;2,844 visits and36 retained byte origins/context. Forty private write effects retain copied/transformed unknown data. |
| Independent A64 replay | 64 cases:48 prefixes plus4 contexts*4 RAM patterns;39,576 source visits,7,680 read effects,3,544 write effects,656 logical edges,64 final boundaries and64 helper-preservation checks. |
| Fresh replay in checker | One NULL prefix and one non-NULL arbitrary-byte composition replay again. |
| Original helper cases | 32 additional cases,608 source visits; exact stack touches/register preservation, including two4096-byte duplicate-touch cases. |
| Source identities | 23 proof pairs, all46 queries UNSAT;192 lifted source instructions, two nonempty premise witnesses and four retained arbitrary-word expression checks. |
| Source provenance | 11 source spans,62 fixups,12 selection rules/7 bank identities/3072 byte inputs, three rehashed consumed cache files and108 original helper bytes. |
| Opcode coverage | 1,169 distinct retired daemon opcodes plus the separately inspected unretired allocator-call opcode;26 helper opcodes execute in compositions, and all27 helper instructions are inspected. |
| Live IDB | Six ranges,1,024 raw bytes,211 displayed rows, seven partial-byte macro rows. Automatic analysis remains incomplete. |

The private pattern is an execution witness, not a definition of unspecified bytes. Source symbolic expressions preserve their identities; fresh A64 checks evaluate them against independent zero,FF and address-dependent backing. Native allocator outcomes, runtime phase producers, memory validity and hardware authentication remain outside this coverage.

```sh
cd /Users/___/dev/dylex/extracted
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/capture_daemon_descriptor_producers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_descriptor_producers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/continue_daemon_descriptor_producers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_descriptor_producers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_descriptor_producers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/replay_daemon_descriptor_producers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_descriptor_producers.py
```

The capture requires the recorded installed cache and the hash-pinned daemon; a different cache is a new ABI observation, not an interchangeable fixture. IDB output is a separately captured read-only observation. The scripts validate its saved raw bytes rather than silently querying another database. Expected final validation is `all_checks_pass=true`, with native execution and IDB mutation false.

Source-lift construction is linear in retained instructions, with a30-second solver limit per query. With F fixups, C cases, J mapped pages, V visits and E effects, the per-page fixup index gives O(F+C*(J+V+E)) replay work, plus symbolic-expression evaluation; sparse VM work additionally depends on its expression DAG. Memory is O(F+largest trace+mapped RAM). Cache/report hashing is linear in consumed bytes. All extents and stack/cursor calculations use bytes; arithmetic widths and modular behavior are explicit.

## Bounded continuation opportunities

| Impact | Remaining boundary | Discriminating evidence |
|---|---|---|
| High | Native reader A/B incoming state. | Continue actual phase/table producers; this enclosing-entry path did not reach either reader. Shared compiler intervals and a resolved entry caller are insufficient. |
| High | New lock-cell publication and consumers. | Compose allocator/initializer outcomes with the known creator, inspect this caller's result gate and enumerate actual users of`0x1010C67C0`. Preserve its distinction from G and the other primary cells. |
| High | Native origin and meaning of the eight-byte input. | Establish allocation-to-initialization-to-call continuity from the malloc8 candidate and actual intervening writes. Do not infer an uninitialized native read from a private unknown fixture. |
| Medium | Thread-context fields and stack-fault behavior. | Recover current pthread layout/guard semantics and helper limit-failure paths from original source. The normal-return preservation result does not establish native fault handling. |
| Medium | Import relocation completeness. | Carry original addends through additional data bindings and downstream consumers. A target name alone is insufficient relocation provenance. |
| Medium | Parallel cursor adapters. | Identify actual upstream counter owners and downstream delta consumers for each adapter; preserve their distinct multipliers/biases and record types. |
| Low | Computed callers/writers beyond the literal census. | Extend bounded operand/data-flow queries to other register forms, paired/unscaled stores and SP-relative aliases. |

Scoped QG1-QG7 cover factual content; DP1-DP18 with falsification probes; this record/adapter/cache/creator increment with the broad objective open; reproducible byte/u32/u64 calculations; source/fixture/unknown/retirement distinctions; original-file/cache/IDB/proof/A64 provenance; and impact-bounded continuation context. The machine-readable gate artifact records exact checked counts and hashes.
