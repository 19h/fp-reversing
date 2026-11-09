# LSKD handler records, compact field lookup and response initialization

The [operation selector](lskd_consumer_report.md) now has checked continuations through all twelve selected handler prefixes. Eight operations prepare a common access bridge that searches for tag0x72. Operation0x1b5c prepares a span bridge that searches for tag0x66. Both reach the same original compact-record lookup implementation. That implementation returns a pointer into the request packet and a16-bit length, with raw status in its record. It does not copy the payload in the checked prefix.

Operation0x1b5b source-initializes the prospective response as a header1 stream: operation0x1b5b, field limit1, capacity8 bytes, zero counters and inline pointer=candidate+0x10. The start operation prepares `_kernel_read_random(workspace+0x9c,4)`; the stop operation prepares a separate null-first-word record for an unnamed helper. Those two calls remain unexecuted. All cases stop before complete business-handler processing or response publication. Native validity, subsequent payload decoding and daemon transport remain **unknown**. The broad objective remains active.

[Original contracts](triage_evidence/lskd_handlers_contracts.json), [retained profiles](triage_evidence/lskd_handlers_profiles.json), [distinct fresh replays](triage_evidence/lskd_handlers_replays.json), [independent checks](triage_evidence/lskd_handlers_checks.json), [twenty-five original/normalized proof pairs](triage_evidence/lskd_handlers_proofs.json), [source identity](triage_evidence/lskd_handlers_source_identity.json), [preservation](triage_evidence/lskd_handlers_preservation.json) and [scoped quality gates](triage_evidence/lskd_handlers_quality_gates.json) retain the evidence.

```text
source caller -> request -> metadata -> operation selector
  +-- eight operations -> common access record R -> tag0x72 lookup
  +-- 0x1b5c ----------> span access record R ----> tag0x66 lookup
  |                                                |
  |                              generic record G -> header/packet search
  |                                                -> length16 + packet pointer
  |                                                -> STOP at bridge continuation
  +-- 0x1b5b -> original initializer -> response header1 -> STOP
  +-- 0x1b59 -> kernel random call arguments -> STOP before call
  +-- 0x1b5a -> stop-helper record ----------> STOP before call
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LH1 | KC and normalized kext identify the pinned build | Addresses, instructions, exact names and original slots | Rehash both; compare complete compiler envelopes and exact bounded windows |
| LH2 | Guarded private memory and abstract PAC implement the declared conditional executions | All guest results | Reject unknown value reads, source/call escapes and undeclared global writes; check original bytes per visit; native authentication/reachability remain separate |
| LH3 | Allocator register models return the declared distinct extents | Source request/workspace/auxiliary/candidate accesses | Verify native allocator/view capacity and lifetime separately; no model writes memory |
| LH4 | Source-produced selector0x3be and retained source-entry bindings establish handler phases | Record encoder proofs and composed continuations | Check original selector lineage, exact handler-entry state and record writes; arbitrary unrelated entry states remain unknown |
| LH5 | R=workspace+0xa8=B+0x28, with B=workspace+0x80 | AVD record codec and dual-base stores | Check both frame cells and source write epochs; the proof explicitly preserves the0x28 relationship |
| LH6 | Listed symbolic cells represent distinct storage except declared aliases | Local record, output and initializer proofs | Reconstruct actual byte epochs; vary stack placement and auxiliary adjacency; arbitrary aliasing is not proved |
| LH7 | Each single-register key abstraction uses its checked original-source key lemma | Codec/initializer/lookup composition | Re-lift both key and composition queries; preserve exact abstraction PC/register and dependent source phases |
| LH8 | Mutable globals remain stable except for the recorded source stores during a fixture | Controller-state and byte-bank dispatch | Original/zero/noise fixtures, exhaustive byte-bank readback and byte-epoch reconstruction; native concurrency unknown |
| LH9 | Inherited constructor/field premises apply to the144 original caller lineages | Source packet provenance and preserved prefixes | Verify constructor alignment8 modulo16, all160 request bytes' source provenance and equality with the published pre-handler traces |
| LH10 | Explicit stream fixtures describe valid compact packets within the declared inline extent | Supplemental lookup results and compact expected model | Keep fixture provenance separate; inspect arbitrary source producers, lengths and aliases separately |
| LH11 | Wire-header arithmetic is considered under the declared loop phase and fixed widths | All-word header/tag/cursor lemmas | Check actual phases at each observed visit; no whole-loop induction, arbitrary malformed-stream or native bounds-safety theorem follows |
| LH12 | Original discarded stack probes target WZR and supply no program values | Original stack-probe continuations | Check exact one-byte probe sites and destination; distinguish mapped poison from initialized data |

LH1-LH12 qualify corresponding results. Source-key abstractions occur only in symbolic composition proofs; the execution probes perform the original instructions without key substitutions. Retained/fresh equality shares the engine. Independent byte reconstruction, compact expected packets, exact chained-slot decoding and source-derived identities check different properties without establishing native behavior.

## Primary provenance and interfaces

| Item | Exact identity / scope |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New extraction |11 complete compiler envelopes;27 bounded windows:12 handler prefixes,9 lookup fragments and6 other windows |
| New byte-bank identities |21 rules, each checked for all256 byte inputs; preceding82 rules rechecked |
| Reused initializer | Exact original entry `0xfffffe000a547cd4`, source field/return windows retained by the construction contracts |
| Common access bridge | Unnamed compiler entry `0xfffffe000a52f01c` |
| Span access bridge | Unnamed compiler entry `0xfffffe000a549bf4` |
| Generic lookup entry | Unnamed compiler entry `0xfffffe000a52eed4` |

Names come from exact original nlist matches only. Shared fragments receive no neighboring symbol's name. The random import stub lies beyond the last LC_FUNCTION_STARTS entry; its exact16-byte window is retained with compiler bounds explicitly unavailable. This does not affect its original chained import membership.

## Twelve handler prefixes and first call preparations

| Operation | Selected fragment | First call / continuation | Recovered role through the current boundary |
| --- | --- | --- | --- |
|0x1b59|`0xfffffe000a50fc90`|call `0xfffffe000a50fd10` -> `0xfffffe000a508d6c`|Prepare a four-byte random-output request; do not execute it |
|0x1b5a|`0xfffffe000a54d5a0`|branch -> `0xfffffe000a531ca0`; call `0xfffffe000a531d60` -> `0xfffffe000a54e220`|Prepare a12-byte record with first qword0; helper semantics unknown |
|0x1b5b|`0xfffffe000a51bf2c`|call `0xfffffe000a51c028` -> `0xfffffe000a547cd4`|Initialize the response candidate as a header1 stream |
|0x1b5c|`0xfffffe000a5953e0`|call `0xfffffe000a5954bc` -> `0xfffffe000a549bf4`|Span access record -> original tag0x66 lookup |
|0x1b67|`0xfffffe000a525b88`|call `0xfffffe000a525c60` -> `0xfffffe000a52f01c`|Common access record -> original tag0x72 lookup |
|0x1b68|`0xfffffe000a592320`|call `0xfffffe000a592438` -> `0xfffffe000a52f01c`|Common access record -> original tag0x72 lookup |
|0x1b69|`0xfffffe000a5534b0`|call `0xfffffe000a55356c` -> `0xfffffe000a52f01c`|Common access record -> original tag0x72 lookup |
|0x1b6a|`0xfffffe000a5909bc`|call `0xfffffe000a590af0` -> `0xfffffe000a52f01c`|Common access record, written through both R and B |
|0x1b6b|`0xfffffe000a51fea0`|call `0xfffffe000a51ff80` -> `0xfffffe000a52f01c`|Common access record -> original tag0x72 lookup |
|0x1b6c|`0xfffffe000a527070`|call `0xfffffe000a527134` -> `0xfffffe000a52f01c`|Common access record -> original tag0x72 lookup |
|0x1b6d|`0xfffffe000a590ce4`|call `0xfffffe000a590dd4` -> `0xfffffe000a52f01c`|Common access record -> original tag0x72 lookup |
|0x1b6e|`0xfffffe000a591374`|call `0xfffffe000a59143c` -> `0xfffffe000a52f01c`|Common access record -> original tag0x72 lookup |

Operations0x1b67/0x1b68/0x1b6d/0x1b6e still lack an original direct caller lineage; their new cases use explicitly declared empty stream fixtures. The name `query` is a fixture label for original method `wT74ohNhs04Oy`, whose business purpose remains unknown. Handler prefixes zero operation-specific scratch/output cells in the workspace, auxiliary storage and stack; these source writes now replace parts of the earlier unknown arena state. No complete arena structure is inferred.

## Access records and bridge codecs

Let `K(R)=u32((R ^ 0xc410a4c0)*0xaed3b63b)`. The eight common access callers prepare this partial32-byte record at R=workspace+0xa8:

| R offset | Width, bytes | Source value |
| --- | ---: | --- |
|+0x00|8|Request pointer |
|+0x0c|4|`u32(K(R)+0x148)` |
|+0x10|2|`u16(K(R)^0x4411)` |
|+0x18|8|Pointer to a source-zeroed caller output word |

Other bytes retain their prior epochs and are not assigned fields here. The common bridge decodes this context and builds a generic lookup record for wire tag0x72. Its generic length/pointer outputs are local temporary cells, at bridge SP+0x0e and SP+0x10. The caller's eventual output word is not filled by this checked search prefix. Payload interpretation and the post-search common bridge continuation remain unexecuted.

For operation0x1b5c, the partial40-byte span access record is:

| R offset | Width, bytes | Source value |
| --- | ---: | --- |
|+0x00|8|Pointer-output address, auxiliary+0x18 |
|+0x08|4|`u32(0x526-K(R)-0xb7647540)` |
|+0x10|2|`u16(K(R)^0x66)` |
|+0x18|8|Length-output address, workspace+0x17a |
|+0x20|8|Request pointer |

The span bridge forwards those two output addresses into generic lookup. Thus successful lookup source-writes the pointer/length directly into these arena cells. In the original additional span caller, that pointer aliases the eight input bytes previously source-copied into tag0x66's request field. No ownership transfer or native lifetime is proved.

AVD stores the common record's selector through `[B+0x34]`, while other fields use R=B+0x28. Treating B and R as independent symbolic bases would omit the selector store. Both source epochs and the declared0x28 alias are checked explicitly.

## Generic lookup record and returned values

Both bridges call `0xfffffe000a52eed4`, at common site `0xfffffe000a52f268` or span site `0xfffffe000a549e04`. Let G be the generic record address and `J(G)=u32((G ^ 0xae0701e7)*0x952f3cb7)`. For wanted wire tag T:

| G offset | Width, bytes | Contract |
| --- | ---: | --- |
|+0x00|4|Source-written raw status at return |
|+0x04|2|`u16(J(G)+T+0x12bd)` |
|+0x08|8|Address of16-bit length output |
|+0x10|8|Address of64-bit pointer output |
|+0x18|4|`J(G)^0x526` |
|+0x20|8|Request pointer |

G+6/+7 and G+0x1c..+0x1f are gaps; initial status bytes can retain prior stack epochs. The source clears both output cells before inspecting the request. On a matching field it stores its length and a pointer to the payload in the request packet. Shared return store `0xfffffe000a50f098` writes W6 to `[X0]`. In this lookup return, X0 remains G; it is not a C status return register.

The bridge continuations are the current boundaries: common `0xfffffe000a52f26c`, span `0xfffffe000a549e08`. Across213 lookup executions,180 return raw `0x5e561849` with the expected pointer/length;33 return `0x5e5571af` with zero outputs. Zero-length matching fields return a nonnull payload-position pointer and length0 in the checked cases. Duplicate-tag fixtures select the first match.

## Original packet reads and loop arithmetic

| Source site | Read / action |
| --- | --- |
|`0xfffffe000a527af8`|Request+0x90 packet pointer |
|`0xfffffe000a57edd4`|Request+0 header word; source comparison uses1 |
|`0xfffffe000a5367d4`|Request+0x0c declared byte capacity; source test is nonzero |
|`0xfffffe000a58b3b4`|Request+8 declared field limit |
|`0xfffffe000a519218`|Unsigned ordinal comparison against that field limit |
|`0xfffffe000a5466f0`, `0xfffffe000a5466fc`|Two tag bytes, big-endian |
|`0xfffffe000a546740`, `0xfffffe000a546748`|Two length bytes, big-endian |
|`0xfffffe000a54678c`|Low16 tag comparison after the address-keyed codec |
|`0xfffffe000a532d4c`|On nonmatch, `next_cursor=u32(cursor+4+u16(length))` |
|`0xfffffe000a532d50`..`0xfffffe000a532d60`|Ordinal increment and unsigned next-cursor comparison to byte capacity |
|`0xfffffe000a531a4c`, `0xfffffe000a531a58`|Store length16 and `packet+u32(cursor+4)` payload pointer |

For valid packets, the recovered compact model is:

```text
clear length16 and pointer64 outputs
check request / packet / header1 / nonzero byte capacity in source order
ordinal = 0; cursor = 0
while ordinal < declared_field_limit:
    read BE16(tag), BE16(length) at packet+cursor
    if tag == wanted_tag:
        length_out = length
        pointer_out = packet + u32(cursor+4)
        raw_status = 0x5e561849
        return through the original shared epilogue
    cursor = u32(cursor+4+length)
    ordinal = u32(ordinal+1)
    continue only if cursor < declared_byte_capacity
otherwise return raw_status = 0x5e5571af with zero outputs
```

The inspected loop uses the declared field limit at+8 and byte capacity at+0x0c. It does not read the construction-time used-field counter at+0x98 or cursor at+0x9c in these executions. Four header-byte reads occur for each inspected record; payload bytes are not read by this prefix. The local header proof covers arbitrary16-bit tag/length and32-bit cursor words under its source phase. The advance proof retains u32 wrap semantics. These local results and valid-stream fixtures do not establish arbitrary malformed-stream acceptance, memory safety or a whole-loop induction theorem.

## Query response initialization and status-field distinction

Original initializer `0xfffffe000a547cd4` runs on the candidate pointer in operation0x1b5b. Its source record has candidate at+0, encoded field-limit/operation/budget words at+8/+0x10/+0x14, encoded selector at+0x18, and raw status at+0x0c. With the caller's source phase, the selector decodes to0x542. Source field initialization and return produce:

| Candidate offset | Width, bytes | Value |
| --- | ---: | --- |
|+0|4|Header1 |
|+4|4|Operation0x1b5b |
|+8|4|Declared field limit1 |
|+0x0c|4|Capacity8 |
|+0x10..+0x8f|128|Zero inline bytes from the preceding original clear |
|+0x90|8|candidate+0x10 |
|+0x98|4|Used-field count0 |
|+0x9c|4|Cursor0 |

Thirteen fresh query cases reach `0xfffffe000a51c02c` immediately after initializer return. Store `0xfffffe000a5323cc` writes raw `0x5e561849` at initializer record+0x0c. X0 equals8 at that boundary, reflecting the source capacity calculation; the record status is the status channel. This differs from the earlier metadata getter, whose status is at record+4, and from generic lookup, whose status is at record+0. The shared workspace address does not imply a shared persistent record type.

This closes source header1 initialization for this response candidate path. No response field is appended yet, and the caller's output reference remains zero or its prior fixture sentinel. Successful business return, frame/displacement preservation and the later publication store remain unknown.

## Kernel random interface and stop boundary

| Interface step | Exact original evidence |
| --- | --- |
| Start call preparation | `0xfffffe000a50fd10`: X0=workspace+0x9c, W1=4, X1 zero-extended4 |
| Kext wrapper | Exact `_kernel_read_random`, `0xfffffe000a508d6c` |
| Wrapper branch | `0xfffffe000a508d70` -> original stub `0xfffffe000a69f394` |
| Stub import slot | `0xfffffe000847c4f8`, original authenticated chained pointer, diversity0, address diversity present in raw chain word |
| Kernel target | Exact `_read_random`, `0xfffffe000be57d68`, original `com.apple.kernel` nlist entry |

The source requests four output bytes; the random function, stub, entropy provider and any resulting data remain unexecuted. No nonce/key semantics are assigned to this destination. The initial interpretation as a clearing call was rejected when the exact original target resolved to `_kernel_read_random`.

Operation0x1b5a branches through `0xfffffe000a531ca0`, source-stores a zero first qword and an encoded word at record+8, and prepares call `0xfffffe000a531d60` to unnamed `0xfffffe000a54e220`. Its decoder, final status, object lifetime and deeper effects remain unknown; no destructor or cleanup prototype is inferred.

## Source epochs, validation and reproduction

The three additional mutable cells are original `0xfffffe000ccc2e10`, `0xfffffe000ccc2db0` and `0xfffffe000ccc2ef8`. Their source stores, and updates to the already modeled cell `0xfffffe000ccc2c60`, are original instruction effects. They are not memory effects supplied by API models. Generic lookup rewrites shared controller state and reuses stack records; native concurrency and initialization remain unknown.

| Validation | Coverage |
| --- | --- |
| Retained/fresh executions |271, complete record equality |
| Original instruction visits / checked bytes |720474 /2881896 |
| Reconstructed reads / writes |136067 /82169 byte epochs |
| Original authenticated handler branches / calls |1851 /439 verified edges |
| Packet-header byte reads |1008, at the expected header addresses |
| Original caller prefixes |144 exactly equal to the published pre-handler visits, reads, writes, calls, branches and execution input |
| Explicit stream fixtures |127:31 empty fixtures inherited by operation word, plus96 valid second/absent/duplicate/zero-length layouts |
| Lookup returns |213:180 found,33 not found |
| Query response initializations |13 |
| Prepared random calls / stop-helper calls |13 /13; targets unexecuted |
| Unchanged default boundaries |19 |
| Register-only allocation models |957; zero modeled memory writes |
| Source constructor records |144; every record address8 modulo16 |
| Prior source-constructed packet bytes |2928, unchanged |
| Source-derived proof pairs |25 original/normalized pairs;668 lifted instruction instances, including overlap and key-abstraction composition |
| Rechecked byte-bank rules |103,26368 byte inputs |

All finite executions vary declared original/zero/noise globals where applicable. Original caller cases and supplemental layouts vary two stack placements and adjacent/separated auxiliary storage. The31 base operation fixtures use original globals and one placement; these are not exhaustive contextual executions. No complete business handler, response publication, native heap/API, random/stop helper, crypto/provider operation or IPC emission executes.

The symbolic composition register sites are query key `0xfffffe000a51bf88/W10`; common bridge keys `0xfffffe000a52f158/W17` and `0xfffffe000a52f1b0/W2`; span bridge keys `0xfffffe000a549d00/W16` and `0xfffffe000a549d50/W0`; generic low32 key `0xfffffe000a52ef74/X10`. Each has its own source key-identity lemma. Initializer field composition inherits source phase W9=0x34b. Arbitrary record bases and wire words remain symbolic; unlisted aliases and unrelated entry states do not follow from these proofs.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_handlers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_handlers.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_handlers.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_handlers.py
```

Published files remain retained; reproduce in an isolated copy. Extraction is O(B+I+256R) in source bytes/instructions/rules. Verification is O(B+C*(V+E)+256R+I) time/retained space for case count C, visits V and epochs E; each guest case is bounded to30000 visits. Symbolic DAG construction is O(I); solver cost is separate with30 s/query timeout. All widths and extents are in bits or bytes; no physical-unit conversion is required.

## IPC boundaries and bounded continuation

No new Mach port or message emission is established. This increment connects source-produced kext packets to original field lookup, response metadata initialization and a kernel random API binding. Internal operation words remain distinct from daemon Mach IDs. Any later link to existing daemon RPC framing/port ownership remains unknown.

| Impact | Bounded continuation / unresolved context | Completion criterion |
| --- | --- | --- |
| High | Common bridge post-search value decoding | Establish length checks, byte interpretation, output-word stores and status before returning to each original handler |
| High | Query response field append and publication | Follow source candidate writes through handler return, displacement/frame state and the known publication store |
| High | Start entropy/backend and stop-helper ABI | Recover original native entry contracts and caller continuations while retaining unexecuted backend boundaries |
| High | Later transport linkage | Match any later emission to exact request framing, destination provenance and original Mach/kernel transport slots |
| Medium | Declared field limit versus used-field counter/cursor | Establish intended producer invariants and valid-stream consumption for additional real callers; no malformed-stream theorem is asserted |
| Medium | Shared records and controller-global coupling | Recover per-epoch uses and native synchronization/initialization without merging incompatible layouts |
| Medium | Four selected operations lack direct source producers | Identify indirect/table callers and their actual request construction |

## Scoped quality gates

QG1 passes: factual source/interface analysis. QG2 passes: LH1-LH12 specify dependencies and falsification probes. QG3 passes for this increment: twelve prefixes, access/lookup records, original packet reads, response initialization and random binding; broad goal remains incomplete. QG4 passes: fixed widths, byte extents, modular arithmetic, counts and algorithmic bounds are explicit. QG5 passes: source/model, lookup/whole-handler, record/register status, epoch/type, pointer/copy and conditional/native claims are separated. QG6 passes: original bytes/exact names/chains, independent epochs, complete fresh equality and re-lifted source-derived proof pairs. QG7 passes: impact-labeled bounded continuation above. Machine checks: [delivery gates](triage_evidence/lskd_handlers_quality_gates.json).
