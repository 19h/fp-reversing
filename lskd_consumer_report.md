# LSKD operation selection and shared-frame interfaces

The [metadata-access continuation](lskd_response_report.md) now reaches a complete operation-selection tree. In the source-produced selector `0x3be` context, fourteen decision nodes select twelve individual 32-bit operation values; all other values select a shared error fragment. The selection theorem covers all `2^32` words under the assumptions below. Selection does not establish handler acceptance, processing success or transport.

Eight original direct callers now have checked constructor-to-selection lineages. Four extend the earlier provider cases: named start/stop wrappers, obfuscated method `wT74ohNhs04Oy`, and span method `R2nPsUOYx6h`. Every retained and fresh case stops before the selected fragment's first instruction. Handler semantics, subsequent IPC, response initialization/publication and native lifetime remain **unknown**. The broad objective remains active.

[Source contracts](triage_evidence/lskd_consumer_contracts.json), [retained cases](triage_evidence/lskd_consumer_profiles.json), [fresh replays](triage_evidence/lskd_consumer_replays.json), [independent checks](triage_evidence/lskd_consumer_checks.json), [nineteen proof pairs](triage_evidence/lskd_consumer_proofs.json), [source identity](triage_evidence/lskd_consumer_source_identity.json), [preservation](triage_evidence/lskd_consumer_preservation.json) and [scoped quality gates](triage_evidence/lskd_consumer_quality_gates.json) retain the evidence.

```text
original source caller
  -> constructor -> compact field appends -> execution wrapper
  -> workspace + candidate clearing -> metadata getter
  -> request.operation32 copied to workspace+0x118
  -> shared-frame pointer preparation
  -> signed-32 operation decision tree (14 nodes)
       +-- one of 12 values -> STOP before selected fragment
       +-- every other word -> STOP before shared error fragment
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LC1 | Original KC and normalized kext identify the pinned build | Addresses, instructions, tables, names | Rehash both; compare complete compiler envelopes, spans, exact nlist entries and chained slots |
| LC2 | Private mapped fixtures and abstract PAC implement the declared conditional source execution | All guest results | Reject source escapes, unmodeled calls and undefined value reads; compare original bytes per visit; native authentication/reachability remain separate |
| LC3 | Register-only allocation models return the declared distinct extents | Request/workspace/auxiliary/candidate lineages | Verify native allocator capacities, descriptors and lifetime separately; models write no memory |
| LC4 | Source-produced selector0x3be context and inherited metadata success establish the entry frame, tag and table | Composed selector theorem and pointer interfaces | Recheck getter lineage, tag0x3be, original root slot and intermediate table/operation preservation; unrelated entry contexts remain unknown |
| LC5 | Fixed symbolic memory cells express this preparer epoch without arbitrary aliasing | Local pointer/reload proofs | Reconstruct actual source write epochs; vary auxiliary adjacency; analyze aliases separately |
| LC6 | Mutable globals remain stable during each fixture | Controller-derived dispatch and stack sizing | Original/zero/declared-noise fixtures; recheck preceding82 byte-bank rules for all256 byte inputs; native concurrency unknown |
| LC7 | Inherited constructor alignment and field contracts apply to source-produced records | 144 actual caller lineages | Verify all constructor records are 8 modulo16; source clearing must replace prior fixture bytes with source provenance |
| LC8 | Finite caller arguments characterize only the tested prefixes | Eight caller compositions and span packet | Vary true object/argument validity and arbitrary span lengths separately; current new span length is8 bytes, and method purpose remains unknown |
| LC9 | Discarded original stack probes target WZR and supply no values to later logic | Stack-probe continuation | Check exact one-byte probe PCs, mapped addresses and discarded destination; unknown poison is not initialized input |
| LC10 | Branch destinations identify source fragments, without an inferred C prototype or semantic function name | Handler map and shared-frame interface | Use compiler boundaries and exact names only; recover actual handler use before assigning argument or business roles |

LC1-LC10 qualify dependent claims. Retained/fresh equality shares the execution engine. Independent byte reconstruction, compact expected packets and source-derived symbolic identities check different properties; they do not prove native behavior.

## Primary provenance

| Item | Exact identity / extent |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Extraction | Nine compiler envelopes;42 spans: preparer1, complete nodes14, arithmetic slices14, unexecuted leaf windows13 |
| Additional source callers | Four complete compiler functions with exact matching nlist names |
| Table provenance |28 original authenticated chained edges, plus preparer-to-root slot |
| Execution source |497160 original instruction visits;1988640 bytes checked against the original KC |

No nearest-symbol assignment is used. The decompiled 61-argument presentation of `0xfffffe000a59bf78` is not an established source ABI. It is entered as a continuation with a shared frame and live registers.

## Eight source callers and request construction

The table lists this build's aligned direct B/BL references to execution wrapper `0xfffffe000a50c508` in its file-backed text segment. The census covers eight sites. Indirect/computed references, other modules and non-file-backed code remain outside that census.

| Caller entry / prior label | Execution call | Operation | Fields | Capacity, bytes | Used, bytes |
| --- | --- | --- | ---: | ---: | ---: |
| `0xfffffe000a5053f4`, start | `0xfffffe000a50544c` | `0x1b59` |0|0|0|
| `0xfffffe000a505480`, stop | `0xfffffe000a5054d8` | `0x1b5a` |0|0|0|
| `0xfffffe000a50550c`, wT74ohNhs04Oy | `0xfffffe000a505568` | `0x1b5b` |0|0|0|
| `0xfffffe000a505638`, R2nPsUOYx6h | `0xfffffe000a5056dc` | `0x1b5c` |1|12|12|
| `0xfffffe000a505848`, scalar64 | `0xfffffe000a5058e0` | `0x1b69` |1|12|12|
| `0xfffffe000a505958`, vault | `0xfffffe000a505a2c` | `0x1b6b` |2|24|24|
| `0xfffffe000a505ac8`, avd | `0xfffffe000a505c68` | `0x1b6a` |5|64|60|
| `0xfffffe000a505de0`, allowed | `0xfffffe000a505eb4` | `0x1b6c` |2|20|20|

Exact additional names are `__Z14LSKDKext_startv`, `__Z13LSKDKext_stopv`, `__ZN30com_apple_driver_FairPlayIOKit13wT74ohNhs04OyEv` and `__ZN30com_apple_driver_FairPlayIOKit11R2nPsUOYx6hEPhjS0_j`. Fixture label `query` refers to wT74ohNhs04Oy; its business purpose is unknown. Prior provider labels retain their earlier scopes.

The first three additional callers source-create a header1 request with no fields, capacity0, source-zeroed counters and inline pointer=request+0x10. A zero-length packet does not prevent this metadata accessor from copying its operation word. Later handler behavior is unexecuted.

R2nPsUOYx6h calls the constructor at `0xfffffe000a505678`, with one field and a payload budget supplied by its input length. Call `0xfffffe000a5056ac` passes `(X0=request,W1=0x66,X2=input_pointer,W3=input_length)` to the recovered span helper. With the eight-byte fixture it source-copies:

```text
BE16(0x66) || BE16(8) || 0b 30 55 7a 9f c4 e9 0e
```

The copied bytes come from the pointed-to input, rather than the pointer's eight-byte representation. Capacity/count/cursor become12/1/12. This closes the earlier static-only additional span-caller gap for these fixtures; arbitrary lengths and subsequent interpretation remain unknown. Each actual caller's constructor-published request reaches its original execution call with all160 bytes carrying source-write provenance.

## Complete operation-selection map

The root at `0xfffffe000a52dd2c` compares the operation as signed32 against `0x1b69`. Lower/upper subtrees combine signed thresholds and equality tests. The gap `0x1b5d..0x1b66`, negative signed values, zero and all other unlisted words select the shared default. The following table describes selection, not successful operation execution.

| Operation word | Selected source fragment | Actual caller evidence in this increment |
| --- | --- | --- |
| `0x1b59` | `0xfffffe000a50fc90` | start |
| `0x1b5a` | `0xfffffe000a54d5a0` | stop |
| `0x1b5b` | `0xfffffe000a51bf2c` | wT74ohNhs04Oy |
| `0x1b5c` | `0xfffffe000a5953e0` | R2nPsUOYx6h |
| `0x1b67` | `0xfffffe000a525b88` | Standalone operation fixture only |
| `0x1b68` | `0xfffffe000a592320` | Standalone operation fixture only |
| `0x1b69` | `0xfffffe000a5534b0` | scalar64 |
| `0x1b6a` | `0xfffffe000a5909bc` | avd |
| `0x1b6b` | `0xfffffe000a51fea0` | vault |
| `0x1b6c` | `0xfffffe000a527070` | allowed |
| `0x1b6d` | `0xfffffe000a590ce4` | Standalone operation fixture only |
| `0x1b6e` | `0xfffffe000a591374` | Standalone operation fixture only |
| Every other u32 word | `0xfffffe000a52e4b0` |19 distinct standalone words |

Fourteen source arithmetic identities reduce each computed table index to its two declared values. Original chained slots supply the two corresponding destinations and authentication diversities. Additional checks establish preservation of the operation word, child phase constants and table-register lineage across every internal edge. Node prefixes preserve arithmetic input seeds; nodes do not modify SP or the tag cell, and all their stores target bounded SP-relative cells. A source-composed acyclic tree then equals the compact table above for every32-bit word. The theorem is conditional on LC1-LC6 and the inherited entry context, without native reachability or PAC authentication proof.

On the three terminal default tests the source prepares W8=`0x5e5571af` before branch. All19 default fixtures reach the shared error entry with that raw word. Its first instruction and resulting return/cleanup are unexecuted here; no completed operation-error ABI is inferred from the prepared word alone.

## Shared-frame preparation and epoch-specific pointer cells

At `0xfffffe000a59bf78`, inherited X24=B=workspace+0x80, X27=request, X22=B+0x98=workspace+0x118, and `[SP+0x160]=A=auxiliary`. Incoming X25 and X21 are saved as G1/G2. Source `0xfffffe000a59bf7c..0xfffffe000a59c040` constructs these eight-byte cells:

| SP offset | Value | SP offset | Value |
| --- | --- | --- | --- |
| `+0x178` |G1| `+0x180` |G2|
| `+0x20` |B+0xc8| `+0x28` |B+0xb0|
| `+0x30` |B+0x120| `+0x38` |B+0x10|
| `+0x40` |A+0x18| `+0x48` |B+0xc0|
| `+0x50` |B+0x9c| `+0x58` |B+0xa8|
| `+0x60` |A+0x60| `+0x68` |A+0x10|
| `+0x70` |A+0x30| `+0x80` |B+0xa0|
| `+0x88` |B+0x128| `+0x90` |A+0x78|
| `+0x98` |B+0xd0| `+0xc0` |B+0xfc|
| `+0xc8` |A+0x70| `+0xd0` |A+0x50|
| `+0xd8` |A+0xa8| `+0xe0` |A+0x88|
| `+0xe8` |A+0x40| `+0xf0` |A+0x58|
| `+0xf8` |A+0x98| `+0x100` |B+0x90|

The register results are X19=request, X20=A+0x20, X27=A+0x28 and X25=B+0x18. Source temporarily computes B+0xfa and overwrites that register; no stored field or semantic role is assigned to that intermediate.

At `0xfffffe000a59c040`, the source reads tag0x3be; subtraction at `0xfffffe000a59c044` selects index0x3b5. Original slot `0xfffffe000846e1c8` contains the authenticated root target, diversity0xa7e8. Operation reload `0xfffffe000a59c048` reads `[X22]` into W8. The source then adds `[SP+0x78]=B+0x20`, `[SP+0x120]=B`, sets X22=B+4 and transfers to the root. All28 pointer cells at root entry are independently checked in each of175 contexts:4900 cell checks.

These are pointer-value interfaces at a specific epoch. Later nodes overwrite cells including SP+0x78, +0x88, +0xf8 and +0x100 with unrelated saved state or narrower words. They are not one persistent C structure. The pointed-to data types and uses remain unknown until the selected fragments consume them.

## Validation and reproduction

| Check | Result / coverage |
| --- | --- |
| Distinct fresh executions |175, exactly equal to retained complete case records |
| Actual original callers |96 prior-provider cases +48 additional-caller cases;8 distinct call sites |
| Other operation fixtures |31 standalone words:12 selected and19 default |
| Original instruction visits / checked bytes |497160 /1988640 |
| Reconstructed reads / writes |93741 /56151 epochs |
| Selected decision edges |653; all28 node outcomes exercised |
| Preparation pointers |4900 cells across175 contexts |
| Original response clear |28000 bytes; candidate remains zero with source provenance |
| Auxiliary region |4096 bytes unchanged and unknown in every case; adjacent/separated fixtures |
| Allocation models |669; register-only, zero modeled memory effects |
| Source constructor records |144; every address8 modulo16 |
| Source-constructed compact bytes |2928 across144 caller packets; includes12 new tag0x66 packets |
| Original discarded WZR probes |175, exact source sites; no undefined private value reads |
| Source-derived proof pairs |19 original/normalized pairs; all UNSAT, source equivalence rechecked |
| Source lift |255 instruction instances, including overlapping slices; not255 distinct instructions |
| Preceding dispatch rules |82 exhaustive rules,20992 byte inputs rechecked |

Four prior providers vary context where defined, global fixtures, two stack placements and adjacent/separated auxiliary storage. Four additional callers vary three global fixtures, two stack placements and two auxiliary locations. Standalone words use original globals, one placement and separated auxiliary storage; finite fixtures are not exhaustive contextual executions. Lower64 D8-D11 remain equal to their initial fixtures at all stop points; upper vector halves/native callee behavior are not proved. No candidate publication, operation leaf/callee, native allocator, synchronization, target file, Mach or IOKit API executes.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_consumer.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_consumer.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_consumer.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_consumer.py
```

Published files are retained; reproduce into an isolated copy. Extraction is O(B+I+N) in pinned bytes/instructions/nodes. Guest verification is O(B+C*(V+E)+256R+I) time/retained space; each case is bounded to30000 visits. Symbolic DAG construction is O(I); solver complexity is separate with30 s/query timeout. Byte counts and fixed u32/u64/signed32 arithmetic require no SI conversion.

## IPC boundaries and bounded continuation

No Mach port is introduced by this increment. The recovered interface runs within the kext from a prepared stream through workspace records and shared-frame selection. Whether any selected fragment reaches an existing daemon RPC or another architectural interface remains unknown. Existing port/emission mappings retain their earlier evidence scopes.

| Impact | Bounded opportunity / unresolved risk | Concrete completion criterion |
| --- | --- | --- |
| High | Per-handler frame and request-field consumption | Recover source uses for one mapped leaf, preserving exact epochs; stop at external/API/provider calls and unknown indirect targets |
| High | Operation0x1b67/0x1b68/0x1b6d/0x1b6e have selection evidence without direct caller lineage | Identify source producers or indirect call contexts; distinguish candidate references from actual construction |
| High | Response header1 initialization and successful publication remain unknown | Establish source candidate writes, returned raw status, displacement and frame preservation before the known publication store |
| High | Internal operation IDs are not daemon Mach IDs | Match any later emission to exact request framing, port provenance and original native transport slots |
| Medium | Shared frame reuses pointer cells as saved-controller state | Recover typed field uses per source epoch; reject a single aggregate type that merges incompatible lifetimes |
| Medium | New span packet has one tested input length | Analyze arbitrary length narrowing/capacity behavior and real source argument provenance separately |
| Medium | Direct-call census excludes indirect/computed callers | Follow original table/vtable references and construction contexts without expanding bounded negative evidence into global absence |

## Scoped quality gates

QG1 passes: factual technical analysis. QG2 passes: LC1-LC10 include dependent results and falsification probes. QG3 passes for this increment: complete selector domain, source caller lineages and preparer interfaces; broad goal remains incomplete. QG4 passes: byte extents, signed comparisons, fixed widths, counts and algorithmic bounds are explicit. QG5 passes: selected/accepted, source/model, pointer/pointed-to bytes, epoch/structure and conditional/native results are separated. QG6 passes: primary source bytes, exact names/chains, fresh byte epochs and independently re-lifted proof pairs. QG7 passes: bounded continuation and impact labels above. Machine checks: [delivery gates](triage_evidence/lskd_consumer_quality_gates.json).
