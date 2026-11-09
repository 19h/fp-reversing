# Selector18 core entry and conditional tag-table producer provenance

Original selector18 `ProcessEncryptedData` reaches provider `WkhY6wTBlbHrpaT0`, which forwards six arguments to exact core symbol `_zgcqcxw1qve0CY` at `0xfffffe000a5302e4`. The core source publishes the two byte-bank pointers needed by a previously unresolved tag-table-pointer fragment. Thirty-six private source prefixes, including eighteen through the actual provider stub, reach the first allocator call with source-defined frame arguments and bank pointers. The allocator remains unexecuted. [WR1-WR6]

Under the explicit same-frame bank-pointer and X26-restoration premises, the fragment at0xfffffe000a589908 source-stores the known shared tag-table address0xfffffe000ccc7b08 at SP+0xD28. All byte inputs resolve the same original pointer slot. This is a conditional frame-pointer producer; a control-flow/reaching-definition chain to the candidate indexed table store remains **unknown**. No actual tag-table writer or completed writer path is claimed. [WR7-WR9]

[Original contracts](triage_evidence/lskd_writers_contracts.json), [entry runs](triage_evidence/lskd_writers_profiles.json), [conditional bank runs](triage_evidence/lskd_writers_bank_profiles.json), [fresh replays](triage_evidence/lskd_writers_replays.json), [independent checks](triage_evidence/lskd_writers_checks.json), [thirteen source proof pairs](triage_evidence/lskd_writers_proofs.json), [source identity](triage_evidence/lskd_writers_source_identity.json), [preservation](triage_evidence/lskd_writers_preservation.json) and [scoped gates](triage_evidence/lskd_writers_quality_gates.json) retain the evidence. The broader daemon/kext/IPC objective remains active.

```text
selector18 descriptor: input3096 B / output3096 B
  -> authenticated ProcessEncryptedData thunk
  -> UserClient method -> descriptor mapping/accessors [unexecuted]
  -> provider vtable+928 -> WkhY6wTBlbHrpaT0
  -> forward six arguments -> _zgcqcxw1qve0CY
       -> original stack probe and six source argument stores
       -> SP+C28 =7920C10, SP+C30 =79170C0
       -> prepare IOMallocAligned(16384 B,64 B) -> STOP before call

conditional writer-side source fragment [separate local cases]
  preserved SP+C28 and restored X26 from SP+C30
  -> byte-bank decoding, every byte input -> pool slot8471AF8
  -> original targetCCC7B10 -> SUB8 -> STR pointerCCC7B08 at SP+D28
  -> same-frame path to indexed STR at A5480A0 remains unknown
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| WR1 | Pinned original KC and normalized kext identify this build | All addresses, source bytes and original pointer chains | Rehash, compare bounded windows and exact nlist names; no nearest-symbol attribution |
| WR2 | Private A64 execution and abstract PAC match declared architectural semantics | Entry/local outcomes | Check each instruction/read/write, target and boundary; native hardware authentication remains unknown |
| WR3 | Static base-class vtables express the declared selector18 binding | UserClient/provider/core association | Verify exact vtable symbols, address points, offsets and original authenticated slots; actual runtime vptr identity/overrides remain unknown |
| WR4 | Mapped private stack and original file guard/controller state express the tested prefix | Source frame/probe results | Compare original/zero/declared-noise controllers, two stack placements and three argument patterns; native guard/controller contents remain unknown |
| WR5 | The actual descriptor/accessor return values populate the declared call registers | Input/output register meanings | Recheck original mapper/accessor and call-field source; these APIs do not execute here; only low32 length/capacity bits are saved by the core |
| WR6 | The first allocator is only prepared |16384-byte/64-byte-aligned request | Verify target slot/name/arguments and stop before BLRAA; return value, failure handling and allocation effects remain unknown |
| WR7 | SP+0xC28 survives from the source entry, and X26 is restored from SP+0xC30 in the same frame | Conditional table-pointer producer | Recover actual predecessor path, frame identity and reaching definitions; one example restore is an anchor, not that proof |
| WR8 | Fixed symbolic cells are distinct except declared source aliases | Local frame/status/store lemmas | Reconstruct byte epochs and source store addresses; arbitrary native aliasing is outside these local lemmas |
| WR9 | The candidate indexed store shares the produced SP+0xD28 value | Any actual tag-table writer conclusion | Establish the source control-flow path and last reaching definition; matching offsets alone are insufficient and no current result assumes this conclusion |
| WR10 | Embedded status and outer return remain separate channels | Selector18 error/output interpretation | Verify source branch/store/return bytes; complete operation outputs and IOKit delivery remain unexecuted |
| WR11 | Conditional bank fixtures establish the local decoder only |1024 local runs | Check all256 bytes, two high-word patterns, two frame placements and original source writes; no accepted tag, vector or object is supplied |

WR1-WR11 qualify corresponding claims. Full native reachability, successful processing, table publication, writer synchronization and daemon transport remain unknown.

## Primary provenance and coverage

| Item | Verified identity / count |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original bounded source windows / pointer slots |10 /8 |
| Entry prefix cases / source visits |36 /4968 |
| Provider-to-core prefixes / argument-to-frame stores |18 /216 |
| Original stack-probe calls / bank-pointer frame stores |36 /72 |
| Conditional local bank cases / source visits |1024 /13312 |
| Combined source instruction-byte checks |73120 bytes |
| Exhaustive bank rules / byte-input evaluations |5 /1280 |
| Source proof pairs / lifted instruction instances |13 /39 |
| Native allocator effects / model memory writes |0 /0 |

## Original selector descriptor and protected class bindings

Selector18 is enabled by bit17 of the original lookup mask0x87E27E8021. Original list slot0xfffffe000846b7f8 points to descriptor0xfffffe000846b410. The normalized48-byte descriptor words are `{0,0xfffffe000a503dc4,0,3,0xC18,0xC18}`. Its last two counts are3096 bytes each; the original function pointer has authenticated chained-format8 membership and diversity0x705D. The raw descriptor bytes and normalized decoded words are both retained.

| Interface | Original symbol/address/slot | Established target |
| --- | --- | --- |
| Selector18 method thunk |0xfffffe000a503dc4 |UserClient vtable offset0x9A8 |
| UserClient vtable |Exact `__ZTV40com_apple_driver_FairPlayIOKitUserClient`,0xfffffe000846a858; address point+16; slot0xfffffe000846b210 |0xfffffe000a5046dc `ProcessEncryptedData`, diversity0x6188 |
| Provider vtable |Exact `__ZTV30com_apple_driver_FairPlayIOKit`,0xfffffe000846b8c0; address point+16; slot0xfffffe000846c1f8 at offset0x928 |0xfffffe000a505828 `WkhY6wTBlbHrpaT0`, diversity0xD715 |
| Provider tail transfer |Original B at0xfffffe000a505844 |Exact `_zgcqcxw1qve0CY`,0xfffffe000a5302e4 |

These are static original class bindings. They do not establish an actual runtime object's authenticated vptr or a daemon connection. The source UserClient method authenticates data-vptrs with discriminator0xCDA1 and has a BRK path when its explicit authentication comparison fails. Authentication success is not inferred from decoded file pointers.

## Mapper, provider registers and saved core frame

The UserClient method reads an input address at input+0 (u64) and requested length at input+8 (u32), then prepares `FPMemoryDescriptor::withAddressRange` with flags5 and task pointer from UserClient+0xE0. It obtains the descriptor address/length and provider pointer at UserClient+0xD8. No mapper/accessor or task API executes in this increment. Native mapping, copy and ownership effects retain their earlier evidence boundaries.

| Provider input | Core register after source forwarding | Core frame store | Source meaning |
| --- | --- | --- | --- |
| X1 |X0 |SP+0xAD8,u64 |Mapped input-data address |
| X2 |W1 low32 |SP+0xAE4,u32 |Descriptor length, low32 bits |
| X3 |X2 |SP+0x5D8,u64 |Output structure+0x14 data address |
| W4=0xC00 |W3 |SP+0xD68,u32 |Output-data capacity3072 bytes |
| X5 |X4 |SP+0xA58,u64 |Output structure+0x0C,u32-reference |
| X6 |X5 |SP+0x610,u64 |Output structure+0x10,u32-reference; further meaning unknown |

The provider method's mangled parameter sequence `PhjS0_jPjS1_` corroborates pointer/u32/pointer/u32/u32-pointer/u32-pointer widths. The source assembly is authoritative for forwarding and truncation; the C dump's heuristic64-bit length declarations do not change the original W1/W3 stores.

The entry source saves160 bytes of registers and reserves0x13C0=5056 additional stack bytes, for a total0x1460=5216-byte SP displacement. Original `___chkstk_darwin` at0xfffffe000a5a1cc4 is called with X9=0x13C0. Its discarded WZR probe reads supply no values to the core. All other private reads require initialization in the independent byte audit.

## Bank publications and first allocation boundary

| Source store | Original pointer source | Source-published value |
| --- | --- | --- |
|0xfffffe000a53043c ->SP+0xC28 |Pool0xfffffe0008471bf0 (POOL+0x510) |0xfffffe0007920c10 |
|0xfffffe000a530458 ->SP+0xC30 |Pool0xfffffe0008471880 (POOL+0x1A0) targets0xfffffe00079170cc; original SUB12 |0xfffffe00079170c0 |

All36 prefix runs preserve those values with source provenance. Two exhaustive source roots resolve controller cells0xfffffe000ccc2d98 and0xfffffe000ccc2c60. Another resolves dispatch table0xfffffe000846c420. The prologue writes the controller cells with original instructions; no API model supplies memory effects.

The first allocation is prepared at0xfffffe000a5304c8: X0=16384 bytes, X1=64 bytes, X8=0xfffffe000c4b9a08, modifier0x3FC0. Original exact kernel names at that target are `_IOMallocAligned` and `_IOMallocAligned_external`. All runs stop before this call. Workspace contents, allocation success/failure handling and subsequent core processing remain unknown.

## Conditional writer-side pointer production

The candidate fragment reads the first bank pointer from SP+0xC28 and the second from X26. Its byte-bank expression uses left0xfffffe0007920c10,right0xfffffe00079170c0,key0x20,add0x0D. Every byte input yields constant0x76 and index0x83. Separate original-source lemmas establish X17=low8(W16) before the bank and show that the later EOR/AND/add produces index0x83 for arbitrary upper input bits. Original pool slot0xfffffe0008471af8 targets0xfffffe000ccc7b10; the source subtracts8 and stores0xfffffe000ccc7b08 at SP+0xD28, PC0xfffffe000a589938.

The1024 local runs cover all256 low-byte inputs, upper-word patterns0 and0xA5F0C300, and two frame placements. Each executes thirteen original instructions, reads the declared frame pointer, two original bank bytes and original pool pointer, then makes exactly one source pointer store. The source never reads or changes a tag-table entry. Initial frame-bank pointers are declared fixtures derived from the separately executed entry prefix; the intervening parent path is not synthesized.

Original instruction0xfffffe000a589da8 is one example of `LDR X26,[SP,#0xC30]`. It is a restore anchor, not proof that it reaches the candidate with the same SP. Candidate indexed store0xfffffe000a5480a0 loads its base from SP+0xD28 and stores W26 with stride4. A same-frame reaching definition from the established conditional pointer store to that indexed store remains unknown. The earlier [object-slot report](lskd_objects_report.md) writer candidates are therefore narrowed without promotion to an actual tag-table writer.

## Embedded status and external-control boundary

| Source outcome | Output structure writes | Outer return |
| --- | --- | --- |
| Provider returns status S32 |Store S32 at+0xC14; when nonzero, clear u32 at+0x0C |0 |
| Descriptor mapping returnsNULL |Store0xFFFFFFD9 (-39) at+0xC14; clear u32 at+0x0C |0 |

The output-data region starts at+0x14, with3072-byte capacity; it ends at+0xC14, where the four-byte embedded status begins. Thus20 B+3072 B+4 B=3096 B, consistent with the original selector descriptor. The inspected failure paths establish no initialization of the u32 at+0x10 or unused output bytes. Complete operation outputs and IOKit copyout remain outside this increment.

User-controlled address/length fields, stored task/provider context, authenticated virtual interfaces, allocator preparation and source frame state are distinct touch points. No new Mach right, incoming/outgoing port or emission site is established. Selector18 is an IOKit method selector, not a Mach message ID. No daemon transport is inferred from this kernel-local route.

## Reproduction, preservation and scoped gates

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_writers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_writers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_writers_bank.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_writers.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_writers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_writers_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_writers_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

The fresh verifier repeats36 entry prefixes and1024 local bank cases, independently reconstructs source bytes/read/write/provenance epochs, checks original descriptors/vtables/fixups, re-lifts thirteen proof pairs and reevaluates five exhaustive banks. The baseline contains2079 artifacts,2073 unchanged with six declared report/index edits. Original analysis.md, C and calls inputs remain unchanged.

Time is O(B+C*(V+E)+I+256R), retained space O(B+C*(V+E)+I), plus solver cost (30 s/query). B denotes pinned bytes, C cases, V visits, E byte-event extents, I lifted/inspected instructions and R byte-bank rules. Address arithmetic, widths and byte extents are explicit;16384 B=16 KiB,5056 B of locals and5216 B total stack displacement are separate quantities.

| Impact | Further investigation | Required evidence |
| --- | --- | --- |
| High | Establish actual table-entry writer | Same-frame control/reaching-definition chain from0xfffffe000a589938 to0xfffffe000a5480a0, original index/value provenance |
| High | Extend actual `_zgcqcxw1qve0CY` entry past allocation | Original allocator-return/ownership evidence and guarded continuation without unknown-value substitution |
| High | Recover tag/vector publication and native lock discipline | Concrete source stores, cached-vector allocation and writer/reader ordering |
| Medium | Recover output-reference/data semantics | Full consumers of saved SP+0xA58/SP+0x610 and successful output writes |
| Medium | Establish daemon-facing counterpart of selector18 | Matching caller, framing, endpoint and port/right ownership evidence |

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
| QG1 | Pass | Factual source/interface analysis |
| QG2 | Pass | WR1-WR11 list dependencies and falsification probes |
| QG3 | Pass for increment | Selector18/core ingress, bank source provenance, conditional producer and status channels covered; full objective incomplete |
| QG4 | Pass | Explicit widths, byte extents, counts and reproduction |
| QG5 | Pass | Entry/local/native execution, conditional/actual writer, embedded/outer status and allocation preparation/effects separated |
| QG6 | Pass | Original source/names/fixups,36 fresh entry prefixes,1024 local cases, thirteen source proofs and five exhaustive banks |
| QG7 | Pass | Impact-labeled continuation table |
