# LSKD shared lookup table, pointer lineage and zero-entry gate

Both vault and allowed providers source-store the same lookup-table address, `0xfffffe000ccc7b08`. Two exhaustive byte-bank expressions select original pool slot `0xfffffe0008471af8`, whose chained pointer targets table+8; original subtraction by8 supplies the saved pointer. This resolves the saved-pointer provenance left open in the [state report](lskd_state_report.md). [LT1-LT4]

The indexed extent is1024 u32 entries,4096 bytes, entirely file-backed and zero in both the original kernel collection and normalized kext. This establishes an indexed extent, not an allocation-object boundary or current native contents. It remains distinct from the presence word `0xfffffe000ccc78d0` and RW cache `0xfffffe000ccc78a8`.

The first lookup compares the complete low32-bit context with the selected entry. A second source gate rejects entry0. Subject to the same-entry/no-concurrent-mutation premise, the local nonzero route requires `entry32 == low32(context64) && entry32 != 0`. This is a local predicate, not an accepted native context or completed provider-operation contract. [LT5-LT8]

Forty fresh private source runs complete original lookup-error wrapper returns0xFFFF5953, raw0x5E55719C. Four contexts with nonzero upper bits and zero lower bits reach the second table read and are rejected there. Cache presence is an explicit opaque-nonnull fixture; the table is never fabricated or modified. Unknown origin loads remain unknown and are overwritten before use. Native cache publication, table updates, successful processing and daemon transport remain unresolved.

[Source contracts](triage_evidence/lskd_lookup_contracts.json), [retained runs](triage_evidence/lskd_lookup_profiles.json), [fresh replays](triage_evidence/lskd_lookup_replays.json), [independent checks](triage_evidence/lskd_lookup_checks.json), [fifteen source proof pairs](triage_evidence/lskd_lookup_proofs.json), [source identity](triage_evidence/lskd_lookup_source_identity.json), [preservation](triage_evidence/lskd_lookup_preservation.json) and [scoped gates](triage_evidence/lskd_lookup_quality_gates.json) retain the evidence. The full interface investigation remains active.

```text
original pool slot8471AF8 -> original pointerCCC7B10
  -> original SUB #8 -> saved frame table pointerCCC7B08
      vault:   SP+30
      allowed: SP+60

full context64 == 0 -> existing error
presence wordCCC78D0 == 0 -> previous unavailable-state error
presence wordCCC78D0 != 0
  -> key32 = low32(context64)
  -> entry32 = u32[CCC7B08 +4*(key32 &3FF)]
  -> entry32 != key32 -> lookup error
  -> entry32 == key32
       -> re-read entry32
       -> entry32 == 0 -> lookup error
       -> entry32 != 0 -> further source route [unexecuted]

every tested original file-table entry is zero
  -> all40 wrapper returns0xFFFF5953
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LT1 | Original KC and normalized kext hashes identify this build | All addresses, bytes and names | Rehash, compare original/normalized windows and original chained-pointer membership |
| LT2 | Private execution and abstract PAC implement the declared architectural instructions | Executed paths and outputs | Reject unknown code/calls/writes; check exact authenticated slots; hardware PAC/native reachability remain unknown |
| LT3 | Original bank inputs and arithmetic preserve the declared source phases | Common saved table pointer | Evaluate all256 byte inputs for each root; match actual pool-read/store epochs in40 runs |
| LT4 | The original file-backed table is the initial analysis state | Zero-entry outcomes | Compare all4096 bytes in both files; reject table fixtures or writes; refresh from matching native state before native claims |
| LT5 | The cache-presence fixture denotes only nonzero presence | Hot-path selection | Check exact source test and fixture bytes; do not dereference or assign a native object type to the opaque value |
| LT6 | Source key/selector phases and saved frames match the checked callers | Local index and gate proofs | Re-lift original fragments, check actual pointer-store-to-load pairs and varied context/placement/controller fixtures |
| LT7 | The first and second entry reads observe the same value | Composed nonzero-key predicate | Compare both read epochs; recover native locking/update discipline; concurrent mutation can invalidate composition |
| LT8 | Upper context bits may have uses outside the local word comparison | Scope of local context identity | Trace subsequent positive consumers; no full-context identity or authentication conclusion follows here |
| LT9 | Certified unknown X13 loads have no uses before their first full-register definition | Guarded initialized-cache continuation | Decode every intervening read/write, independently scan explicit operands and prove the W13 write zero-extends to all64 bits |
| LT10 | Only inherited allocation/free register effects are modeled | Complete private error-wrapper returns | Check model targets and lack of memory writes; native heap, synchronization and post-free lifetime remain unknown |
| LT11 | Indexed-store candidates are a syntactic source inventory | Writer-search prioritization only | Recover aliases/reaching definitions; other addressing, indirect helper writes, undecoded words and other images preclude a complete writer claim |

LT1-LT11 qualify the corresponding claims. No fixture supplies an accepted table entry, successful provider result or native object lifetime.

## Primary provenance and exact pointer production

| Item | Verified value |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New bounded source windows |12 |
| Fresh cases / source instruction visits |40 /228037 |
| Preserved complete preceding nonzero-cache prefixes |24 |
| Source table-pointer stores / store-to-hot-entry pairs |40 /38 |
| Original table u32 reads / second-stage zero-key rejections |42 /4 |
| Certified unknown loads / def-use instruction rows |38 /2584 |
| Source proof pairs / lifted instruction instances |15 /99 |
| Exhaustive table-root banks / byte-input checks |2 /512 |
| Register-only models / model memory writes |280 /0 |

The original source pointer chain is unauthenticated format8 at slot0xfffffe0008471af8, raw word0x0010000005CC3B10, decoded target0xfffffe000ccc7b10. The source subtracts8 before storing the frame cell. Exact nlist searches give no symbol at table, table+8 or the presence word; semantic labels derive from source consumption, not symbol names.

| Provider | Bank inputs and index | Pointer-producing instructions | Saved cell |
| --- | --- | --- | --- |
| Vault |Left0xfffffe0007920d10,right0xfffffe00079173c0,key0x2F,add0x4C; constant0x37,index0x83 |0xfffffe000a52fca8 LDR;0xfffffe000a52fcac SUB #8;0xfffffe000a52fcb0 STR |SP+0x30 |
| Allowed |Same banks,key0xBB,add-0x60; constant0xE3,index0x83 |0xfffffe000a55d150 LDR;0xfffffe000a55d154 SUB #8;0xfffffe000a55d158 STR |SP+0x60 |

The bank inputs themselves come through original pool slots0xfffffe00084719d8 and0xfffffe0008471d10, with respective source biases-4 and-12. The source loads the resulting table address directly; it does not load a table pointer through the presence word.

A bounded normalized-pointer search for table offsets-8,-4,0,+4,+8 finds two aliases: pool0xfffffe0008471af8 ->table+8 and pool0xfffffe0008471958 ->table-4. The second alias does not establish a count/header type for the preceding word. Encoded arithmetic aliases and other pointer biases are outside this search.

## Two-stage entry predicate and source routes

| Provider | First entry load | Saved index | Second entry load |
| --- | --- | --- | --- |
| Vault |0xfffffe000a5939c4 |SP+0x3C |0xfffffe000a56dfb8 |
| Allowed |0xfffffe000a531170 |SP+0x74 |0xfffffe000a52dc00 |

The first stage stores/selects raw0x5E561849 when the full low32-bit key equals the entry and0x5E55719C otherwise. Its index is `key32 &0x3FF`; original loads use stride4 bytes. The second stage tests for entry0. The source phase proofs establish the constants used in that test, rather than treating obfuscated branch registers as arbitrary flags.

| Secondary route | Index | Original target | Pointer diversity | Execution in this increment |
| --- | --- | --- | --- | --- |
| Vault entry0 |0x53E |0xfffffe000a5410cc |0x9A15 |Two table-reading cases |
| Vault entry nonzero |0x54A |0xfffffe000a54b194 |0x9A15 |Static only |
| Allowed entry0 |0x297 |0xfffffe000a5611b0 |0x891D |Two table-reading cases |
| Allowed entry nonzero |0x28B |0xfffffe000a511608 |0x891D |Static only |

The verified second-stage count is exactly two vault and two allowed cases, each with two original table reads. Positive targets source-save the selected index at SP+0x18 (vault) or SP+0x58 (allowed), but no current run enters those targets. Their later object/record consumers remain unknown.

The composed predicate is proved over arbitrary32-bit entry/key values from the first-stage source status selection and second-stage source branch arithmetic. It requires equal values at the two loads. It neither validates a native context nor proves that upper context bits are unused elsewhere. Original file-table zeroes provide a complete rejection result for these checked local paths, including keys whose lower32 bits are zero.

## Unknown-load independence on initialized-cache paths

| Provider | Unknown load | First definition before any use | Checked instruction rows per case |
| --- | --- | --- | --- |
| Vault |0xfffffe000a57eef8,8 unknown bytes ->X13 |0xfffffe000a551f64 `ADRP X13,#0xfffffe000ccc2000` |102 |
| Allowed |0xfffffe000a57282c,8 unknown bytes ->X13 |0xfffffe000a531164 `AND W13,W11,#0x3FF` |34 |

Nineteen cases per provider reach these loads; the two full-zero contexts reject earlier. All38 load epochs retain missing-initialization masks and provenance. No unknown private byte is marked known after the load. Each following source instruction reads no X13/W13 before the listed definition. Capstone def/use and an independent explicit-operand scan agree on2584 rows. The allowed W13 assignment zero-extends the new index to X13 and has no dependency on the unknown prior64-bit value; this is a separate source proof. All paths end with no live unknown register value. [LT9]

The cache-presence fixture is0x630000e800, with no pointed-to object initialized. The table retains its original file bytes throughout all runs. The twelve controller-global/stack/auxiliary variations per provider from the prior nonzero-cache batch retain their complete preceding prefixes. Additional contexts cover0,1,0x3FF,0x400,0xFFFFFFFF,0x100000000,0x1234567800000000 and0xFFFFFFFFFFFFFFFF. These are finite private architectural cases, not native runtime observations.

## Writer inventory and external interface boundary

Every aligned word in the1688356-byte kext TEXT_EXEC extent is inspected separately:422089 words,422038 decoded instructions and51 undecoded words. This avoids terminating the scan at the first undecodable word. Forty-one decoded store instructions use an explicit register index shifted left by2. The contracts preserve exact bytes, base/index registers and addresses for all41. None has an established alias to the table from this syntactic scan alone. No complete writer inventory is claimed. [LT11]

Neither the lookup table, saved index, presence word nor RW-cache value is established as a Mach right. No new incoming/outgoing port, right transfer, message ID or emission site is established. Local error-wrapper completion does not connect these providers to daemon transport.

## Reproduction, preservation and scoped gates

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_lookup.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_lookup.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_lookup.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_lookup.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_lookup_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_lookup_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

Fresh verification re-executes40 complete source prefixes, compares retained results, reconstructs byte/provenance epochs, matches24 complete prior prefixes, checks source-produced saved pointers, independently re-lifts15 proof pairs and repeats the bounded store inventory. Every source write is reconstructed independently; model memory writes remain0. The preservation baseline contains1982 artifacts;1976 remain unchanged with six declared report/index edits. Original analysis.md, C and calls files remain unchanged.

Time is O(B+C*(V+E)+I+256R) plus solver cost (30 s/query); retained space is O(B+C*(V+E)+I). B denotes source bytes, C cases, V visits, E byte-event extents, I lifted/scanned instructions and R bank rules. All address arithmetic uses explicit byte offsets and32-/64-bit modular widths. The source index extent is1024*4 B=4096 B=4 KiB; allocation-object extent remains unknown.

| Impact | Further investigation | Required evidence |
| --- | --- | --- |
| High | Establish table-entry writers and joint publication of presence | Source aliases/reaching definitions, original stores and producer/update control flow |
| High | Establish native synchronization between the two entry reads | Actual lock identity, ownership, write ordering and matching-build runtime state |
| High | Recover positive-route record/object consumers | Original source after0xfffffe000a54b194 and0xfffffe000a511608, native-valid table/context prerequisites |
| Medium | Resolve table-4 alias | Source use of pool0xfffffe0008471958; no count/header type inferred from adjacency |
| Medium | Connect local providers to daemon exchange | Matching caller/endpoint, framing, port/right and ownership evidence |

| Gate | Scoped result | Evidence |
| --- | --- | --- |
| QG1 | Pass | Factual source/interface analysis |
| QG2 | Pass | LT1-LT11 list dependencies and falsification probes |
| QG3 | Pass for increment | Saved-pointer provenance, hot error paths, second-stage predicate and writer candidates covered; broader goal incomplete |
| QG4 | Pass | Exact byte extents, widths, counts, source formulas and reproduction |
| QG5 | Pass | Indexed/allocation extents, file/native contents, local/accepted-context predicates, models and writer aliases separated |
| QG6 | Pass | Original bytes/chains,40 fresh byte audits,24 prior prefixes,2584 def/use rows and15 source proof pairs |
| QG7 | Pass | Impact-labeled continuation table |
