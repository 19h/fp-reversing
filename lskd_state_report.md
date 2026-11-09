# LSKD lookup state, dead-load certificates and complete stop return

The two private-read frontiers in the [preceding continuation report](lskd_continuations_report.md) now have source-level def/use certificates for the zero-lookup-cache paths. Each original load defines X13; the following82 or85 instructions do not read X13/W13 before the original `ADRP X13` overwrites it. The eight-byte words remain uninitialized in the analysis model. No value is guessed, initialized, substituted, or consumed. This resolves24 guarded error continuations under the stated cache/state premises. [ST1-ST12]

The complete original `LSKDKext_stop()` caller also executes in twelve private cases. It preserves the execution-wrapper status in X19, prepares request and response stream frees, restores its frame and returns0. Native free effects remain register-only models, with no model memory writes. No native synchronization or IPC executes.

A second cached word at `0xfffffe000ccc78d0` controls entry to prospective per-context lookup paths. Its file value is zero. Twenty-four additional opaque-nonnull fixtures retain the original read guard; initialized-cache execution remains **unknown**. Separate local proofs recover the prospective1024-entry/u32 lookup index and status selection under explicit saved-frame premises. No table or accepted context is constructed.

[Source contracts](triage_evidence/lskd_state_contracts.json), [retained cases](triage_evidence/lskd_state_profiles.json), [fresh cases](triage_evidence/lskd_state_replays.json), [independent checks](triage_evidence/lskd_state_checks.json), [seven source proof pairs](triage_evidence/lskd_state_proofs.json), [source identity](triage_evidence/lskd_state_source_identity.json), [preservation](triage_evidence/lskd_state_preservation.json), and [scoped gates](triage_evidence/lskd_state_quality_gates.json) retain the evidence. The broader daemon/kext/IPC objective remains active.

```text
analysis preflight at the original load
  lookup-cache value == 0
    -> execute original load into X13, retaining unknown-byte provenance
    -> original source path: no X13/W13 use for82 or85 instructions
    -> original ADRP X13,#CCC2000 overwrites the value
    -> original error continuation -> execution-wrapper return0xFFFFFFFF

  lookup-cache value != 0
    -> retain original private-value guard before the load
    -> initialized-cache/saved-frame execution remains unresolved

original LSKDKext_stop caller
  -> construction -> execution-wrapper return0
  -> save X0 in X19
  -> request stream cleanup -> response stream cleanup [register models]
  -> MOV X0,X19 -> original frame restoration/RETAB -> return0
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| ST1 | Pinned original KC and normalized kext identify this build | Source bytes, names and pointer roots | Rehash both and compare bounded windows, exact nlist and original chain membership |
| ST2 | Guarded private execution and abstract PAC implement the declared architecture semantics | Private outcomes | Reject unlisted code/calls/writes and noncertified unknown reads; native authentication/reachability remain unknown |
| ST3 | Source registers/flags and memory operations follow the checked instruction uses/definitions | Dead-value independence | Re-decode every instruction; independently scan explicit operands; verify no intervening X13/W13 use and the unconditional kill |
| ST4 | Cached word0xfffffe000ccc78d0 remains zero through the certified path | Zero-state path and dead-load permission | Check source epochs and the two source selector phases; native concurrent changes are outside the private model |
| ST5 | Source phases W23=0x72D and W28=0x8AC and the captured callback roots hold | Local cache gates and paths | Check all379 inputs, original branch slots and source-produced records; other states are not classified |
| ST6 | Unknown origin words retain their prior missing-initialization masks | Load certificate and lack of initialization | Independently reconstruct byte epochs; allow only the declared eight-byte origin read; do not mark bytes known after loading |
| ST7 | The source kill is an unconditional ADRP assignment to X13 | Independence from every prior64-bit X13 value | Decode destination/PC-relative immediate independently; compare six isolated original-instruction executions and NZCV |
| ST8 | Only inherited allocator/free register effects are modeled | Complete stop return and cleanup preparation | Verify exact targets/views/pointers and caller clobbers; source makes all memory writes; native lifetime remains unknown |
| ST9 | Callee-saved X19 retains the saved wrapper status across cleanup | Original stop result | Check48 helper return contexts and twelve complete frame restorations; establish native ABI/lifetime separately |
| ST10 | Prospective lookup proofs receive the stated saved context/table-pointer cells | Initialized-cache layout/index/status schema | Recover actual SP+0x30/SP+0x60 pointer initialization and table extent/content; no current execution supplies these premises |
| ST11 | Fixed symbolic cells are distinct except declared source aliases | Local arithmetic/store proofs | Reconstruct actual private alias epochs; arbitrary native aliasing is outside scope |
| ST12 | Post-model storage is inspection memory; inherited WZR probes provide no value | Final snapshots and stack probing | Check no model memory writes and exact discarded probe sites; native post-free accessibility remains unknown |

ST1-ST12 qualify corresponding claims. The certificate establishes independence of the loaded value along the checked architectural paths. It does not establish general native initialization behavior, cache ownership, hardware PAC success, or the absence of faults under different environments.

## Primary provenance and coverage

| Item | Verified identity / count |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New bounded source windows |16 |
| Fresh cases |379 =355 preceding inputs +24 nonzero-lookup-cache fixtures |
| Exact preceding / additional parent prefixes |355 /24 |
| Original instruction visits / instruction-byte checks |1258134 /5032536 bytes |
| Source read / write epochs |253019 /127997 |
| Certified discarded unknown loads / subsequent X13 uses before kill |24 /0 |
| Def/use instruction checks / original X13 kills |2004 /24 |
| Complete original stop-method returns |12 |
| Stream-free preparations / GP-and-SP cleanup returns |24 /48 |
| Local source proof pairs / lifted instruction instances |7 /56 |
| Exhaustive context-root banks / byte-input evaluations |2 /512 |
| Isolated original kill-instruction checks |6 |
| Register-only models / model memory writes |2104 /0 |

The baseline is1949 artifacts, with1943 unchanged and six predeclared report/aggregator edits. Original inputs, published producers and IDBs remain intact. All private source bytes and read/write epochs are rechecked; no unknown origin word is promoted into a known fixture value.

## Exact origins, callbacks and kill

| Path | Original load | Source-private extent | Initialized companion / callback |
| --- | --- | --- | --- |
| Vault |0xfffffe000a57eef8 `LDP X13,X8,[SP,#0x18]` |First8 bytes at SP+0x18 lack initialization |Second8 bytes are the source-written target0xfffffe000a56a150 loaded into X8 |
| Allowed |0xfffffe000a57282c `LDR X13,[SP,#0x58]` |8 bytes at SP+0x58 lack initialization |A later source load obtains target0xfffffe000a5299dc from SP+0xB8 |

Both origins read SP and write X13. They do not set NZCV. The permitted eight-byte access is recorded as a discarded unknown load, with its original missing-initialization mask. All other private value reads require source/fixture initialization. [ST3-ST7]

| Path | Intervening instruction count, including kill | X13 kill |
| --- | --- | --- |
| Vault |82 in each of12 cases |0xfffffe000a551f64 |
| Allowed |85 in each of12 cases |0xfffffe000a551f64 |

The kill lies in the original release adapter's prologue: `ADRP X13,#0xfffffe000ccc2000`. It reads no register and unconditionally writes X13. Its destination register and signed PC-relative immediate decode to that page address directly from the original machine word. Six independent private executions with incoming X13 values0,1,bit63 set,all ones,0xA5A5A5A5A5A5A5A5 and0x1234567887654321 produce the same page value and preserve NZCV. Finite cases corroborate the instruction decoder; the absence of an input X13 operand establishes value independence.

The two-run argument is structural. After the origin, two states may differ in the loaded X13 value and the unused storage word. Each intervening instruction reads equal inputs, so it produces equal control, address, flag and memory effects. Independent byte reconstruction rejects any other use of unknown private bytes. The source kill makes X13 equal again. Later checked value reads do not consume the original unknown storage. Architectural output values are therefore independent of all64 possible bits of that load under the stated path premises. Debug snapshots of raw simulator storage are not treated as known native values.

This certificate changes the analysis guard's admissible paths. The original instructions, target bytes, source branch choices and unknown-byte masks remain unchanged. No replacement instruction, guessed register value, memory initialization or native API effect is introduced.

## Distinct cached words and conditional source paths

| Cell | Source evidence | Current boundary |
| --- | --- | --- |
|0xfffffe000ccc78a8 | RW pointer cache in the preceding write/unlock/free adapters | Twelve existing opaque-nonnull cases stop before IORWLockWrite; native creation/lifetime unknown |
|0xfffffe000ccc78d0 | Presence word controlling the prospective context lookup;49 zero-valued source read epochs | Its native runtime value, producer and relation to the saved table pointer remain unknown |

Two independent exhaustive byte-bank expressions resolve original pool slot0xfffffe0008471c80 to0xfffffe000ccc78d0. Vault uses left0xfffffe000791d3b0/right0xfffffe0007920e10/key0x65/additive-0x40. Allowed uses left0xfffffe00079172c0/right0xfffffe0007919cb0/key0xB5/additive0x14. All256 byte inputs per expression resolve the same original slot and cell. The original pointer has verified chained-format8 membership.

| Local source gate | Zero cached word | Nonzero cached word |
| --- | --- | --- |
| Vault, phase0x72D |Index0x3F0 ->0xfffffe000a56d4f4 |Index0x3E6 ->0xfffffe000a59399c |
| Allowed, phase0x8AC |Index0x47B ->0xfffffe000a57dd18 |Index0x475 ->0xfffffe000a531144 |

These partitions are source-lifted over all64-bit cache values. The actual source cache tests occur after the frontier loads; the earlier analysis preflight permits a load only when its zero-state path has a certificate. Twenty-four additional nonzero-cache fixtures retain the original preflight stop and execute neither origin. The declared pointer0x630000e800 is opaque and no pointed-to object or table is initialized. Native initialized-cache behavior is not inferred from this fixture.

The zero-state paths complete both nonzero-context provider error continuations. Each of twelve vault and twelve allowed cases writes raw0x5E561848 and returns0xFFFFFFFF from the execution wrapper. This remains distinct from the preceding zero-context rejection raw0x5E55719C ->0xFFFF5953.

## Prospective initialized-cache lookup schema

The following results are static local proofs under saved-frame premises. No current hot-path execution reads a table, establishes its allocation, or validates a context. [ST5, ST10-ST11]

| Source context | Saved decoded/masked context | Saved table pointer | Saved index |
| --- | --- | --- | --- |
| Vault0xfffffe000a59399c |SP+0x28 |SP+0x30 |SP+0x3C |
| Allowed0xfffffe000a531144 |SP+0x50 |SP+0x60 |SP+0x74 |

Composing the preceding masked-context identities with these source slices yields:

```text
key32   = low32(context64)
index32 = key32 AND 0x3FF
entry32 = table[index32]                 // original u32 load, stride4 bytes
status  = entry32 == key32 ? 0x5E561849 : 0x5E55719C
```

The address range is1024 entries times4 bytes =4096 bytes =4 KiB. The full low32-bit key is compared after indexing; an equal low10-bit index alone is insufficient. Upper context bits are not part of this local word comparison; their other uses remain bounded by the preceding record decoding and uninspected subsequent interfaces.

Vault's status is selected into W26; allowed's status is stored at SP+0xB8. This does not establish the native table pointer, accessibility, initialization, ownership, update rules, or successful provider behavior. The saved frame cells are explicit proof premises, rather than fabricated source writes.

## Complete original stop caller

Exact nlist resolves `__Z13LSKDKext_stopv` at0xfffffe000a505480, with compiler end0xfffffe000a50550c. The original body constructs operation0x1B5A, receives the checked wrapper result and performs two cleanup calls. [ST1-ST2, ST8-ST9]

| Source point | Established behavior |
| --- | --- |
|0xfffffe000a5054dc |`MOV X19,X0` saves the execution-wrapper status |
|0xfffffe000a5054e8 |Call0xfffffe000a50d088 with the request pointer from SP+8 |
|0xfffffe000a5054f4 |Call0xfffffe000a50d088 with the response pointer from SP+0 |
|0xfffffe000a5054f8 |`MOV X0,X19` restores the saved result |
|0xfffffe000a5054fc..0xfffffe000a505508 |Restore saved GP/frame state, restore SP, original RETAB |

The source request uses its inline buffer and the published response is the preceding source-cleared160-byte candidate. Both cleanup paths reach the original stream-free preparation at0xfffffe000a517dd0, X0=view0xfffffe000847af60, X1=request or response object, target `_IOFreeTypeImpl` at0xfffffe000c4ba368. Only its declared register clobber/return model runs. The view and160-byte metadata identity were established in the [readback report](lskd_readback_report.md).

All twelve original method cases restore SP and GP X19-X29 and return0. Forty-eight cleanup helper returns preserve their source GP/SP contexts. The final source return uses X19, independently of incidental cleanup X0 values. C++ mangling confirms the no-argument name; a source-language return type is not inferred from mangling.

No original target-file, credential, loader, native heap, synchronization, cryptographic or Mach API executes. The two cleanup models initialize/free no memory. Post-model bytes remain inspection storage; native ownership and physical destruction remain unknown.

## Reproduction and algorithmic scope

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_state.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_state.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_state.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_state.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_state_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_state_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

Expected:379 fresh cases;355 exact preceding prefixes plus24 parent prefixes;24 certified unknown loads with2004 def/use checks and zero uses before24 kills;24 nonzero-cache guards retained; twelve complete original stop returns; seven local source proof pairs UNSAT. The audit preserves unknown-byte masks and reconstructs all source writes independently.

Time is O(B+C*(V+E)+I+256R), plus source mapping and solver-dependent cost (30 s/query); retained space is O(B+C*(V+E)+I). B is source bytes, C cases, V visits, E byte-event extents, I lifted instructions and R bank rules. The def/use certificate scan is linear in its2004 instruction rows. Address/key widths and byte offsets are explicit.

No new Mach port, right transfer or external message emission is established. Neither cached word is assigned a Mach port-right type. The completed stop return and local candidate ownership remain separate from a daemon exchange.

## Bounded continuations

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| High | Recover saved hot-path table-pointer lineage | Original reaching definitions of SP+0x30/SP+0x60, actual table extent/content and update ownership |
| High | Establish producers and lifetime of both cached words | Source initialization/publication, matching runtime build and stable identities; distinguish the RW cell from the lookup-presence word |
| High | Extend the initialized-cache certificate | Check both alternative source paths and any new saved-frame prerequisites before admitting further unknown loads |
| Medium | Recover successful provider output contracts | Native-valid contexts/parameters and complete subsequent consumers; current provider results are errors |
| Medium | Connect completed local methods to daemon transport | Matching endpoint, source caller chain, framing, port/right and allocation ownership evidence |

## Quality gates

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
| QG1 | Pass | Factual source/interface analysis |
| QG2 | Pass | ST1-ST12 identify dependent claims and falsification probes |
| QG3 | Pass for this increment | Both prior frontiers conditionally resolved, hot guards preserved, prospective schema and complete stop return covered; broad goal incomplete |
| QG4 | Pass | Explicit widths/byte extents, exact counts, source proof and reproducible verification |
| QG5 | Pass | Unknown loads versus uses, source/cache-state premises, model/native effects, local/IPC completion and static/executed schemas separated |
| QG6 | Pass | Original bytes/names/chains,379 fresh epoch audits,2004 use/definition rows, independent kill decoding and seven re-lifted proof pairs |
| QG7 | Pass | Impact-labeled continuation table |
