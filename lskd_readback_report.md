# LSKD response readback, field codecs and stream cleanup

The original query method at `0xfffffe000a50550c` now completes in twelve guarded private executions. It verifies response operation `0x1B5B`, reads tag `0x65` as a big-endian u32, prepares request and response stream frees, and returns `0x13180000` in W0. Native allocation/free effects remain **unknown**. The prior query-publication result is extended to a conditional method return; no native request, Mach message, random backend or cryptographic operation executes. [LR1-LR10]

The additional accessors establish 156 field returns: 36 big-endian u32 outputs and 120 unchanged eight-byte copies. Vault and allowed requests reach two further internal helpers. AVD reads four address fields, then distinguishes a zero context error from a nonzero context continuation to the helper already bounded on the stop path. These are finite source executions, with local arithmetic lemmas separately proved over their declared symbolic domains.

[Source windows and exact names](triage_evidence/lskd_readback_contracts.json), [retained executions](triage_evidence/lskd_readback_profiles.json), [fresh executions](triage_evidence/lskd_readback_replays.json), [byte-epoch checks](triage_evidence/lskd_readback_checks.json), [eight local proof pairs](triage_evidence/lskd_readback_proofs.json), [seven codec/status proof pairs and nine exhaustive banks](triage_evidence/lskd_readback_auxiliary.json), [source identity](triage_evidence/lskd_readback_source_identity.json), [preservation](triage_evidence/lskd_readback_preservation.json), and [scoped quality gates](triage_evidence/lskd_readback_quality_gates.json) retain the evidence. The broad investigation remains active.

```text
query response [operation 0x1B5B; 00 65 00 04 13 18 00 00]
  -> operation getter -> compare 0x1B5B
  -> tag 0x65 lookup -> nonnull payload AND length 4
  -> BE32 -> saved result
  -> request cleanup -> response cleanup [register-only free models]
  -> original W0 load -> original method return 0x13180000

vault   tag 0x8B ------------------- raw8 -> helper A52F9F4 [STOP]
allowed tag 0x7E ------------------- BE32 -> helper A55CE30 [STOP]
AVD     tags 0x6B/0x6C/0x89/0x8A -- raw8 -> decoded context check
                                           zero -> error wrapper return
                                        nonzero -> helper A54E220 [STOP]
```

## Assumption register

| ID | Assumption or bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LR1 | Pinned original KC and normalized kext identify this build | Names, instructions, tables and layouts | Rehash both; compare original source windows, exact nlist matches and original chained pointers |
| LR2 | Guarded private execution and abstract PAC implement the declared register/memory semantics | Execution and branch observations | Reject unlisted source, call targets, private value reads and global stores; verify original PAC diversity and slot membership; native authentication remains unknown |
| LR3 | Allocator/free models supply only declared register effects | Method returns and cleanup preparation | Models initialize/free/write no memory; check target, metadata view, object pointer and source call site; actual ownership effects remain unknown |
| LR4 | Globals have no concurrent writer during each private run | Dispatcher state | Original, zero and declared-noise fixtures; nine exhaustive byte-bank checks; native concurrency remains unknown |
| LR5 | Source outer-wrapper SP is 16-byte aligned (0 modulo 16) | Compact u32 outer record-pack lemma | Check source caller stack states; the unrestricted formula has a counterexample, so the proof explicitly includes alignment; its record address is 8 modulo 16 |
| LR6 | Fixed symbolic cells are distinct except declared source aliases | Local gate/load/store lemmas | Reconstruct every byte epoch; vary stack placement and auxiliary location; arbitrary aliasing is outside the proof |
| LR7 | Source packet extents and seeded parameter storage are accessible | Field reads and provider continuations | Check actual source constructor packets, pointer/length outputs and all consumed bytes; native user-pointer validity remains unknown |
| LR8 | Retained memory after modeled frees is inspection storage | Final snapshots | Do not infer native post-free accessibility; source makes no modeled memory write |
| LR9 | Two explicit context values and declared version/parameter fixtures bound the provider sample | AVD split and new helper boundaries | Compare 0 with 0x1234567887654321 across both placements, both auxiliary locations and three global fixtures; other provider states remain unknown |
| LR10 | Inherited discarded stack probes load WZR and supply no later value | Stack-probe continuation | Check the two exact one-byte probe sites and discarded destination; uninitialized bytes are not promoted to input values |

Claims above and below depend on the indicated source, private-execution and proof premises. Fresh replay equality shares the execution engine; independent byte reconstruction, original pointer decoding and source arithmetic checks establish additional properties without establishing native behavior.

## Primary provenance and bounded coverage

| Item | Verified identity or count |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New extraction | 36 bounded original source windows; complete query method separately retained |
| New exact controller cells | Six eight-byte cells; original values and source writes retained |
| Fresh cases / earlier complete prefixes equal | 343 / 343 |
| Source instruction visits / instruction-byte checks | 1049089 / 4196356 bytes |
| Source read epochs / write epochs | 207649 / 108970 |
| Register-only models / modeled memory writes | 1730 / 0 |
| Original authenticated edge checks | 3348 |
| New bank rules / byte-input evaluations | 9 / 2304 |
| Source-derived UNSAT proof pairs / lifted instruction instances | 15 / 123 |
| Original query method returns / stream free preparations | 12 / 24 |

The six additional controller cells are `0xfffffe000ccc2eb8`, `0xfffffe000ccc2e18`, `0xfffffe000ccc2ee8`, `0xfffffe000ccc2ba8`, `0xfffffe000ccc2ec0`, and `0xfffffe000ccc2ea0`. None is read in the preceding 343 complete prefixes. Each new global store is restricted to the independently retained exact eight-byte cell. An additional AVD window at `0xfffffe000a5354cc..0xfffffe000a5354f8` was required for the nonzero-context branch; the guard rejected it before extraction.

Compiler-start envelopes are retained as boundary metadata. In particular, the envelope beginning at `0xfffffe000a50eccc` contains many shared chunks; this report assigns roles only to the bounded executed windows. No neighboring symbol is used to name an unnamed chunk. Original inputs, external trace/dump material and IDBs are preserved.

## Routine attribution

| Exact entry | Exact original symbol | Established role and evidence boundary |
| --- | --- | --- |
| `0xfffffe000a50e8a8` | `_NxUj27MuIpS68FLnG` | Direct carrier/out-word wrapper for the previously recovered operation getter; original call to `0xfffffe000a54f50c`; normalized status return |
| `0xfffffe000a50e170` | `_kfszHrZ3N4HMtvfB5Bws` | Direct request/tag/output wrapper for the u32 field receiver; call at `0xfffffe000a50e364` reaches `0xfffffe000a55132c` |
| `0xfffffe000a55132c` | No exact nlist symbol | Encoded record receiver; generic lookup; require pointer != 0 and length == 4; BE32 output; raw status at record+0x18 |
| `0xfffffe000a50eccc` | No exact nlist symbol | Encoded record receiver; generic lookup; require pointer != 0 and length == 8; raw eight-byte copy; status at record+0x10 |
| `0xfffffe000a50d088` | `_npoKianhz5eqeqJHjqa9` | Direct stream cleanup wrapper; encoded record call at `0xfffffe000a50d254` reaches `0xfffffe000a560468` |
| `0xfffffe000a560468` | No exact nlist symbol | Cleanup record receiver; inspect stream buffer and prepare typed stream free; inline-buffer branch and original return executed |
| `0xfffffe000a50550c` | `__ZN30com_apple_driver_FairPlayIOKit13wT74ohNhs04OyEv` | Query analysis label; source construction, response readback and full method return observed under declared models |

These roles describe observed/checked interface behavior, not inferred cryptographic purpose. Semantic meaning of constant `0x13180000` is **unknown**.

## Record and value contracts

All offsets are bytes. Integer expressions use unsigned arithmetic modulo 2^32 unless a width is stated. `R` is the encoded receiver record address; gaps are not asserted initialized. Layouts are minimum accessed footprints rather than inferred C type sizes. [LR1, LR2, LR5-LR7]

| Receiver | Offset | Accessed field |
| --- | --- | --- |
| u32 `0xfffffe000a55132c` | +0x00 | Encoded selector, u32 |
| u32 | +0x04 | Encoded tag, u16 |
| u32 | +0x08 | Pointer to caller u32 output, u64 |
| u32 | +0x10 | Request carrier pointer, u64 |
| u32 | +0x18 | Raw result status, u32 |
| raw8 `0xfffffe000a50eccc` | +0x00 | Encoded selector, u32 |
| raw8 | +0x08 | Pointer to caller eight-byte output, u64 |
| raw8 | +0x10 | Raw result status, u32 |
| raw8 | +0x14 | Encoded tag, u16 |
| raw8 | +0x18 | Request carrier pointer, u64 |
| cleanup `0xfffffe000a560468` | +0x00 | Encoded selector, u32 |
| cleanup | +0x08 | Stream object pointer, u64 |
| cleanup | +0x10 | Cleanup result code, u32 |

For the u32 receiver, `K = u32((R xor 0xAE0701E7) * 0x952F3CB7)`. The selector decodes by addition: `u32(encoded_selector + K) = 0x26C` on the checked path. Its tag decodes as `u16(encoded_tag - K - 0x5DEF)`. The direct wrapper emits the inverse selector/tag forms under LR5. The receiver key identity itself is proved for every 64-bit record address.

The raw8 key is `u32((R xor 0xEFB8EF0D) * 0xE384F389)`; XOR with the encoded selector produces `0x2EA` on the checked paths. The cleanup key is `u32((R xor 0xDDD14603) * 0xB90EE68B)`; XOR produces `0x75E` on the checked path. Both key identities are proved over all 64-bit record addresses. The [unrestricted packing query](triage_evidence/lskd_readback_u32_pack_unrestricted.smt2) retains a SAT witness with SP=0x143615D7 and tag=0x5403; SP modulo16 is7. The qualified source packing query retains its explicit SP modulo16=0 premise and is UNSAT. Raw8 tag decoding retains its original bounded source arithmetic; no unsupported simple inverse is assigned to it.

Both field receivers call the previously established generic tag lookup `0xfffffe000a52eed4`, with decoded generic selector `0x526`. New call sites are `0xfffffe000a551574` (u32) and `0xfffffe000a50ef6c` (raw8). The original bank pointers and all 256 byte inputs independently resolve each call to that target. Generic lookup success is raw status `0x5E561849`; a null payload pointer or mismatching exact field length selects `0x5E5571AF`. Each receiver's status store remains distinct from its incidental X0 scratch value.

| Field consumer | Tag | Bytes | Encoding / output observed |
| --- | --- | --- | --- |
| Query response | 0x65 | 4 | BE32(0x13180000) -> caller saved u32 |
| Allowed request | 0x7E | 4 | BE32(0x13579BDF) -> handler saved u32 in the fixture |
| Vault request | 0x8B | 8 | Unchanged little-endian address bytes -> OTHER_OUT fixture address |
| AVD request | 0x6B | 8 | Unchanged address bytes -> PARAM+0x00 |
| AVD request | 0x6C | 8 | Unchanged address bytes -> PARAM+0xA0 |
| AVD request | 0x89 | 8 | Unchanged address bytes -> PARAM+0x60 |
| AVD request | 0x8A | 8 | Unchanged address bytes -> PARAM+0xBC |

The raw8 instruction at `0xfffffe000a544014` loads eight bytes and `0xfffffe000a544018` stores the same value. It does not perform the common tag0x72 bridge's big-endian conversion. Its pointer/length predicate is checked at `0xfffffe000a521bfc..0xfffffe000a521c14`. The u32 predicate is at `0xfffffe000a57dc00..0xfffffe000a57dc18`; byte loads at `0xfffffe000a525d90`, `0xfffffe000a525d98`, `0xfffffe000a525da0`, and `0xfffffe000a525da8` feed the output store at `0xfffffe000a525dd8`. The intervening obfuscated arithmetic is proved equal to the original BE32 value for all four-byte inputs.

The operation and u32 direct wrappers normalize raw result `s` as `u32(s - 0x5E561849)`. Cleanup uses `u32((s - 0x7B7C2C7C) * 0xD0B18B03)`. The two raw success namespaces must remain distinct. These local wrapper formulas are source-lifted proofs, not inferred from one return value.

## Query return and cleanup

The query's response operation accessor call is at `0xfffffe000a5055a4`; source reads and compares operation `0x1B5B` at `0xfffffe000a5055c8/0xfffffe000a5055cc`. The field read occurs at `0xfffffe000a505608`, with W1=0x65 and X2 pointing to SP+0x0C. The caller does not use the field accessor's status as its return word: its original final instruction at `0xfffffe000a505624` loads the saved u32 into W0. [LR1-LR8]

Calls at `0xfffffe000a505614` and `0xfffffe000a505620` clean up request and response respectively. Their outer record receiver is `0xfffffe000a560468`, distinct from the still-unexecuted `0xfffffe000a54e220` helper. Source tests whether object+0x90 is null or equals object+0x10; the latter identifies the checked inline buffer. Both query objects use that inline branch. Behavior of a separate dynamically allocated buffer is **unknown** in this increment.

The typed free preparation at `0xfffffe000a517dd0` has X0=`0xfffffe000847af60`, X1=request or response object, and target `_IOFreeTypeImpl` at `0xfffffe000c4ba368`, with diversity `0x560F`. The native function is not executed. Only a declared register clobber/return model is applied; it changes no memory. The source later writes cleanup success `0x7B7C2C7C` at `0xfffffe000a5258e0`, and the direct wrapper normalizes it to zero.

Original 64-byte view metadata at `0xfffffe000847af60` has chained name pointer `0xfffffe000847af70` -> `0xfffffe000791b050`, string `site.LSKDDispatchStream`, flags 100 and extent 160 bytes. It is byte-identical to the original constructor, candidate-allocation and error-free views at `0xfffffe000847b160`, `0xfffffe000847ae60`, and `0xfffffe000847b020`. The first 16 runtime link bytes are zero in the file; native runtime links are **unknown**.

All twelve original method returns restore SP and GP X19-X29, and all 343 cases preserve D8-D11 low64. Request and response frees add24 source preparations. Their modeled physical effects, reference balancing and native lifetime validity remain **unknown**.

## AVD control and remaining boundaries

At `0xfffffe000a595890`, AVD reloads the exact saved common tag0x72 output. Its address and bytes match the preceding source BE64 output store without an intervening overwrite. The branch at `0xfffffe000a595908` is therefore dependent on decoded context, after four successful raw8 field reads. [LR1, LR2, LR7, LR9]

| Cases | Context fixture | Result |
| --- | --- | --- |
| 12 AVD | 0 | Raw handler status0x5E55719C -> wrapper return0xFFFF5953; candidate, auxiliary and workspace free preparations |
| 12 AVD | 0x1234567887654321 | Call at0xfffffe000a531d60 -> helper0xfffffe000a54e220; stop before call |
| 24 vault | Both context fixtures | Call at0xfffffe000a5961d0 -> unnamed helper0xfffffe000a52f9f4; stop before call |
| 24 allowed | Both context fixtures | Call at0xfffffe000a518af8 -> unnamed helper0xfffffe000a55ce30; stop before call |

These three next-call sites account for 60 stopped continuations. Full caller records, register states and original authenticated slots are retained. Their downstream state effects and ultimate return behavior are **unknown**. The 48 common scalar helper boundaries, 13 start/random boundaries, 13 stop boundaries, 12 span/random boundaries and 19 selected default leaves remain bounded by preceding reports.

No new incoming/outgoing Mach port, port-right transfer, or message emission is established. The added executions concern local object/field interfaces and source cleanup preparation. Their local response publication and return must not be counted as an external reply.

## Reproduction and verification limits

Run from this directory, preserving the existing source files:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_readback.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_readback.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_readback.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_readback_auxiliary.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_readback.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_readback_flag_correction.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_readback_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_readback_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

Expected: 343 fresh cases,343 exact preceding prefixes,12 original query returns,156 additional field returns,8 local proof pairs and7 codec/status proof pairs, all UNSAT. Nine byte-bank rules evaluate 2304 byte inputs. The delivery verifier re-lifts both proof sets, reconstructs the field roles and context dependency, rechecks original metadata/slots, and validates preservation/report links. The frozen baseline is 1837 artifacts: 1831 remain unchanged, with six predeclared report/aggregator edits.

Time is O(B+C*(V+E)+I+256R), plus source mapping lookups and solver-dependent cost (30 s per solver query); retained space is O(B+C*(V+E)+I). B is source bytes, C cases, V instruction visits, E byte-event extents, I lifted instruction instances and R bank rules. Values and addresses are unsigned with explicit byte/bit widths; counts are exact. The method-return theorem is conditional finite execution; local SMT lemmas do not establish native reachability or general completion.

The [summary-flag consistency check](triage_evidence/lskd_readback_flag_correction.json) verifies 24 corrected inherited boolean fields in the twelve query cases. The wrapper-return and query-success flags now agree with the actual recorded returns. Reconstructing the preceding draft restores its complete pinned producer/profile hashes; all 343 source event sequences and every other result field are unchanged. Fresh replay and delivery checks include the corrected fields.

## Bounded continuations

| Impact | Next investigation | Evidence required |
| --- | --- | --- |
| High | Recover the shared0xfffffe000a54e220 interface for stop and nonzero-context AVD | Compare exact incoming encoded records and source selectors; establish local state/control effects before any backend |
| High | Recover0xfffffe000a52f9f4 and0xfffffe000a55ce30 | Decode their incoming record layouts and outgoing ABI boundaries; current names and semantic purpose remain unknown |
| Medium | Establish native stream ownership | Match allocator/free view runtime links and buffer mode; static metadata equality does not prove physical ownership |
| Medium | Preserve record alignment in lifting/emulation | Retain LR5 and source stack evidence; unrestricted address substitution changes the outer packing formula |
| Medium | Connect these local fields to a daemon-originating request | Require a source call chain and matching operation/tag/byte order; the historical RAX startup trace alone does not establish this path |
| Low | Compare another matching build | Require its UUID/hash, exact source and chains; current addresses/formulas are build-specific |

## Quality gates

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
| QG1 | Pass | Factual binary/interface analysis |
| QG2 | Pass | LR1-LR10 include dependencies and falsification probes |
| QG3 | Pass for this increment | Getter, query return, cleanup, AVD split and next interfaces covered; broad goal explicitly incomplete |
| QG4 | Pass | Fixed-width formulas, exact byte offsets/counts and reproducible producers/verifiers |
| QG5 | Pass | Alignment counterexample resolved by explicit premise; raw/normalized status, copy/conversion, local/external publication and private/native evidence remain separate |
| QG6 | Pass | Original bytes, exact names, original chains, fresh epoch audit and15 source proof pairs |
| QG7 | Pass | Impact-labeled continuation table |
