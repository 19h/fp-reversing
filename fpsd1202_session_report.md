# FPSD1202 selected-session operation, digest and block-transform path

Request1202's marker4d branch compares the selected session's CF-derived Mach name with the received local name. Under the checked CPU phase, words A=1/2 select a digest/block-transform path; the tested other words return original status0 with a zero-length OOL reply. Eight data-path profiles produce an encoded SHA-1 digest followed by an AES-128 block transform and return original status8. Their stored transform bytes and counters are diagnostic A5 bytes without source-write provenance. Successful native session state, processing, transport and daemon/kext completion remain unknown. [FS1-FS8]

This continues the [control-endpoint and OOL report](fpsd1202_ool_report.md). The broader interface investigation remains active.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FS1 | The pinned thin image and matching live IDA bytes identify this implementation. All instruction addresses and source equations depend on that identity. | Rehash the thin image,133 executed source spans and every accessed original format12 fixup/binding; distinguish the IDB input metadata hash. |
| FS2 | The frozen successful FPSD1200 session snapshot and separate registration field supply the declared starting composition. | Independently reconstruct startup owners/globals, the pool/mask, registration constructor/store and exact payload hash. Pin the successful predecessor receipt; its10093981-visit prefix is not freshly replayed here. Native temporal continuity is unknown. |
| FS3 | Marker `0x4577df4d` is an explicit field control. Its associated CF reference/name pair derives from the frozen private session model. | Check the exact initial patch and pair; change the modeled name from6800 to6801 and move the populated slot by896 bytes. A source-produced marker4d session with initialized transform bytes remains unknown. |
| FS4 | Request words, inline16 bytes and mapped OOL16 bytes are declared receive-side inputs. | Vary A, B, C, OOL content and inline content independently; reconstruct initial RAM hashes and every declared patch. Native receive conversion, client pairing and entitlement context remain unknown. |
| FS5 | CF name extraction, once/locks, PAC, stack probing and input deallocation use explicit private ABI models. No application or cryptographic result is injected. | Recompute every argument/result/clobber, full CPU checkpoint, original read/write journal and complete final RAM. No native API or mapping effect is executed. |
| FS6 | Name, operation and counter simplifications depend on the retained CPU phases. | Check those phases at source checkpoints, rerun three retained SMT queries and independently lift three original instruction expressions, including signed LE overflow semantics. |
| FS7 | Digest/AES identification is finite algorithm correspondence on diagnostic inputs. | Join all20 digest stores at their production epochs to independent SHA-1; compare all8 block calls/5 distinct tuples with a separate AES reference and pinned OpenSSL CLI, including a standard known vector. No complete implementation-equivalence or native token-validity theorem follows. |
| FS8 | Thirteen complete bounded profiles define the observed outputs and side effects. | Read application status from W0 at the original return, distinguish simple/complex reply layouts, inspect actual pool-address accesses and seed provenance. Keep later success, ownership, concurrency, provider and deeper-layer joins open. |

## Provenance and evidence [FS1-FS8]

| Primary object | Identity / extent |
| --- | --- |
| Thin arm64e daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Live IDA input metadata | SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7` |
| Fresh source catalog |133 matching spans;7941 distinct instructions /31764 bytes |
| Original execution journals |251460 instruction visits;31029 reads;10032 writes;104 modeled external calls |
| Accessed original format12 words |281 rebases;10 bindings, independently recomputed |
| New session checkpoints |146 complete GP31/SP/NZCV/Q32 frames, in addition to inherited checkpoints |
| Session predecessor | `queue7_success` in [lifetime checks](triage_evidence/fpsd1200_lifetime_checks.json.zst); frozen payload and successful receipt pinned |
| Registration predecessor | `services_success`: CF reference `0x5000000200`, raw private name `0x1003`, source publication at header+40 |
| Fresh SDK validation | Five hashed headers and repeated arm64e compile-only assertions for the inherited Mach/NDR/CF/deallocator ABI |
| Independent block oracle | OpenSSL3.5.9, version and executable SHA-256 retained; separate byte-oriented FIPS197 reference |

Evidence: [producer](triage_evidence/recover_fpsd1202_session.py), [source/profiles/proofs](triage_evidence/fpsd1202_session_checks.json.zst), [IDA/SDK/oracle attestation](triage_evidence/fpsd1202_session_ida_readback.json.zst), [independent auditor](triage_evidence/audit_fpsd1202_session.py), [fresh receipt](triage_evidence/fpsd1202_session_audit.json.zst) and [publication verifier](triage_evidence/verify_fpsd1202_session_publication.py). IDA byte reads request no database edits. No native target API executes. The independent CLI uses OpenSSL to compute diagnostic reference blocks separately from target instruction replay.

## Session name and operation selection [FS2-FS6]

The inherited route first rejects the registered control endpoint for these received names, scans slot markers and selects the declared4d slot. Original call `0x1004a0834` requests `CFMachPortGetPort(slot+0)`. This increment supplies the frozen model's name6800 and continues original instructions. For all-u32 name n and received local name p, under W23=`0x7d7adee7`, W24=`0x6cf4`:

```text
v = (n XOR 0x7d7adee7) + ((n << 1) AND 0xfaf5bdce) - p
  = n + 0x7d7adee7 - p                 [modulo 2^32]

compare at 0x1004a0860: v == 0x7d7adee7 iff n == p
```

Both the retained query and independent source lift are UNSAT. The name6801 control scans onward and returns original status5 before any pool store, OOL read or transform. Names are task-local fixture values, not globally meaningful native endpoint identities.

Original `0x1004c481c` reads slot+812. Its source-derived bytes are `e5c8df06`; no global enum meaning is assigned. Original `0x10049595c` stores a four-byte value to slot+816. Across the retained C=3/0 controls, that value equals `C XOR 0x8b3dc651` (`0x8b3dc652` / `0x8b3dc651`). This finite relation does not alone establish the field's complete domain or lifetime.

At `0x100495960..0x100495984`, the fresh phase is W20=3943, W10=6cf4, W9=19a3, W22=A. The unsigned comparison reduces to `(A-1)<2`, selecting exactly A=1 or2 over the complete u32 domain under that phase.

| Table key / word address | Original target | Selected behavior |
| --- | --- | --- |
|1b08 / `0x101047730`| `0x10059b5c4` | Digest/block-transform route, A=1/2 |
|19a3 / `0x101046c08`| `0x100528dd8` | Other-operation continuation |

The source table addresses are base `0x101039ef0` plus8*key. A=0/3/4/ffffffff follow the second target and return original application status0 in the retained composition. This is a branch/status observation, not successful payload processing.

```text
received local name -> registered-control comparison -> marker4d slot
                                                          |
                                                   CF-derived name
                                                          |
                               mismatch ------------------+-- match
                                  |                              |
                        continue scan -> status5             store +816
                                                                 |
                                      A outside {1,2} -----------+--- A in {1,2}
                                             |                            |
                                   status0, zero OOL            digest -> block transform
                                                                          |
                                                             first inline-byte comparison
                                                                          |
                                                                 counters -> status8
```

## Digest and block-transform records [FS1,FS4,FS5,FS7]

The selected route calls the same generic digest interfaces previously recovered in the [certificate report](rpc502_certificate_report.md) and [identity-cache report](daemon_identity_cache_report.md). Shared code and representations are established; shared transport, policy or ownership does not follow.

| Original caller | Callee | Established observation |
| --- | --- | --- |
| `0x10059b6e0` | `0x10045c4f0` | Digest initializer; catalog includes the encoded SHA-1 IV stores |
| `0x1008a38ec`, twice | `0x100440be4` | Two scalar-input update calls on the selected route |
| `0x1006ad510` | `0x100440be4` | Further digest helper call after OOL copying |
| `0x10053da30` | `0x100539c20` | Private frame adapter for the block transform |
| `0x100539e78` | `0x10053948c` | Original block-transform body |
| `0x10084ddb4`, `0x10084ddb8` | Original byte loads | First inline input byte and first encoded block-output byte |

The independent audit joins eight source reads at `0x1008dac1c` to the XOR98 representation of big-endian B/C, then all20 individual source output stores to SHA-1 over those two four-byte words followed by the16 OOL bytes. All16 OOL input bytes are read at `0x1006b1464`. In each retained data case, the encoded digest is `SHA1(B_be32 || C_be32 || OOL16) XOR 0x98` bytewise. The full20-byte output is verified at its original store epochs; the next transform consumes its first16 bytes. This is finite source/oracle correspondence, not a proof for every input length or digest mode.

At the body entry, X0 points to this observed32-byte record. Other private-frame fields are not assigned a general type.

| Record offset | Width | Role established in these calls |
| --- | --- | --- |
|0|u32|Encoded control/result:166d4332 initially,8b3dc651 after the body|
|4|u32|Other control word c98cc033; complete meaning unknown|
|8|u64|Pointer to16-byte encoded input|
|16|u64|Pointer to16-byte encoded output|
|24|u64|Pointer to selected slot+852,16 stored bytes|

Original `0x10053968c..0x10053970c` loads all16 stored bytes in reverse address order; source instructions apply the low-byte XOR98 adapter. The independent byte-oriented AES-128 reference passes the FIPS197 known vector and agrees with the pinned CLI on all8 calls /5 distinct block tuples. The standard algorithm and128-bit block/key sizes are defined in [FIPS197-upd1, DOI10.6028/NIST.FIPS.197-upd1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf); SHA-1 is defined in [FIPS180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

The byte correspondence is AES encryption with XOR98 representation adapters on the input, output and stored16 bytes. Stored bytes are A5*16 with known-mask00*16; the decoded diagnostic reference key is therefore3d*16. No native secret or source-produced usable session key is established. The encoded record result becomes8b3dc651 in every block call. Raw body/adapter return X0 is0 in baseline/word2/moved-slot/inline-zero and30 in the four changed-digest controls; its complete return convention remains unassigned. It is not treated as the enclosing application's status, which is8 in every data case.

| Controlled case | Encoded block input | Encoded block output |
| --- | --- | --- |
|Baseline, word2, moved slot, inline zero|56f84e1fc35398de94d02c02d7919388|47f2bdf8ca4328e8986fc87bc8d09fb5|
|B=0|8392b2aa9fd0d60058a3c94df9dba62b|fbcacabf8b042c5d0221ca25eee87a57|
|C=0|6bdcc845e31b9a683560aeae46759d01|f44f5919369ab5f2d12ed6837562bf53|
|OOL all zero|b7b04cfc7fd693f76e3f75fc6406037b|d67d51912fa9fedaa4d796a228fd38a6|
|OOL reversed|41bef28a4990db66db4495e73c21a2b9|d321f04d1f95ab0a4025750004e4462c|

The checked inline data begins40, or00 in its control. Only that first byte is read on these failure paths, followed by a load of the first encoded transform byte. None of these profiles covers a matching16-byte comparison or its continuation. A complete comparison/acceptance predicate remains unknown.

## Session counters, outputs and port boundary [FS3-FS8]

| Original instruction | Slot offset / effect |
| --- | --- |
| `0x10049595c` | +816 four-byte publication on matching-name paths |
| `0x1004d8b34..0x1004d8b3c` | +868 u32 load, add1 and store |
| `0x1004d8b40..0x1004d8b7c` | +872 u32 conditional-increment expression |

For the second expression, the fresh X13 low32 is6cf4. Let K=74c29d8b, t=W21, Y=old slot+872. An independently instruction-lifted all-u32 query, with exact ARM signed LE condition flags, proves `new=Y+1+(t!=K)` modulo2^32. All eight data cases have t=K and increment both fields fromA5A5A5A5 toA5A5A5A6. Their initial counters have known-mask00*8. Attempt/success/usage semantics and native initialization remain unknown.

No profile reads slot+880..895. This is checked against actual computed pool addresses and widths, not a literal-offset census. The earlier marker4d/tail publisher is still unjoined.

Application status is obtained from original W0 at `0x100004848`. Reply+32 is a status field only in the simple36-byte form; it lies inside the OOL address in the complex72-byte form. The four zero-status profiles return count0, an A5-seeded address and A5-seeded inline output, with no original payload-output producer established. These private seed values do not establish native disclosure, mapping ownership or meaningful successful processing.

| Case | Visits | Original status | Reply bytes | OOL input bytes read | Pool stores |
| --- | ---: | ---: | ---: | ---: | ---: |
|word0|3162|0|72|0|1|
|word1|29298|8|36|16|3|
|word2|29298|8|36|16|3|
|word3|3162|0|72|0|1|
|word4|3162|0|72|0|1|
|word_ffffffff|3162|0|72|0|1|
|different_session_name|4399|5|36|0|0|
|live_slot_index1|29327|8|36|16|3|
|wordB_zero|29298|8|36|16|3|
|wordC_zero|29298|8|36|16|3|
|OOL_zero|29298|8|36|16|3|
|OOL_reverse|29298|8|36|16|3|
|inline_zero|29298|8|36|16|3|

Every complete case requests input `mig_deallocate(address,16)` at original call `0x100004854`, then clears the received OOL address/count. The model records the call without unmapping. Reply destination remains the declared received reply name6400, published at `0x100004b9c`; reply ID is1302. This increment creates no port-right descriptor, new endpoint, Mach send, IOKit call or hardware submission. The complex descriptor carries memory; a raw CF-derived name comparison does not establish sender authorization or native right ownership.

## Validation and bounded continuations [FS1-FS8]

The independent auditor reconstructs all13 entries without importing the new producer, checks the complete original instruction/read/write journals, modeled API ABI and final mutable RAM, and verifies146 new session CPU checkpoints. It checks649 complete CPU frames including243 inherited ABI checkpoints,31735808 inherited final RAM bytes and851968 bytes each of pool, defined mask and extra private mapping. Three retained queries and three independently source-lifted queries are UNSAT. Fresh live IDA bytes match133 spans. SDK header hashes and compile-only assertions pass. Algorithm checks cover8 full20-byte SHA-1 outputs,8 block calls,5 distinct diagnostic tuples, an independent AES known vector and the pinned CLI.

The frozen registration/session prefixes are pinned rather than freshly executed. No native target, CF/Mach/VM/IOKit effect or concurrent execution is validated. The three original input files are preserved. JSON evidence and the manifest are archived as zstd ultra22 and byte-compared after decompression. New and changed text plus decoded typed RAM are checked for analyst-path literals.

| Impact | Further question / discriminating evidence |
| --- | --- |
|High|Locate the original producer of marker4d together with slot+852/+868/+872. An initialized successful state would replace the present diagnostic controls and distinguish field meanings.|
|High|Follow the source-side comparison and its original matching continuation. Establish its exact representation/domain before assigning authentication or payload-processing semantics.|
|High|Join source-produced state to the existing daemon/kext/provider ABI evidence with matched request lineage and endpoint ownership; helper reuse alone supplies no such join.|
|Medium|Connect marker4d publication/tail+880 and later retirement without inventing an object lifetime from adjacent stores.|
|Medium|Compare the shared SHA-1 helper's record/initialization contracts across certificate, identity and session callers; keep algorithm reuse separate from policy equivalence.|
|Low|Expand operation-word controls only where a new branch or unresolved phase warrants them; the current operation-selector theorem already covers allu32 A under its checked phase.|

## Quality gates

- **QG1**: Factual source/ABI analysis; no normative premise is required.
- **QG2**: FS1-FS8 list assumptions, dependencies and falsification probes.
- **QG3**: Routine roles, incoming name selection, reply locations, data/control flow, environment and architectural touchpoints are covered within the stated bounded scope.
- **QG4**: Byte widths,896-byte stride, u32 modulo arithmetic, endian conversion and fixed-size cryptographic references are reproducible; algorithmic time/space costs appear in the scripts.
- **QG5**: Complex reply+32, source status0, diagnostic keys/counters, first-byte-only input reads and the absence of tail access are explicitly distinguished.
- **QG6**: Pinned source/fixups, fresh live IDA/SDK checks, original journals, independent replay/solvers and primary cryptographic standards support the claims.
- **QG7**: Impact-ranked continuations preserve the unresolved native and cross-layer boundaries; the broader goal remains active.
