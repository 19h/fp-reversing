# Actual zero-tag local result, frame custody and RETAB boundary

The [actual zero-tag unwind](userclient_zero_tag_unwind_report.md) now continues beyond its workspace retirement request. Under the explicit ordinary workspace-return/frame-preservation and additional frame/guard separation premises, equal saved/current canaries permit the original local result decode: W0=0xce515bda XOR 0x31ae0066=0xffff5bbc, with X0 zero-extended to `0x00000000ffff5bbc`. The source restores X19-X29, D8-D11's low 64 bits, the saved signed-link bit pattern and the original SP, then reaches RETAB. Unequal canaries instead select the original stack-check failure request. Native authentication, release effects, guard equality, an actual return and a public error-domain interpretation remain unknown.

This joins the actual fallback's two retained predecessor modes and all five admitted body lengths 0..4 to the original frame producer and both guard outcomes. It adds no native execution, IDA query, IDB mutation or concrete input content. Earlier [caller-return](userclient_caller_return_report.md) and [transfer-boundary](userclient_transfer_boundary_report.md) reports retain their conditional/historical boundaries. This result does not establish that a native provider invoked this exact input path or consumed this result.

F is the post-prologue frame SP; S0=F+0x10f0 is the incoming SP. C/S/B/T/I and O[j] retain the preceding report's context/workspace/protected-buffer/container/original-input/source-copy meanings. Selected conditions remain D=0, U=0x6685 and L2<=4. Byte counts are decimal; offsets and abbreviated PCs are hexadecimal with prefix `0xfffffe000`.

| Evidence | Identity / coverage |
| --- | --- |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Checks, decoded SHA-256 | `cb373730b6e5f027bb2eef3fa0b37aae926071d5d84c3015d27ef05e4bdcf4eb` |
| Audit, decoded SHA-256 | `d9712fd01f9046792f0a5ae2bb667b8681712a03697b8b26994800c150f7ec0c` |
| Additional source capture | Seven spans / 60 words, covering prologue, original probe, guard, local result, epilogue and failure veneer |
| Carried selected path | 839 distinct words / 1151 instruction instances |
| Combined selected coverage | 899 distinct words across the carried path and new normal/failure/frame components |
| Additional original frame custody | 30 prefixes; 17 cells each; 510 cells / 4080 B reconstructed |
| Original import pointers | Stack probe, stack guard and stack-check failure: three original slots |

The [extractor](triage_evidence/recover_userclient_zero_tag_return.py), [auditor](triage_evidence/audit_userclient_zero_tag_return.py), [checks](triage_evidence/userclient_zero_tag_return_checks.json.zst), [audit](triage_evidence/userclient_zero_tag_return_audit.json.zst) and [delivery verifier](triage_evidence/verify_userclient_zero_tag_return_delivery.py) preserve original byte, pointer, frame-store and solver provenance.

## Frame producer and continued flow

```text
original entry a635208: PACIBSP [opaque signature result]
  -> save 16 register words at S0-80 .. S0-1
  -> FP=S0-10
  -> original stack probe, requested size 1070
       read S0-1080 = F+70; read S0-10f0 = F
  -> SP=F; saved canary at FP-80 = F+1060
  |
  | original prefix frame records + source preservation certificates
  v
actual fallback -> empty-command MISS -> restore O[13] .. O[0]
  -> T/B/C retirement request/ordinary-return boundaries
  -> S16384 retirement request a6662b0
       [fourth ordinary return; frame and callee-saved state preserved]
  -> compare saved F+1060 with current ___stack_chk_guard
       |
       +-- unequal -> BL a66692c -> veneer a69f294
       |              -> BRAA a69f2a0 to ___stack_chk_fail [pending]
       |
       +-- equal -> EOR W0,W26,W23 at a6662cc
                    -> X0=00000000ffff5bbc
                    -> restore saved registers and SP=S0
                    -> RETAB a6662f8 [authentication/return unknown]
```

| Contract | Source-established consequence |
| --- | --- |
| ZR1 | Original PACIBSP precedes register saves. The frame producer reserves 0x80 B, sets FP=S0-0x10, invokes the original probe with X9=0x1070, then reserves 0x1070 B more. Consequently SP=F, FP=F+0x10e0 and S0=F+0x10f0. The PAC result is an opaque symbolic 64-bit saved-link value; no native signing algorithm is executed. |
| ZR2 | The original probe at `a5a1cc4` executes 13 source words for the requested size, makes exactly two discarded byte reads at F+0x70 and F, and returns by the nominal link `a635244`. It performs no store, preserves the frame's saved words and does not change SP or FP. Successful native paging/probing is not established. |
| ZR3 | Original STUR at `a635264` stores the entry guard at F+0x1060. Original STP instructions populate the 16 register words listed below. Each of 30 retained prefixes independently reconstructs all 17 cells from original stores and matches the retained known/provenance bytes and boundary FP. Concrete prefix values are witnesses; no symbolic canary is fixed to their recorded zero value. |
| ZR4 | The earlier finite parent intentionally leaves FP opaque and omits the saved window. Both actual parent modes preserve their incoming FP expression. Their complete source-store inventories, plus the carried zero-tag continuation's 35 stores, are classified and checked against the protected saved window. The original frame invariant therefore refines that opaque state; it is not an equality entailed by the unrefined parent alone. |
| ZR5 | After the exact workspace request `_IOFreeAligned(S,16384)` at `a6662b0`, a separate ordinary-return premise forgets X0-X18/X30 and preserves callee-saved registers, SP and frame storage. No selected subsequent instruction accesses C, S, B or T. Saved raw MISS remains in W26; W23 remains SUCCESS until the result decode. Native release effects remain unknown. |
| ZR6 | LDUR at `a6662b4` reloads F+0x1060 through FP-0x80. LDR at `a6662bc` loads the original guard pointer and LDR at `a6662c0` observes the current guard. B.NE at `a6662c8` takes the failure path exactly when the two independent symbolic 64-bit observations differ. Equality and inequality are exhaustive and disjoint. |
| ZR7 | Equal canaries permit EOR W0,W26,W23 at `a6662cc`. Raw MISS XOR SUCCESS is exactly 0xffff5bbc, and the W0 write clears X0's upper 32 bits. The epilogue restores X19-X29, D8-D11's low 64 bits, the saved signed-link bit pattern and SP=S0 without changing X0. Its terminal opcode is RETAB at `a6662f8`; authenticated control transfer remains unknown. |
| ZR8 | Unequal canaries select original BL `a66692c` to veneer `a69f294`, setting nominal link `a666930`. The veneer loads the original `___stack_chk_fail` pointer at slot `847c478` and executes BRAA at `a69f2a0`, target `c629694`, modifier equal to the slot address. The failure callee's native behavior and any subsequent return remain unknown. |

| Saved frame offset | Width | Source value | Original save PC | Restore PC |
| --- | --- | --- | --- | --- |
| 0x1060 | 8 B | Entry guard observation | `a635264` | `a6662b4` |
| 0x1070 / 0x1078 | 8 B each | D11 / D10, low 64 bits | `a63520c` | `a6662f4` |
| 0x1080 / 0x1088 | 8 B each | D9 / D8, low 64 bits | `a635210` | `a6662f0` |
| 0x1090 / 0x1098 | 8 B each | X28 / X27 | `a635214` | `a6662ec` |
| 0x10a0 / 0x10a8 | 8 B each | X26 / X25 | `a635218` | `a6662e8` |
| 0x10b0 / 0x10b8 | 8 B each | X24 / X23 | `a63521c` | `a6662e4` |
| 0x10c0 / 0x10c8 | 8 B each | X22 / X21 | `a635220` | `a6662e0` |
| 0x10d0 / 0x10d8 | 8 B each | X20 / X19 | `a635224` | `a6662dc` |
| 0x10e0 / 0x10e8 | 8 B each | Incoming X29 / opaque PACIBSP output link | `a635228` | `a6662d8` |

The four D-register claims concern the original 64-bit source saves and reloads. They do not assert preservation of full 128-bit Q-register values. FP is restored to the incoming caller value before RETAB; the compiler canary is checked while FP still addresses this frame. The local status decode occurs before W26 and W23 are overwritten by their incoming saved values.

| Interface | Original source identity | Established boundary |
| --- | --- | --- |
| Stack probe import | Slot `847c618` -> target `a5a1cc4`; call `a635240` | Original read-only source helper composed for X9=0x1070; native stack accessibility unknown |
| Guard import | Slot `847c5f8` -> `cacb000`, kernel `___stack_chk_guard` | Separate entry/current observations; no stability/equality assumption on the failure path |
| Guard failure import | Slot `847c478` -> `c629694`, kernel `___stack_chk_fail` | Original failure request through BL/veneer/BRAA; callee unexecuted |
| Local operation result | `a6662cc` -> RETAB boundary `a6662f8` | Exact zero-extended local result under equal guard and ordinary workspace return |

The integer calculation is bitwise u32: `0xce515bda XOR 0x31ae0066 = 0xffff5bbc`. Its unsigned value is 4,294,925,244; a two's-complement signed-u32 interpretation would be -42,052. Neither interpretation establishes errno, IOReturn, a daemon-visible error name or an actual external return value. No new Mach endpoint, message emitter, right disposition or IOKit selector is established.

## Frame refinement, preservation and validation

The old actual-parent model carries FP as the unchanged opaque `EW_a_entry_X29`; the selected continuation similarly preserves `TI_initial_X29`. Their existing premises alone do not establish either equals F+0x10e0. This report supplies the missing source producer and 30 original-prefix witnesses, then proves preservation. Admission queries explicitly refine the actual cut with the original frame relation rather than silently treating an independent seeded FP as an inherited fact.

The parent store ledgers contain 446 stores in one retained mode and 413 in the other, totaling 859. Every store must have a unique source-affine root/offset or a checked original-image address. Frame stores lie below F+0x1060, including the source helper's scratch range down to F-0x70. Other owner intervals are certified separate from the frame under the actual parent's ownership facts. Integer source offsets and independently proved u64 subrange/disjointness relations keep all writes outside [F+0x1060,F+0x10f0). The carried continuation's 35 stores receive the same classification; no larger legacy frame is imported. The new guard-global read separately requires frame/guard-range separation, as detailed below.

The guard global at 0xfffffe000cacb000 lies outside the five normalized image ranges used by the earlier ownership model. Two SAT omission checks, one per retained mode, show that those earlier premises admit F=guard_address-0x1060 even with the original FP refinement. This is a counterexample to a model entailment, not evidence of a native alias or vulnerability. Consequently the new source-frame model explicitly requires [F,F+0x10f0) to be disjoint from the separately captured [guard_address,guard_address+8) range. All 30 original prefix frames satisfy it, and all 20 refined length/guard admissions retain it. The old premises alone do not establish it.

This is a source/frame-preservation composition under the existing ordinary-return/surviving-storage premises and the additional frame/guard separation condition. It does not inventory every native alias writer. Opaque external callees could invalidate a native frame unless those premises hold. The modeled guard observations remain independent; the recorded prefix guard value does not force equality at exit.

The audit proves 44 new nonvacuous source/frame/ownership obligations and re-solves 157 predecessor source/projection/domain/alias obligations: 201 UNSAT obligations in total. Twenty separate actual-cut admissions are SAT, covering both retained modes, all five body lengths and both canary outcomes under the frame/guard refinement. Two further SAT checks expose the omitted guard separation in the old model. Three source mutations produce SAT violations. All 60 captured new words are covered across the 37-word entry/probe component, 18-word normal exit and 11-word failure exit, with six guard words shared by the two exits. The new access ledger contains 22 frame cells and 231 disjoint integer cell pairs; all 48 source memory-access instances are classified.

The new frame interpreter has no default value for an unknown cell or register. Every frame access must reduce to an exact saved/source cell in [F,F+0x10f0); static reads must lie in an original image segment or the separately captured 8 B kernel guard range. The frame is separate from image ranges and, by an explicit additional condition, from that guard range. Distinct source cells must be disjoint, while repeated exact cells retain explicit source versions. The workspace-return model retains only surviving frame state; the post-return access ledger contains no retired context/workspace/buffer/container access.

Three changed-source controls must yield satisfiable violations: replacing the status EOR at `a6662cc` with NOP, replacing guard B.NE at `a6662c8` with NOP under unequal guards, and changing the FP/link LDP at `a6662d8` from offset 0x70 to 0x60. The last mutation still reads defined saved cells but restores the wrong FP/link pair. No live target bytes are modified.

The new prologue/probe/exit components take O(1) source time and space for this fixed 4336 B frame. This excludes native callees and the carried 14-byte restore loop. Store/access inventory takes O(I); exact same-frame cell comparison takes O(A^2) time and O(A) auxiliary space. Prefix reconstruction takes O(C*W) for C recorded prefixes and W scanned stores; extraction also inspects O(Bin+I) bytes/instructions. SMT search is separate, limited to 60 s per new query and 120 s per retained query. The fresh delivery verifier rebuilds extraction/audit and canonical queries, checks the corpus/manifest, preserves original inputs and checks every owned file for analyst paths.

## Assumption register

| Assumption | Dependent results / stress test or falsification probe |
| --- | --- |
| ZR-A1: Pinned source, original collection and receipt identities | ZR1-ZR8. Rehash both images, all new words/import pointers and dependent artifacts; rebuild extraction and audit. |
| ZR-A2: Original source frame/probe context and accessible selected stack range | ZR1-ZR4, ZR6-ZR8. Execute the captured probe symbolically, check two exact read addresses, original SP/FP equations, saved layout and frame/image separation. Frame/guard-global separation is an explicit additional premise: check all 30 witnesses and two old-model omission counterexamples; establish native stack/range separation separately. |
| ZR-A3: Same original-prefix frame epoch through the actual parent/continuation | ZR3-ZR8. Reconstruct 510 cells from last original stores and known/provenance bytes; certify opaque FP passthrough and classify all intervening source writes. Native alias-writer exclusion remains unknown. |
| ZR-A4: Existing selected fallback and three earlier ordinary T/B/C returns | ZR4-ZR8. Re-solve the carried 157 obligations and retain their byte/argument/descriptor/retired-owner limits. This report does not generalize other tag/type/length or allocation outcomes. |
| ZR-A5: Fourth ordinary workspace return preserves callee-saved registers, SP and frame storage | ZR5-ZR8. Check the carried exact call site/arguments/link, forget volatile registers, prohibit retired-storage accesses and establish native callee effects separately. |
| ZR-A6: Saved/current canaries are independent symbolic observations; equality only conditions normal exit | ZR6-ZR8. Check both exhaustive outcomes and 20 actual-cut admissions, reject the removed guard branch and investigate native guard stability separately. |
| ZR-A7: Source lift and opaque PAC boundary adequately represent these finite data/control effects | ZR1-ZR8. Cover every captured word, classify all accesses, reject three source mutations and retain a separate opaque saved-link bit pattern. Native signature generation/authentication and Q-register upper halves remain unknown. |
| ZR-A8: Local status/RETAB boundary retains its stated scope | ZR7-ZR8. Match the actual outer caller and its status/copy-out path before assigning public error semantics, authenticated return or daemon transaction identity. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Join this exact core input/caller identity to the surrounding provider/handler and establish how the nonzero local result affects copy-out, descriptor publication and external completion. |
| High | Follow actual nonzero-tag construction at `a642454` through node/body allocation and append; retain decoded D/U/L2 and source-byte custody. |
| High | Identify a matched daemon producer/transaction for the recovered protected header and 0x50db wire type; a coincident scalar does not establish transport. |
| Medium | Compose oversized-body failure `a662440` through the same guard/restore boundary and compare status/lifetime channels. |
| Medium | Recover other type handlers and wider extents with the same frame/source-state discipline. |
| Low | Establish native guard/PAC/allocator behavior for a pinned execution environment if evidence becomes available; this report's source effects remain conditional. |

## Quality gates

- **QG1**: Pass. Factual source/interface analysis requires no normative judgment.
- **QG2**: Pass. ZR-A1 through ZR-A8 identify dependencies and falsification probes.
- **QG3**: Pass. Original frame/probe/save custody, both guard outcomes, local result and register/SP restoration reach the RETAB/failure-request boundaries; the full investigation remains active.
- **QG4**: Pass. Byte extents, offsets, u32 XOR/zero extension, signed interpretation, low64 register scope and complexity are explicit.
- **QG5**: Pass. Opaque/refined FP, recorded/symbolic canaries, old/new guard-range separation, saved/current registers, local/public result and source/native return remain distinct.
- **QG6**: Pass. Original words/pointers/stores, prefix provenance and independently rebuilt solver/mutation receipts supply primary evidence.
- **QG7**: Pass. Continuations address outer provider completion, ordinary construction, matched daemon transport, rejection cleanup and generalization.
