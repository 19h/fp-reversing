# Constructor input fields, allocation/header agreement and span-count provenance

Original source closes the conditional input-to-frame join left open by [the header-codec report](daemon_header_codec_report.md). Entry `0x100700d80` saves the incoming encoded length E, preserves it to the allocation calculation, and supplies the same saved value to the header-length writer. The selected size guard admits exactly `P<=0xfffffff5`, where `P=E XOR 0x8b3dc651`. The requested record allocation and node extent are P+10 B without u32 wrap. [CI1-CI5]

The span path also uses this P. Its saved u64 count representation is `u64(P)+0x3d96fe86313b0569`; the later decoder recovers P exactly. Zero bypasses payload copying; nonzero reaches setup with countdown P and the source pointer saved by the entry. This establishes the allocator/header/span-count relationship under the stated frame, call and owner premises. Native phase production, allocation success, complete constructor admission/return and daemon-kext delivery remain unknown.

Evidence: [original source, pointers, banks and retained occurrences](triage_evidence/daemon_constructor_inputs_source.json), [static queries and translations](triage_evidence/daemon_constructor_inputs_checks.json), [extractor](triage_evidence/recover_daemon_constructor_inputs.py), [validator](triage_evidence/validate_daemon_constructor_inputs.py), [preservation](triage_evidence/daemon_constructor_inputs_delivery.json), [scoped gates](triage_evidence/daemon_constructor_inputs_quality_gates.json). No original probe/generator, target code, native API or new emulation was run. Reference data sufficed; no additional IDA access or mutation occurred.

| Evidence | Exact scope |
| --- | --- |
| Original thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh source | 16 fragments, 795 instructions, 3180 B; 21 original pointer records |
| Prior source recapture | 31 ranges, 9688 B, from the header and payload ledgers |
| Static certificate | 16 UNSAT component queries; 844 translated instruction instances, 792 SSA definitions |
| Allocation selectors | Two original byte-bank pairs, 256 inputs each; 512 exact cases select the original `_malloc` slot under the recorded bank-root premise |
| Retained private evidence | 12 send profiles; 60 constructor-entry episodes and 60 allocation pairs; 36 u32-root and 24 span-root occurrences |
| Altered controls | Nine source/field/occurrence/liveness/bank alterations rejected |

Addresses below are original unslid VAs; offsets/constants are hexadecimal. Byte extents are decimal unless prefixed `0x`. u32/u64 arithmetic wraps at its stated width. These are internal flattened-control interfaces, not recovered C/AAPCS parameter lists.

## Entry snapshot and field provenance [CI1-CI4]

Let K be the shared-core frame SP. Entry `0x100700d80` has the following exact saves. Each input remains symbolic; no unavailable value is assigned a chosen native value.

| Incoming operand | Destination | Width | Established downstream use |
| --- | --- | --- | --- |
| Resolved table[W11] continuation | K+`0x6ed0` | 8 B | Reloaded by early-return component `0x10076de60` |
| X0 | K+`0x5508` | 8 B | Container/collection operand, later append and common-stage input |
| W19, named H_e | K+`0xa658` | 4 B | Identifier operand; common-stage reload at `0x1005ae7b4` |
| Low16(W9), named T | K+`0xa65e` | 2 B | Internal discriminator, later signed load and wire XOR`0x11c3` |
| W21, named E | K+`0xa660` | 4 B | Encoded payload extent; allocation operand and header relay |
| W10, named V | K+`0xa664` | 4 B | u32 scalar operand, later copied to K+`0x8f8` |
| X12, named W | K+`0xa668` | 8 B | Raw additional scalar operand; its complete u64 serialization is not recovered here |
| X20, named S | K+`0xa670` | 8 B | Span source pointer, reloaded by payload setup |

The identifier is saved at K+`0xa658`. The nearby K+`0xa620` field copied elsewhere by key setup is not identified with it. Equal widths or adjacent frame locations do not establish an input-field mapping.

The source overwrites temporary W9/W10 after their saves. W21 remains the incoming encoded extent through entry, guard and node-allocation argument preparation. The record-allocation block consumes it before later repurposing X21 as a table base. Register and frame epochs therefore remain explicit.

```text
entry W21 = E --------------------> record size u32(P+10)
      |
      +--> K+a660 --> K+988 ------> header P = E XOR8b3dc651
      |
      +--> additive saved count --> decoder --> span countdown P

entry X20 = S --> K+a670 ---------> selected span source
entry W10 = V --> K+a664 --> K+8f8 -> u32 wire payload V XOR8b3dc651
```

## Compatible phase and size guard [CI2-CI4]

Entry does not admit an unconditional phase interpretation. For a nonnull container, the original edge pair to the guard and then node-allocation prefix constrains incoming W8 to `0x6cf4` and decoded P to the nonwrapping size domain. The certificate quantifies over every u32 incoming phase and encoded extent. This recovers the compatible route; it is not a native observation that a caller produces that phase.

| Selected boundary | Source contract |
| --- | --- |
| Entry phase`0x6cf4`, container null | Index`0xab69` -> `0x10076de60`, IA`0x0fad` |
| Entry phase`0x6cf4`, container nonnull | Index`0xabaa` -> `0x10083c564`, IA`0x0fad`; W9=`0x757b7df7` |
| Guard admitted | Index`0xc1cd` -> `0x1006958b0`, IA`0x9b18` |
| Guard not admitted | Index`0x79f1` -> `0x10076de60`, IA`0x9b18` |
| Early-return component | Reloads K+`0x6ed0`, branches with IA`0x151e`; native return and public status meaning unproved |

Under the selected predecessor phase, the obfuscated guard recovers `P=E XOR0x8b3dc651`. Its `CMN W9,#10; CSET ...,LO` tests absence of u32 carry. Thus admission is exactly `0<=P<=0xfffffff5`; the extent `N=P+10` lies in [10,4294967295] B. The source size result is zero-extended into the pointer-sized allocation argument. This is an exact integer bound, not a native allocation measurement or successful allocation claim.

Other incoming phase states can select other original table entries. The theorem about the selected edge pair is not a complete dispatcher admission policy. The private raw W6 marker assigned before early branches is not given a public error-name interpretation.

## Allocation arguments and original imports [CI2-CI4]

| Source site | Established normal-route interface |
| --- | --- |
| `0x100695920..0x100695928` | Node request32 B; selected local W22=`0x6cf4`, W23=`0xc714` |
| `0x10069592c` | Returned node pointer N saved at K+`0x38a0` |
| `0x100948a8c..0x100948b9c` | Node+0/+8 cleared; node+`0x10` receives plain u32(P+10) |
| `0x100948bf8` | Record-buffer allocation argument P+10 B |
| `0x100948bfc` | Returned buffer pointer stored at node+`0x18` |
| `0x100948bdc` | Before that call, save Q=`u64(P)+0x3d96fe86313b0569` at K+`0xa678` |

The node+`0x10` theorem is modular for arbitrary encoded E. The size guard supplies its nonwrapping operational domain. Original register-write checks establish that X0 retains the requested extent between its calculation and the record allocation, and X8 retains Q until the save. Preservation across allocation calls additionally requires the selected callee's ordinary saved-register/frame contract; native execution of that contract is not established here.

| Call | Bank roots, conditional frame slots | Key/addend | Exhaustive result |
| --- | --- | --- | --- |
| Node, `0x100695928` | `100fc4230`,`101031fa0`; K+`0x9b0`/`0x9a8` | u8`0xf3`, add`0xcbca` | All256 inputs select table index`0xcc0d` |
| Record, `0x100948bf8` | `100fc4130`,`101031ea0`; K+`0x968`/`0x960` | u8`0xa3`, add`0xcb9b` | All256 inputs select table index`0xcc0d` |

Correction: the record allocator loads its left bank pointer from K+`0x968` at `0x100948bbc`. The earlier `0x5f0` table label was incorrect. The frozen source ledger and generator retain that historical label; the [cleanup report and explicit erratum](daemon_constructor_failure_report.md) supersede that one metadata field. The numeric bank-selection theorem is unchanged and remains conditional on actual bank roots.

The original slot is `0x10109ff58`, an authenticated libSystem `_malloc` bind with IA diversity`0x6aa4`, address diversity zero and total addend zero. Both call instructions supply that diversity. The bank theorem requires the listed frame slots to contain those bank roots and K+`0x9d8` to contain the original pointer-table base. It proves the selection for every controller byte under those roots; native roots, PAC and allocator behavior remain separate premises.

Allocation-result branches are retained as original frontier bindings. No new allocation-failure fixture or execution is performed; failure cleanup and public result semantics remain outside the accepted normal-route contract.

## Header and scalar field relays [CI3-CI5]

Key setup copies the same saved E from K+`0xa660` to K+`0x988`, and copies V from K+`0xa664` to K+`0x8f8`. The header proof established that its length writer emits `u32[K+0x988] XOR0x8b3dc651`. Consequently its emitted length is exactly P, while the allocation/node extent is P+10 B.

This closes the preceding report's missing conditional allocator/header-length join. It assumes the same frame epoch, no intervening overwrite of these fields, disjoint heap/frame owners and the normal allocation-call preservation contract. Original frame stores in the selected prefix and register liveness support that composition; they do not establish arbitrary native aliasing or concurrent stability.

The scalar writer's V field similarly comes from the entry's W10 through K+`0xa664` and K+`0x8f8`. Its clear wire payload is BE32(V XOR`0x8b3dc651`), which the established reader recovers as V. This is a data-representation contract, not an application-specific meaning for V.

## Span count and source provenance [CI2-CI5]

For the selected internal discriminator `0x4118` (wire tag`0x50db`) and core-frame epoch`0x6cf4`, source phase calculations produce K+`0x8e0`=`0x24aa`, K+`0x920`=`0x9546`, and the count-gate inputs W14=`0x53c3`, W9=`0x5bc`. The original path is:

```text
after header 1004f4bc4
  -> [6f0f] 1005e72c4
  -> [24aa] 10058ac54
  -> [64ae] 1004c1dd4
       |
       +-- P=0  -> [4cf4] 1005ae7a0
       |
       +-- P>0  -> [4d18] 1005e58cc
                    -> [b1df] 100614278, countdown=P, source=S
                    -> loop end [b16e] 1005ae7a0
```

The count gate loads the full u64 Q saved at K+`0xa678`. Its arithmetic yields W13=`P XOR0xcec4fa97`; the predicate is exactly P!=0. Payload setup then recovers X15=`u64(P)`, reloads S from K+`0xa670`, loads the record buffer through node+`0x18`, and establishes the previously proved loop phase `0xb16e`.

The additive Q representation is proved for every u32 encoded E. It is not inferred from its zero-input value, and the decoder is not modeled as a low32 truncation of an arbitrary u64. The known producer supplies the full word. This resolves the span-count production premise for this selected route; arbitrary alternate producers of K+`0xa678` remain outside the claim.

Together with [the payload inverse](daemon_payload_codec_report.md), this identifies the selected nonzero span operation as P reads from S+i and P encoded stores at record-buffer+10+i, descending through i=P-1..0. The allocator provides P+10 B conditionally; actual source extent, readable S, successful allocation, disjoint owners and native continuity remain premises. The zero-length route bypasses copying. This does not prove full admission of every discriminator or payload size/type combination.

## Typed roots, saved continuations and next interface [CI2, CI6-CI8]

| Root under incoming phase`0x6cf4` | Established defaults | Saved continuation |
| --- | --- | --- |
| `0x100828290`, u32 cases | Internal T=`0x86b4` -> wire`0x9777`; E=`0x8b3dc655` -> P=4; S=0; additional raw u64 operand=`0x2c220a381b62f9ab` | Index`0x222` -> `0x100781e0c`, IA`0x151e` |
| `0x10069d718`, span cases | Internal T=`0x4118` -> wire`0x50db`; E/S remain caller inputs; raw W10=`0x8b3dc651`; additional u64 operand has the same constant | Index`0x1ee` -> `0x1006d8264`, IA`0x151e` |

The raw defaults are reported without assigning meanings to unused operands. The complete 8 B scalar route remains unresolved. Both roots reach entry `0x100700d80` in the retained selected episodes; native upstream phase production and a complete census of all callers are not established.

At common stage `0x1005ae7a0`, under incoming W16=`0x6cf4`, source clears an8 B local cell at K+`0x80b8`, reloads the container from K+`0x5508` into X8, reloads H_e from K+`0xa658` into W9, supplies X11=&[K+`0x80b8`], and preserves the phase in X22. It selects original index`0x18e2` -> `0x1006fd1b8`, IA`0xa818`. This identifies the next data/control interface; the callee's behavior, output-cell meaning and eventual constructor result remain unknown.

## Retained evidence and quantitative limits [CI6]

Each of the 12 preserved send profiles contains five selected constructor-entry episodes: three from the u32 root and two from the span root. Each recorded episode follows entry, guard, node allocation, record allocation, preparation and key setup, with two private modeled `_malloc` calls. Total counts are60 episodes,60 node/buffer pairs,36 u32-root and24 span-root occurrences.

The recorded allocations are32 B nodes and payload-plus10 B buffers. Payload extents in the source summary are explicitly derived from recorded allocation sizes; they are not incoming-register snapshots. Original heap-store/packet evidence in the preceding reports independently supports buffer/header layouts. All PAC authentication in the retained episodes was bypassed by the private model. The four historical profiles without a successful send remain outside these occurrence claims.

## Assumption register and falsification probes

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CI1 | Exact thin build and original source/fixups; all addresses and equations | Rehash executable, recapture16 fragments and31 prior ranges; other builds invalidate address transfer |
| CI2 | Selected entry/core/type epochs; guard, roots and span route | Universal compatible-route theorem plus selected phase calculations; native phase producer and other phase paths remain unknown |
| CI3 | Listed bank/table roots and ordinary saved-register/frame allocation ABI; cross-call E/H provenance | Exhaust all256 byte inputs per bank, verify original bind/modifiers, locate actual native roots and callees before generalizing execution |
| CI4 | Valid nonwrapping frame/heap owners, stable saved fields and no interfering alias/write; field and extent joins | Source write/liveness records delimit the prefix; actual allocator/frame/lifetime/concurrency evidence is still required |
| CI5 | Selected span discriminator and saved-Q producer; exact copy count/source | Rebuild Q/decoder/source-relay queries; another Q producer or altered frame invalidates the composition |
| CI6 | Retained models accurately describe their own events; finite occurrence counts | Verify pinned profiles, ordered branch/call episodes and allocation sizes; private addresses and PAC bypass are not native observations |
| CI7 | Normal scalar/span roots do not prove all type/extent admission or source validity | Recover full constructor type tree, u64 route and source-owner checks; no malformed or failure fixture is newly executed |
| CI8 | Common-stage input contract is not the final constructor result | Follow `0x1006fd1b8`, establish local-cell effects, list/lifetime changes and final status/continuation behavior |

## Bounded continuation, reproduction and gates

| Impact | Next evidence target | Remaining uncertainty |
| --- | --- | --- |
| High | Continue at `0x1006fd1b8` with the container/identifier/output-cell contract | Lookup/replacement/list behavior and the final constructor result |
| High | Complete type admission, 8 B scalar serialization and lifetime paths | Full typed-record ABI beyond the selected u32/span roots |
| High | Establish native endpoint/owner/phase continuity across FairPlayIOKit and daemon | Selector26/RPC502/700 pairing, rights and delivery remain unproved |
| Medium | Map every constructor caller's raw operands back to its public/architectural source | Which fields are externally supplied versus internal constants and borrowed pointers |
| Low | Reuse the additive count codec and unified payload-length contract | Avoid inferred equality from similar XORs or frame/register names |

```text
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_constructor_inputs.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_constructor_inputs.py
```

Extraction is O(image bytes + fixup count + retained journal bytes), for the fixed12-profile corpus. Translation is O(selected instruction instances); byte-bank checks are exactly512 cases. Solver complexity is separate with15000 ms per query. Unspecified registers/controller loads remain independent bit-vector variables; no private CPU or target instruction stream runs. All extents use B; widths, endianness and modular domains are explicit in the source contracts and linked header report.

QG1: No normative content is required. QG2: CI1-CI8 identify dependencies and falsification probes. QG3: Entry fields, selected guard/calls, header/scalar relays, span count/source and next frontier are covered for this increment; full goal completion remains unproved. QG4: u32/u64 domains, byte extents, additive count codec, nonwrapping admission and computational cost are explicit. QG5: Compatible versus native phase, named loads versus native memory, source joins versus ownership and finite models versus execution are separated. QG6: Original source/fixups/banks, independent queries and frozen event ledgers provide primary provenance. QG7: Impact-bounded continuations retain the complete constructor, owner and endpoint obligations.

The goal remains active. Native PAC, authorization, allocation/ownership, complete constructor return and actual daemon-kext exchange remain unknown.
