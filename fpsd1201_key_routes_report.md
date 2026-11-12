# CoreFP1201 optional-input routes and signed comparison record

The continuation after the seed tuple performs one source-defined state update, invokes two record predicates, then selects a read from an optional-input pointer that is zero in the retained fixture. A separate selector-byte experiment identifies image+0x1d44409 as an exact equality-to-1 gate into an earlier preparation route. That route needs an object loaded from image+0x1d32e18, whose original backing is 0x176cb4e3. Both experiments stop before the unresolved reads. The complete 35-instruction helper at 0x439734 selects signed or unsigned u64 less-than from an address-keyed record. These are conditional source contracts; native initialization, complete mixing/output and daemon/kext exchange remain unknown.

## Evidence and assumption register

The [producer](triage_evidence/recover_fpsd1201_key_routes.py), [checks](triage_evidence/fpsd1201_key_routes_checks.json), [independent auditor](triage_evidence/audit_fpsd1201_key_routes.py), [receipt](triage_evidence/fpsd1201_key_routes_audit.json), [IDA availability record](triage_evidence/fpsd1201_key_routes_ida_availability.json) and [publication verifier](triage_evidence/verify_fpsd1201_key_routes_publication.py) retain the evidence. Logical JSON links resolve to compressed `.json.zst` artifacts. The preceding [seed report](fpsd1201_seed_report.md) and [predicate report](fpsd1201_predicates_report.md) remain the restoration authorities.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| KR1 | The pinned original CoreFP image, compiler bounds and format12 rows identify the source. | Verify universal/slice hashes, complete parent/leaf bytes, every dependency and selected dispatch row. A different installed image is not substituted. |
| KR2 | Frozen private prefix models and the omitted request1200/status-check boundary apply to all restored continuations. | Refresh 19717 original prefix visits, compare its full result/CPU, then compare every new initial RAM page with the receipt-restored source. Discharge the omitted call and initialization before claiming native admission. |
| KR3 | Post-tuple cases inherit the declared entropy/time and clobber premises of their seed receipts. | Restore all retained touched RAM and full CPU for each selected case. Check the first state update independently and preserve the untouched tuple/context bytes. No new entropy/time return is supplied. |
| KR4 | Selector values 0, 1, 2 and 255 are explicit sensitivity inputs, not observed native states. | Retain the original zero byte and each one-byte control; prove the equality-to-1 partition for all 256 possible bytes. Recover its actual writers before assigning a native readiness meaning. |
| KR5 | Selector cases model CASAL as a sequential compare/exchange. | Verify its exact original instruction, original 0x5d96 token, 0xa94ef replacement and complete before/after CPU/RAM. Native ordering, ownership and synchronization remain unknown. |
| KR6 | Private IA/PAC transfers use original decoded slots and normalized targets. | Check each reaching load, format12 row, IA diversity, address-diversity bit and complete CPU. Native PAC acceptance is outside this model. |
| KR7 | The complete comparison leaf receives valid record backing; u32/u64 operations wrap modulo their widths. | Lift all 35 instructions, prove the address-key identity and body for an arbitrary key, and execute 128 boundary cases at four placements. The 36 B accessed footprint does not establish a C object size or wire ABI. |
| KR8 | Original file/global and private stack backing are not established native objects. | Stop before both unresolved loads; trace their exact producers rather than supplying a guessed pointer. Preserve the distinction between zero, an unmapped backing value, and initialized native state. |

CoreFP universal SHA-256: `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; arm64e slice SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Preferred image base is zero. The full parent `[0x8e81c8,0x8fcfa0)` is 85464 B, SHA-256 `4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e`. Complete leaf bytes are checked independently against that original image.

## Pointer roles and source frontiers [KR1-KR6,KR8]

The actual selector read at 0x8ea8b0 uses the pointer loaded from SP+0x3c8. That pointer resolves to image+0x1d44409. It is separate from the saved pointer at SP+0x390 to image+0x1d47fb0. The earlier bounded indexed-xref snapshot of selected globals did not establish the selector's writer or lifecycle.

| Frame / source location | Recovered role in these cases | Evidence boundary |
| --- | --- | --- |
| SP+0x3c8 -> image+0x1d44409 | One-byte selector, read 0x8ea8b0 | Only exact value 1 selects preparation |
| SP+0x390 -> image+0x1d47fb0 | Separate saved global pointer | Not the selector byte |
| SP+0x438 | Optional-input value/pointer used by later mixing | Zero on the retained fallback route; its native lifetime is unknown |
| SP+0x450 -> image+0x1d32dd0 | Preparation object holder/base | Read at 0x8eadf8 |
| image+0x1d32dd0+0x48 | Next preparation-object value | Read at 0x8eadfc: 0x176cb4e3, matching original file bytes |
| SP+0x418 | Encoded control word | 0xf1d46bcc in the retained prefix; source store 0x8e89f4 |
| SP+0x498 -> C+0x6f0 | Seed tuple/time scratch T | T=SP+0x1a30 in these frames |

Each selector case refreshes the frozen prefix and restores the previous pre-CASAL receipt. After its explicit one-byte control, the original comparison at 0x8ea8b4 tests equality to 1. Values 0, 2 and 255 take 0x8eb7a4, source-store X13=0 into SP+0x438, restore the token, and stop before the first entropy call. Value 1 takes 0x8ea8ec, executes 453 source instructions in total, reads the holder field above and reaches 0x8eaebc with X23=0x176cb4e3. The next original instruction is `LDR X15,[X23,#8]`; it is not executed. This exposes an unresolved initialization/object premise, not an observed native fault or proof that the backing word is a valid pointer.

```text
before CASAL receipt -> declared sequential CASAL -> selector byte
                                                     |
                             +-----------------------+------------------+
                             |                                          |
                          byte == 1                                  byte != 1
                             |                                          |
                       preparation route                      SP+438 <- 0; token reset
                             |                                          |
                  holder+48 -> 0x176cb4e3                      stop before entropy
                             |
                   stop before object+8 load
```

| Selector / gate | Dispatch index | Original slot | Original target | IA diversity |
| --- | --- | --- | --- | --- |
| Selector byte == 1 | 0x8954 | 0x1cc63e0 | 0x8ea8ec | 0x1414 |
| Selector byte != 1 | 0x892c | 0x1cc62a0 | 0x8eb7a4 | 0x1414 |
| Later optional-input arm | 0x5b47 | 0x1caf378 | 0x8eba0c | 0x7dd1 |
| Later local tuple arm | 0x5b31 | 0x1caf2c8 | 0x8ebee8 | 0x7dd1 |

The first selector partition is proved over every u8 input under the recorded source phase/register inputs. The four concrete selector cases do not establish arbitrary upstream reachability.

## First mixed word and later input gate [KR1-KR3,KR6,KR8]

Four post-tuple cases restore `clock_A`, `clock_B`, `clock_error_no_write` and `clock_A_clobber` from the preceding seed receipt, before 0x8eb9b4. There is no input patch or omitted instruction inside these new suffixes. Each executes 276 original instructions and exactly one state-array write. With all state/key terms u32:

```text
S[1] <- (S[1] XOR ((S[0] XOR (S[0] >> 30)) * 1664525)) + T[0]
```

Original 0x8ebb98..0x8ebbd4 implements this first iteration with state index i=1 and tuple index j=0. The independent oracle reads both original state words and the tuple from the restored initial RAM, then checks the exact store address, width and result. Each case has S[0]=305419896, initial S[1]=775181657 and T[0]=267242409, producing S[1]=651046122 modulo 2^32. The other 623 state words receive no new store. The tuple remains unchanged; the four cases share the first consumed tuple word, so this single update does not establish independence from later time/key inputs.

The source at 0x8eb9b4..0x8eb9e4 also computes a u32 term from the saved optional-input value. Under the recorded W27=0xc1f7, a universal identity reduces that term to low32(SP+0x438's contents), stored at SP+0x428. This distinguishes pointer-derived data from the tuple, global state array and control word. Its later complete mutation/use is not executed here.

After two complete predicate calls, the later gate at 0x8ebe90 uses W=MEM32[SP+0x418], Q=W22 and the source phase W23=0xc1f7. Define t=(Q>0x61cde228) as an unsigned comparison, represented by 0 or 1:

```text
index = ((W & 1) == t) ? 0x5b47 : 0x5b31
```

The source-derived partition is proved for every u32 W and Q at that phase. All four retained cases reach this gate with W=0xf1d46bcc and Q=0x61cde226, selecting the optional-input arm at 0x8eba0c. The source computes j=1, byte offset 4, then forms X12=MEM64[SP+0x438]+4. The saved value is zero; execution stops before `LDR W13,[X12]` at 0x8eba44, with X12=4. No read from address 4 occurs and no guessed backing is supplied. The alternative tuple arm is source-resolved but not taken by these four suffixes.

```text
receipt before key-mix preparation
               |
        one state[1] update
               |
      leaf 1abbe0 -> result 245a at R+20
               |
      leaf 439734 -> result 252a at R+00
               |
       encoded control/index gate
               |
      optional-input index j=1
               |
       saved input 0 + 4
               |
   stop BEFORE load at 0x8eba44
```

## Complete helper at 0x439734 [KR1,KR6,KR7]

Analysis label: `compare_select_signed_or_unsigned_less_record`. No IDB symbol is changed. The complete `[0x439734,0x4397c0)` body is 140 B / 35 instructions, with no calls or stack adjustment. It preserves X0=R, modifies X8-X14 and NZCV, and writes only the u32 at R+0. Define H and h:

```text
H = u64(((R XOR 0x2f2e0531b9d8df3b) XOR 0xab99749f60a72103)
        * 0xfcf33521)
h = low32(H)
```

| R-relative offset | Width | Decoded field / effect |
| --- | --- | --- |
| +0x00 | 4 B | Output; prior contents are not read by this leaf |
| +0x04 | 4 B | false_choice = raw - h |
| +0x08 | 4 B | mask = raw + h |
| +0x0c | 4 B | mode = raw + h; only bit 0 selects signedness |
| +0x10 | 8 B | A = raw - H |
| +0x18 | 8 B | B = raw - H |
| +0x20 | 4 B | true_choice = raw XOR h |

```text
test = (mode & 1) ? signed64(B) < signed64(A) : unsigned64(B) < unsigned64(A)
MEM32[R] = mask XOR (test ? true_choice : false_choice)
```

The source's OR-minus-AND address expression equals XOR for every u64 R. Its exact constant construction and multiplication feed the remaining body. Two compositional UNSAT obligations establish that identity and the complete remaining body for every independent u64 key and every raw record byte. A monolithic query exceeded its 30 s budget and is not counted as a proof. The delivered obligations do not assume unsigned ordering is preserved by modular addition/subtraction; comparisons apply to the decoded operands at their proper widths.

The 128 isolated original-byte executions cover four record placements, four mode values (0, 1, 2, 0xffffffff), and eight operand pairs covering equality, opposite order, zero, 2^64-1 and the signed boundary. One placement crosses a mapped-page boundary. All 48 surrounding test bytes are compared, establishing the selected four-byte output and preservation of the rest in those cases. The universal body proof covers the output equation; these finite runs separately check the complete instruction execution and untouched bytes. The minimum accessed footprint is 36 B. Native object size, packing and external serialization remain unknown.

The selected caller at 0x8ebe34 reaches the leaf through original slot 0x1d03648, IA diversity 0xba46. The preceding call at 0x8ebca0 selects 0x1abbe0 through slot 0x1d03a70, IA diversity 0x9eeb. Every row and transfer is retained in the journal. R=FP-0xb8=0x7a037f38. All four calls decode H=0xe7e28d864cc1a100, mode=0, A=0x61cde225 and B=0x61cde226, so the test is false and the output is 0x252a at R+0. The earlier leaf at 0x1abbe0 instead writes its independent output 0x245a at R+0x20. Both complete calls and the unchanged remainder of each 44 B caller-record snapshot are independently checked. Their output offsets are separate ABI contracts.

## Verification, cross-layer limits and bounded continuation

Eight fresh producer prefixes and one independent prefix refresh preserve the previous request1200/status gap and all declared private models. Independent suffix replay checks 1728 visits, 278 reads, 102 writes, 48 IA/PAC models, four sequential CASAL models, 46 CPU checkpoints and 454656 B of initial/final RAM each. The 128 isolated leaf cases and five delivered UNSAT obligations pass. The three source-route obligations additionally check 41 exact instructions and four original dispatch rows. A conservative producer/auditor time/space bound is O(C*(B+F+V+J+R)+L*K), including per-case image setup, prefix effects, retained visits/byte effects and isolated leaf cases; C counts profiles, B source bytes, F prefix effects, V source visits, J serialized journal bytes, R read/write effects, L leaf instructions and K isolated cases. Solver work has a separate 30 s per-query bound.

Read-only MCP discovery listed only `firmware_dump.bin`; a recall attempt against the previous CoreFP target could not resolve that database. No current target-IDB corroboration or target-specific memory retrieval occurred. The source-file and retained-receipt checks above supply this increment's evidence; the prior IDA snapshot is historical. No database is mutated.

The new suffixes add no Mach operation, incoming/outgoing native port, right transfer or emission site. They do not discharge request1200, execute the later request1201 builder, identify a native output payload or pair a daemon/kext exchange. C[0:128] still contains the nine source-produced prefix bytes followed by 119 diagnostic zeros; none of those remaining bytes becomes source-defined here.

| Impact | Bounded continuation | Required discriminating evidence |
| --- | --- | --- |
| High | Recover selector-byte and preparation-holder initialization. | Actual writers of image+0x1d44409 and image+0x1d32e18, object layout/lifetime, and their relation to the frozen warm-prefix models. |
| High | Join optional-input production to the later mixing reader. | Same-epoch producer of SP+0x438 and successful preparation through the object+8 boundary; backing values alone do not establish valid native pointers. |
| High | Complete mixing, state lifetime and C[9:128] production. | Original-byte updates and an independent whole-state/output oracle without replacing unresolved pointer inputs. |
| High | Discharge request1200 and join the request1201 endpoint lineage. | Original return checks, reply state and matched daemon/kext endpoint/right epochs. |
| Medium | Classify additional callers of the signed/unsigned comparison leaf. | Preserve each caller's key, operand decoding, mode and output offset rather than merging private record ABIs. |
| Low | Compare the local source contracts with the daemon's recovered seed-material path. | Explicit image-specific mappings and data dependencies; structural similarity does not prove shared state or transport. |

Quality gates: **QG1** factual analysis requires no normative content. **QG2** KR1-KR8 state dependencies and falsification probes. **QG3** this increment covers selector/environmental state, pointer and control frontiers, one mixed-state update, complete obfuscated helper ABI and cross-layer evidence limits. **QG4** B denotes bytes; u8/u32/u64 widths, modulo arithmetic, signedness, extents, counts and complexity are explicit. **QG5** backing/native objects, two selectors, two predicate-output offsets, conditional source paths and native faults remain distinct. **QG6** pinned original bytes, receipt-restored CPU/RAM, independent replay, complete source lift and dispatch rows support the claims; unavailable target IDA is explicit. **QG7** the continuation table bounds and ranks the remaining work. The full goal remains active.

## Separate environmental interface follow-up

The [network-identity increment](corefp_network_identity_report.md) recovers the nearby six-byte cache and its lazy initializer. Its original writes affect image+0x1d443c0 and status +0x1d25200; the once predicate is +0x1d443c8. They do not initialize the selector at +0x1d44409 or holder at +0x1d32e18. Getter reachability from the protected parent remains unknown, so this environmental interface does not discharge the optional-input frontiers above.
