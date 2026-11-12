# CoreFP1201 auxiliary bit interfaces and complete arithmetic consumer

Original `0x59f4e8` computes an encoded magnitude's bit length; original `0x57af24` selects a magnitude bit using an encoded signed index. Complete private continuations identify `0x1142154`, through wrapper `0x1142c08`, as a Montgomery exponentiation consumer on the tested canonical odd inputs. Fourteen independently replayed complete results match `pow(b,e,n)`. Two even-modulus controls remain diagnostic. Eight retained unbacked auxiliary descriptors stop before their first payload read. The next complete-case boundary is unexecuted `0x981bc8 -> 0x32f628`; native export, request completion and daemon/kext pairing remain unknown.

## Evidence and assumption register

Primary evidence is the pinned CoreFP arm64e source, the [fresh IDA readback](triage_evidence/fpsd1201_auxiliary_ida_readback.json), complete private [execution journals](triage_evidence/fpsd1201_auxiliary_checks.json), and a separate [fresh replay receipt](triage_evidence/fpsd1201_auxiliary_audit.json). Logical JSON links resolve to compressed `.json.zst` artifacts. The [producer](triage_evidence/recover_fpsd1201_auxiliary.py) and [auditor](triage_evidence/audit_fpsd1201_auxiliary.py) retain reproducible fixtures and distinct integer oracles. This increment resumes the [product report](fpsd1201_product_report.md)'s audited checkpoints; it does not rerun their prefix instructions.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| AX1 | The pinned image, original bytes, compiler starts, banks and fixup words identify these bodies. All addresses below depend on this image. | Independently parse the universal image and selected slice; compare 79512 original fixup words, 1602 starts, 3072 B of banks and all 40412 B of selected code. A mismatch rejects this increment. |
| AX2 | Original control-flow destinations are modeled from authenticated IA rows with address diversity 0. Private reachability depends on that model. | Check each source pointer load, row target/diversity, complete pre-branch CPU frame and continued journal. Native PAC validation is unknown. |
| AX3 | The preceding product receipt validates the restored private state. Complete consumer claims depend on its canonicalized input and prepared pair. | Pin receipt SHA-256 `219fd7b1a149580151b1fe9475f25652cf2990e526c7ce872d3bf53bec57ca7e`, generator/auditor identities and exact restored RAM; separately associate each checkpoint's reaching pointer load. |
| AX4 | Twelve new exponent descriptors and 186 isolated helper records are explicitly supplied diagnostic inputs. Their native production is unknown. | Reconstruct every changed byte independently and compare before/after controls. No arithmetic result is injected. Preserve the eight unbacked retained boundaries. |
| AX5 | The numerical exponentiation interpretation requires the tested canonical odd-modulus context and nonnegative exponent. Universal consumer equivalence is unproved. | Compare complete results with independent integer exponentiation, and each square/query/conditional-product order with the exponent bits. Keep even controls and earlier width-mismatched counterexamples separate. |
| AX6 | Declared private stack, RAM, mutable globals and guard state suffice for these executions. Native initialization, descriptor capacity and ownership remain unknown. | Check all reads/writes, full CPU observations, three complete RAM regions and operand preservation. Stop before unbacked reads or unretained callees; execute no native target API. |
| AX7 | A local arithmetic result and stack-accounting store establish no native IPC join. Transport conclusions depend on explicit API/right evidence. | Check the executed bodies and call journal for Mach operations; follow the unexecuted export dependency before assigning destination, lifetime, transport or daemon/kext identity. |

The universal image SHA-256 is `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; the arm64e slice SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Both new IDA spans match IDA original bytes and the reference file. No IDB edits are requested.

| Body | Compiler-bounded extent | Size | IDA's initial function end | Role |
| --- | --- | --- | --- | --- |
| `0x59f4e8` | `[0x59f4e8,0x59f708)` | 544 B | `0x59f61c` | Magnitude bit length; plain RET at `0x59f704` |
| `0x57af24` | `[0x57af24,0x57b094)` | 368 B | `0x57b05c` | Magnitude bit selection; plain RET at `0x57b090` |

The initial IDA extents omit reachable continuation blocks. Compiler boundaries and original bytes supply the complete selected extents; no function-boundary edit is needed for this evidence.

## Descriptor and length record [AX1-AX4,AX6]

Descriptors retain signed count `s32(MEM32[D+4]-0x4b0cf050)`, payload pointer `MEM64[D+8]`, and little-order 32-bit magnitude limbs decoded by XOR `0x1ac70ef2`. Word D+0 remains metadata of unknown native capacity/ownership meaning. A negative count supplies magnitude limbs under the same absolute-count rule; it does not change either helper's magnitude result.

For length-record address A and p=low32(A), all arithmetic below is modulo 2^32 unless stated otherwise:

```text
H = (p XOR 0x1766cddd) * 0xb7a7bfff
MEM32[A] + H = 0x951a
```

| Length-record offset | Width | Role / emission |
| --- | --- | --- |
| +0x00 | 32 bits | Encoded entry state, read at `0x59f574` |
| +0x04 | 32 bits | Result `0x4fe66f44 + magnitude_bit_length`, stored at `0x59f6fc` |
| +0x08 | 64 bits | Descriptor D, read at `0x59f57c` |

The source expression `((2*(p AND 0x11f97c13)-p+0x6e0683ec) XOR 0x79604e31)*0xb7a7bfff` equals H for every 32-bit p; retained and independently reconstructed solver obligations pass. The selected state derives the count subtraction constant from flattened state, then applies a signed absolute-count operation. It scans encoded zero limbs downwards at `0x59f650`, decodes the highest nonzero limb, and scans its highest set bit.

```text
q = signed32(abs32(decoded_count))
if q <= 0: return 0
j = q - 1
while j >= 0 and encoded_limb[j] == 0x1ac70ef2: j -= 1
if j < 0: return 0
return 32*j + bit_length(encoded_limb[j] XOR 0x1ac70ef2)
```

The return above denotes the unbiased mathematical result; the actual store adds `0x4fe66f44`. Leading encoded-zero limbs are tolerated. Forty isolated complete cases cover zero, positive/negative counts, up to 2048 significant bits, two extra leading zero limbs, a null-payload zero count, and count INT32_MIN. The last count remains negative after width-limited absolute value and returns zero without a payload read. Native admission of that representation remains unknown. The scan takes O(q+32) time and O(1) auxiliary space for backed finite counts.

## Bit-selection record [AX1-AX4,AX6]

For bit-record address A, the selected entry state is:

```text
H = ((low32(A) XOR 0x542fbf9b) * 0x4386951d) mod 2^32
MEM32[A+8] + H = 0x6873
t = s32(((MEM32[A+4] XOR H)*0xef42366d + 0x02a682df) mod 2^32)
index = abs32(t)                         # unsigned bit pattern
```

| Bit-record offset | Width | Role / emission |
| --- | --- | --- |
| +0x00 | 32 bits | Result `0xc0a17a28 OR selected_bit`, stored at `0x57b088` |
| +0x04 | 32 bits | Encoded signed index |
| +0x08 | 32 bits | Encoded entry state |
| +0x10 | 64 bits | Descriptor D |

The inverse index codec is `(((t-0x02a682df)*0x43ea4365) mod 2^32) XOR H`; `0x43ea4365*0xef42366d = 1 mod 2^32`. The negative arm `0xfd597d21-u` equals `-(u+0x02a682df)` modulo 2^32. Two more retained and independent UNSAT obligations establish these identities.

The source compares `index>>5` with the signed absolute-count value. An admitted limb is read at `0x57b060`, decoded, shifted by `index mod 32`, masked to one bit, and combined with the even result bias. An index outside the active count returns the biased zero without reading payload. For ordinary backed descriptors this equals `(abs(magnitude) >> abs(t)) AND 1`. Negative indices therefore reflect to their absolute value; they do not select two's-complement sign-extension bits. INT32_MIN index retains unsigned magnitude 2^31 and lies outside every tested small descriptor. INT32_MIN count produces zero under the signed count comparison.

The 146 isolated complete cases cover six magnitudes, both count signs, 12 index values including limb boundaries, negative indices and INT32_MIN, plus null-payload zero/minimum-count controls. Each helper preserves its descriptor, active payload and non-result record bytes and restores its 16 B stack reservation. The bit helper takes O(1) time and O(1) auxiliary space for an admitted record.

Both bodies update private obfuscation globals and use original lookup/fixup rows for intra-body continuations. The length body touches globals `0x1d43eb0` and `0x1d37f68`; the bit body touches `0x1d377f8` and `0x1d37f68`. Those dependencies are retained and checked; these are not claims of side-effect-free native functions.

## Consumer arithmetic, control flow and return [AX1-AX6]

The incoming consumer record from the prior report contains Q at +0, output descriptor at +8, encoded control at +0x10, auxiliary descriptor at +0x18, imported input descriptor at +0x20 and modulus descriptor at +0x28. The auxiliary descriptor is an exponent input in the tested arithmetic sequence. The explicit null-auxiliary path retains the source-initialized scalar 65537. Twelve new controls replace only the auxiliary input descriptor/backing at the audited pre-length checkpoint; their values are diagnostic inputs, not native context products.

```text
Earlier audited prefix: Mont(b, R^2 mod n) -> bR mod n; copy R mod n -> accumulator
                              |
                      bit_length(exponent)
                              |
             for index = bit_length-1 down to 0
                 square accumulator in Montgomery domain
                 query exponent[index]
                 if 1: multiply by converted b
                              |
             source initializer produces ordinary scalar 1
                 Mont(accumulator,1) -> ordinary result
                              |
                 copy to consumer output descriptor
                              |
       child RETAB -> wrapper stores zero adjustment -> caller resumes
                              |
             stop before 0x981bc8 -> 0x32f628
```

This is the compact interpretation supported by the tested complete sequences and the prior primitive contracts. It is not a universal proof for every descriptor, alias, exponent sign or modulus. The audit checks every query index in descending order, one square per significant exponent bit and one conditional product per set bit, including zero exponent and the 32-bit dense/sparse cases.

| Caller site | Original slot | Target | IA diversity | Local role |
| --- | --- | --- | --- | --- |
| `0x11425bc` | `0x1d037a8` | `0x59f4e8` | `0x7c9f` | Exponent bit length |
| `0x11429e4` | `0x1d04298` | `0x9dd7e4` | `0xb7d3` | Montgomery square wrapper |
| `0x1142ac8` | `0x1d04058` | `0x57af24` | `0xe454` | Exponent bit query |
| `0x1142be4` | `0x1d03d18` | `0x74fd0c` | `0xca9b` | Conditional Montgomery product |
| `0x1142700` | `0x1d039d8` | `0x181b00` | `0x58b1` | Scalar-one initialization |
| `0x11427b0` | `0x1d03d18` | `0x74fd0c` | `0xca9b` | Final domain conversion |
| `0x114283c` | `0x1d039b8` | `0x649430` | `0x8dc5` | Output descriptor/limb copy |
| `0x981bc8` | `0x1d03d10` | `0x32f628` | `0xa77e` | Next unexecuted dependency |

All selected rows use key IA and address diversity 0. Each original pointer association and pre-call frame is checked. The incoming checkpoint call additionally pins the reaching load in the preceding receipt; a new load is not fabricated after restoration.

The 12 retained continuations comprise four backed source-scalar controls and eight unbacked auxiliary controls. The eight stop before `0x59f650`, whose computed 4 B read address is `0xa5a5a5a710087af5`; that instruction is not executed. This is a declared private-fixture boundary, not an observed native fault. The four backed controls complete the child and wrapper: n=3 and n=7 match modular exponentiation; n=2 and n=0xfffffffe remain even-modulus diagnostic controls.

The 12 explicit exponent controls use n=65537 with e in {0,1,2,3,17,65537,0x80000001,0xffffffff}, and n=0xffffffff with e in {0,2,17,65537}. Their canonical imported b values are respectively 65536 and 0x12345678. The former tests zero and parity-sensitive powers; the latter supplies nontrivial interior-base cases. All 12 match independent modular exponentiation. In particular, `(0x12345678^17) mod 0xffffffff = 0x71793aef`. No claim of a native RSA key, signature decision or authorization result follows from these diagnostic moduli/exponents. The earlier six retained width-mismatched odd counterexamples remain applicable outside the canonical contract.

All 16 complete children execute RETAB `0x1142874`, restore their raw incoming cursor, return through wrapper RETAB `0x1142e2c`, and resume caller `0x9819c8`. Wrapper STR `0x1142e18` writes an 8 B zero stack adjustment to the caller cursor. This is a stack-accounting output, distinct from the arithmetic descriptor. The root status remains `0xa5a5a5a5`; its separate output seed is preserved. Candidate inline `P+0x880..P+0x8ff` is neither read nor written by these continuations. The next record contains that destination pointer and the arithmetic result descriptor, but its receiving implementation remains unexecuted.

| Emission location | Object | Established consequence |
| --- | --- | --- |
| `0x59f6fc` | Record+4, 4 B | Biased bit length |
| `0x57b088` | Record+0, 4 B | Biased selected bit |
| `0x114283c` calling `0x649430` | Consumer output descriptor/backing | Complete local integer delivery |
| `0x1142e18` | Separate cursor cell, 8 B | Zero stack adjustment on 16 complete calls |
| `0x981bc8` | Outgoing private record | Unexecuted dependency; no downstream emission established |

No newly executed path invokes a Mach API or emits a Mach right. Incoming arguments and outgoing arithmetic/cursor values are private process objects. The [Mach-port report](mach_ports_report.md) retains the established transport evidence; native endpoint identity, rights, lifetime and daemon/kext/deeper joins remain unknown [AX7].

## Independent checks and bounded continuation

Fresh replay checks 210 profiles, 427091 source visits, 66724 reads, 25205 writes, 13710 explicit PAC models, 778 helper points and 48 consumer points. Independent numerical checks cover 56 bit-length returns, 329 bit selections and 14 complete modular exponentiations. There are 186 complete isolated helper returns, 16 complete consumer children/wrappers and eight pre-read frontiers. Three retained and three independently reconstructed solver obligations pass. Complete initial/restored/final RAM, original pointer associations and complete observed CPU frames are checked separately; passing private guard comparisons does not establish native initialization. The publication verifier checks logical hashes, compressed storage, owned-file scope and decoded typed-RAM path hygiene.

| Impact | Bounded next investigation | Falsification / current limit |
| --- | --- | --- |
| High | Recover `0x32f628` and connect the result descriptor to the candidate inline destination. | Establish source byte order, length, zero/padding behavior and complete return. Current call is unexecuted; no output buffer write is claimed. |
| High | Establish source-produced modulus, exponent and input admission. | Trace native context producers and width/normalization invariants. Existing canonical controls and width-mismatched counterexamples constrain interpretations. |
| High | Join completed request1201 output to transport and the daemon/kext/deeper endpoint. | Follow the remaining caller return, reply/right path and concrete identity. Local arithmetic completion supplies no IPC join. |
| Medium | Bound exponent representation and timing dependence. | Query-index order and conditional-product counts vary with the diagnostic exponent. Native exponent secrecy, scheduling and observability remain unknown; no native side channel is established. |
| Medium | Recover malformed-count and capacity admission. | INT32_MIN yields helper zero locally; trace validators before interpreting that behavior beyond the private record. |
| Low | Extend consumer coverage beyond one-word moduli and nonnegative exponent inputs. | Prior primitives cover wider canonical products; the complete consumer has not been validated at those widths. |

Quality gates: **QG1** factual technical analysis requires no normative content. **QG2** AX1-AX7 record assumptions, dependent results and probes. **QG3** this increment covers helper roles, incoming/outgoing record fields, arithmetic/data/control flow, original dispatch interfaces, exact result/stack stores and port consequences. **QG4** B denotes bytes; counts/limbs, signedness, modular widths and complexity are explicit. **QG5** zero, leading-zero, negative index/count, INT32_MIN, even modulus, canonical preconditions, unbacked and native limits remain separate. **QG6** reference bytes, fresh IDA, source parsing, pinned predecessor receipts, fresh replay and separate integer oracles support the claims. **QG7** impact-ranked continuation is bounded. The full investigation remains active.

The [export and complete helper report](fpsd1201_export_report.md) resolves the previous 0x32f628 boundary. Sixteen retained complete arithmetic cases export 128 B into the candidate destination and finish the local helper; two explicitly shortened exports reject locally while the caller still publishes its root success marker and saved nominal width. Native parent continuation and delivery remain unexecuted.
