# Retirement metadata query and caller contract

The original query returns a raw u16 element-extent field and optional zone/offset outputs. Two offset layouts destructively read a u16 field when the discriminator is nonzero. The selected retirement caller supplies discriminator1, rejects zero extent or an insufficient remaining span, and passes the recovered base, original14/32 B request, zone and element extent to the next kernel routine. Native metadata coherence, allocation identity, ownership and actual retirement remain unknown.

This extends [kernel allocator boundaries](kernel_allocator_boundary_report.md) and the earlier [selected48 B MixedData retirement](mixed_data_retirement_report.md). The earlier report establishes a selected allocation-displacement inverse and clear/handoff contract. This increment models all68 query instructions, both offset-index encodings, optional outputs and the14/32 B caller gates. No new Mach endpoint, right transfer or emission site is established.

## Primary evidence and claim register

New source comes from kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The normalized kext SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` pins predecessor caller evidence. Compiler-bounded query/caller/lower function captures exactly match the earlier MixedData capture; the caller also matches the allocator-boundary capture. No additional IDA evidence was needed.

| Original function role | Interval, exclusive end | SHA-256 |
| --- | --- | --- |
| Query, no exact original symbol | 0xfffffe000bd792dc..0xfffffe000bd793ec | 8737406c13403ba799774cafdf2c732ebd297133dc0325628543e619cbaeb436 |
| Size-retirement caller | 0xfffffe000bcfec48..0xfffffe000bcfed8c | 2f24125bb30423f5d7b6079ca4359defa18f0e42618e8afc5988c3e12a70c1ba |
| Next retirement routine | 0xfffffe000bcfed8c..0xfffffe000bcfeeb0 | 623d907bbadae6222b2b3f2ee324feb2e5b8459b6424ffdaff3c2a7519a9c229 |

| Claim | Established result | Dependencies |
| --- | --- | --- |
| KQ1 | The unsigned range gate admits exactly a nonwrapping8 B span within the runtime interval | KQ-A1-A4 |
| KQ2 | Accepted metadata forms the exact10-bit zone index,192 B zone address and u16 extent result | KQ-A1-A4 |
| KQ3 | Optional outputs, zero-offset routes and special-layout offset/read-clear effects follow the source; aliased outputs have the observed store order | KQ-A1-A5 |
| KQ4 | Both large-layout index encodings, signed boundary calculation and indexed offset/read-clear tail are covered by modular source certificates | KQ-A1-A5 |
| KQ5 | The14/32 B caller admits only nonzero extent with offset+request<=extent and requests the regular recovered base, original request, zone and element extent | KQ-A1-A6 |
| KQ6 | The query/caller ABI joins preserve the relevant registers and use two distinct frame cells; five separate composition formulas establish base/extent and field-validity consequences | KQ-A1-A7 |
| KQ7 | The complete query has five store instructions, no external call, and no SP or callee-saved GPR write; these bounds qualify its architectural effects | KQ-A1-A5, KQ-A7. Native side effects outside the declared storage epoch remain unknown |

## Query arguments, range gate and classification

| Query input | Recovered meaning |
| --- | --- |
| X0 | Pointer P to classify |
| X1 | Nullable8 B zone-output cell |
| W2 | Raw discriminator: zero preserves a selected offset field; nonzero clears it after reading |
| X3 | Nullable8 B offset-output cell |
| Return X0 | Zero-extended u16 extent E from zone+0x34, or0 on range rejection |

The query has BTI C and ordinary RET instructions, with no stack frame or external call. The model implements the C/Z flags used by ADDS/CMP/CCMP and the unsigned/equality conditions that consume them. It does not infer native return, PAC behavior elsewhere or allocator ownership.

Runtime globals at0xfffffe0007e66e50/+8 provide unsigned bounds L/U. With MAX=2^64-1, the source range gate is exactly:

```text
P <= MAX-8  AND  L <= P  AND  P+8 <= U
```

Thus the first8 B span fits the declared interval without carry. This does not validate the requested14/32 B allocation or its lifetime. On range rejection the query returns0, performs no store through X1, and stores u64 zero through X3 only when X3 is nonnull. If output pointers alias, a store through X3 can affect their shared cell; absence of a store through X1 does not imply an unchanged aliased cell.

Let M be the runtime metadata root read at0xfffffe0007e66f00. Accepted classification computes:

```text
J = M + ((P >> 10) AND 0xffffffff0)
H = load_u16_le(J)
Z = 0xfffffe000caeb480 + 192 * (H AND 0x3ff)
E = load_u16_le(Z + 0x34)
```

J is the selected metadata record address. The source metadata zone index is10 bits; the zone stride is192 B. The prior allocator's u16 base-index address calculation alone does not prove agreement with this classification. Runtime initialization and matching metadata/descriptor epochs must discharge that relationship.

An accepted metadata record can contain E=0 in the symbolic input domain, in which case the query may still publish Z. Range rejection and a zero extent field can therefore both produce return0 with different output effects. Whether either state occurs in an initialized native allocator remains unknown.

## Offset layouts and destructive reads

All pointer additions and shifts below have the source's u64 bit-vector semantics. Define T=P+E and C=((P XOR T)>=0x4000), using unsigned comparison. This is the source crossing predicate; no nonwrapping element extent is inferred from the earlier8 B range check.

| Source condition | Offset result D | Metadata write when W2!=0 |
| --- | --- | --- |
| X3=0 | No offset output | None |
| X3!=0 and H bit0x400 clear | 0 | None |
| Offset enabled, C false | 0 | None |
| Offset enabled, C true, u16(J+0x10) high nibble0xb | u16(J+0x12) | u16 zero at J+0x12 |
| Crossing, not special layout, E<=0x4000 | 0 | None |
| Crossing, not special layout, E>0x4000 | Indexed layout below | Conditional u16 zero at indexed record+2 |

For the large indexed layout, i=u8(J+3) when H high nibble is0xe; otherwise i=u16(Z+0x38). It forms K=J+16*i and the source signed boundary B:

```text
B = ((ASR64((K-M) << 28, 32)) << 14)
```

If unsigned T<B, D=0. Otherwise D=u16(K+2). The latter read is followed by a u16 zero store at K+2 when W2!=0. Both index encodings, the LSL/ASR calculation and both read/clear tails are modeled. The large-layout proof uses verified prefix, address and tail certificates; the address certificate also proves containment of the selected field in the declared metadata region.

The destructive stores are at0xfffffe000bd79378 and0xfffffe000bd793e4. They occur after reading the u16 value and before publishing the offset and zone outputs. They are explicit stores, not atomic read-and-clear instructions; the model establishes no synchronization with another reader/writer.

| Output effect | Source location |
| --- | --- |
| Rejected-range offset zero | 0xfffffe000bd79310 |
| Accepted offset D as zero-extended u64 | 0xfffffe000bd793cc |
| Accepted zone Z when X1!=0 | 0xfffffe000bd793d4 |

The accepted zone store follows the offset store. An additional byte-array proof covers the accepted zero-offset route with X1=X3: the final shared cell contains Z. The ordinary caller uses distinct cells. Metadata/output/frame separation is a declared premise for the other effects; this is not an unrestricted alias contract.

## 14/32 B caller validation and next request

Let F be SP at entry to the lower size-retirement function. Its64 B frame places the offset result at F-64 and the zone result at F-56. Saved callee registers occupy the remaining frame cells. At0xfffffe000bcfec9c, the original BL passes P in X0, F-56 in X1, discriminator1 in W2 and F-64 in X3.

The complete query register/store inventory shows no SP or X19-X30 write and only the five listed stores. Its metadata stores are disjoint from the caller frame under KQ-A3. Its two output cells do not overlap the saved-register cells. These facts, the source argument/result certificates and the prior caller-frame contract support the modular join; no monolithic inlined byte-array proof or native execution is claimed.

The selected caller at0xfffffe000bcfeca0 restores the original request N from X21, retains returned E in X4, and reads D from the frame. It selects error frontier0xfffffe000bcfed78 if E=0 or unsigned D+N>E. For N=14/32 B and the query's u16 offset domain, D+N cannot overflow u64.

| Original next-call operand | Established value on admission |
| --- | --- |
| Call site / target | 0xfffffe000bcfecdc ->0xfffffe000bcfed8c |
| X0 | Original heap argument |
| X1 | P-D modulo2^64; nonwrapping when P>=D |
| X2 | Original N,14 or32 B |
| X3 | Query zone output Z |
| X4 | Raw returned element extent E |

The caller forms both a regular signed32-bit-adjusted pointer and an alternate pointer with top16 bits0x2bad. For every u16 D, -D fits signed32 bits, so the source CSEL selects the regular P-D expression on the modeled admitted route. This establishes the requested bit pattern, not a valid allocation base or live object.

Four separate composition formulas cover zero/special-offset query outputs with each request extent. With D/E in the u16 domain, E!=0, D+N<=E and P>=D, they establish nonwrapping recovery, (P-D)+D=P and E>=N. A fifth integer-domain formula transports field validity/separation from the metadata region to the selected two-byte field. These formulas are distinct from the33 source obligations.

The earlier MixedData report follows the shared next routine through selected validation/element-clear/handoff paths for a48 B owner request. This increment establishes the14/32 B input contract at that routine. Its native heap/zone checks, actual clear, actual retirement and later reuse remain separate obligations.

## Artifacts, assumptions and validation

[Extractor](triage_evidence/recover_kernel_retirement_query.py), [instruction audit](triage_evidence/audit_kernel_retirement_query.py), [delivery verifier](triage_evidence/verify_kernel_retirement_query_delivery.py), [checks archive](triage_evidence/kernel_retirement_query_checks.json.zst), and [audit archive](triage_evidence/kernel_retirement_query_audit.json.zst) provide the source and formula receipts.

Decoded checks SHA-256: `1b023a4fd38b4ca2fbaea78f555e8f8be3827c14208e6ac818b526c548af09d0`.

Decoded audit SHA-256: `00a032b581454f770fe34ff3d811be3d4e918090b8cf2f94cfcb220088af6090`.

The capture contains222 original instructions in three compiler-bounded functions, with four exact predecessor-function matches. The audit covers84 newly selected instructions, including all68 query words, and21 reused caller instructions. Its33 nonvacuous source obligations account for718 instruction instances and685 linked-edge checks across the recorded obligations. Five composition formulas and five predecessor obligations are re-solved. Changing a u16 clearing store to NOP yields a SAT counterexample to the clear effect.

Memory is byte-addressed and little-endian. Loads through overlapping addresses observe coherent bytes. Fresh read variables are bound by definitional equalities to those byte-array reads; dependency closure removes only unused read definitions. Store/read expansion preserves address aliasing. Large-layout geometry and memory effects use modular certificates with explicit register, unchanged-memory and region-validity joins. These are solver representations of the source, not native allocator execution.

| Assumption | Dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| KQ-A1: Only the pinned collection and predecessor image are covered | KQ1-KQ7 | Original bytes/compiler bounds, four predecessor matches, fresh extraction and exact five-store/register census; recapture for another build |
| KQ-A2: Modeled AArch64 C/Z, unsigned conditions, u32 zero extension, u64 shifts and SXTW semantics apply | KQ1-KQ7 |33 reconstructed nonvacuous source formulas, all-pointer range checks, arbitrary u16/u32 fields and changed-store SAT control |
| KQ-A3: Selected global, metadata, zone, output and frame storage is valid, nonwrapping and separated as declared | KQ1-KQ7 | Explicit intervals; metadata window0x100020 B covers the modeled u16 index domain; two-byte field containment/transport lemma; alias-output case is admitted separately. Native table capacity/validity remains unknown |
| KQ-A4: Runtime bounds/root and relevant metadata belong to a stable matching epoch during each query | KQ1-KQ6 | Global loads, both index encodings, raw signed boundary and coherent byte-array reads; initialization/concurrent mutation require independent evidence |
| KQ-A5: Optional pointer presence, large-layout register joins and ordinary leaf return apply | KQ3-KQ7 | All optional-output rejection cases, accepted no-offset variants, complete68-word coverage, prefix/address/tail certificates and output store order; arbitrary metadata/output aliasing is outside the separated domain |
| KQ-A6: Caller cut receives query-domain u16 E/D, original N and the saved heap/pointer state | KQ5-KQ6 | Universal14/32 B gate/argument proofs, source BL arguments, complete query preserved-register census and four zero/special-offset composition formulas. Native allocation identity/liveness remains unknown |
| KQ-A7: Modular source certificates are joined under their declared private-storage and metadata premises | KQ4-KQ7 | Five composition formulas, five predecessor rechecks, exact frame-cell aliases and no SP/callee-saved GPR writes. This does not establish whole-command reachability, public error status or daemon transaction identity |

## Bounded continuation and quality gates

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Initialized bounds/root, zone fields and a matching native metadata epoch | Discharge the input-state premises and determine realized layouts/extent |
| High | Next routine's heap/zone validation for the14/32 B caller contexts | Extend the recovered request through conditional clear and zone handoff |
| High | Allocation identity, ownership and synchronization around destructive offset reads | Determine lifecycle and inter-reader coherence; source stores alone establish no atomic protocol |
| High | Same-image daemon/provider request and reply tied to endpoint/selector | Correlate internal metadata/error behavior with external IPC |
| Medium | Initialization agreement between allocation u16 base indexes and metadata10-bit zone indexes | Establish matching native classification, without treating symbolic-domain differences as a defect |
| Medium | Other output-alias combinations and independent caller contexts | Extend the explicit separated-storage API contract |
| Low | Exact native symbol/type provenance for the unnamed query and zone records | Refine nomenclature beyond source-derived roles |

Extraction requires O(B+I+S) time/space for consumed image bytes B, instructions I and scanned symbols S. Formula construction requires O(instruction instances+byte-array/query DAG); solver search is separate. Source obligations use QF_AUFBV with30 s/query limits; small composition/prior formulas use their recorded bit-vector/integer domains. Extents, strides and frame sizes use B; field widths and unsigned/signed operations are explicit. No target code or IPC executes and no IDA database is modified.

- **QG1**: Claims concern factual source, data/control flow and ABI effects.
- **QG2**: KQ-A1-KQ-A7 specify assumptions, dependencies and falsification probes.
- **QG3**: Range rejection, all query blocks/layouts, optional outputs, destructive stores,14/32 B caller gates/arguments and modular joins are covered. The full interface goal remains active.
- **QG4**: u16 fields, u32 discriminator, u64 addresses,8 B outputs/range check,16 B metadata stride,192 B zone stride,64 B frame and proof/coverage counts are explicit and reproducible.
- **QG5**: Pointer-range admission versus allocation validity, extent0 versus rejection, source stores versus atomic protocol, address/field certificates versus native metadata, and modular composition versus monolithic/native execution remain distinct.
- **QG6**: Primary captures, full68-word query inventory,33 source obligations, five composition formulas, five predecessor rechecks,685 linked-edge checks and a mutation counterexample support the bounded claims.
- **QG7**: Ranked continuation preserves runtime initialization, next-routine validation, native lifetime/locking, external transactions and broader alias contracts as unresolved evidence frontiers.

The [next small retirement dispatch](kernel_retirement_dispatch_report.md) now establishes the complete 73-word lower body. Its guard admits query-derived zone IDs below 690, and its reciprocal expression indexes the u32 zone flags at 4*ID. Normal data14/typed32 paths have distinct heap-class predicates before bzero(base,E); conditional post-clear proofs restore the frame and transfer zone/accounting/base/E to the zone tail. This does not discharge the native metadata epoch or allocation ownership premises above.

The [retirement diagnostic continuation](kernel_retirement_diagnostics_report.md) establishes the original _panic argument producers after the lower dispatch rejects geometry or heap class. Both complete callees, their source literals, name-table fixups and diagnostic global stores are retained. The source requests do not discharge native ownership, metadata coherence or actual termination premises.

The [complete zone-retirement tail](kernel_zone_retirement_report.md) now establishes reclassification/displacement gates, per-thread and CPU accounting, authenticated-cache boundaries, current/spare magazine publication, both-full helper custody, and nesting/pending/deeper-release continuations. Its source proofs do not establish native authentication, helper effects, actual reclamation or a matching daemon transaction; no new Mach endpoint is established.

The [both-full magazine helper](kernel_retirement_magazines_report.md) returns the incoming cache or zero under the ordinary ABI. Every modeled nonzero normal return passes a producer-count reset; linked original-byte components then publish one pointer through C+6/C+0x10. Allocation instead consumes C+4/C+8. Whole-CFG, instruction and list/state evidence retain explicit native synchronization, external-memory-effect, reclamation and transaction-identity limits; no additional Mach endpoint is established.
