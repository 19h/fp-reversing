# RPC502 public-key records and Montgomery arithmetic interfaces

Original initialized-worker execution identifies two obfuscated entries as Montgomery arithmetic routines: `0x100539ea0` squares an operand and `0x10094593c` multiplies two operands. All224 complete calls in four retained cases match independent integer arithmetic. Their final public-exponent outputs match `pow(signature,65537,N)`. The parent carrier X11 at `0x10097531c` supplies the actual modulus and exponent through recovered certificate fields. The four workers return `0xffff5bdb`; these results establish arithmetic and private ABI roles, not an accepted protected operation.

This extends the frozen [issuer/verification report](rpc502_auth_report.md). The separate [alternate certificate continuation](rpc502_policy_report.md) establishes a later original path through another certificate family. Neither increment adds an observed Mach or IOKit emission. The broad interface investigation remains active and incomplete.

## Assumption register and evidence boundary

| ID | Assumption | Dependent results | Stress test / falsification probe | Verified boundary |
| --- | --- | --- | --- | --- |
| R1 | The exact supplied daemon slice is the intended source | Addresses, literals, codecs and routine roles | Rehash original slice/universal relation, UUID, instruction bytes, fixups and compiler starts; attest installed pairing separately | Original file provenance checked; installed execution pairing unknown |
| R2 | The original registered callback supplies the retained predecessor state | Worker operands, certificate records and all arithmetic calls | Require actual callback return; retain stack/heap/image state into worker; examine alternate startup writers | Original callback executed; complete process startup not executed |
| R3 | Inherited API, PAC, MAX CPU, heap and serial-lock declarations apply to these private cases | Finite worker paths and returns | Reject unknown imports/bytes/owners; vary declared external inputs; compare native PAC/scheduling separately | No native target/API or IDB mutation |
| R4 | Recovered record views cover the selected fields without defining unknown padding | Integer/argument/context layouts | Check actual caller/callee loads, active extents, source-write epochs, masks and SDK offsets | Partial analyst types; complete source types unknown |
| R5 | Counts decode as signed32 with a modular bias; limb indices retain source width | Integer values and active byte extents | Check negative/zero/INT_MIN local arithmetic, declared capacities and signed-index bounds | Local full-domain count proof; retained counts and extents verified separately |
| R6 | Full-call outputs and row arithmetic independently identify Montgomery behavior | Routine names and public-exponent interpretation | Recompute every full result using modular inverse and every retained carry/store row; vary zero/nonzero/range-boundary inputs | Four finite complete worker cases;wrapper C co-varies with signature width;unrestricted routine equivalence unknown |
| R7 | Selected bytes were defined by source before their observation | Public keys, context fields and active limbs | Reconstruct last original stack-store epochs; require heap knownness masks; do not use inactive snapshot bytes | Active header/limb/context bytes checked; observer windows alone are not definedness evidence |
| R8 | Public mathematical signature relations are distinct from target trust and operation success | Certificate and encoding interpretation | Compare exact DER TBS/signature, public exponent result and digest block; recover all caller policy/date/authorization gates | Embedded certificate relation verified; native trust unknown |

[Profiles](triage_evidence/rpc502_rsa_profiles.json) retain four complete callback/worker sequences, actual argument/return records, source-read row values, post-store words and original visit journals. [Contracts](triage_evidence/rpc502_rsa_contracts.json) retain12 original source spans in8 physical compiler intervals,1513 consumed pointer/import records,four local proofs and SDK compilation. [Independent checks](triage_evidence/rpc502_rsa_checks.json) verify every retained source visit, every full product and selected row, active byte epochs and four fresh canonical executions. Compiler intervals are not assumed to be complete semantic functions. [R1-R7]

## Integer and certificate representations

All offsets are bytes. Header words and limbs are little endian. K below is `0xada56e3c`.

| Selected view | Offset | Representation / established meaning |
| --- | ---: | --- |
| Integer header,16 bytes |0 | Raw u32 capacity in limbs |
| Integer header |4 | Stored u32; signed used-count is `int32(stored-0x693be708 mod2^32)` |
| Integer header |8 | Raw64 pointer to encoded u32 limbs |
| Active limb array |4*j | `encoded_word XOR K`; least significant limb first |
| Certificate record |210 hex | Modulus integer header |
| Certificate record |320 hex | Public-exponent integer header |

The mathematical integer is the sign of the decoded count times `sum((limb[j] XOR K)*2^(32*j))`, for `j<abs(count)`. The source magnitude selection at `10053a03c..58` and `100945ae8..b04` is proved for all2^32 stored words. INT_MIN gives unsigned magnitude `0x80000000`; that scalar fact does not authorize such an extent. Retained active counts fit recorded capacities. Root/Key-Services modulus capacities are64 limbs; working temporaries include130-limb capacity. Zero active count reads no limb bytes. [R4,R5,R7]

The two parent moduli decode byte-exactly to the embedded Root and Key Services DER public keys; both observed exponents are65537. This closes the earlier gap between an associated parent record and actual key material. The X11 record's active fields and source-known bytes are checked directly, separately from the child's raw signature/digest tail. [R7,R8]

## Two selected call interfaces

| Field | Square entry100539ea0 | Product entry10094593c |
| --- | --- | --- |
| Caller adapter |10053da74 |100947dbc |
| Actual BLRAA / return PC |10053dcac /10053dcb0 |100948020 /100948024 |
| Selected argument extent |40 bytes |48 bytes |
| Context pointer64 |+0 |+0 |
| Modulus integer pointer64 |+32 |+8 |
| Output integer pointer64 |+16 |+16 |
| Left/operand pointer64 |+24 |+24 |
| Right integer pointer64 |Same operand used twice |+40 |
| Address-keyed control32 |+8, ADD decoding |+32, XOR decoding |
| Observed decoded control |9d3a hex |973e hex |
| X1 seed-pointer update |Referenced u64 increases70 hex |Referenced u64 increasese0 hex |
| Inner row entry / post-store PC |1005fc0d0 /1005fc124 |10097fbc8 /10097fc24 |

For argument pointer P, the square control is `stored8 + ((low32(P) XOR7a9247f6)*31b6b333) mod2^32`. The product control is `stored32 XOR (((low32(P) XOR966e5812)*592e2f77) mod2^32)`. Both address-key normal forms are proved for all2^32 low pointer words, without an alignment precondition. These different codecs and control values remain separate. Every captured call returns to its actual adapter and restores entry SP. Argument padding and complete function prototypes remain unknown. [R4-R6]

The [SDK partial views](triage_evidence/rpc502_rsa_layouts.c) assert integer,context,40-/48-byte argument and certificate-key offsets under arm64e. Compilation verifies those analyst layouts; it does not recover an original C declaration or validate native PAC. [R3,R4]

| Montgomery context field | Observed role |
| --- | --- |
|+0, pointer64 | Integer equal to `R mod N` |
|+8, pointer64 | Precomputation integer: starts as `2R mod N`, reaches `R^2 mod N` through eleven squares |
|+16, u32 | `n0prime = -N[0]^-1 mod2^32` |
|+20..23 | Meaning/definedness not established |

Here `R=2^(32*n)`, with n the modulus's active limb count. Retained Root/Key-Services cases use n=64 and R=2^2048. Root's low limb is7794c92d hex and n0prime is3f12915b hex. Context radix and n0prime are independently checked at every call. The partial precomputation role follows actual call order and values; a complete context lifecycle remains unknown. [R4-R7]

## Exact selected inner-row arithmetic

The code processes source limb j and stores output limb j-1 in the retained row entries. All observed j are1..63. Zeroth-limb preparation and outer/final carry code lie outside these entries, so a single row is not presented as a complete modular product. Full before/after integer oracles separately check those surrounding effects. [R6]

```text
square row at1005fc0d0:
  U = (T[j] XOR K) + high32(pre_X13) + W6*(A[j] XOR KA)
  V = high32(pre_X5) + W3*(N[j] XOR K) + low32(U)
  T[j-1] = low32(V) XOR K

  KA = (((W20-0xf1d) mod2^32) OR incoming_W30) XOR W12
       = K in retained rows

product row at10097fbc8:
  U = (T[j] XOR K) + high32(pre_X26) + W13*(A[j] XOR K)
  mask = zero_extend(((W5-0xdc7) mod2^32) OR W15) XOR X0
  V = high32(pre_X22) + W10*(N[j] XOR K) + (U AND mask)
  T[j-1] = low32(V) XOR K

  mask = 0xffffffff in retained rows
```

The verifier uses actual pre-state,actual source-read encoded words and actual post-state/store bytes. It does not supply arithmetic outputs to the guest. Square/product row constants and index codecs are captured separately. The source store expression `x-((2*K mod2^32) AND (x<<1))+K mod2^32` equals `x XOR K` for every32-bit x; a local proof establishes the identity. [R5-R7]

For u32 factors and carry/limb terms, the largest accumulated value is `(2^32-1)^2+2*(2^32-1)=2^64-1`. The independent row equations therefore fit their retained64-bit carry registers without an unstated wider integer. All quantities are dimensionless integers; byte sizes and limb counts are distinguished explicitly. [R5,R6]

The identification follows the independently verified `A*B*R^-1 mod N` relation. Montgomery's primary paper describes that representation and its conversion using R and R^2; this is mathematical context, not source-code provenance or library attribution. [Montgomery,1985,DOI10.1090/S0025-5718-1985-0777282-X](https://class.ece.iastate.edu/tyagi/cpre681/papers/Montgomery.pdf)

## Public exponent sequence and varied external inputs

```text
actual original callback returns
  -> eleven squares:2R ->4R ->...->R^2 mod N
  -> product(R^2,S) = S*R mod N
  -> square(R) = R; product(R,S*R) = S*R
  -> sixteen squares -> S^65536*R
  -> product with S*R -> S^65537*R
  -> product with1 -> S^65537 mod N
  -> source verification/status continuation
```

The [independent sequence check](triage_evidence/rpc502_rsa_sequence_checks.json) verifies every input/output in the complete exponent order and the actual context precomputation pointer. A complete group has28 square calls and4 product calls. The first group processes the embedded Key Services signature under Root. Three full-width leaf cases execute a second group under Key Services; the short leaf stops before that second arithmetic group. Inner-row counts vary for shortened/zero active operands, while complete-call outputs remain checked. [R6,R8]

| Explicit leaf signature | Whole worker instruction steps | Complete Montgomery calls | Retained inner rows | Result |
| --- | ---: | ---: | ---: | --- |
|128 zero bytes |12598351 |32 |125055 |ffff5bdb |
|256 zero bytes |14443154 |64 |173439 |ffff5bdb |
|256-byte within-range nonzero representative |17379799 |64 |250110 |ffff5bdb |
|256-byte representative equal to issuer modulus |14633037 |64 |177471 |ffff5bdb |

Within DER,only the outer signature BIT STRING and its enclosing lengths change;TBS bytes remain identical. The second-file wrapper also supplies C=128 for the128-byte case and C=256 for all three256-byte cases. Those inputs are not a matched-C isolation of signature width. Carrier+28 remains unread in all four arithmetic cases;no complete C semantics are assigned. The nonzero representative is derived deterministically from an existing public signature modulo the Key Services modulus. No new valid leaf signature is constructed. All seven final public-exponent outputs match Python pow. Four embedded outputs exactly match the independent SHA-1 DigestInfo block; external unsigned cases fail. [R6,R8]

RFC8017 defines the deterministic encoding `00 ||01 ||FF...||00 ||DigestInfo`. It also specifies signature representative range checks for RSAVP1. The `S=N` private input computes a zero residue in this internal arithmetic sequence and is subsequently rejected. This does not establish full RSAVP1 implementation conformance, missing caller checks or an accepted invalid signature. [RFC8017,sections5.2.2,8.2.2,9.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.2)

## Verification, preservation and bounded continuation

[Independent checks](triage_evidence/rpc502_rsa_checks.json) contain exact assertion/source-visit counts,196 squares,28 products,all224 complete output checks,726075 selected row checks,seven public-exponent outputs,four fresh complete replays,four fresh local proofs and a fresh SDK compile. Active stack/heap byte checks are counted separately. No native target API or binary executes;source binaries and IDBs remain unchanged. [R1-R8]

Reproduction from the extracted directory,using the existing analysis interpreter and solver runtime:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_rsa_cases.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_rsa.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_rsa.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_rsa_sequence.py
```

Time/space are O(C*(B+V+E+S)+rows),for cases,source bytes,visits,events and retained state,plus key-size-dependent integer arithmetic. Each local solver is bounded to60000 ms. This is a finite corpus and local scalar proof set,not a full-domain equivalence proof for the protected implementation.

[Preservation](triage_evidence/rpc502_rsa_preservation.json) checks1047 previous artifacts,1041 byte-identical plus six permitted reporting/index/aggregator updates. Original input files remain unchanged. [Scoped quality gates](triage_evidence/rpc502_rsa_quality_gates.json) cover both new reports and exclude any broad-goal completion claim.

| Impact | Further foundational question | Evidence that resolves it |
| --- | --- | --- |
| High | Complete signature grammar,range,algorithm and trust policy | Recover callers and padding/status byte producers around the exact exponent outputs; compare malformed encodings and caller gates |
| High | Protected continuation after valid certificate family | Follow the [AAA continuation](rpc502_policy_report.md),its original first-file data and subsequent field consumers |
| Medium | Complete integer/context lifecycle and alternate sizes | Trace allocations,normalization,zero/negative counts,aliasing,precomputation publication and cleanup across callers |
| Medium | Library/toolchain attribution | Compare original instruction/data structure evidence against primary implementations; arithmetic identity alone is insufficient |
| High | Native daemon/kext/deeper coupling | Match successful operation predecessors,port objects,rights,provider/slice identity and observed transport epochs |

QG1: factual technical analysis. QG2:R1-R8 register and probes. QG3: arithmetic/record increment covered; full goal active. QG4: exact widths,byte extents,carry bounds,complexity and proofs. QG5: zero/short/range cases and local/native limits separated. QG6: original byte/fixup/DER,independent math,replay and SDK provenance. QG7: bounded impact table above.
