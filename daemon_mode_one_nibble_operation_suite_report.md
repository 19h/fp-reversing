# Encoded carry, XOR and input/output numeric maps

The four successors build carry,XOR,input-decoder and output-encoder tables for the previously recovered encoded addition. Carry fixes the numeric symbol encoding to generator0x0b among the eight sum-compatible encodings. Under that same map,the selected XOR ROM slice is bitwise XOR,another slice is the static decoder,and the final helper implements the static encoder followed by Q. The resulting private interfaces consistently implement four-bit sum/carry/XOR and role-specific numeric conversion. They do not yet establish full-word carry propagation,native output or daemon/kext pairing. [OP1-OP8]

Evidence: [source and ROM cells](triage_evidence/daemon_mode_one_nibble_operation_suite_source.json.zst), [1378 UNSAT /two SAT and ledgers](triage_evidence/daemon_mode_one_nibble_operation_suite_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_nibble_operation_suite.py), [validator](triage_evidence/validate_daemon_mode_one_nibble_operation_suite.py), [preservation](triage_evidence/daemon_mode_one_nibble_operation_suite_delivery.json), [quality gates](triage_evidence/daemon_mode_one_nibble_operation_suite_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_nibble_operation_suite.py), [publication audit](triage_evidence/verify_daemon_mode_one_nibble_operation_suite_publication.py). Context: [encoded addition and inverse map](daemon_mode_one_encoded_addition_report.md), [workspace passes and P/Q state](daemon_mode_one_workspace_passes_report.md), [checkpoint/LOCAL gate](daemon_mode_one_record_checkpoint_report.md), [image-root context](daemon_mode_one_record_rounds_report.md), [interface ABI](interface_abi_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image | `fairplayd.arm64e`,SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Current source |Four complete BRAA-terminated fragments,249 instructions /996 B;245 nonbranch sites translated |
| Prior recapture |Six ranges /4676 B |
| Data |928 original ROM bytes;800 cumulative selected cells across sum/carry/XOR/static maps |
| Control provenance |Six authenticated records /eight source slot-modifier bindings |
| ISA checks |14 UMULL,one UDIV,three bitfields,one register LSR and four corrected comparison GPR-write reports;no SP write |
| Accepted queries |1378 UNSAT /two abstract SAT,including all686 predecessor queries replayed |
| Carry and XOR |Two256-iteration loops;64 inverse-address cases,512 ROM cases and32 Q-access cases |
| Numeric maps |Two16-iteration loops;16 inverse cases,16 decoder-ROM cases and16 encoder-ROM/16 encoder-Q cases |
| State interfaces |Two recovered incoming-register contracts,four full outgoing contracts,shift/divisor proofs |
| Integrity |Eight source/shift/carry/encoding/candidate/target/lineage/native-claim alterations rejected |

F denotes the private frame. Retain the coordinate function and private maps from the predecessor:

```text
C(label) = F+0x8b0 + ((799*label) mod962)
P = first workspace-derived permutation
I = inverse(P),stored at C(593+k)
Q = second workspace-derived permutation,stored at C(k)
ROM = preferred image address0x100e755f0
```

Offsets/extents are bytes;scalar arithmetic is modular u32/u64 unless explicitly widened. Valid coherent nonwrapping mappings,stable saved roots,immutable selected image bytes,frame/object disjointness and no outside mutation of composed private maps remain premises. The inherited loader/selector contracts identify ROM;native ASLR and live mapping identity remain unverified. No target execution,emulation,API/IPC request,IDA access,IDB mutation or hardware PAC test occurred. These entries are private continuations rather than established public APIs or compiler-function boundaries. [OP1-OP4]

## Shared numeric encoding

The carry ROM slice decodes to only symbols12 and11. Across all256 operand-symbol pairs,only the generator11 encoding among the eight preceding cyclic encodings agrees with unsigned numeric carry:

```text
E = [12,11,7,15,1,0,3,5,2,14,10,4,9,6,8,13]
E(0)=12
E(1)=11
```

The original sum ROM satisfies

```text
SUM_ROM(E(a),E(b)) = E((a+b) mod16)
```

The earlier report's generator0 encoding remains a valid sum equivalence. Its relation to this numeric map is `Eold(n)=E((5*n)mod16)`. Carry selects the numeric orientation,and the independently selected static decoder/encoder cells agree with it. All256 sum/carry/XOR tuples and universal4-bit operand queries are retained. [OP1,OP3,OP6]

The two workspace-derived encoding roles are

```text
Ein  = P composed with E
Eout = Q composed with E
```

P and Q are permutations under the replayed source/array contracts. Their statistical independence,equality or necessary inequality is not established. Their roles must remain distinct even when describing a shared arithmetic convention. [OP2-OP4,OP6]

## Carry-table construction

The69-instruction loop at `0x100c1c8a0` starts with W10=0. It decodes both nibbles of the byte index through I,reads the carry ROM slice and applies Q. For operand byte b=x+16*y:

```text
a = I[x]
c = I[y]
offset = (653*(579+a+16*c)) mod928
symbol = (((ROM[offset]+0x44)>>4) AND15) XOR2
byte[C(677+b)] = Q[symbol]<<4
```

The carry decoding expression always produces a nibble for any u8 ROM value. The selected256 original cells satisfy

```text
symbol = E(floor((E_inverse(a)+E_inverse(c))/16))
```

Thus the runtime table contract is

```text
CARRY[Ein(a)+16*Ein(b)] = Eout(floor((a+b)/16))<<4
```

Carry is stored in the high nibble. Its low four bits are zero,and its two possible high-nibble symbols are Eout(0),Eout(1). These are encoded symbols,not a plain native0/1 carry flag. Of the256 table operand pairs,136 have numeric carry0 and120 have carry1. The counts describe complete table structure,not a distribution of native requests. [OP3-OP6]

W10 advances by one. The first255 steps repeat through slot0x7dba;the final step selects0x7dc2 -> `0x100d398e4`,modifier0x84a5. The inherited first entry used slot0xaae2 with modifier0xd429. Distinct authenticated records therefore target this same continuation;the metadata is specific to the recorded edge. Native authentication remains untested. [OP1-OP3,OP7]

## XOR-table construction

The60-instruction loop at `0x100d398e4` starts with W16=0. It again decodes both operand nibbles through I,then uses another ROM coordinate family:

```text
a = I[x]
b = I[y]
offset = (653*((a+16*b) XOR0x16)) mod928
r = ROM[offset]
n = u32(r-7)
l = n AND0xff
symbol = (n XOR(l>>4) XOR(l>>3) XOR0xbbbbbbbb) AND0xff
byte[C(333+x+16*y)] = Q[symbol]
```

For the actual selected256 cells,the decoded symbol equals

```text
E(E_inverse(a) XOR E_inverse(b))
```

The complete selected raw-byte alphabet contains16 values,and its decoded symbols are exactly0..15. Unlike carry's intrinsic four-bit extraction,this XOR bound depends on the original selected image-byte alphabet. The source proofs bind all256 ROM accesses and all16 alphabet cases to initialized Q cells. No nibble assumption is applied to arbitrary bytes from the whole928-byte bank. [OP1,OP3-OP5]

The resulting interface is

```text
XOR[Ein(a)+16*Ein(b)] = Eout(a XOR b)
```

The generated XOR table is symmetric and each row/column permutes the output symbols. Its diagonal is the constant Eout(0). Associativity or a shared input/output identity is not inferred when the encoding roles differ. [OP3-OP6]

The variable-register shift at `0x100d39914` has an actual count of four. The hidden UDIV divisor at `0x100d399a4` is962. Both are freshly proved from the full source;the register-shift opcode and its32-bit count mask are checked. The lower-five-bit rule is documented in the primary [Arm armasm Reference Guide6.01,ARM DUI0802B,sections5.79 and5.81](https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44). [OP1,OP3,OP5]

W16 advances by one. Slot0x7dc2 repeats for the first255 steps;slot0x8d55 selects `0x100c62804` after the final step,modifier0x84a5. [OP3,OP5,OP7]

## Input-decoder map

The47-instruction helper at `0x100c62804` starts with W1=0 and reads I[s] for s=0..15. Its static ROM slice is

```text
r = ROM[(653*(266+(I[s] XOR9))) mod928] XOR0x68
byte[C(659+s)] = r
```

The selected16 ROM cells decode each static symbol k to E_inverse(k). Therefore

```text
DEC[s] = E_inverse(P_inverse(s)) = Ein_inverse(s)
```

All16 private inverse accesses and16 ROM addresses are proved. The selected ROM bytes fall in0x60..0x6f,and XOR0x68 produces the numeric nibble. The helper exits after16 stores through slot0x2d7e -> `0x100d31494`;slot0x2d8f repeats before then,modifier0x0701. [OP1,OP3-OP5]

## Output-encoder map

The73-instruction helper at `0x100d31494` starts with W10=0. It transforms the numeric counter into a ROM coordinate,combines the loaded byte with a counter-dependent XOR mask,uses that result as a Q symbol,and stores to C(936+n). The16 ROM addresses and masks are retained as independently calculated candidates;every candidate address and decoded Q symbol is then proved against the original complete source. No candidate alone is accepted as a source theorem. [OP1,OP3,OP5]

For every numeric nibble n:

```text
ROM_value_at_original_source_address(n) XOR source_mask(n) = E(n)
byte[C(936+n)] = Q[E(n)] = Eout(n)
ENC[n] = Eout(n)
```

The counter advances by one. Slot0x2d7e repeats for n<15;slot0x5d09 selects `0x100d845e0` after n=15,modifier0x0701. The selected ROM cells,raw values,masks and16 Q accesses are all source-bound. [OP1,OP3,OP5,OP7]

Static E/E_inverse are mutual inverses. The private maps DEC and ENC compose with different workspace-derived permutations P,Q. Their mutual-inverse identity is not required or proved. An abstract SAT control sets P to identity and Q to a0/1 transposition,then exhibits a failed DEC(ENC(n)) round trip. It establishes no native reachable workspace or encoding pair. [OP6,OP8]

## Primitive interfaces and encoding scope

For numeric a,b,n in0..15,the recovered contracts are:

| Private interface | Exact result |
| --- | --- |
| SUM[Ein(a)+16*Ein(b)] |Eout((a+b) mod16) |
| CARRY[Ein(a)+16*Ein(b)] |Eout(floor((a+b)/16))<<4 |
| XOR[Ein(a)+16*Ein(b)] |Eout(a XOR b) |
| DEC[Ein(a)] |a |
| ENC[n] |Eout(n) |

SUM is the preceding report's table,reinterpreted under the carry-selected encoding. The other four are the current source loops. The sum/carry pair represents the31 possible unsigned sums0..30;all256 operand tuples are checked. The code here constructs separate tables. A consumer that joins or propagates those fields across a larger word is not yet established. This is a local primitive suite,not identification of a complete cryptographic algorithm. [OP3-OP6,OP8]

The source uses no new arithmetic overapproximation in these four helpers. Named byte loads remain component interfaces:their values compose with the already proved P/Q/inverse maps and the exact selected ROM bytes. The686 replayed queries retain predecessor arithmetic cuts and premises;replay does not turn them into native execution. The two SAT results are abstract algebra/map-role controls. [OP2-OP6]

## Register epochs and incoming context

W9=0x7dba is recovered from the original earlier second shuffle. The intervening builder's write census preserves X9/W9. A separate source proof establishes its outgoing X8=ROM,W10=0 and X20=F+0x8b0. The arbitrary unused W9 in the earlier builder's abbreviated component model is not used as evidence of that reaching value. [OP2-OP3,OP7]

| Boundary | Source-proved context |
| --- | --- |
| Carry -> XOR |W11=0x7dc2,W16=0,W12=799,W13=0x73acf,W14=0x441fef,W15=962;ROM/root preserved |
| XOR -> decoder |W1=0,W9=0x2d7e;ROM/root preserved |
| Decoder -> encoder |W10=0,W16=653,W0=928,W11=799,W13=0x883fddf1,W14=962 |
| Encoder -> next phase |W2=0x0a15c815,W4=0x2a65c9df,W12=0xa77b2501,W22=0xf402e748,W24=0xc5141de1;ROM/root preserved |

The decoder temporarily places a wide multiplication result in X16,but the later `MOV W16,#653` overwrites it before the encoder. The encoder consumes that final653 value. Numeric registers and counter roles are checked at the boundary rather than inferred from an earlier instruction with the same register name. Full outgoing fixed-register ledgers are retained. [OP3,OP7]

## Private state layout and external boundaries

All initialized domains remain disjoint under C(label):

| Labels | Role | Cells |
| --- | --- | --- |
|0..15 |Q forward permutation |16 |
|72..327 |Encoded sum |256 |
|333..588 |Encoded XOR |256 |
|593..608 |Inverse P |16 |
|659..674 |Input decoder |16 |
|677..932 |High-nibble encoded carry |256 |
|936..951 |Output encoder |16 |

This accounts for832 known cells of the962-coordinate private domain. The other130 cells are not claimed initialized by this suite. The corresponding ROM evidence covers800 distinct selected cells of928,including the preceding sum table;the remaining128 ROM cells are not claimed unused. [OP1,OP3-OP5,OP7]

The new four loops make544 byte writes:256 carry,256 XOR,16 decoder and16 encoder. Their destinations are disjoint from Q and inverse(P),so those input maps remain stable. The296-byte workspace,saved request/LOCAL words,frame-view roots and budget remain untouched. The F+0x750=F+0xc80 root is still not consumed here. [OP3-OP5,OP7]

All four continuations have a single terminal BRAA and no internal call,branch or trap. Their byte accesses are private map/table data and the inherited immutable ROM;there is no new controller-word read. They establish no new Mach send/receive,port allocation,right transfer or message-emission site. Native owners,actual output serialization and a matched daemon/kext contract remain unknown. The next frontier is `0x100d845e0`,whose semantics are outside this proof. [OP1,OP4,OP8]

## Assumption register and bounded continuation

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| OP1 |Pinned image,ROM and pointer records identify this variant |Recapture996 current/4676 prior code bytes,928 ROM bytes,six authenticated records and eight bindings;reject eight alterations |
| OP2 |Predecessor private maps and reaching register context compose |Replay all686 predecessor queries;recover W9 from its producer and prove preservation;bind actual ROM/counter/root output from the prior builder |
| OP3 |ISA widths,SSA and component memory interfaces are accurate |Translate245 sites;check raw opcodes,all selected source/ROM/Q accesses,stored values,register-shift masking and four full outgoing contracts |
| OP4 |Mappings are coherent/nonwrapping,roots/image bytes stable,objects disjoint and no outside mutation affects private maps |Check832 distinct cells and source/destination separation;native mappings/owners remain unproved |
| OP5 |Finite domains exhaust the helper control/address behavior |Prove two256-step and two16-step counters,512 ROM pair cases,all scalar-map cases,16 encoder candidates,and actual shift/divisor constants |
| OP6 |Numeric orientation and map roles are kept distinct |Test all eight sum-compatible encodings against carry;prove shared sum/carry/XOR laws and static codec inversion;retain abstract failed private-map round-trip control |
| OP7 |Register and storage epochs are interpreted at the correct boundary |Check W9 production,X16 product overwrite by W16=653,counter-role transitions,all logical label domains and outgoing fixed registers |
| OP8 |Local arithmetic does not establish full-word behavior or cross-layer output |Analyze0x100d845e0 and actual consumers/encoding transitions/owners/serialization;native encoding reachability and daemon/kext linkage remain unknown |

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| High |`0x100d845e0` and successors |Actual workspace/primitive-table consumers and any use of F750 or LOCAL-derived state |
| High |Arithmetic lifting of consumers |Bind lookup operands/results to these encoding versions;prove carry propagation and any required transcoding |
| High |Caller-visible output and daemon/kext linkage |Owners/extents,result serialization and matched external contract |
| Medium |P/Q relationship |Compare exact scalar/shuffle recurrences to establish whether encoding values coincide;role distinction alone does not decide equality |
| Medium |Other ROM cells or operation variants |Independent source-selected ranges and semantics;do not extrapolate these800 cells to all928 |

For this fixed image,the four loops take bounded work/space. With m-symbol maps,the binary tables require O(m^2) work/space and the two numeric maps O(m);here m=16. Static finite checking is linear in the listed source cases;SMT runtime is solver-dependent,limited to15000 ms per query and20 s per process.

QG1:Claims concern factual source,private ABI,typed arithmetic and provenance.

QG2:OP1-OP8 identify premises,dependent results and falsification probes.

QG3:The increment covers carry/XOR/static numeric orientation,input/output maps,register boundaries,storage domains,architectural limits and publication artifacts;the broader objective remains active.

QG4:249*4=996 B current code;256+256+16+16=544 current byte writes;832+130=962 private cells;800+128=928 ROM cells. Symbol widths,carry shift and modular arithmetic are explicit.

QG5:Prior sum-compatible encoding versus carry-selected numeric orientation,input versus output roles,and temporary versus final register values remain distinct. Native/full-word conclusions are not inferred.

QG6:Claims trace to the pinned image,original pointer records,exact ROM cells,fresh source comparison,1378 UNSAT/two abstract SAT and686 replayed predecessor queries. The register-shift rule has a primary Arm reference.

QG7:Impact-ranked continuation covers real consumers,arithmetic lifting,encoding equality,ROM scope and actual output/peer ownership. No unrelated target probing is included.

## Workspace state installation follow-up

The next two traversals and state initializer repurpose all Q/I storage as two64-byte data planes while preserving the800 SUM/CARRY/XOR/decoder/encoder cells. Their later consumers must use the new frame epoch. See [workspace state installation](daemon_mode_one_workspace_state_install_report.md).
