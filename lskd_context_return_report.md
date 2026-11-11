# Context re-encoding, original operation selector and record return

The source frontier `0xfffffe000a527b24` re-encodes the working 512 B context and its saved pointer word, then selects the cached RW release adapter and the inner result-store epilogue. This closes a selected representation-restoration path left open by the [paired-codec report](lskd_context_codec_report.md). It does not establish restoration on every operation path, native lock ownership or a complete daemon transaction. [RT1-RT8]

The other frontier, `0xfffffe000a5323f0`, decodes the named outer wrapper's original W1 as a signed operation selector. Values 1, 2, 4 and 5 reach a shared operation-body frontier; all other signed values select the re-encoding default path. Values 2 and 4 also inspect and sometimes update the distinct context word at `+0x144`. The four operation meanings remain **unknown**. [RT1-RT4]

[Evidence](triage_evidence/lskd_context_return_checks.json.zst), [extractor](triage_evidence/recover_lskd_context_return.py) and [publication audit](triage_evidence/verify_lskd_context_return_publication.py) retain 16 spans / 543 instructions / 2,172 B. Thirty-nine UNSAT queries cover 399 lifted instruction instances in 35 pieces; two SAT controls test signedness and the distinction between a true clock predicate and a zero result. Eighteen dispatch slots and two data-root slots retain original chained-pointer metadata. One exhaustive bank checks 256 byte inputs; two register audits cover 187 rows. No new native execution, IDA access or IDB mutation occurs.

```text
working context is decoded at P; phase S=6e3
  |
  +-> clock/context comparison false -> private status -> A527B24
  |
  +-> operation frontier A5323F0: original outer W1
       +-> 1,2,4,5 -> shared operation body A52A7D8 [further effects open]
       +-> other  -> default status06367832 -> A527B24

A527B24:
  current bytes at P -> byte rewrite -> descending word swaps -> encoded bytes
  P -> pointer permutation/affine/XOR -> encoded word at saved SP+1f8
  -> index4d1 -> A52A508: release record with null explicit RW pointer
  -> established adapter A551F38 -> cached RW domain
  -> saved index106 -> A50EF94: output u32 at original record+38
  -> guarded inner return -> bridge
  -> outer derived displacement D=0: reload output into W0 -> guarded return
```

Constants/address suffixes in the diagram are hexadecimal; byte counts elsewhere are decimal. Returning calls, matched frames, stable seed/slot epochs and normal guard/PAC behavior qualify the composition.

## Assumption register and source provenance

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| RT1 | Pinned original KC and normalized FairPlay image describe this build | Instructions, constants, banks and original slots | Rehash and compare original/normalized code and data; compare actual runtime identity separately |
| RT2 | Phase S=`0x6e3`, saved outer record/key and frame roots match the named-wrapper template | Original W1 decode, selector tree and downstream routes | Replay the even-record key join and source frame definitions; match actual predecessor/frame epochs |
| RT3 | Scalar/SIMD semantics, signed comparisons and low-five-bit register-shift counts describe these instructions | Selector partition and representation formulas | Rebuild the fail-closed lift and replay source queries; signed/unsigned SAT control and exact u32/u64 widths expose alternatives |
| RT4 | The context pointer/state and table reads are valid and stable during each selected piece | State144 routing and update-to-common-body join | Match reaching context root and intervening writers; record state updates do not identify public operation semantics |
| RT5 | Seed, slot and pointer epoch match the paired codec; the 512 B object is accessible, nonwrapping and disjoint from live frame/control storage | Re-encoding and repeated-read compatibility | Compare seed/slot epochs, prove storage separation and pointer validity; audits do not exclude indirect alias writes |
| RT6 | Release returns, preserves required callee-saved registers and does not overwrite the caller's result/frame cells | Release-to-result continuation and status preservation | Recover callee effects and aliases; source cached-pointer reload does not prove identity with an earlier acquisition |
| RT7 | Normal guard/PAC return and zero outer derived displacement D preserve the original record location | Final outer W0/X0 mapping | Check both guard comparisons, return authentication and cursor preservation; no actual D=0 or complete named operation is proved |
| RT8 | The selected paths are bounded; common operation body, other exits and upstream transport remain separate | Interpretation and completeness limits | Trace A52A7D8 and actual daemon/IOKit callers/serialization; do not treat the clock predicate as an external success condition |

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. All retained code is compared between them; 192 B of representation constants at `0xfffffe0007920f10` are retained. Supplied C lines 41069-41390 and 49932-49987 corroborate the two original frontier bodies. The decompiler's many fragment parameters are not recovered public ABI declarations. All three supplied inputs remain unchanged. [RT1,RT3]

## Signed operation selector and state144 interface

Source `0xfffffe000a5323f4..a53241c` loads saved outer record R from SP`+110`, reads R`+3c`, and adds low32 of the entry key saved at SP`+e8`. The [named wrapper](lskd_reader_lineage_report.md) wrote `u32(original_W1-Kout32)` there; its aligned record supplies `Kout32=low32(Kentry64)`. Thus W20 is exactly original W1, including its full 32-bit pattern. Source MBA tests then implement signed partitions at 4, 2 and 5, followed by exact tests at 1, 2 and 5. Register LSR uses its low five count bits; its selected count is 31. [RT2-RT3]

| Original W1 interpreted as signed32 | Source route indices | First selected operation/default destination |
| --- | --- | --- |
| 1 | `1ab -> 69e -> 9ab` | `0xfffffe000a52a7d8`, shared operation body |
| 2 | `1ab -> 68f -> 220` | `0xfffffe000a526c7c`, state144 test |
| 4 | `1c7 -> 58f` | `0xfffffe000a5184d4`, state144 test |
| 5 | `1c7 -> 580 -> 980` | `0xfffffe000a52a7d8`, shared operation body |
| Values below 2 except 1 | `1ab -> 69e -> 999` | `0xfffffe000a527b24`, re-encoding default |
| 3 | `1ab -> 68f -> 17` | Same re-encoding default |
| Values at least 6 | `1c7 -> 580 -> 17` | Same re-encoding default |

These rows partition every signed32 value. The negative-value row includes every W1 pattern with bit31 set; it must not be interpreted using unsigned ordering. Original slots independently establish all destinations, including aliases `0x999` and `0x17` to the same default body. Each default selector arm writes W21=`0x06367832` and restores phase `0x6e3`. None of the four selected operation names or external numerical opcode assignments is inferred beyond original W1. [RT1-RT3,RT8]

Let C=`u32[context+0x144]`, B=`0x13f6f63f`, and state144=`u32(C-B)`. The initializer previously recovered in the [vector-origin report](lskd_vector_origin_report.md) writes B, corresponding to normalized state zero. These word tests are separate from byte174 and word178.

| W1 | C=B | C!=B | Eventual common frontier |
| ---: | --- | --- | --- |
| 2 | Index `30a` -> `a5144f0`: store B+10 at `+144` | Index `325` directly | `0xfffffe000a52a7d8` |
| 4 | Index `34e` -> `a5536a8`: store B+1 at `+144` | Index `325` directly | Same |

The updates occur at `0xfffffe000a514504` and `0xfffffe000a5536c0`, respectively. Both stores write four bytes. Both update fragments select `S-0x3be=0x325`, whose original target is the common frontier. The normalized values 1 and 10 are source state values, not assigned enum names. Further common-body record/call effects remain open. [RT3-RT4,RT8]

## Re-encoding the working representation

For the selected flag255 seed decoder, let S be `u32[seed_table+0x1c]`, T=`u32(S*0x030c5e1f)`, and P the working pointer saved at body SP`+0x1f8`. The source reads the same four permutation indices and mask construction as the paired writer. Let Q_T be that byte permutation and let the two mask words be Mlo=`u32(T*T) XOR T`, Mhi=`u32(T*T+T) XOR T`. Scratch A=SP`+0x210` starts at zero; scratch B=SP`+0x218` receives P. The working-data key is K=`u32(low32(P)*0x030c5e1f) XOR S`. [RT3,RT5]

For byte offset n from 0 through 511, the retained SIMD body implements:

```text
mask8(n,K) = low8(K) XOR low8(u32(n+K)*u32(n-K))
encoded_byte[n] = u8((working_byte[n] XOR mask8(n,K))*0x93)

for i = 63 down to 1:
    j = urem(u32(((K+u32(i)) XOR K)*0x01000193), u32(i))
    swap_u64(context+8*i, context+8*j)

E(P) = A_M(Q_T(P)) XOR M
A_M operates on two u32 words: word -> u32(word*0x01000193+Mword)
saved_word[SP+0x1f8] = E(P)
```

The SIMD source handles 32 blocks of 16 B; its offset increases by 16. The descending shuffle exchanges 63 pairs of eight-byte cells. Its divisor lies in 1..63, so `j<i`, and every accessed cell lies within the 512 B object. The original UDIV/MSUB sequence is retained; the remainder-domain and transposition inverse arguments come from the paired-codec certificate. The writer multiplier `0x93` and reader multiplier `0x9b` obey `(0x93*0x9b) mod 256=1`. This is a bijective representation transform for a fixed key, independent of any unestablished cryptographic role. [RT3,RT5]

Source `0xfffffe000a527e70..a527e80` stores E(P) into the frame's saved word. This span does not publish that word into the global vector slot. Under the earlier codec's stable seed/slot epoch, E(P) matches the existing slot representation, while the bytes at P now encode the current working context. The result concerns current bytes after any preceding updates, rather than equality to the original initializer. It closes the selected default/rejection route's representation restoration; selected operations can have further effects before reaching any restoration. [RT5,RT8]

Two independently decoded write-register audits cover 187 rows. They preserve the live permutation indices, mask vector, continuation index, private status and frame registers across the relevant subspans. V8..V11 are SIMD registers, distinct from X8..X11; their use is not a scalar-register overwrite. Indirect writes still require the object/frame separation premise. The entire retained re-encoding span has no BL/BLR-family call. Source and query pieces split pointer permutation from affine arithmetic; no monolithic native execution is claimed. [RT3,RT5]

At the end, preserved W9=`0x106` and newly derived index `0x4d1` select `0xfffffe000a52a508`. The original format8 slot for `0x4d1` has authentication diversity `0x52ea`; the saved `0x106` slot targets the inner result store with diversity `0x96f0`. Chained-pointer metadata establishes static targets and encoded authentication fields, not successful runtime authentication. [RT1-RT2,RT7]

## Cached RW release and record-return boundary

The release body first saves `TABLE[0x106]` into X20. It builds a 16 B record envelope at Rrelease=FP`-0xb0`, initializing only these fields:

| Offset | Width | Source value / decoding |
| --- | ---: | --- |
| `+0` | 4 B | `u32(field+lowkey)=0x1d3`, where lowkey=`u32((low32(Rrelease) XOR 0xdfb9786f)*0xe1d88903)` |
| `+4` | 4 B | Gap; not initialized by this source span |
| `+8` | 8 B | Zero explicit RW pointer |

The initialized union is 12 B. The established adapter at `0xfffffe000a551f38` decodes selector `0x1d3` as RW release; a null explicit pointer selects a fresh read of cached global `0xfffffe000ccc78a8`. This is distinct from the selected clock reader's explicit SecureTime`+0x18` RW release. Cached-pointer identity with an earlier acquisition remains unknown. [RT1,RT6]

| Recovered bank/interface component | Source or original slot | Result |
| --- | --- | --- |
| Left bank root | `a561508`, original slot `0xfffffe00084719e8` | `0xfffffe00079174c0` |
| Right bank root saved at SP`+1c0` | `a561518..a561520`, original slot `0xfffffe0008471b00` | `0xfffffe0007919db0` |
| Bank key / additive | `0x18` / `0x930` | Exhaustive constant `0xdf`, index `0xa0f` |
| Original selected call slot | `0xfffffe0008471498` | `0xfffffe000a551f38`, diversity `0x84cc` |
| Emission/call instruction | `0xfffffe000a52a5b0` BLRAA | Calls the established RW adapter under the bank/frame premises |
| Returning continuation | `a52a5b4..a52a5c8` | Reload phase `0x6e3`; BRAA saved X20 to `a50ef94` |

Both original bank-root slots are verified format8 unauthenticated data pointers; the selected call slot is authenticated. These data-root fixups must not be treated as call sites or Mach-port emissions. The body constructs an internal record and invokes a kernel adapter; no new Mach message or port right is established by this increment. X20 and the private status W21 must survive the returning release, and the release must preserve the relevant frame cells. The source route alone does not prove balanced acquisition/release on a native object. [RT1-RT2,RT6-RT8]

At `0xfffffe000a50ef98..a50efac`, the inner continuation loads the original outer record and writes `u32(W21+0xf9c8e134)` at record`+0x38`. Its normal epilogue checks the guard, restores the frame and performs RETAB. It does not assign the logical status to W0: this inner boundary returns its result through the record. [RT2-RT3,RT6-RT7]

| Private W21 | Stored u32 at original record`+0x38` | Signed32 interpretation | Provenance / limitation |
| --- | --- | ---: | --- |
| `0x06371ecc` | `0x00000000` | 0 | Arithmetic mapping of the earlier gate-true value; later operation code can change W21 |
| `0x06371ecb` | `0xffffffff` | -1 | Prior CONTROL low byte differs from 1 after the true unsigned comparison |
| `0x0636782c` | `0xffff5960` | -42656 | Prior unsigned accumulator/limit comparison is false |
| `0x06367832` | `0xffff5966` | -42650 | Unsupported original W1 default path |

Each row is the exact modular32 sum. These are numeric result patterns, not recovered public error names. In the named outer wrapper, source `0xfffffe000a50e864..a50e878` applies its derived stack displacement D and reloads W0 from the resulting SP`+0x50`. If D=0, this location is exactly the original record`+0x38`, because that record began at entry SP`+0x18`. Loading W0 zero-extends X0; the table's signed32 interpretation does not mean a sign-extended negative signed64 return. Actual D=0, final guard success and authenticated return remain premises. Earlier cursor restoration at bridge entry does not prove cursor preservation through the entire operation. [RT2-RT3,RT6-RT7]

A true `U<LIMIT` clock predicate does not establish a zero final result: the retained SAT control combines a true predicate with original W1=0 and the unsupported-selector result. This is an abstract source-stage composition, not a native context fixture. Separately, byte `+0x174`=0 bypasses the selected clock reader and follows a common status path; skipping that reader is not itself rejection. The paired initializer's zero normalized limit constrains the unsigned comparison if evaluated, rather than proving the skipped path executes that comparison. [RT2-RT4,RT8]

## Reproduction, bounded follow-up and quality gates

The extractor compares retained code with the original KC and normalized image, records original fixups and source excerpts, and serializes the exact solver queries. `--verify` recomputes the evidence and checks equality. The publication audit independently replays 39 new UNSAT queries and two SAT controls, plus 96 prior UNSAT queries and six SAT controls from the codec, reader-lineage and comparison certificates. It independently decodes the two register audits, verifies all bytes/constants/fixups, checks the preserved inputs and exact manifest delta, and scans every owned artifact and decoded archive for analyst paths. No native execution or live IDA lookup is required for these bounded claims. [RT1-RT8]

Extraction/expression work is O(N+I+L+256R) time and space for consumed source/index bytes N, lifted instruction instances I, modeled byte lanes L and bank rules R; SMT solving has separate input-dependent cost. The fixed object transform uses O(512+63) time and O(1) auxiliary target storage for in-place data, plus the fixed frame scratch. Addresses and opcode constants are hexadecimal; access widths and object extents are in bytes; status operations are modular32, pointer operations modular64, and branch ordering is signed32 only where specified.

| Impact | Bounded question | Discriminating evidence |
| --- | --- | --- |
| High | What do original W1 values 1,2,4,5 do? | Extend `a52a7d8` through its actual record call, recover field lifetimes, and compare all four predecessors |
| High | Which daemon request reaches this wrapper and context epoch? | Join daemon serialization, kext dispatch and the named wrapper's actual arguments; match image, object, seed and slot epochs |
| High | Is the cached RW release paired with the relevant acquisition? | Track the cached pointer reload and intervening writers across the same native lifetime, including failure/teardown paths |
| High | Which writers change byte174, word178 and state144? | Trace candidate writes, including the distinct `a56c8dc` source family, to a proven context root; its daemon-input lineage is unknown |
| Medium | Does every selected operation restore representation and cursor? | Enumerate operation continuations and writes to the bridge cursor; check exceptional guard/PAC exits separately |
| Medium | Are numeric results translated at another interface? | Trace callers' width/signedness and result-record consumers before assigning error names |
| Low | Do static target aliases share runtime authentication context? | Compare slot-specific diversities and actual call modifiers; target equality alone does not establish interchangeability |

**QG1**: No normative claim is required. **QG2**: RT1-RT8 register premises, dependent claims and falsification probes. **QG3**: This increment covers the selected re-encoding, operation discrimination, state updates, cached release and conditional result boundary; prior transport reports retain the wider IPC scope. **QG4**: Byte extents, exact integer widths, modular arithmetic and bounded algorithm costs are explicit. **QG5**: Guard/cursor/call/epoch conditions, skipped-reader behavior and unknown operation meanings remain explicit; no whole-operation success is inferred. **QG6**: Original bytes, original chained fixups, supplied-source excerpts, dependency hashes and replayable source queries provide primary provenance. **QG7**: Impact-ranked follow-up questions bound the remaining interfaces and lifecycle joins.


The [shared operation preflight](lskd_operation_preflight_report.md) now binds original W1 values 1,2,4,5 to a no-op hook followed by an `initKernelAESHW()` record wrapper. Nonzero initializer low32 results enter the prior conditional return path unchanged; zero continues operation dispatch. The continuing source recovers original X2/X4-low32, saves the address of cached-byte cell CCC7848, and establishes count thresholds 32/16 for W1=1/5 with units still unknown. Native epochs, full operation meanings and daemon transport remain open.
