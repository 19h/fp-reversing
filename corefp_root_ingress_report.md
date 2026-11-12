# CoreFP root-record ingress, stack adjustment and result propagation

Subsequent coherent entry: the [VM lifecycle report](corefp_vm_lifecycle_report.md) now executes four original upstream calls through this ingress with caller-produced mode `0x114e4318`, the source-created metadata object and its VM backing. Complete selected failure returns and caller cleanup pass independent replay; the earlier zero-mode fixtures below retain their stated scope.

Subsequent evidence: the [ingress callers report](corefp_ingress_callers_report.md) establishes three conditional local producers of this ingress record. Their mode preimage decodes to `0x114e4318`, whereas the twelve complete executions below deliberately use mode zero. The new coherent upstream entry stops earlier at `_vm_allocate`; it does not complete these caller-produced inputs through the root. The fixture results below retain their stated scope.

Original routine `0x5f4584..0x5f4908` constructs the record passed to adapter `0x8fcfa0`, which calls protected root `0x8e81c8`. It loads a u64 seed from original image cell `0x1d435b0`, places it at its SP, supplies that word to the adapter, then adds the returned word to SP before reading the root result and copying it to ingress offset `+0x20`. This establishes a source consumer for the adapter output: a stack adjustment in this caller. Its meaning in other callers remains unknown.

Twelve complete private executions traverse the original ingress, adapter, root, lookup and cleanup epilogues. The root record is produced by original instructions rather than patched. Selected failure paths produce adapter output zero, preserve the caller's SP and copy the root's raw marker to ingress `+0x20`, independently of residual X0. Ingress scalar and entry-stack variations are included. Native caller admission, successful processing and daemon/kext pairing remain unknown; the full goal stays active.

The earlier IA `0x41d4` candidates are also separated: `0x77d398` enters `0x779ff0` in a complete original wrapper prefix; the local bank equations at `0x9d4064` and `0x1174224` select `0x656b80` and `0x59fb30`, conditional on their stated cached roots and dispatch base. An identical address-key family does not establish an identical callee or field semantics.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_root_ingress.py), [checks](triage_evidence/corefp_root_ingress_checks.json), [independent auditor](triage_evidence/audit_corefp_root_ingress.py), [audit receipt](triage_evidence/corefp_root_ingress_audit.json), [IDA attempt receipt](triage_evidence/corefp_root_ingress_ida.json) and [publication verifier](triage_evidence/verify_corefp_root_ingress_publication.py) retain this increment. JSON links resolve to `.json.zst`. The [preceding adapter report](corefp_root_adapter_report.md) establishes the local low16-delta-times16 contract and its separate internal/external words; the [lookup release report](corefp_lookup_release_report.md) establishes the frozen failure cleanup models.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; supplied daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Code/data offsets below are CoreFP preferred-base-zero addresses. Record offsets use hexadecimal notation. Scalars are u32; pointers, SP and adapter words are u64. Extents are bytes (B), not inferred native allocation sizes.

| ID | Assumption and dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| RI1 | Hash-pinned original images and format12 fixups identify the analyzed code. All source results depend on them. | Check all retained original extents, pointer rows, dependency hashes and independent instruction replay. New IDA byte readback failed after connection closure and supplies zero corroborating bytes; current native/IDB image equivalence is not established by this increment. |
| RI2 | Entry X0 addresses the declared private ingress record, its two pointer fields address the frozen private referents, and the encoded inputs select root operation `0xc1f7` and mode zero. Complete failures depend on this fixture. | Construct input bytes independently through the original unsimplified key; check source-produced root fields. Vary the third scalar through 0,1,`0xffffffff`,`0xa5a5a5a5`. Upstream production of this ingress record and native admission remain unknown. |
| RI3 | Entry SP is aligned/backed and normal callee/stack-check behavior applies. The coherent result-forwarding claims depend on these conditions. | Compare entry SP offsets -16,0,+16 B; check complete CPU, every data access, source-produced record addresses and final SP/X19-X30 restoration. Successful paths with nonzero adjustment are not executed. |
| RI4 | Once, allocation, bootstrap, lock and PAC effects retain the frozen sequential private models. Failure compositions depend on them. | Compare primary/fallback discovery, null certificate allocation, static/heap lock, caller-register clobber and unlock 0/5. Original callbacks execute; native ownership, PAC authentication, concurrency and transport remain unknown. |
| RI5 | The image seed loaded at `0x5f4830` has its original-file value before that load. Seed/oracle results depend on this initial state. | Independently reconstruct image pages; verify the single eight-byte read from `0x1d435b0` and absence of an earlier overlapping source write. It is not a native initialized-state or immutable-global claim. |
| RI6 | The two local candidate-bank theorems assume the original cached A/B roots and dispatch base `0x1c81940`. Their target results depend on those conditions. | Check original root pointer rows and defining/consuming instructions; exhaust all 256 low-byte inputs per bank pair. Whole-function execution, cached-pointer epoch validity and concurrency are not established for those two candidates. |
| RI7 | Literal IA-diversity census covers only aligned `MOV X17,#0x281b` immediately followed by `BRAA/BLRAA` in original `__text`. Candidate counts depend on that scope. | Independently rescan instruction words and enclosing compiler bounds. Other modifier constructions and computed callers are excluded; equal diversity does not establish a target. |
| RI8 | Exact field transformations and finite coherent paths do not assign native semantic types. Interpretations depend on this boundary. | Preserve the scalar mixer as an explicit function, retain distinct marker/X0/SP channels, and check the stopped sibling callee before its first instruction. No buffer length, authorization property, complete successful request or matched daemon/kext transaction is inferred. |

## Source record transformation [RI1-RI3,RI8]

Let `I` be entry X0, `S` entry SP, and `R = S - 0x50` the source-created root record. The routine's frame SP is `S - 0x60`, so `R = frame_SP + 0x10`. Let `q0`, `q10` and `q14` be u32 loads at ingress offsets `0x00`, `0x10` and `0x14`. All equations in this section use arithmetic modulo `2^32`; address keys use the address low32.

```text
Ki = (low32(I) XOR 0xd914ae5d) * 0x08c5d407
Kr = (low32(R) XOR 0xd97ffe38) * 0xfcf33521
v  = q14 + Ki
t  = v * 0x2dd4c139 + 0x31f01626

F(v) = t XOR 0x1b8e4fe2
       XOR ((t XOR 0x49b63a0a) + 0xc1154c69)
       XOR ((t XOR 0xa377af8e) + 0x2bd4d9ed)
       XOR ((t XOR 0xa26243c6) + 0x2ac135a5)
       XOR ((t XOR 0x3fff5fdf) + 0xb75c29be)
```

`F` is an exact source expression with unknown higher-level semantics. It is not assigned a length, size, key or status interpretation.

| Ingress source | Root destination | Source-stored value | Root-side decoded value / role |
| --- | --- | --- | --- |
| u64 at `I+0x18` | `R+0x08`, 8 B | Pointer passthrough | First frozen private referent |
| u32 at `I+0x14` | `R+0x10`, 4 B | `F(q14+Ki)-Kr` | `F(v)` after root adds its key |
| u32 at `I+0x00` | `R+0x14`, 4 B | `q0+Ki+Kr+0x513c5990` | Operation `q0+Ki+0x513c5990` |
| u32 at `I+0x10` | `R+0x18`, 4 B | `Kr XOR ((q10-Ki)*0x59529999+0x30f52b5f)` | Mode `(q10-Ki)*0x59529999+0x30f52b5f` |
| u64 at `I+0x08` | `R+0x20`, 8 B | Pointer passthrough | Second frozen private referent |

These are 28 distinct source-written bytes in the retained 40 B root view. `R[0:8]` and `R[0x1c:0x20]` retain initial private fill before the root call. The root later writes four result bytes at `R+0`. Neither 40 B nor the 48 B ingress snapshot is asserted to be a native allocation or complete structure size. This caller reads its ingress through offset `0x1f` and writes the four-byte output through offset `0x23`, an accessed view of 36 B with holes.

The independent auditor lifts all 88 original instructions in `0x5f4688..0x5f47e8`, binding only the five explicit ingress loads. Eleven UNSAT queries prove the two key premixes/keys, decoded operation/mode, exact `F` transformation, both pointer transfers, the mode preimage and the postcall address identity. Field theorems quantify independent u32 keys at two symbolic cutpoints validated by the separate original-key proofs. These are proof composition boundaries, not restored runtime frames or execution gaps. A direct combined trial timed out and is retained as an uncounted `unknown`; the composed certificates establish the stated source equations. No source annotation supplies a semantic proof.

## Original call chain and stack consumer [RI1-RI5,RI8]

```text
ingress I -> routine 0x5f4584
  |
  +-- construct R at frame_SP+0x10 using original instructions
  +-- 0x5f4830: read seed s from image+0x1d435b0
  +-- 0x5f4834: store s at frame_SP
  +-- 0x5f48c0 -> slot0x1d04e20, IA0x281b -> adapter0x8fcfa0
  |     external word E is the ingress caller's frame_SP word
  |     internal word Iw := s-256; separate source-created stack location
  |     0x8fd1b8 -> slot0x1d05150, IA0x41d4 -> root0x8e81c8
  |       original root increment: Iw := Iw+256
  |       selected failure -> record R+0 marker; matched-pointer unlock
  |     adapter writes E := 16*((Iw-s) mod65536)
  |
  +-- 0x5f48c8: load returned E
  +-- 0x5f48cc..0x5f48d0: SP := frame_SP+E
  +-- 0x5f48d4: load u32 [SP+0x10]
  +-- 0x5f48d8: store that word to ingress I+0x20
  +-- stack-check/ordinary epilogue; residual X0 survives
```

The original seed value in these private initial images is `0x94a2bbf66116513d`; it is loaded by source rather than inserted as a root-parameter fixture. The adapter's tested failures restore its internal word to this seed and write external zero. Consequently the ingress read at `0x5f48d4` addresses the original `R+0`. In general its address is `R + returned_E` modulo `2^64`; a nonzero output changes which memory word is read. Native backing and successful nonzero-adjustment behavior remain unknown.

The source retains three separate output mechanisms:

| Channel | Selected failure behavior | Evidence |
| --- | --- | --- |
| Root `R+0` -> ingress `I+0x20` | Raw `0x45e2a20f`, or `0x45e2a2e3` for lookup failure | Original four-byte load/store at `0x5f48d4/0x5f48d8` |
| Residual X0 | Unlock result 0 or 5 | Preserved through both source caller epilogues |
| Adapter word at frame SP | Zero | Separate eight-byte store; original caller then adds it to SP |

Unlock result 5 still forwards marker `0x45e2a20f`; the declared lock ledger remains held. The first seven complete profiles reproduce primary/fallback, heap/static, clobber and lookup/unlock error conditions. Five more vary the decoded scalar and stack address. The thirteenth profile stops at sibling callee `0x779ff0` before its first instruction; it is not a completed ingress call.

## Distinct callees and remaining caller frontier [RI1,RI6-RI8]

| Earlier literal callsite | Target / original slot | Evidence scope |
| --- | --- | --- |
| `0x77d398` | `0x779ff0` / `0x1d05158` | Original complete wrapper prefix and authenticated-edge model; stop before callee body |
| `0x8fd1b8` | `0x8e81c8` / `0x1d05150` | Complete coherent ingress/adapter/root failure calls |
| `0x9d4064` | `0x656b80` / `0x1d050e0` | Conditional local original-bank theorem; whole candidate routine not executed |
| `0x1174224` | `0x59fb30` / `0x1d04ed8` | Conditional local original-bank theorem; whole candidate routine not executed |

The two conditional bank contracts assume their source-cached pointer roots and dispatch base `D=0x1c81940`:

| Candidate | A root | B root | XOR before B lookup | All-256 identity | Pointer slot |
| --- | --- | --- | --- | --- | --- |
| `0x9d4064` | `qword(0x1d10b08)-8 = 0x174f220` | `qword(0x1d09870) = 0x18ac170` | `0xa5` | `x XOR B[A[x] XOR 0xa5] = 0xd6` | `D+8*(0x1061e+0xd6)` |
| `0x1174224` | `qword(0x1d09500) = 0x1ac19c0` | `qword(0x1d0b590)-12 = 0x1c78040` | `0x27` | `x XOR B[A[x] XOR 0x27] = 0x18` | `D+8*(0x1069b+0x18)` |

Each identity is exhaustively checked for byte `x=0..255`; the original `UXTB` index admits only that byte. The source state-word mixer can therefore vary without changing the selected local target under these pointer preconditions. These statements do not prove complete candidate reachability, retained-pointer validity across arbitrary epochs or common record semantics. In particular the root-like key expression near `0x9d3f70` does not identify the protected root.

The ingress itself has original reference slot `0x1d03c60`, IA diversity `0x6073`. The root adapter has reference slot `0x1d04e20`, encoded word `0x8008281b008fcfa0`, IA diversity `0x281b`. The new full-`__text` literal census finds twelve `0x281b` candidates:

| Callsite | Target established here |
| --- | --- |
| `0x5f48c0` | `0x8fcfa0` in twelve complete executions |
| `0xa32144` | unknown |
| `0xb55950` | unknown |
| `0xb56ca8` | unknown |
| `0xb580ac` | unknown |
| `0xbec190` | unknown |
| `0xbed628` | unknown |
| `0xe5d5d4` | unknown |
| `0xe675bc` | unknown |
| `0xe67bf8` | unknown |
| `0xfcc454` | unknown |
| `0xfcdb88` | unknown |

The remaining eleven lie in compiler-function extent `0x9e8ab0..0x111d200`. Their eight-byte literal/call sites and original compiler bounds are retained for the census; the containing large function is not executed or semantically reconstructed here.

## Validation, limits and next steps

The retained thirteen profiles comprise twelve complete ingress returns and one stopped sibling prefix: 45629 original client visits, 9753 reads, 4949 writes, 683 PAC models, 203 API/model events, 86 ingress points, 48 handoffs, 24 lock events, 14 bootstrap calls and 10 certificate-allocation attempts. Independent replay verifies all thirteen initial CPU frames and 3047424 B each of initial/final touched RAM. The source inventory contains 23 complete functions/import stubs, totaling 122472 B; the stopped sibling frontier has four additional original fetch-backing bytes, with no callee instruction executed. Eleven UNSAT certificates cover 88 lifted sites; 50 separate exact instruction checks and 512 exhaustive byte cases support the field/bank contracts. Nine independent frozen daemon children cover 333 original daemon visits, without full daemon CPU/RAM replay.

IDA memory queries for `9d34d4` and `1173af0` each returned zero facts/notes without truncation. The subsequent batched byte request failed with an Assist connection-closed error after transmission; it may have run, but returned no bytes and was not repeated. It contributes **zero new live byte corroboration**. Source claims rely on the pinned original files and independent replay/lift, not a successful current IDB read. No IDB mutation, native call or native port operation is performed.

No new incoming/outgoing Mach port or message emission site is established. Nine daemon children repeat the frozen unchanged-ID rejection under its independent driver. Native namespace/right lineage, successful request delivery and a matched kext transaction remain open.

| Impact | Bounded next question | Discriminating evidence |
| --- | --- | --- |
| High | Who produces ingress fields at `I+0`, `I+0x10` and `I+0x14`? | Resolve the `0x6073` caller family and retain original stores/epochs before applying this recovered transform to native-looking values. |
| High | Which of the eleven large-function `0x281b` candidates call the root adapter? | Resolve their reaching pointer loads; diversity alone is insufficient. |
| High | What changes the internal root word on successful paths, and where does the adjusted SP point? | Trace original word stores and result relocation together; zero-output failure evidence does not establish successful backing or semantics. |
| High | Can an actual input producer resolve the coherent optional-input frontier? | Join producer fields and state to the [cold seed/context report](corefp_cold_seed_report.md), then check the previously unexecuted read before classifying output. |
| Medium | Do the two conditional bank contracts hold at their complete caller epochs? | Reconstruct the cached pointer definitions and reach the actual callsites through their source control flow. |
| Medium | Can daemon/client/kext endpoint and right histories be joined? | Establish matched image/epoch request translation and connection lineage rather than infer pairing from local record or stack stores. |

The local ingress transformation has fixed instruction count and O(1) time/space; the frame uses 96 B before child work. Producer/auditor time/space is conservatively bounded by O(C*(B+P*F+V*J+R)), for profiles C, source/image bytes B, touched pages P, fixups F, visits V, journal entries J and retained RAM R. This includes per-page fixup scans and reaching-load journal searches. Client execution is bounded to 30000 visits per profile; solver queries have separate 30 s bounds. This is not a native performance estimate.

- **QG1**: Factual technical analysis; no normative premise is required.
- **QG2**: RI1-RI8 enumerate assumptions, dependent results and falsification probes.
- **QG3**: The original ingress transformation, adapter-output consumer, selected complete returns and bounded caller/bank frontier are covered; the full investigation remains incomplete.
- **QG4**: Hexadecimal field offsets, byte extents, u32/u64 wrap and separate arithmetic/execution complexity are explicit and reproducible.
- **QG5**: Record result, residual X0, stack delta, complete/prefix executions, conditional bank epochs and unavailable IDA bytes are separated. Successful/native questions remain unknown.
- **QG6**: Hash-pinned originals, independent CPU/RAM replay, instruction lift, solver queries and exhaustive bank cases are retained; the failed IDA read is not counted as corroboration.
- **QG7**: Impact-ranked continuation identifies concrete missing producer, caller, successful-stack and cross-level lineage evidence.
