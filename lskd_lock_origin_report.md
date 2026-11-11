# LSKD RW-lock construction records and destination provenance

The RW allocation fragment at `0xfffffe000a531028` belongs to a record adapter entered at `0xfffffe000a552490`. That adapter loads its publication destination from record `+8` into X20. Under decoded phase `0x90d`, a nonnull destination and a returning nonnull `IORWLockAlloc` result reach the previously unresolved store at `0xfffffe000a56d3c8`. The result goes to the supplied destination. This resolves the selected store's X20 lineage through the adapter. [LO1-LO4]

A second preparer, `0xfffffe000a52ea1c`, supplies LSKD cell `0xfffffe000ccc78a8` as that destination. Its decoded parent phase must be `0xc2b1dbf2` to select child phase `0x90d`. The source chain is established conditionally on that phase and a returning bounds helper. A native caller producing that phase, a completed native allocation, and the last reaching pointer epoch remain **unknown**. The sample-processing cell `0xfffffe000ccceab8` is a separate address. [LO3-LO6]

The subsequent [start-flow report](lskd_start_lock_flow_report.md) sources that parent phase from the operation `0x1b59` handler under its retained state `0x3be`, after the returning entropy loop and null seed-pointer gate. It also establishes source seed publication before construction, the allocation-failure return and the successful acquisition handoff. Native execution and pointer lifetimes remain open.

The [original-source capture](triage_evidence/lskd_lock_origin_checks.json.zst) contains 633 instructions and 2,532 B from ten spans, eight original bank-pointer roots, ten exhaustive byte-bank rules covering 2,560 inputs, six authenticated continuation slots, two exact import bindings and five supplied-reference excerpts. Eighteen UNSAT queries lift 118 instruction instances and check the record codecs, selected gates, publication and status arithmetic. The [extractor](triage_evidence/recover_lskd_lock_origin.py) and [publication audit](triage_evidence/verify_lskd_lock_origin_publication.py) retain the reproduction and delivery checks. No new target execution or IDA access was needed.

```text
generic wrapper A50B36C(destination)
  -> child record phase 90D, destination at +8
  -> adapter A552490
       destination == 0 -> status FFFF5966
       destination != 0 -> IORWLockAlloc
         result == 0 -> status FFFF5964, no pointer store
         result != 0 -> [destination] = result, status 0

global preparer A52EA1C(parent record)
  -> bounds helper(child + 64 B, limit) returns [PREMISE]
  -> destination = CCC78A8
  -> child phase = parent phase + 3D4E2D1B (mod 2^32)
       parent phase C2B1DBF2 -> child phase 90D -> chain above

LSKD CCC78A8 -> prior acquire / unlock / conditional free-and-clear
sample CCCEAB8 -> separate startup publisher / sample adapters / AES cleanup
```

All addresses in the diagram abbreviate the common prefix `0xfffffe000`. The source order describes selected static paths. It does not establish an inter-thread order or one native lifetime.

## Record and return contracts

Let R be the child record address, E its encoded u32 field, P its destination address, and A the prospective allocation result. All u32 arithmetic is modulo 2^32.

```text
K(R) = (low32(R) XOR AE0701E7) * 952F3CB7
D    = E - K(R)
S    = D - A5
J    = D OR (2 * ((S XOR NOT u32(P == 0)) AND 1))
```

The source writes and reads these exact fields. The 20 B accessed footprint is not an inferred allocation size or a C structure declaration. [LO1-LO3]

| Child offset | Width | Meaning and exact source |
| --- | --- | --- |
| `+0` | 4 B | E, written at `0xfffffe000a50b498` and decoded at `0xfffffe000a5525bc` |
| `+8` | 8 B | P, written at `0xfffffe000a50b49c` and loaded into X20 at `0xfffffe000a5525c0` |
| `+0x10` | 4 B | Status, written at `0xfffffe000a57dcb4` |

The generic wrapper `0xfffffe000a50b36c` encodes `E=K(R)+0x90d` and supplies its incoming X0 as P. It subsequently loads the status field into W0 at `0xfffffe000a50b538`. The supplied decompilation omits the incoming-pointer record store from the displayed body even though its signature retains an argument. The original `STR X0,[SP,#0x18]` establishes that transfer. The captured supplied C remains preserved, and the instruction evidence qualifies its displayed data flow.

| Phase `D=0x90d` outcome | Source selection | Effect |
| --- | --- | --- |
| P is null | J=`0x90d` -> `0xfffffe000a57dcb0` | Status `0xffff5966`, signed32 `-0xa69a`, no allocator or pointer store on this suffix |
| P is nonnull | J=`0x90f` -> `0xfffffe000a530fc4`, saved S=`0x868` | Allocation call `0xfffffe000a531028` |
| A is null after that call | Index `0x868` -> `0xfffffe000a57dcb0` | Status `0xffff5964`, signed32 `-0xa69c`, no destination write on this suffix |
| A is nonnull after that call | Index `0x8b4` -> `0xfffffe000a56d3c0` | `STR X0,[X20]` at `0xfffffe000a56d3c8`, then status 0 |
| Publication completed | Index `0x441` -> `0xfffffe000a57dcb0` | Store status at R`+0x10`, restore saved registers and return |

The return-state arithmetic fixes W24=`0xb025eddd` and W23=`0xb025e4d5` on this selected allocation route. Original slots retain the respective diversities `0x0cc5`, `0x7e6f` and `0xac26`. The source does not read the previous destination word before the selected allocation and publication. Repeated entry can therefore write a new result to the same supplied address under these premises. Actual repetition, competing writers and native reclamation remain unknown. [LO2-LO4]

## Global destination and status namespace

The preparer at `0xfffffe000a52ea1c` reads B from parent record `+8`, encoded parent control from `+0x20` and the limit from `+0x28`. Its accessed parent footprint is 48 B. It passes `(B+64 B, limit)` to the known bounds helper at `0xfffffe000a561058` before constructing the child record at B. Successful native bounds validation and the writable backing extent remain premises. [LO3-LO4]

```text
Q = parent_word20 XOR low32((parent_address XOR C410A4C0) * AED3B63B)
child_destination = FFFFFE000CCC78A8
child_E = K(B) + Q + 3D4E2D1B
child_D = Q + 3D4E2D1B
child_D == 90D  iff  Q == C2B1DBF2
```

The destination bank resolves original pool slot `0xfffffe0008471818` directly to the LSKD cell. At `0xfffffe000a52ec78`, source stores that address at B`+8`. The child call at `0xfffffe000a52ecd4` selects original slot `0xfffffe0008471600`, target `0xfffffe000a552490`, diversity `0x86eb`. The destination is preserved in callee-saved X20 along the selected child path, subject to the allocator's ordinary callee-saved-register contract. No inference from matching frame offsets is required for this destination join.

After the child returns, the preparer translates its status S32 into the parent record's field at `+0x10`. Original arithmetic at `0xfffffe000a52ecd8..0xfffffe000a52ed04` reduces to `u32(S32+0x5e561849)` for every u32 value. [LO2-LO4]

| Child status | Parent field `+0x10` | Established local result |
| --- | --- | --- |
| `0x00000000` | `0x5e561849` | Source publication path completed |
| `0xffff5964` | `0x5e5571ad` | Returning allocator supplied null |
| `0xffff5966` | `0x5e5571af` | Generic adapter received a null destination |

The global preparer's fixed cell address is nonnull, so its phase-90D route selects the allocation arm. The third row describes the generic adapter's domain. The two status namespaces must remain distinct when following an outer method or daemon reply. The parent preparer stores a field and restores its registers. No scalar return-ABI meaning is assigned to incidental X0 on that return.

## Allocation binding and retirement join

| Operation | Kext wrapper | Original import slot | Exact kernel entry |
| --- | --- | --- | --- |
| `IORWLockAlloc` | `0xfffffe000a508d7c` | `0xfffffe000847c3b0` | `0xfffffe000c4bb6e4` |
| `IORWLockFree` | `0xfffffe000a508d84` | `0xfffffe000847c3b8` | `0xfffffe000c4bb780` |

The [RW lifecycle report](rw_lifecycle_report.md) retains the kernel's group, typed allocation view, initializer and free-prefix contracts. This increment resolves the selected allocation store's destination record lineage. The [LSKD continuation report](lskd_continuations_report.md) had already established that its free adapter `0xfffffe000a5529a8` loads the same LSKD cell and, under phase `0x52f` with a nonzero cell, selects `0xfffffe000a579364`. The call at `0xfffffe000a5793b8` uses `IORWLockFree`, followed by `STR XZR,[X20]` at `0xfffffe000a5793bc` if the call returns. New original recapture verifies that cell, API and clear site. [LO1-LO5]

| Domain | Cell and original pointer root | Source-established relationship |
| --- | --- | --- |
| LSKD | `0xfffffe000ccc78a8`, slot `0xfffffe0008471818`, displacement 0 | Conditional construction into this cell, prior write acquisition/unlock, conditional RW free and clear |
| Sample processing | `0xfffffe000ccceab8`, slot `0xfffffe00084725d0`, displacement -4 | Separate selected mutex startup publication, nominal RW fallback consumers and mutex cleanup in the [cached-lock report](cached_lock_origin_report.md) |

The cell difference is `0x7210` B, or 29,200 B. A common IOKit group and common RW API wrappers do not establish common pointer ownership. Matching native creation, acquisition, release and destruction still requires actual callers, the last reaching cell writes and one live pointer epoch. No new incoming or outgoing Mach port, Mach right transfer or external message emission is established. [LO5-LO6]

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| LO1 | The pinned original collection and normalized kext describe this build. All addresses and nominal bindings depend on that identity. | Rehash both and compare every selected instruction byte, original chained slot and exact nlist symbol. |
| LO2 | Source key and branch slices use their stated record operands and widths. The local codecs and selected paths depend on those operands. | Re-lift the original bytes, solve all 18 mismatch queries and vary all symbolic address, status and pointer bits. |
| LO3 | The selected child phase is `0x90d`. The global preparer additionally requires parent phase `0xc2b1dbf2` and a returning bounds helper. | Recover an actual caller and its last reaching encoded control, record backing and bounds return. Other phases are outside the attributed construction path. |
| LO4 | The records and destination are writable and suitably distinct for the stated stores, and allocation returns normally preserving callee-saved registers. Publication/status composition depends on this. | Establish concrete extents, aliases, native call contract and X20 identity across the call. No allocator result or writable native object is invented. |
| LO5 | Prior LSKD consumer and free phases apply to their previously recorded contexts. The source retirement join uses those bounded contexts. | Recheck their original root, continuation and API. Prove native ordering, pointer stability and ownership separately. |
| LO6 | A matched native lifetime requires one reaching publication and actual consumers in a common epoch. | Enumerate intervening writers, concurrent accesses and reclamation, then correlate with the exact loaded build. A static cell match alone cannot satisfy this premise. |

## Bounded continuation

| Impact | Further question | Evidence needed |
| --- | --- | --- |
| High | Does the source start caller producing parent phase `0xc2b1dbf2` execute natively? | The subsequent start-flow report supplies its source phase and frame. Matching runtime entropy returns, bounds, authentication and pointer epochs remain required. |
| High | Which publication reaches each LSKD acquire, unlock and free? | Last reaching cell writes and actual lifetime/order evidence, including repeated construction. |
| High | What reaches the sample-processing cell between startup and cleanup? | Complete its separate writer and owner lineage. The LSKD constructor establishes no writer to that address. |
| Medium | Where do the two status namespaces reach daemon-visible results? | Source method/caller status forwarding and transport reply field correspondence. |
| Low | Which other destinations use the generic construction adapter? | Resolve remaining caller records and phase values with original pointer-bank provenance. |

## Verification and scoped quality gates

Run `recover_lskd_lock_origin.py --verify` with the repository evidence directory on Python's module path and the installed Z3 Python module and library available. It re-extracts the pinned original bytes, exhausts every bank input, verifies original pointer roots and exact imports, re-lifts each arithmetic slice, and compares the complete regenerated artifact. Each retained query also contains its original SMT-LIB text. `verify_lskd_lock_origin_publication.py` checks the manifest delta, original inputs, compressed artifacts and path scrub.

The instruction lift costs O(I) DAG construction and space. Byte-bank checks cost O(256R) for R rules. Original source capture also includes file reading and pointer-chain traversal. Solver cost is separate with a 10 s limit per query. No native synchronization timing or allocation-capacity bound follows from these counts.

- **QG1** passes for factual source and interface analysis.
- **QG2** passes with LO1-LO6, dependent results and falsification probes.
- **QG3** passes for the construction-record, conditional global destination, return/status and retirement interfaces in this increment. The full investigation remains active.
- **QG4** passes with u32 modular formulas, u64 pointer fields, 20 B and 48 B accessed footprints, a 64 B bounds argument, and explicit byte counts.
- **QG5** passes with separate cells, selector premises, status namespaces, local source composition and unknown native epochs.
- **QG6** passes with original bytes, chained roots, exact imports, supplied reference excerpts, 18 source-derived proofs and complete recapture.
- **QG7** passes with impact-ranked caller, publication, status and lifetime questions.
