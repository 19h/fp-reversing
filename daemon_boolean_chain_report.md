# CoreML-named and Classic-named Boolean client-bit collector

Private entry 0x1004586D8 now has a recovered 24-byte record contract and a
bounded semantic role: for selector 0xB3D4 with a non-NULL state pointer, it
queries `FairPlay-CoreML-Client` and `FairPlay-Classic-Client` through the same
Boolean adapter and ORs contributions 0x1 and 0x2 into that state word.
The Classic contribution overlaps the previously identified first-query
`com.apple.private.fpsd.client` contribution 0x2. State bit 0x2 alone cannot
identify its producer.

All completed listed models write encoded status 0x8B3DC651, which decodes
to zero under the observed XOR codec. The fixed-selector NULL-state-pointer
branch instead reaches the same status store with raw 0x74C29D88. These are
private source contracts, not native entitlement/admission observations or
proof of final operation success. The names alone establish no CoreML or
Classic framework activity.

## Evidence and reproduction

This extends the [second-result/private-bridge report](daemon_secondary_result_report.md),
[String parser report](daemon_secondary_string_report.md) and
[first Boolean consumer](daemon_entitlement_result_report.md).
Original daemon: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
All source addresses are unslid VAs. The original files suffice; no new IDA
query, IDB change, saved-analysis-memory change or native target/framework/IPC call was
performed for this increment.

Evidence: [24 uniform models](triage_evidence/daemon_boolean_chain_profiles.json),
[eight mixed models](triage_evidence/daemon_boolean_chain_mixed_profiles.json),
[original contracts/ledgers](triage_evidence/daemon_boolean_chain_contracts.json),
[ten source proof pairs](triage_evidence/daemon_boolean_chain_proofs.json),
and [independent replay checks](triage_evidence/daemon_boolean_chain_checks.json).
API outcomes and imported data words are declared private models, not data
observed in the annotated RAX trace. The earlier pure host-strtol reference
is not executed or used as a new library-return source here.

From `/Users/___/dev/dylex/extracted`, apply this prefix to each script in order:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

probe_daemon_boolean_chain.py
probe_daemon_boolean_mixed.py
recover_daemon_boolean_chain.py
prove_daemon_boolean_chain.py
validate_daemon_boolean_chain.py
```

## Recovered private record and entry gate

Let F be the protected-core frame, R=F+0x10CB8 its bridge record and S the
bridge child SP. In the private placement F=0x680004F230,
R=0x680005FEE8 and S=0x680004F150=F-0xE0. These are harness addresses,
not native fixed addresses. Offsets, masks, selectors and status words below
are hexadecimal; ordinary sizes/counts are decimal bytes unless specified.

| Bridge-record offset | Width, bytes | Source-established role |
| --- | ---: | --- |
| +00 | 8 | Borrowed pointer to 32 token bytes, retained F+C100 |
| +08 | 4 | Encoded status output, written at 0x1003FDCFC |
| +0C | 4 | Encoded selector input |
| +10 | 8 | Pointer to mutable u32 state, retained F+6ADC |

The caller writes 20 field bytes; the completed callee writes the remaining
four-byte status. This is a 24-byte private call record, distinct from the
40-byte Boolean-query records and from Mach message layouts. A compile-only
[reconstructed C layout](triage_evidence/daemon_boolean_chain_sdk.c) and
[LLVM output](triage_evidence/daemon_boolean_chain_sdk.ll) check both layouts'
sizes/offsets. The C definitions are analysis artifacts, not exported headers
or proof of a native allocation owner.

With `K24(R)=u32((low32(R) XOR 0x7CF28BE0)*0x83918153)`, the caller stores
`raw=(phase24+0xD64D96E8) XOR K24(R)`. The callee's original instructions at
0x100458824..0x10045885C decode `tag=raw XOR K24(R)`. Separate universal
address-key, post-key decode and composition lemmas establish the match.
The retained caller gives tag 0xB3D4. No formal key cut replaces the actual
MUL in the CPU profiles.

The entry loads the state pointer from R+0x10 at 0x100458860 and tests it for
NULL. A source-local equation covers arbitrary u32 tag and u64 pointer words;
only the retained tag's targets are assigned here:

| State pointer for tag B3D4 | Index | Exact original slot / IA discriminator | Target |
| --- | --- | --- | --- |
| NULL | B3D4 | 0x101093D90 / 5CDC | 0x1003FDCFC |
| non-NULL | B3DE | 0x101093DE0 / 5CDC | 0x1003452D0 |

Both slots have addrdiv=0. Source preloads W8=0x74C29D88 before this branch.
Thus the NULL target is the common four-byte status writer, without entering
the token/key collector. Under the observed XOR 0x8B3DC651 codec that raw word
is FFFF5BD9; its symbolic error name and native delivery meaning are unknown.
The current continuous callers supply a non-NULL frame-state pointer; the
NULL branch is a static/local-theorem contract, not a newly observed native
or complete continuous NULL-input execution.

## Sequential key queries and record reuse

```text
fairplay-client numeric conversion returns nonzero
  state |= 8
  copy token32 -> bridge record R -> entry 0x1004586D8
    selector B3D4, state pointer non-NULL
      key FairPlay-CoreML-Client
        Boolean adapter 0x10046EF4C -> save marker/flag in registers
      refresh the same 32-byte token destination
      key FairPlay-Classic-Client
        same Boolean adapter and same 40-byte record address
      combine both results with the prior state
      write bridge encoded status -> return
  caller reloads status -> retained paths reach malloc(32) frontier
```

| Key | Original CString address | NUL-inclusive bytes | Adapter call / return PC | State contribution |
| --- | --- | ---: | --- | --- |
| FairPlay-CoreML-Client | 0x100FD5565 | 23 | 0x10034547C / 0x100345480 | 1 |
| FairPlay-Classic-Client | 0x100E74ED0 | 24 | 0x1003455E4 / 0x1003455E8 | 2 |

Both calls select 0x10046EF4C with selector 8BB2 through the original
Boolean-query contract. Their 40-byte record is 0x680004F1A0, flag pointer
0x680004F177 and token pointer 0x680004F178. These coordinates are reused
across two call epochs. The first marker/flag are loaded into W20/W25 at
0x100345480/0x100345484 before the second call overwrites the record/result
byte. The underlying adapter clears the flag before constructor handling;
the second call does not inherit a true result from the first flag byte.

Copy32 at 0x1003454F8 refreshes F+C100 -> S+0x28 before the Classic query.
It uses helper 0x10046F89C via slot 0x10109FC88 / IA 34A1. The new copy proof
covers all 256 payload bits at the recorded nonoverlapping placements. Token
bytes are compared to the first task's original-token snapshot in every new
task-argument instance. Equal bytes establish lineage, not authenticated
Mach-sender provenance.

The generic adapter's exact interfaces remain CFStringCreateWithCStringNoCopy
at 0x10033376C, SecTaskCreateWithAuditToken at 0x10047D9AC,
SecTaskCopyValueForEntitlement at 0x1002B7728, CFBooleanGetTypeID at
0x10030ACB0, CFGetTypeID at 0x10030AD04 and CFBooleanGetValue at 0x10052BCC4.
Original loaded slots/imports and call arguments are retained per invocation.
The same PC does not imply the same object instance or record epoch.

The Classic CString is selected through an exhaustive 256-input byte bank
and an original rebase word plus its source bias. Another exhaustive bank
resolves the bridge dispatch-table base to 0x101039EF0. The two checks cover
512 byte inputs; they do not establish native shared-global values, hardware
PAC success or every control/environment state.

## Exact accumulation equation and mixed-result evidence

At 0x1003455F0 the retained saved phase word is B3D4; the state logic uses
its low byte D4. For arbitrary upper phase bits, four marker/flag bytes and
old u32 state, the original instructions at 0x1003455E8..0x100345634 yield:

```text
coreml  = (coreml_marker  != 5B) AND (coreml_flag  != 0)
classic = (classic_marker != 5B) AND (classic_flag != 0)
new_state = old_state OR (coreml ? 1 : 0) OR (classic ? 2 : 0)
```

The final STR W8 is at 0x100345634 through the supplied state pointer.
The theorem covers all four byte domains and all old-state words in the
retained relative, disjoint frame layout. Canonical modeled outcomes are
5B/flag0 on constructor/query-NULL paths and 5C/flag0 or flag1 on Boolean
false/true paths. Other marker/flag combinations belong to the local equation's
mathematical domain, not claimed native adapter outcomes.

| Modeled CoreML result | Modeled Classic result | State with earlier private bit clear, legacy bit8 set | State with earlier private bit2 and legacy bit8 set |
| --- | --- | --- | --- |
| false | false | 8 | A |
| true | false | 9 | B |
| false | true | A | A |
| true | true | B | B |

The overlap is source-established: the earlier first-query writer ORs bit2
and this collector independently ORs the Classic contribution bit2. Neither
path clears it. Consequently a final bit2 value does not distinguish those
two identified producers. Bit1 identifies a CoreML-named contribution in
this recovered path; this is not an exhaustive inventory of all writers in
the binary or a native entitlement-to-permission map.

## Bridge status and environmental touchpoints

All 28 completed profiles reach 0x100345664/0x100345668, which load raw status
0x8B3DC651, then the exact route to 0x1003FDCFC stores it as u32(R+8). The
caller reloads four bytes at 0x1007F7A88. Source proofs establish the constant
store and arbitrary-word caller load; the retained XOR codec decodes this
raw value to zero. A separate all-status-word proof of the original caller
comparison at 0x1008017F8 establishes this exact zero-code value under the
retained caller phase. This is a local zero-code predicate, not final admission.
The record's result channel is four bytes, not one of the
Boolean adapter marker bytes.

The same encoded-zero result occurs for the listed constructor-NULL,
query-NULL, false, true and mixed outcomes. Their state contributions differ.
This separates collector completion from final policy: the caller continues
and all 28 retained paths stop before malloc(32) at 0x100570148. No actual
allocation, published object, final output owner or native admission result
is established. Non-NULL CFError and wrong-type outcomes in these new record
epochs are not newly sampled by this matrix.

The bridge also updates two global words before the state-pointer gate.
Its actual first root is 0x1010B7D88, distinct from 0x1010B7D48 used by the
preceding adapter. The shared second cell is 0x1010C4670. For arbitrary old
u64 words A/B and bridge SP S, define:

```text
d = u64(B - A - (S+48))
u64(1010B7D88) := u64(d*0A5CD4CF + 673E3A80075F02C6) @ 10045881C
u64(1010C4670) := u64((d XOR 73D046208EAED1A6)*0A5CD4CF) @ 100458820
```

Here the stack offset and constants in the display are hexadecimal. The
local all-u64 proof covers these exact source updates. Their native initial
values, synchronization, concurrency and broader meaning remain unknown.
They are separate from the caller-visible u32 client-bit state. The NULL
state-pointer route is not assumed side-effect-free because these global
writes precede its test.

## Assumptions and verification

| ID | Premise and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| BC1 | Pinned source mapping/bytes and original import/fixup words identify the target. | Rehash image; independently decode every used slot and exact target/modifier; reject mismatches. |
| BC2 | Retained predecessor selector/frame, private cells and declared file/BSS/controller/allocator state define these contexts. | Preserve all 32 frozen prefixes; vary controller/backing contexts; recover native initialization before environment claims. |
| BC3 | Bridge/query records, token spans, state and stack cells have the recorded readable/writable extents and disjoint relative placements. | Verify exact widths/masks and copy bytes; stop at unknown owners; investigate native aliases/ownership separately. |
| BC4 | Constructor/query/Boolean outcomes and object identities are explicit API models. Native values/correlations/feasibility are unknown. | Use NULL, strict query, false, true and mixed models; separate every key/object epoch; widen to CFError/wrong types before broader outcome claims. |
| BC5 | The state equation uses saved low phase byte D4 and source-preserved registers between proof fragments. | Check B3D4 in all completed traces; verify intervening instruction write sets; quantify upper phase bits and all marker/flag bytes locally. |
| BC6 | API models preserve X18..X29 and vary X0..X17/NZCV; full vector/ABI effects are not covered. | Fresh CPU replay checks arguments, stack, preserved registers and all journaled effects with changed undefined-byte backing. |
| BC7 | PAC is logical; table/key bank cancellation is a bounded original-data property. | Verify IA/addrdiv/diversity, actual slots and all 512 bank inputs; native authentication and all environment states remain outside scope. |
| BC8 | Byte equality, status zero and bit accumulation are not authenticated sender or final authorization evidence. | Join the original receiver/trailer and final object/status publication; preserve multiple producers of bit2 and native owner gaps. |

Ten original/simplified proof pairs independently solve UNSAT. They cover
address-key decoding/composition, local pointer-index equations, full
marker/flag/state domains, saved phase, status channel, paired global update
and the Classic token copy. The NULL-state-pointer target is statically
established; the continuous profiles exercise the non-NULL caller path.

Fresh replay checks 32 profiles over 96,824 source visits, 21,092 reads,
6,360 writes, 1,852 logical edges and 976 declared API transitions. All
1,942 unique visited opcodes match original bytes. There are 60 new Boolean
adapter entries, 56 returns, four strict query frontiers, 52 token-argument
instances and 120 source-issued release requests. None are native framework
effects or native reference-count observations.

Probe/recovery/replay cost is O(total visits + source/artifact bytes + 512
bank inputs); space is O(one private CPU map + journals). BV proofs add solver
resources and expression-DAG storage. All extents, widths and fixed-width
modular equations are exact; no native timing estimate is asserted.

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| high | Follow the malloc(32) frontier into object/status publication. | Source allocator outcomes, owner fields, error cleanup and final output transfer, with native execution kept distinct from models. |
| high | Establish how the accumulated client bits and stored numeric value are consumed. | Source-continuous reads and final policy/object effects; bit2 provenance must remain nonexclusive. |
| high | Establish authenticated token origin and original caller owner extents. | Receive-trailer bounds/copies and actual B+38/B+40 pointee contracts. |
| medium | Extend this key/record matrix to CFError and non-Boolean returns. | Actual error/type cleanup routes and collector joins in the new frame epochs. |
| medium | Recover shared-global initialization/concurrency and deeper Security IPC. | Matching runtime implementations and synchronization/transport evidence, not key names alone. |

No new incoming/outgoing Mach port, emission site or right disposition is
established. These strings are query keys, not bootstrap endpoints.

QG1: Pass for factual source/interface analysis; no normative judgment is required.

QG2: Pass for this increment; BC1-BC8 identify premises, dependencies and falsification probes.

QG3: Pass for this increment; two key interfaces, 24/40-byte records, selector/pointer/status ABI, token refresh, flags and shared roots are covered. The broad goal remains active and incomplete.

QG4: Pass; extents, widths, exact counts, modular equations, reproduction commands and complexity are explicit.

QG5: Pass within scope; key/object/record epochs, result widths, overlapping bit producers, global versus frame state, static NULL branch and native gaps are separated.

QG6: Pass; original bytes/fixups/banks, compile-only layout checks, 20 SMT readbacks and independent A64 replay support the scoped claims.

QG7: Pass; impact-labeled continuations cover allocation/publication, numeric/bit consumers, owners, error types and deeper runtime/IPC context.

Publication evidence: [preservation](triage_evidence/daemon_boolean_chain_delivery.json)
and [scoped quality gates](triage_evidence/daemon_boolean_chain_quality_gates.json).
