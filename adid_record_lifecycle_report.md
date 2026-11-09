# CoreADI adid: record construction, allocation layers and value consumers

Original code constructs the holder/nested-record pair used by the [collection lookup/update](adid_context_lookup_report.md). It requests 96 and 176 bytes through `0x1000621d4`, initializes the key/EUID and encoded-zero value, and records a VMM-derived Boolean. The nested tag distinguishes reserved keys -16..-2, key -1 and all other 64-bit values. A declared private pipeline preserves a source-constructed object through the original callback update and a local serializer.

The source allocation path is `0x1000621d4 -> 0x1002698cc -> 0x100267044`. No imported `malloc` is reached in the retained constructor cases. Larger allocation probes reach original anonymous `mmap` requests, where the private engine stops. This refines the earlier description of `0x1000621d4` as a context getter: it gates a size-sensitive allocation interface on the same initialized context cell. Complete native allocator, publication, persistence and driver contracts remain unknown. The full investigation remains active.

## Identity, assumptions and probes

Source: `/System/Library/PrivateFrameworks/CoreADI.framework/adid`; selected arm64e base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. Addresses and arithmetic below refer to this exact slice. Original bytes/fixups are independently reread; no IDB or binary is modified.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| R1: pinned original bytes/fixups describe the inspected image | Source sites, function bounds and local contracts | Fresh readback covers every retained instruction, compiler range, eight windows and three complete allocation functions. Actual native loaded-image integrity/selection remains unknown. |
| R2: frozen private API/PAC/vector/atomic models support the retained paths | Constructor, allocation and callback witnesses | Twelve fresh replays reproduce source/events/object bytes. Hardware PAC, native API results, concurrency and allocator integrity under all states remain unproved. |
| R3: declared fragment entry/frame inputs delimit the experiments | Constructor and local field codecs | Constructor starts at `0x10019c578` using a prior original callback frame, operation/control value `0xd5b`, explicit expected status/key/EUID inputs. Codec fragments use explicit `0xcf8` control and presence inputs. Feasible predecessors and native invocation are unknown. |
| R4: constructor allocation calls and subsequent writes identify these local extents | 96-/176-byte object requests and partial initialization | Original allocation targets, results, all post-return object stores and untouched bytes are checked. Complete native C types, allocator API semantics and initialization guarantees outside the inspected constructor are unknown. |
| R5: stated fixed source constants and modular widths apply locally | Tag, normalization, rounding and codec reductions | Six full-domain local BV obligations pass. Mapping proof additionally requires positive power-of-two alignment and a non-overflow bound; neither proof establishes memory validity or native reachability. |
| R6: one explicit publication fixture connects the constructed record to lookup | Source-object continuity through callback update/serializer | The fixture writes the decoded collection view/entry at the count-load boundary, without patching object fields. Constructor entry and publication remain analyst choices; a naturally reachable lifecycle is not established. |
| R7: serializer and parser operate on distinct local byte views | Field representations and persistence lead | Independent byte oracles cover all retained cases; symbolic proofs cover all field bits. Missing intermediate transformations prevent an asserted on-disk round trip or complete file grammar. |
| R8: literal-family matches identify source candidates rather than native aliases | Six direct+0x98 literal sites and larger inventory | The entire text is scanned under the declared MOV-wide grammar and reconstructed independently through Capstone. Synthesized/interprocedural accesses can be missed; common bias does not prove native object identity. |
| R9: mapping/API boundaries and cold-context controls remain bounded | Allocation-to-VM arguments and failure exits | Four mmap argument boundaries stop before mapping; two constructor cold-context controls stop at the original failure exit. Native OOM, cleanup, free/coalescing and failure consequences remain unknown. |
| R10: source snapshots describe their exact representation/mutation epoch | Pipeline preservation and partial-byte findings | Initial/final objects and each store's prior bytes are retained. Unwritten bytes are not promoted to native uninitialized-data exposure; other epochs, publication, locks and ownership require separate evidence. |

Artifacts: [profiles](triage_evidence/adid_record_lifecycle_profiles.json), [contracts/literal inventory/proofs](triage_evidence/adid_record_lifecycle_contracts.json), [producer](triage_evidence/probe_adid_record_lifecycle.py), [recoverer](triage_evidence/recover_adid_record_lifecycle.py), [checks](triage_evidence/adid_record_lifecycle_checks.json), [validator](triage_evidence/validate_adid_record_lifecycle_delivery.py), [quality gates](triage_evidence/adid_record_lifecycle_quality_gates.json) and [prior-artifact preservation](triage_evidence/adid_record_lifecycle_preservation.json).

## Construction and allocation sequence [R1-R6,R9]

```text
declared original callback frame + constructor inputs
                    |
0x10019c578: expected-status gate and control reduction
                    |
0x10019c654: request 96 bytes -> protected allocation facade
                    |                     |
              holder O              initialized context gate
                    |                cell 0x1002dd2e8
0x10019c7cc: request 176 bytes             |
                    |             0x1002698cc wrapper
              nested Q                   |
                    |             0x100267044 allocator body
          O+0 = Q + pointer bias          |
                    |              existing arena / mmap boundary
       initialize key, tag, EUID, VMM, zero value
                    |
       stop at 0x10019cb24 before publication
                    |
       explicit decoded-view publication fixture
                    |
       original full callback -> Q+0x98 update -> reply 0
                    |
       local serializer reads the same Q+0x98
```

The constructor entry's operation/control input `0xd5b` reduces to state `0x1ed9`; its expected encoded status is `0x0059248f`. The matching branch selects pointer cell `0x1002d2ca8`, target `0x10019c5e8`, diversity `0x3fce`. This is a local gate contract; its preceding helper and naturally successful prerequisite remain unknown.

Both allocation requests select target `0x1000621d4` with diversity `0xd825`. That 660-byte function checks context cell `0x1002dd2e8` at `0x10006234c`; a zero cell returns NULL. The nonzero retained path calls `0x1002698cc` at `0x100062440`, diversity `0xc582`. Its original wrapper reaches allocator body `0x100267044`. The three complete functions and all visited bytes are retained. No exact third-party allocator provenance/version is assigned.

The constructor stores an encoded holder pointer in frame+`0x1a80`; it initially places encoded NULL at holder+0, then replaces it with encoded Q after the second allocation. Clearing the context cell before either allocation makes original code reach `0x1001f7d00`, with encoded marker W5=`0x005874c4`. The probes stop at that exit; later cleanup and native allocation failure are not inferred.

## Requested extents and explicit stores [R1,R3-R5,R10]

These offsets are bytes in the local little-endian representation. Pointer arithmetic is modulo 2^64; u32 fields wrap modulo 2^32. Let X=`0xda8ca8cae5dfbd2d`, U=`0x0046d726`, P=`0x6fac17cb61e34e69`, S=`0x37ae849540968152`.

| Holder O, requested extent 96 bytes | Width | Final constructor value |
| --- | --- | --- |
| +0x00 | u64 | Q+P; initialized as P before second allocation |
| +0x08 | u32 | U |
| +0x10 | u64 | S |
| +0x18 | u32 | U |
| +0x20 | u64 | Raw zero |
| +0x38 | u32 | `0x16911135` |
| +0x5c | u32 | Explicit frame input from+0x2524 |

| Nested Q, requested extent 176 bytes | Width | Constructor value / established role |
| --- | --- | --- |
| +0x00 | u32 | Key-class tag below |
| +0x08 | u64 | Key XOR X; frame input+0x2be0 |
| +0x10 | u64 | X, encoded scalar zero |
| +0x18 | u32 | U |
| +0x58 | u64 | S |
| +0x60 | u32 | U |
| +0x84 | u32 | U |
| +0x88 | u32 | U |
| +0x90 | u64 | S |
| +0x98 | u64 | X, encoded scalar zero; later request-value field |
| +0xa0 | u32 | Explicit frame+0x34dc input: EUID+U in these fixtures |
| +0xa4 | u32 | U + `(VMM query succeeds AND returned value == 1)` |
| +0xa8 | u64 | P, encoded NULL |

The source VMM helper at `0x10002ba5c` requests `kern.hv_vmm_present` via `_sysctlbyname` at `0x10002bd94`. Its returned byte is 10 exactly for success/value1, otherwise 9. Constructor `0x10019ca90` stores U+byte-9 at Q+0xa4. Query values0/1/2 and status5/value1 controls distinguish those cases. No host environment query executes.

The inspected post-allocation constructor writes **40 distinct bytes of O** and **76 distinct bytes of Q**. It does not clear the complete requested extents in this region. Retained untouched bytes include earlier allocator/state contents and remain unchanged by the constructor. This is exact local byte coverage; complete native initialization and any externally observable disclosure remain unknown.

## Exact key-class partition [R1,R3,R5]

Original arithmetic at `0x10019c830..0x10019c8d0` reduces its encoded-key expression to the logical 64-bit key and stores:

| Key bit pattern | Stored u32 tag |
| --- | --- |
| `0xfffffffffffffff0..0xfffffffffffffffe` (signed -16..-2) | `0x61aec522` |
| `0xffffffffffffffff` (signed -1) | `0x61aec521` |
| Every remaining u64 value | `0x61aec520` |

This is a full-domain local proof, with original-code boundary cases. The six first request fields -8,-6,-5,-4,-3,-2 occupy the first class. Application meanings of the classes and the untested native constructor callers remain unknown; no account/content/cryptographic type is assigned.

## Allocation normalization and VM touch points [R1,R2,R5,R9]

For request n, original `0x1002674a0..0x10026756c` normalizes the size as:

```text
if n <= 0xffffffffffffff7f:
    N = max(32, (n + 31) AND 0xfffffffffffffff0)
else:
    N = 0xffffffffffffffff
```

The reduction is proved for all u64 n. For the accepted arithmetic domain, N is 16-byte aligned and N>=n+16. This is an internal chunk-size contract, not a native usable-size/API guarantee. Cold context and requests `0xffffffffffffff7f`, `0xffffffffffffff80`, `0xffffffffffffffff` return NULL in the retained finite states. Smaller successful probes return 16-byte aligned addresses within private source-initialized mappings; no imported malloc call occurs.

Two original VM branches use distinct allocator metadata alignment fields:

| Original mmap callsite | Observed local sizing formula | Retained state/input examples |
| --- | --- | --- |
| `0x100267b1c` | `(N + P + 62) AND (-P)`, u64 | P=16,384 bytes; requests 4,294,967,295 and 4,294,967,296 bytes each produce mapping length4,294,983,680 bytes |
| `0x100267cb8` | `(N + G + 95) AND (-G)`, u64 | G=65,536 bytes; requests65,535 and65,536 bytes each produce mapping length131,072 bytes |

P/G are values in the retained initialized allocator state, not independently established native host page parameters. Both callsites pass address0, protection3, flags`0x1002`, fd bit pattern`0xffffffff`, offset0. Source pointer resolution and original import identity establish `_mmap`; the frozen engine stops with `unreviewed_mapping_guard` before those larger mapping requests are modeled successfully or executed natively.

For a positive power-of-two alignment and the proof's explicit non-overflow bound, the first formula rounds N+63 upward to alignment, and the second rounds N+96 upward. Runtime arena selection, limits, linked/tree bins, free/coalescing, locking, VM ownership and all mapping-failure cleanup remain incomplete.

## Field+0x98 consumers and local representations [R1,R3,R5-R8]

| Direct literal-based site | Source operation | Evidence boundary |
| --- | --- | --- |
| `0x10012009c` | Read Q+0x98, then eight byte stores through`0x1001201b0` | Local serializer under control`0xcf8`/presence fixture |
| `0x10013f998` | Store parsed eight-byte value at Q+0x98 | Local parser under corresponding declared control/presence fixture |
| `0x10019c310` | First key/EUID-match request-value update | Previous full-callback evidence; source-constructed-node pipeline added here |
| `0x10019cae8` | Initialize Q+0x98 to encoded zero | Constructor fragment |
| `0x10019f654`, copy at`0x10019f65c` | Read encoded value and copy it through frame+0x2288 pointer | Static local access/copy; complete invocation/admission unknown |
| `0x10019fac8` | Write value loaded through frame+0x2288 pointer | Static local copy-in; complete invocation/admission unknown |

A whole-text scan covers 631,898 four-byte units, including two undecoded units. The declared consecutive MOV-wide grammar finds 518 members of six pointer-literal families and exactly six constructions of `0x9053e8349e1cb22f`, the nested-pointer inverse plus0x98. The full inventory records every hit and its original member bytes. Capstone independently reconstructs the same inventory. This does not enumerate all synthesized/interprocedural accesses or prove object aliasing across every matching site.

The original local serializer emits:

```text
stored = value XOR 0xda8ca8cae5dfbd2d
local_output8 = BE64(value), each byte XOR 0x73
```

The local parser consumes a different byte view:

```text
value = BE64(each local input byte minus 0x19 modulo256)
stored = value XOR 0xda8ca8cae5dfbd2d
```

Both local operations have full-domain proofs and original-code cases, including byte underflow and absent-field controls. Their byte views are not asserted to be directly composable. Intervening buffer transformations, actual file I/O/framing and the on-disk grammar remain unknown.

The declared pipeline runs the constructor, retains exact object bytes, publishes a collection view immediately before the original count load at `0x10019bdcc`, executes the full original callback with second field`0x0123456789abcdef`, then reads that same nested object in the serializer. Only Q+0x98 changes during the callback; payload`00000000` is emitted through the existing XPC sites. Serializer output is `72503614fad8be9c`. Source object fields are not patched between stages. The fragment entry and publication fixture still prevent a native lifecycle/reachability claim.

## Validation and bounded continuation

All **99,288 checks** pass across61 private cases:21 constructor stages (19 complete/two cold-context exits),21 allocator probes, nine serializer stages, nine parser stages and one original callback update. Twelve fresh replays reproduce44,507 source hooks. Fresh source verification covers14,704 distinct instructions,14 compiler ranges,85,568 ordered visits, eight windows and three complete allocation functions. Six new local SMT proofs solve `unsat`. Original inputs, prior source/proof/profile artifacts and IDBs remain preserved; the [preservation readback](triage_evidence/adid_record_lifecycle_preservation.json) records explicit reporting updates.

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_record_lifecycle.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_record_lifecycle.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_record_lifecycle_delivery.py
```

| Impact | Remaining source/interface evidence |
| --- | --- |
| High | Recover naturally successful predecessors of the constructor and normal publication of O/Q into the collection. Establish count/capacity/entry grammar, duplicate policy, replacement, retirement and error cleanup. |
| High | Follow the two additional value copy paths and all key-class consumers to determine public/internal operation mapping and downstream protected/IOKit use. |
| High | Recover the intermediate byte-view transforms, full serialization/parser framing and actual persistence read/write/flush callers before asserting a file round trip. |
| High | Recover allocator state initialization, bins/free/coalescing, native locking and mmap/munmap ownership/error paths. Distinguish requested bytes, normalized chunk bytes and mapping extents. |
| High | Link actual provider image/peer/port/rights identity, callback replies and selector26/100/PRnut72j9/kernel-RPC paths. This increment reaches neither IOKit nor a new Mach emission boundary. |
| Medium | Follow consumers of the untouched object bytes and VMM-derived field. Constructor byte coverage alone establishes neither native disclosure nor an environment-policy consequence. |

QG1-QG7 pass for the stated increment: descriptive findings, R1-R10 assumptions/probes, scoped coverage, exact arithmetic/extents/proofs, explicit fragment/publication/byte-epoch boundaries, fresh primary-byte/fixup/replay provenance and impact-labeled continuation. The full daemon/kext/deeper-interface objective remains active and incomplete.
