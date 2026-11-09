# CoreADI adid: collection lookup, EUID partition and request-value update

The original callback now has a recovered local collection contract. A decoded count and encoded array pointer lead through 16-byte entries, holder objects and nested records. The source selects the first nested record whose key matches the request's first 64-bit field and whose EUID matches the audit-derived EUID. It writes the encoded second request field at nested offset `0x98`. Under the declared private fixtures, 18 matched cases complete with payload `00000000`; 17 collection misses retain `ffff501f` (-45025). No IOKit API boundary is reached in these cases.

This establishes a request-to-memory update path in original code. Native collection construction, complete object types, field meanings beyond the observed roles, effective peer credentials and native driver transactions remain unknown. One deliberately inconsistent count/null-pointer fixture reaches a private unmapped read; it is retained separately from completed callbacks. The full interface investigation remains active.

## Source identity and assumption register

Addresses refer to `/System/Library/PrivateFrameworks/CoreADI.framework/adid`, selected arm64e slice base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. Original bytes, chained pointers and independent `dyld_info` output are freshly checked. The [state producer/codec report](adid_state_producer_report.md) supplies the local representation model; the [request codec/context report](adid_context_report.md) supplies earlier request and status arithmetic.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| L1: pinned original slice and fixups describe the inspected provider | Addresses, instructions, pointer targets and local contracts | Fresh checks cover all retained instructions, complete compiler ranges, five windows and 20 original pointer cells. Actual loaded-image selection and integrity remain unknown. |
| L2: frozen private API, PAC, vector and sequential atomic models permit these continuations | Original-code paths, updates and replies | Baseline preserves the prior instruction sequence; nine fresh runs reproduce source/events/reads/writes, including the invalid-collection boundary. These share declared models; hardware PAC and native API behavior remain unproved. |
| L3: the previous aligned local 64-byte codec applies at the retained address | Prepared collection view | Fixtures encode before the original transformation at `0x100199778`; original code produces the independently specified view. No instruction-PC jump selects a lookup path. Other state epochs and addresses require their own preconditions. |
| L4: analyst-owned count/array/objects represent only the stated experiments | Positive lookup and update witnesses | Counts, pointers, keys and EUIDs are varied together and independently. Native constructors, allocation/ownership and validity of these records are unknown; no native authenticated context is inferred. |
| L5: source u32/u64 operations use modular arithmetic and unsigned comparisons | Count, cursor, pointer and field reductions | Five new full-domain local BV proofs and three prior request/status proof readbacks pass. Memory validity and whole-program reachability are excluded from those arithmetic proofs. |
| L6: observed offsets describe this local view rather than a complete native type | Partial data layout and semantic field roles | All owned-region reads/writes are compared with an independent collection oracle. Unread entry fields and other nested fields remain untyped. Follow constructors and consumers to falsify broader type assignments. |
| L7: request bytes and modeled audit EUID are separate inputs | Key/EUID conjunction and encoded value provenance | All six admitted first fields and EUIDs 0, 265 and 501 are exercised; key-only and EUID-only mismatches fail independently. Real peer identity, entitlement authority and native audit-token delivery remain unknown. |
| L8: owned arrays/objects remain readable and stable during the bounded scan | Linear scan and first-match semantics | Later and duplicate matches reproduce first-hit behavior; up to 256 entries are checked. Native mutation, locking, reclamation, aliasing and concurrent ordering require separate evidence. |
| L9: completed private callbacks delimit reply claims | Wrapper status, payload and application emission site | 41 callbacks complete, with exact four-byte payloads and source XPC reply callsites. A zero payload does not establish protected-operation completion, downstream consumption or a native request/driver transaction. |
| L10: the null-array/count-four fixture is an explicit inconsistent-state control | Private address-`0x18` boundary and count/pointer invariant lead | Counts zero and one with null array complete; count four attempts a later read. The boundary is freshly replayed, with `native_fault_inferred=false`; native construction/reachability remains unknown. |

Artifacts: [profiles](triage_evidence/adid_context_lookup_profiles.json), [contracts/proofs](triage_evidence/adid_context_lookup_contracts.json), [producer](triage_evidence/probe_adid_context_lookup.py), [recoverer](triage_evidence/recover_adid_context_lookup.py), [checks](triage_evidence/adid_context_lookup_checks.json), [validator](triage_evidence/validate_adid_context_lookup_delivery.py) and [quality gates](triage_evidence/adid_context_lookup_quality_gates.json). Earlier source/proof/profile artifacts and original inputs remain preserved.

## Request-to-record flow [L1-L4,L6-L9]

The wire request is 28 bytes. Three BE32 header fields occupy offsets 0, 4 and 8; the first BE64 field begins at byte 12 and the second at byte 20. Earlier reports call the first field a selector because the source admits the six negative values below. This increment establishes its additional role as the local lookup key. Application meanings such as account identifier, context identifier or configuration selector remain unknown.

```text
28-byte request                    audit token/model
  first64 -> key XOR encoding       EUID -> u32 addition
  second64 -> value XOR encoding           |
           |                               |
           +--------+----------------------+
                    |
64-byte source state -> original codec -> decoded view
                    |
          count + encoded array base
                    |
           array[i], stride 16 bytes
                    |
              entry[i]+8 -> holder+0 -> nested record
                                         +0x08: encoded key
                                         +0xa0: encoded EUID
                                               |
                                    first conjunction match
                                               |
                           store encoded second64 at +0x98
                                               |
                              four-byte payload 00000000
                                               |
                       XPC send_reply at 0x1000aaa70
```

The fixture is injected before the original state load and transform, at `0x100199778`. Original callback entry, request parsing, audit/entitlement models, environmental prerequisites, original lookup/update and subsequent reply path remain in the execution sequence. Explicit private memory preparation replaces the collection; it does not recover a native collection producer.

## Partial local data ABI [L1,L3-L6]

All offsets below are bytes in the decoded/native little-endian local view. Addition/subtraction on pointer encodings is modulo 2^64; count/EUID arithmetic is modulo 2^32. These are observed fields, not complete C structure declarations.

| Region | Offset / width | Recovered local role |
| --- | --- | --- |
| Decoded 64-byte view | `+0x00`, u32 | `0x16e4e4d3 + N`; N is the normalized entry count |
| Decoded view | `+0x08`, u64 | `P + 0x58ce03d8d8c95487`; P is the array base |
| Array entry i | `16*i + 0x00`, eight bytes | Untyped; no read in the retained lookup cases |
| Array entry i | `16*i + 0x08`, u64 | `O_i + 0x2d1ade42073e28af`; zero O_i skips the entry |
| Holder O_i | `+0x00`, u64 | `Q_i + 0x6fac17cb61e34e69`; zero Q_i skips the entry |
| Nested Q_i | `+0x08`, u64 | Lookup-key bit pattern XOR `0xda8ca8cae5dfbd2d` |
| Nested Q_i | `+0x98`, u64 | Receives second request field XOR `0xda8ca8cae5dfbd2d` on first match |
| Nested Q_i | `+0xa0`, u32 | EUID + `0x0046d726` |

The largest known field ends at byte `0xa4` (164 bytes). The private fixture reserves 256 bytes per holder/nested object; that reservation is not a recovered native allocation size. Other bytes and the top-level view's remaining fields retain their earlier evidence boundaries.

## Original access and control sites [L1,L5-L8]

| Operation | Entry zero site | Later-entry site |
| --- | --- | --- |
| Read encoded holder from array entry+8 | `0x10019bf0c` | `0x10019c1c4` |
| Read encoded nested pointer from holder+0 | `0x10019bf74` | `0x10019c230` |
| Read/compare nested key at+8 | `0x10019bfbc` / `0x10019bfc0` | `0x10019c278` / `0x10019c27c` |
| Read/compare nested EUID at+0xa0 | `0x10019c018` / `0x10019c01c` | `0x10019c2c4` / `0x10019c2c8` |
| Branch after EUID comparison | `0x10019c044` | `0x10019c2ec` |
| Common successful value store at+0x98 | `0x10019c310` | `0x10019c310` |

The key/EUID comparison inputs are loaded at `0x10019be70` and `0x10019be74` from frame slots `SP+0x1c18` and `SP+0x29f4`. The encoded second field is loaded through a pointer at `0x10021ac34`, stored into frame slot `SP+0x24b8` at `0x10021ac38`, then loaded at `0x10019c30c` for the common store. Retained variations independently confirm the request-to-value correspondence.

Count-zero selection begins with `0x10019bde0`. The first-entry continuation at `0x10019c048` reduces to testing `N <= 1`; its branch is at `0x10019c094`. Later continuation at `0x10019c0d0` normalizes the circular unsigned comparison; its branch is at `0x10019c14c`. Both select original pointer cell `0x1002c9e30` for continuation to `0x10019c150`, or `0x1002c9fb8` for the common exit `0x10019c098`; both cells have diversity `0xb42b`.

Under the observed source prefix:

```text
origin        = 0xb1e4c5a4
end           = origin + N                         mod 2^32
cursor(i)     = 0x17a54c85 + i                     mod 2^32
source index  = cursor(i) + 0x00000bae + 0xe85aa7cd mod 2^32
              = i
next position = cursor(i) + 0x9a3f7920             mod 2^32
              = origin + i + 1                    mod 2^32
continue iff  = (next position - origin) <u (end - origin)
```

The actual source tests whether end/current lie below origin and selects the appropriate unsigned comparison. The full-domain circular-comparison proof establishes the reduction, including arithmetic wrap. This proves local arithmetic, without establishing valid memory for every count/address.

For readable, stable objects, the normalized operation is:

```text
N = u32(view.u32_at_0 - 0x16e4e4d3)
P = u64(view.u64_at_8 - 0x58ce03d8d8c95487)
for i in 0 .. N-1:
    entry_base = u64(P + 16*i)
    if entry_base == 0: continue
    O = u64(load_u64(entry_base + 8) - 0x2d1ade42073e28af)
    if O == 0: continue
    Q = u64(load_u64(O) - 0x6fac17cb61e34e69)
    if Q == 0: continue
    if load_u64(Q+8) != (first64 XOR 0xda8ca8cae5dfbd2d): continue
    if load_u32(Q+0xa0) != u32(EUID + 0x0046d726): continue
    store_u64(Q+0x98, second64 XOR 0xda8ca8cae5dfbd2d)
    return payload_status_0
return payload_status_minus_45025
```

The local scan takes O(N) time and O(1) auxiliary space under L8. The evidence producer/validator has O(B+F+R+V+sum(N)) work/space in source bytes, fixups, retained records/visits and declared fixture extents, with finite source-hook caps. Actual scheduler time, native concurrency and memory residency are outside this model.

## Cases, outputs and invariant counterexample [L2,L4,L7-L10]

| Case family | Observed result |
| --- | --- |
| Unmodified baseline | Completed callback; payload `ffff501f` |
| Null holder entries; N=0,1,2,3,4,8,16,31,32,255,256 | N array reads at offsets `8+16*i`; misses complete with `ffff501f` |
| Null nested pointers, key mismatches, EUID mismatches | Short-circuit reads agree with the respective failed predicate; payload `ffff501f` |
| Four-entry array; match at 0,1 or 3 | Scan stops at first match; only that record's+0x98 changes; payload `00000000` |
| Duplicate matches at indices 1 and 3 | Only index 1 is updated; index 3 retains its initial field |
| Mixed null-nested/key-mismatch/EUID-mismatch/match | Final entry is updated; payload `00000000` |
| Paired key for each first field -8,-6,-5,-4,-3,-2 | All six complete the same observed update operation under the fixture |
| Paired EUID 0,265,501; EUID501 with stored EUID0 control | Paired cases update; mismatched control returns `ffff501f` |
| second64=0,1,2^64-1,0x0123456789abcdef, plus ordinary fixture value | Corresponding XOR-encoded value stored exactly; payload `00000000` |
| first64=0,1,-1,1234,0x0123456789abcdef | Rejected before collection fixture/codec boundary; payload `ffff5037` (-45001) |
| Null array; N=0 or 1 | Completed miss; no array dereference |
| Null array; N=4 | Entry-zero base is skipped; later-entry read at address `0x18`, source `0x10019c1c4`, stops at explicit private memory boundary; no reply |

The null-array control does not support a global `if P==0: return miss` rule. The per-entry base guard permits progression to index 1 when N>1. The retained inconsistent fixture demonstrates a local invariant requirement; native constructors, reachable inputs and fault consequences remain unknown. No native defect is established.

All 41 completed callbacks have wrapper status 0, output length four bytes, `_xpc_dictionary_set_data` at `0x1000aa9fc` and `_xpc_dictionary_send_reply` at `0x1000aaa70`. Collection miss, early field rejection and successful update are distinct payload outcomes. The common source exit stores an encoded result marker; a hit supplies `0x0059248f` and a collection miss `0x005874ae`, whose prior status reduction yields 0 and -45025 respectively.

No new Mach port name, right or destination object is recovered. XPC peer objects and reply API emission are application-layer observations; the underlying libxpc Mach send, right dispositions and kernel delivery are not executed by the private API model. The original IOKit interfaces documented in the [IOKit report](adid_iokit_report.md), [caller report](adid_iokit_caller_report.md) and [protected dispatch report](adid_driver_dispatch_report.md) remain separate paths.

## Validation and bounded continuation

All 23,470 [checks](triage_evidence/adid_context_lookup_checks.json) pass. Coverage comprises 42 private cases, 36 prepared collection cases, 18 updates, 17 completed collection misses, five early rejections, one inconsistent-collection boundary, 647 array reads, 34 holder reads, 29 nested-key reads, 24 nested-EUID reads and 18 value writes. Fresh source readback covers 15,946 distinct instructions, 13 compiler ranges, 1,952,144 ordered visits, five source windows, 20 pointer cells and 2,106 observed pointer-cell reads. Five new proofs and three prior request/status proofs solve `unsat`; nine fresh replays cover normal, later/duplicate/mixed, nonroot, argument, rejection and inconsistent-collection cases, with 425,671 source hooks. The [preservation readback](triage_evidence/adid_context_lookup_preservation.json) records the prior artifact identities and explicit reporting/aggregator updates.

Reproduction uses the existing local Python environment and `z3`:

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_context_lookup.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_context_lookup.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_context_lookup_delivery.py
```

| Impact | Further evidence / falsification target |
| --- | --- |
| High | Recover all writers of the count, encoded array pointer and holder/nested pointers, including constructors, publication and retirement. Establish actual allocation extents and native count/pointer invariants. |
| High | Follow readers/writers of nested+0x98, +0x08 and +0xa0 to establish application meanings, value lifetime, subsequent protected/IOKit use and whether negative first fields denote operation slots. That semantic assignment is currently a hypothesis. |
| High | Recover locking and reclamation around lookup/update. First-match selection and duplicate behavior are established for stable private objects; native uniqueness and synchronization remain unknown. |
| High | Trace how a naturally constructed record reaches this operation from persistence/startup and CoreFP XPC requests. Match actual provider image, peer/entitlements, replies and failure conversions. |
| High | Connect remaining driver paths through actual selector26/100 responses, PRnut72j9, host-slot/RPC family selection and native port/right identity. A zero ADID update payload does not establish that chain. |
| Medium | Test whether native invariants exclude null array with count>1 and duplicate key/EUID entries. Promote neither private counterexample to a native failure or authorization claim without constructor/control evidence. |
| Medium | Recover underlying libxpc/Mach emission and right ownership for this callback, independently of the separate legacy Mach fallback and IOKit transport. |

QG1-QG7 pass for this increment: descriptive scope; L1-L10 assumptions/probes; coverage of the stated local contract; exact byte/bit widths and proofs; explicit invalid-state and native boundaries; fresh primary-byte/fixup/replay provenance; impact-labeled continuation. The full daemon/kext/deeper-facility objective remains active and incomplete.
