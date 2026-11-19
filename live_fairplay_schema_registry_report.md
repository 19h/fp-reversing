# Installed selector 26 schema output and shared table

FairPlayIOKit's selector 26 core feeds the u32 written by the schema reader into an internal table lookup as its key. The installed code reads the same global holder cell at `0xfffffe000cd4e8a0` as the existing-node UIDList replacement path. With a nonzero holder, it saves this schema caller's own continuation and encodes a 48 B lookup record. A null holder selects the shared typed allocation call. A scalar type error reaches the cleanup transfer without reading the holder. [Scalar producer](live_fairplay_schema_scalar_report.md) [UIDList replacement](live_fairplay_replacement_report.md) [Auditor](triage_evidence/audit_live_fairplay_schema_registry.py) [Receipt](triage_evidence/live_fairplay_schema_registry_audit.json.zst)

```text
schema reader return
  |-- u32 -> saved output -> shared holder cell
  |                           |-- ready -> schema callback -> lookup record -> BLRAA
  |                           `-- null  -> typed header descriptor --------> BLRAA
  `-- type error -> workspace status --------------------------------------> BRAA
```

## Installed control flow

F is the frame base, S the workspace, C the auxiliary region, G the header pointer read from the global holder cell and R the private lookup record at S+0x968. Addresses below are unslid VAs from build `26C5035r`.

| Installed site | Effect |
| --- | --- |
| `0xfffffe000a67790c` | Enter the success caller. A logical transfer with modifier `0x8d40` enters the shared holder routine at `0xfffffe000a69bd88`. |
| `0xfffffe000a69bde8`, `0xfffffe000a69bdec` | Read G through the pool-selected global cell and save the cell's address at F+0x9e0. |
| `0xfffffe000a69be10` | With modifier `0xa830`, branch to `0xfffffe000a69c18c` when G is nonzero or `0xfffffe000a69be14` when G is zero. |
| `0xfffffe000a677944` | The ready path resumes the schema caller. It restores the saved default W23=`0xce515bb2` from F+0x9ec and selects the scalar consumer on the nonzero-G predicate. |
| `0xfffffe000a6779a8`, `0xfffffe000a6779ac` | Load F+0x648, then read the raw scalar V from S+0xbc4. The consumer forms V XOR `0x31ae0066` and selects lookup entry `0xfffffe000a69c2fc`. |
| `0xfffffe000a69c31c`, `0xfffffe000a69c550` | Save schema continuation `0xfffffe000a6779e4` at C+0x30 and common trampoline `0xfffffe000a69c788` at C+0x680. |
| `0xfffffe000a69c558` | Clear the u32 index cell at S+0xa28. |
| `0xfffffe000a69c5a8`, `0xfffffe000a69c5ac` | Read the u64 entry-array address A at G+8 and u32 capacity M at G+4. |

The saved default belongs to the holder-return phase. The ready branch proceeds independently of that default and the scalar consumer produces W23=`0x160` as a continuation-table index. The UIDList replacement caller shares the holder cell and the first lookup call site and uses a different saved caller continuation. Native object lifetime and serialization for the two callers remain unknown. [Original phase and holder predicates](userclient_schema_registry_report.md) [Installed replacement bindings](live_fairplay_replacement_report.md)

## Private lookup record

Let K64 be `((R XOR 0xec7859d5734a22b2) * 0x8c229611) mod 2^64` and K32 be its low 32 bits. The audit evaluates the installed helper's 20 codec words in isolation for R and checks the six ordered writes below. The inherited token decodes the packet's key32 as V. The corresponding occupied-entry comparison key is `0x1ee45f68039f9913 + zero_extend32(V)`, which fits in u64 for every V. [Original lookup probe contract](userclient_hash_table_lookup_report.md) [Installed helper mapping](live_fairplay_table_cleanup_report.md)

| Offset | Width | Value or role | Installed writer |
| --- | ---: | --- | --- |
| R+0x00 | 8 B | Adding K64 yields `0x652019cc00000000 OR zero_extend32(V XOR 0x6a48ac59)`, modulo 2^64. | `0xfffffe000a69c654` |
| R+0x08 | 8 B | Found-byte destination S+0x10. | `0xfffffe000a69c654` |
| R+0x10 | 8 B | Index32 destination S+0xa28. | `0xfffffe000a69c660` |
| R+0x18 | 4 B | Helper status-output slot. Caller leaves these bytes untouched. | None in this suffix |
| R+0x1c | 4 B | Padding in the retained helper contract. Caller leaves these bytes untouched. | None in this suffix |
| R+0x20 | 8 B | A from G+8. | `0xfffffe000a69c658` |
| R+0x28 | 4 B | `(K32 + 0x541) mod 2^32`. | `0xfffffe000a69c668` |
| R+0x2c | 4 B | `((M + 0x4f950919) mod 2^32) XOR K32`. | `0xfffffe000a69c668` |

The six writes total 40 B. The caller retains C+0x440 in X19 as the payload destination at the pending lookup. The helper's capacity, array and occupied-entry requirements remain separate from this packet formation. An occupied hit and an available insertion candidate can both return success and an index under the retained contract, with the found byte distinguishing them. The audit stops before either outcome.

| Transfer | Installed site -> target | Resolved slot / modifier | State at transfer |
| --- | --- | --- | --- |
| Ready lookup | `0xfffffe000a69c6bc` -> `0xfffffe000a5ef4e4` | `0xfffffe0008491288` / `0x6a0f` | X0=R, X19=C+0x440, nominal X30=`0xfffffe000a69c6c0`. |
| Null-holder allocation | `0xfffffe000a69bee0` -> `0xfffffe000c509774` | `0xfffffe0008491258` / `0xd0c8` | X0=`0xfffffe0008492400`, X19=`0xfffffe000a677944`, nominal X30=`0xfffffe000a69bee4`. |
| Type-error cleanup transfer | `0xfffffe000a682dec` -> `0xfffffe000a6a342c` | Modifier `0xb23e` | X19=C+0x418, which retains the container. Raw W23 was stored at S+0x1c by `0xfffffe000a682dc8`. |

The null-holder target is `_IOMallocTypeImpl`. The descriptor is `site.FPHashTable`, signature `21`, flags32 `0x64`, size 16 B. Six adapter words match the older image exactly. The seventh is a direct branch resolving to `0xfffffe000bd46a80` in the installed image. The earlier UIDList constructor audit binds initialization, rollback and reload for its caller. This audit establishes the schema allocation request with its own continuation. The initial allocation outcome, subsequent holder reload and cleanup completion are unknown. The audited suffix contains no Mach send or port-right operation. [Installed shared constructor](live_fairplay_shared_table_report.md) [Mach ports](mach_ports_report.md)

## Verification and assumptions

| Scalar fixture | Model input | Result |
| --- | --- | --- |
| Synthetic ADID field, V=`0x00000000` | Ready header, capacity 128, first modeled array address | Token `0x541`, entry comparison key `0x1ee45f68039f9913`. |
| Derived u32, V=`0x01234567` | Ready header, capacity 64, second modeled array address | Token `0x541`, entry comparison key `0x1ee45f6804c2de7a`. |
| Same synthetic ADID field | Holder set to zero | Pending typed 16 B allocation. |
| u64, zero-length span, 8 B span | Holder unused | Status `0xce515ae1` at S+0x1c in each case. Committed cursor remains 18 B, 10 B or 18 B, respectively. |

The audit pins the collection SHA-256 and embedded kernel and kext UUIDs, hashes the full installed core, checks 293 words in 16 core spans with four pool-address relocations, and matches 20 helper codec words byte for byte. It verifies 75 core branch fixups, six 256 B bank arrays and four selectors over all 256 byte inputs each. It reproduces each of the five earlier scalar records and carries their register and frame state into the suffix, using a fresh replay of the zero ADID field for the null arm. The six suffixes cover 560 instruction visits, 22 logical transfers, 24 stores and seven holder/header reads. Thirteen archived source counterexample queries reproduce UNSAT with a 115 s per-query limit. The selected suffix uses O(1) work and auxiliary space relative to table capacity. Probe cost belongs to the pending helper.

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| R1 | Image identity, instruction translation and fixed-up slot metadata support all site and target claims. | Rehash the collection and full core, compare the retired and installed source spans at their respective offsets, and re-resolve each slot. |
| R2 | Replayed source-owned cells and the scalar reader define carrier state, key V and the error status. | Compare all five preceding receipts byte for byte, check ten carried frame cells per suffix and verify that the continuation preserves protected bytes and cursor. |
| R3 | The ready and null holder values, capacities and array addresses are model inputs. | Run the same scalar with both ready and null conditions, vary capacity and array independently of the packet scalar definition, and check the exact holder reads and packet stores. Actual table storage is unknown. |
| R4 | The integer instruction model treats authenticated transfers as nominal targets with modifiers. | Resolve the chained metadata and check the call ABI at the boundary. Authentication, target side effects and native behavior require separate evidence. |
| R5 | The ADID field is a representation-compatible fixture. | Match its container subview and staging lineage against a correlated daemon/kext transaction before attributing a native ADID operation to this path. |

| Impact | Open interface |
| --- | --- |
| High | Lookup result ownership across the saved callbacks. The found byte, index and status need to be followed separately to the schema caller's payload destination. |
| High | Native relationship between the daemon's ADID operation and the provider's staged schema record. |
| Medium | Allocation, publication and holder reload using the schema-specific continuation, plus subsequent disposition of the error status and retained container. |
| Low | Compare the nominal lookup encoding across additional callers that use the same private record shape. |

QG1 factual scope, QG2 explicit falsification probes, QG3 coverage through all three stated endpoints, QG4 reproducible counts and widths, QG5 modeled and native evidence boundaries, QG6 pinned image provenance, and QG7 bounded open interfaces pass for this increment. The end-to-end daemon/kext transaction remains open.
