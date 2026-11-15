# FPHashTable lookup: cleanup records, probe policy and raw outputs

The routine at `0xfffffe000a5ae354` is the shared table-probe helper used by both lookup calls in marker-unequal client cleanup. Their original call sites, `0xfffffe000a626f10` and `0xfffffe000a6270a0`, resolve to the same authenticated pointer slot and construct the same internal token 0x541. The helper distinguishes a matching occupied entry from an available insertion candidate: both return raw status `0x31ae0066` and an index, but only a match sets the optional found byte to 1. A candidate leaves that byte at 0. Cleanup tests both channels before consuming an entry. [HL1-HL8; HL-A1-HL-A8]

The previous initializer's u32 default `0x629f8775` is now classified by this consumer as empty. The adjacent values `0x629f8776` and `0x629f8777` serve as tombstone and occupied states, respectively. Entry+8 contains the key representation `0x1ee45f68039f9913 + zero_extend(key32)`. The helper never writes the entry array. Entry+16 is a raw payload consumed by cleanup; its object type, ownership and any task, UID or Mach-port interpretation remain unknown. These are consumer-side classifications, not proof of the corresponding producers. [HL3-HL7; HL-A3-HL-A8]

Primary evidence: [original functions, spans, banks and fixups](triage_evidence/userclient_hash_table_lookup_checks.json.zst), [source obligations and synthetic replay](triage_evidence/userclient_hash_table_lookup_audit.json.zst), [extractor](triage_evidence/recover_userclient_hash_table_lookup.py), [auditor](triage_evidence/audit_userclient_hash_table_lookup.py), [publication verifier](triage_evidence/verify_userclient_hash_table_lookup_publication.py). Context: [initializer](userclient_hash_table_initializer_report.md), [shared-holder bootstrap](userclient_hash_table_bootstrap_report.md), [UIDList cleanup](userclient_uidlist_cleanup_report.md), [context lifecycle](userclient_context_lifecycle_report.md), [descriptor/task flow](context_descriptor_task_flow_report.md). Original files and existing source receipts suffice; no additional IDA access or IDB mutation was needed.

```text
node+4 raw marker -> key32 = marker XOR 0x31ae0066
  -> lookup #1 -> status success AND found bit0=1
     false -> UIDList-node free path
     true  -> index -> entry+16 -> saved payload
              -> lookup #2, same key and table
                 status success AND found bit0=1
                   true  -> entry update/removal frontier
                   false -> completion/free-decision frontier

lookup helper:
  initial index = key32 AND (capacity - 1)
  occupied + equal key -> index output, optional found=1, success
  empty               -> first tombstone or current index, success
  other               -> remember first tombstone, advance/wrap
  capacity visits     -> exhausted status, index output untouched
```

This is a static conditional contract for the pinned image. The constructor establishes capacity 128 and a 3072 B array. Coherent input/output storage, stable source bytes and ordinary authenticated control flow are explicit premises. A native daemon-kext transaction and runtime serialization remain unknown. [HL-A1-HL-A8]

## Evidence and coverage

| Quantity | Verified value |
| --- | --- |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Complete helper | 334 instructions / 1336 B, `0xfffffe000a5ae354..0xfffffe000a5ae88c` |
| Cleanup region | 197 instructions / 788 B, `0xfffffe000a626dc8..0xfffffe000a6270dc`; checked against the previously captured full destroy function |
| Source partition | 491 modeled instructions / 1964 B: 303 helper and 188 caller; 24 transfers / 96 B retained separately; remaining 16 instructions are PAC/BTI entry or landing instructions |
| Models | 29 spans; every selected PC covered by at least one source obligation |
| Static data | Six 256 B arrays; three bank rules / 768 byte-input cases; four pool pointers; 21 original chained branch pointers |
| New proof obligations | 37 nonvacuous UNSAT queries; 2142 instruction instances; array-store exclusion included in every obligation |
| Predecessor obligations | Four re-solved queries: global publication, header 0/128, valid entry address and entry-default/loop contract |
| Separate replay | 18 synthetic cases, 29,134 source instruction instances, 302 distinct helper PCs, 407 entry visits; array unchanged and frame restored in every completed case |
| Altered evidence | Four rejected changes: instruction byte, bank byte, branch target and complete-function byte |
| Checks decoded SHA-256 | `16fba57feb5ae001eb4309a331352acc8ec6a512045171d45d878e5a3b970f22` |
| Audit decoded SHA-256 | `7f9b62cf8034038c7443678fd0f13e8eb257ec7c453e8f6d0596be3a6fe46e68` |

The replay interprets the captured source against independent synthetic records and arrays, then compares status, flag, index and exact visited-index sequence with a separate reference algorithm. Cases cover constructor defaults, key zero, occupied hits, collisions, tombstones, unknown states, wraparound, last-probe hits, exhausted tables, maximum u32 key, null optional flag, null array, capacity 1 and a non-power-of-two capacity. The alternate pointer-retag instruction is source-proved separately and does not execute in these contiguous-array cases. This is not a native execution trace. [HL2-HL8; HL-A2-HL-A6]

## Exact interfaces and source locations

| Evidence | Source locations | Recovered role |
| --- | --- | --- |
| HL1 | `0xfffffe000a626dcc..0xfffffe000a626f10` | Current cleanup phase, raw marker-to-key mapping, first 48 B record, first call binding |
| HL2 | `0xfffffe000a5ae374..0xfffffe000a5ae514` | Controller updates, address-dependent record codec, null-array gate, token/count/key decode and optional flag dispatch |
| HL3 | `0xfffffe000a5ae524`; `0xfffffe000a5ae538..0xfffffe000a5ae654` | Optional flag clear, initial masked index, remembered-index sentinel, key representation and probe constants |
| HL4 | `0xfffffe000a5ae65c..0xfffffe000a5ae6fc` | Index wrap and visit-budget guards |
| HL5 | `0xfffffe000a5ae704..0xfffffe000a5ae7c8` | 24 B entry stride, state classification, occupied-key comparison, first-tombstone retention and successor |
| HL6 | `0xfffffe000a5ae7cc..0xfffffe000a5ae868` | Empty-candidate selection, matched flag, index output and raw memory status |
| HL7 | `0xfffffe000a626f14..0xfffffe000a626fb0` | First success/found tests, selected entry address and entry+16 payload read |
| HL8 | `0xfffffe000a626fb4..0xfffffe000a6270d8`; `0xfffffe000a5ae86c..0xfffffe000a5ae888` | Second record/call/gate; helper frame restoration and RETAB |

| Call | Table binding | IA modifier |
| --- | --- | --- |
| First lookup, `0xfffffe000a626f10` | Index 0xf19, slot `0xfffffe000847a7e8` -> `0xfffffe000a5ae354` | 0x6a0f |
| Second lookup, `0xfffffe000a6270a0` | Same index, slot and target | 0x6a0f |
| Helper's branch-table root | Pool index 0x33, slot `0xfffffe0008472098`, bias -12 -> `0xfffffe0008472f20` | Unauthenticated data-pointer fixup |

The first call uses the F bank pair with key 0x47 and additive 0xe9e. The second uses the V pair with key 0x98 and additive 0xe84. Their independently checked byte-input constants are 0x7b and 0x95; both select index 0xf19. The helper's B pair uses key 0x93, constant 0xec and additive -0xb9 to select pool index 0x33. Original chained membership, words, targets and diversity are retained. The helper address has no exact symbol in the original collection's symbol lookup; the functional name here is recovered from these consumers. [HL1,HL2,HL8; HL-A1,HL-A2]

## Private 48 B lookup record

Let R be the record pointer in X0. All arithmetic below uses modular u64 or u32 operations at the displayed width. The source-derived codec key is:

```text
K64 = ((R XOR 0xec7859d5734a22b2) * 0x8c229611) mod 2^64
K32 = low32(K64)
```

| Offset | Width | Input/output interpretation for token 0x541 |
| --- | --- | --- |
| +0x00 | 8 B | Encoded key word; adding K64 gives `0x652019cc00000000 OR zero_extend(key32 XOR 0x6a48ac59)` |
| +0x08 | 8 B | Optional pointer to one found byte; zero skips both clear and set |
| +0x10 | 8 B | Required pointer to a u32 index output |
| +0x18 | 4 B | Raw status output; not a W0 return value |
| +0x1c | 4 B | No helper read or store in the captured function |
| +0x20 | 8 B | Entry-array pointer P |
| +0x28 | 4 B | Encoded token: subtract K32 to recover 0x541 |
| +0x2c | 4 B | Encoded capacity: XOR K32, then subtract 0x4f950919 to recover N |

The two caller pre-multiply expressions are independently proved equal to the helper's original pre-multiply expression. Each equality is substituted by congruence through the common u64 multiplication before decoding the caller's actual stores. The receipts record these cuts. This establishes both original caller records, rather than only a hypothetical record schema. Other token domains remain outside this contract. [HL1,HL2,HL8; HL-A2,HL-A3]

The first record is at caller SP+0x90, with found byte at SP+0x86, index at SP+0x7c and status at SP+0xa8. The second reuses SP+0x90, with found byte at SP+0x87, index at SP+0x80 and the same status slot. Both use the same key32 and table array/capacity under the stable-header premise. The caller clears the respective index before each call; the second found byte is also explicitly cleared before the helper's own optional clear. [HL1,HL7,HL8; HL-A3,HL-A5]

## Entry states, key decoding and probe policy

| Entry offset | Width | Lookup consumer |
| --- | --- | --- |
| +0 | 4 B | `0x629f8775`: empty; `0x629f8776`: tombstone; `0x629f8777`: occupied; other values advance without a key comparison |
| +4 | 4 B | No read or store by the helper |
| +8 | 8 B | Occupied-key match iff raw value equals `0x1ee45f68039f9913 + zero_extend(key32)` modulo 2^64 |
| +16 | 8 B | No helper read or store; cleanup reads this field after a confirmed first hit |

For the recovered constructor, `N=128`, `initial=key32 & 127`. The helper probes linearly, wrapping an index at or above N to zero. Its visit counter starts at zero, increments once per inspected entry, and is checked before the next inspection. The guard equation is proved for all u32 capacities and visit counters below `0xffffffff`; the constructor path's counter range 0..128 satisfies this bound. Thus an unchanged constructor-sized table inspects at most 128 entries. This does not establish coherent concurrent mutation. [HL3-HL5; HL-A3,HL-A4,HL-A6]

The remembered index starts at u32 `0xffffffff`. A tombstone changes it only while that sentinel remains. An occupied mismatch and every other state leave it unchanged and continue. An empty entry returns the first remembered tombstone if one exists, otherwise the current empty index. A matching occupied entry returns its current index regardless of a remembered tombstone. Exhaustion returns failure even when a tombstone was remembered; it does not publish that tombstone index. [HL5,HL6; HL-A3,HL-A4]

```text
lookup(key32, N, P):                 // conditional ordinary-return model
    if P == 0: return NULL_ARRAY
    if found_pointer != 0: *found_pointer = 0
    i = key32 & (N - 1)
    remembered = UINT32_MAX
    for visits = 0 .. N-1:
        if i >= N: i = 0
        if entry[i].state == OCCUPIED and key_matches(entry[i], key32):
            if found_pointer != 0: *found_pointer = 1
            *index_pointer = i
            return SUCCESS
        if entry[i].state == EMPTY:
            *index_pointer = remembered if remembered != UINT32_MAX else i
            return SUCCESS
        if entry[i].state == TOMBSTONE and remembered == UINT32_MAX:
            remembered = i
        i = i + 1
    return EXHAUSTED
```

This pseudocode requires positive N and the bounded counter premise. In the raw source, N=0 keeps the wrap phase returning to itself; it is excluded from the constructor contract. No caller or native path producing a zero-capacity published header is established. For general positive capacities, the initial bit mask is not a modulo operation; the separate capacity-3 replay checks the literal mask-plus-linear-probe behavior. Lookup uses O(N) time and O(1) auxiliary space for this contract; the key/state comparisons and pointer arithmetic are constant-width operations. [HL3-HL5; HL-A3,HL-A4,HL-A6]

## Output channels and cleanup control flow

| Outcome | Raw status at R+0x18 | Found byte if supplied | Index output |
| --- | --- | --- | --- |
| Null array for token 0x541 | `0xce515bbf` | Untouched; null gate precedes clear | Untouched |
| Matching occupied key | `0x31ae0066` | 1 | Matched entry index |
| Empty/insertion candidate | `0x31ae0066` | 0 | First tombstone, otherwise empty index |
| Probe budget exhausted | `0xce515bd9` | 0 | Untouched |

The raw status words receive no errno interpretation. For a null optional flag pointer, the helper skips its flag stores and still publishes successful indexes. It requires a valid index pointer on the successful paths; no optional index-pointer check is present in this function. A status store precedes the ordinary epilogue, so observing that word alone does not prove successful authenticated return. [HL2,HL3,HL6,HL8; HL-A2-HL-A6]

| Caller gate | Exact branch targets and consequence |
| --- | --- |
| First status test, `0xfffffe000a626f24` | Equal to `0x31ae0066`: table index 0x4ff -> `0xfffffe000a626f44`; otherwise index 0x2d4 -> `0xfffffe000a626920`, the previously recovered UIDList-node free path |
| First found test, `0xfffffe000a626f80` | Bit0 set: index 0x2fc -> `0xfffffe000a626fa8`; otherwise index 0x2d4 -> node free |
| First payload read, `0xfffffe000a626fac` | Read selected entry+16 into caller SP+0x18; no type or ownership transfer follows from this read alone |
| Second combined test, `0xfffffe000a6270b0..0xfffffe000a6270d8` | Success and found bit0 set: index 0xaf7 -> `0xfffffe000a6270dc`; otherwise index 0xa8f -> `0xfffffe000a627308` |

The first call's marker is the raw node+4 word. Locally, the caller transforms it to `key32 = marker XOR 0x31ae0066`. The marker-equal fast cleanup therefore corresponds to zero under this local decode, while the marker-unequal processing path has a nonzero decoded key. This does not establish a system UID, PID, Mach-port name, authorization principal or application identifier. The second call repeats the same lookup after saving entry+16, and does not itself modify the table. The reason for repeating it, including any intended concurrency policy, remains unknown. [HL1,HL7,HL8; HL-A5-HL-A8]

## Memory, control and environmental touch points

The helper uses a 112 B frame: saved optional flag pointer at SP+0, an address-derived controller input at SP+8, and six saved register pairs at SP+0x10..+0x6f. Source obligations establish SP and X19-X30 restoration under intact saved-cell premises; PACIBSP/RETAB and authenticated internal branches remain hardware-authentication premises. The source updates u64 controller cells `0xfffffe000ccc3158` and `0xfffffe000ccc32f8` at `0xfffffe000a5ae3c0` and `0xfffffe000a5ae3c4`. Cleanup's call-pointer selection reads controller cells `0xfffffe000ccc3330` and `0xfffffe000ccc32f8`; exhaustive bank checks make the selected pointer independent of the low-byte controller input. This does not prove atomicity or native global coherence. [HL1,HL2,HL8; HL-A1,HL-A2,HL-A6]

Every source proof checks that its modeled stores lie outside the full decoded entry-array extent. The model separates frame, record, header, found/index outputs and array, and excludes the complete five Mach-O VM regions, including zero-fill storage. The complete helper's stores are to its frame, controller cells, optional found output, required index output and record status. Its code has no external call or Mach trap. The only calls in the selected cleanup region are the two helper calls. No new incoming or outgoing Mach-port operation or emission location is established by this increment. Broader port interfaces remain in the [Mach-port report](mach_ports_report.md). [HL1-HL8; HL-A1-HL-A8]

For occupied-key and caller payload reads, the contiguous-array interpretation requires the tag condition `(P XOR (P+24*i)) & 0xffc0000000000000 == 0`. The alternate MOVK replaces the computed address's top 16 bits with 0xc8a2; that raw effect is proved separately. The constructor-sized whole-array premise `(P XOR (P+3071)) & mask == 0` supports valid indexes 0..127. Valid native dereference of the alternate tagged address is not established. [HL5,HL7; HL-A4,HL-A5]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HL-A1: Pinned original/normalized images and recorded pointer chains | All recovered source identities and bindings | Fresh extraction, full function/region bytes, exact hashes, original chain membership, changed-byte/target rejection |
| HL-A2: Token 0x541, source-width record encoding and ordinary authenticated transfers | Record decoder, helper entry/null gate, internal paths and return | Two original caller joins; independent valid records; all 768 bank inputs; raw PAC metadata retained; other tokens/native authentication unknown |
| HL-A3: Positive coherent capacity; stable array/header and readable extents | Probe policy and constructor-table lookup | Header 0/128 predecessor proof; maximum key, capacities 1/3/128, collisions and exhaustion; raw zero-capacity wrap cycle separately proved |
| HL-A4: Visit counter below `0xffffffff`, valid index and no pointer wrap/tag crossing for ordinary array reads | Bounded scan, entry-key access and contiguous-array interpretation | Universal phase guards, initial-index bound, last-probe/full-table cases, exact alternate-retag equation; current capacity128 bounds count to128 |
| HL-A5: Private record/frame/output storage disjoint from array, header and full image VMs; stable saved cells | Output meanings, payload read, array preservation and frame restoration | Nonvacuous separation premises; array-store exclusion in every query; replay output patterns, array immutability and saved-register checks |
| HL-A6: Per-PC controller reads are conservative values; no native synchronization asserted | Pointer selection and conditional ordinary-return composition | Independent controller symbols plus exhaustive byte-bank identities; raw u64 controller stores retained; runtime races/coherence unknown |
| HL-A7: State names identify this consumer's branch roles only | Empty/tombstone/occupied classification and key representation | Initializer defaults, all three states and unknown-state replay; producers and update/removal rules still required |
| HL-A8: Static/synthetic evidence does not identify native peers or payload ownership | Limits on UID/task/port semantics, daemon-kext pairing and completion | No target API invocation, IDB mutation or native trace added; recover producers/update callees and correlated transactions before extending those claims |

## Bounded continuation

| Impact | Next evidence target | Expected consequence / boundary |
| --- | --- | --- |
| High | Entry update/removal calls at `0xfffffe000a6271e8` and `0xfffffe000a6272f4`, reached from `0xfffffe000a6270dc` | Resolve writer-side state/key/payload and count/tombstone contracts; distinguish entry invalidation from resource destruction |
| High | Completion/free decision at `0xfffffe000a627308`, optional typed free at `0xfffffe000a6273e8` | Join saved entry+16 to deallocation conditions and UIDList successor cleanup; payload ownership remains unknown until this is done |
| High | Producers of node+4 and occupied entries, then per-client context references | Establish key provenance, caller influence and lifetime; local XOR key decoding alone does not identify a principal |
| Medium | Serialization around the shared holder, repeated lookup and controller cells | Determine why lookup repeats and which fields may change across cleanup phases |
| Medium | Correlated fairplayd call records and kext client callbacks | Bind these local table operations to an actual connection/transaction; no new port endpoint follows from this helper |
| Low | Other internal token domains and non-constructor capacities | Extend generic helper behavior without weakening the established token0x541/capacity128 contract |

## Quality gates

- **QG1**: Technical evidence and explicit scope only; no normative judgment is required.
- **QG2**: HL-A1-HL-A8 identify dependent claims and falsification probes.
- **QG3**: Routine function, both caller records, probe control, state/key data flow, outputs, source locations, environmental touch points, Mach-port scope and remaining interfaces are covered for this increment; the full investigation remains active.
- **QG4**: Widths, offsets and dimensions are explicit: 48 B record, 24 B stride, 128 entries, 3072 B array, 112 B helper frame; exact modular integer arithmetic has no rounding term. Extraction/model construction is O(B+I+256R+query DAG), excluding SMT search; each solver query has a 30 s timeout. Replay is O(cases*N) time, with evidence-output space proportional to recorded paths.
- **QG5**: Candidate success versus hit, optional flag versus required index, zero capacity, full-table tombstones, counter width, alternate retag, raw status versus authenticated return, and native concurrency are explicitly distinguished.
- **QG6**: Claims trace to original image bytes, original fixup membership, complete helper/region capture, reconstructed nonvacuous source obligations, independent reference replay and four predecessor queries. No external source or symbol name is fabricated.
- **QG7**: Ranked continuation identifies update/removal, payload ownership, producers, synchronization and daemon correlation; none is claimed complete here.
