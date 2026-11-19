# Installed selector 26 schema lookup results

The installed schema caller uses helper success to copy the selected entry's 8 B payload. It tests the found bit afterward. Consequently, a first empty candidate can return helper success, write an index and copy its payload, then produce a caller error. An occupied hit with a null payload passes the found check and produces a different error. A null entry array gives a helper error before any of those output operations. Eight replays reproduce these distinctions from the installed instruction bytes and declared table inputs. [Auditor](triage_evidence/audit_live_fairplay_schema_lookup_result.py) [Receipt](triage_evidence/live_fairplay_schema_lookup_result_audit.json.zst)

```text
decoded u32 -> token 0x541 request -> shared lookup
    |
    +-- helper error -------------------------------------> publish helper status
    |
    `-- helper success -> copy entry+16 -> test found bit
         |-- bit clear -----------------------------------> publish ce515bc4
         `-- bit set -> test copied payload
              |-- zero -----------------------------------> publish ce515bda
              `-- nonzero --------------------------------> next caller block
```

## Return contract and caller data flow

Addresses are unslid VAs for build `26C5035r`. F is the caller's frame base, S the workspace, C the auxiliary region, A the entry-array address, M the u32 capacity and R the private lookup record at S+0x968. Both ready-holder inputs are carried from the installed scalar and request replays. [Scalar producer](live_fairplay_schema_scalar_report.md) [Shared-holder request](live_fairplay_schema_registry_report.md)

| Channel | Width and address | Installed producer | Installed consumer |
| --- | --- | --- | --- |
| Status | 4 B at R+0x18 | Helper store at `0xfffffe000a5ef9f8` | Caller load at `0xfffffe000a69c6cc` |
| Found | 1 B at S+0x10, addressed by R+0x08 | Clear at `0xfffffe000a5ef6b4`; hit sets one at `0xfffffe000a5ef9c4` | Schema callback reads at `0xfffffe000a677a64` and branches on bit 0 |
| Index | 4 B at S+0xa28, addressed by R+0x10 | Helper store at `0xfffffe000a5ef9dc` | Caller load at `0xfffffe000a69c708` |
| Payload | 8 B at entry+0x10, copied to C+0x440 | Caller load at `0xfffffe000a69c728` and copy through restored X19 at `0xfffffe000a69c72c` | Schema callback reads C+0x440 at `0xfffffe000a677ab8` |
| Caller error | 4 B at S+0x1c | Store at `0xfffffe000a682dc8` | Pending cleanup transfer at `0xfffffe000a682dec` to `0xfffffe000a6a342c` with modifier `0xb23e` |

The first probe is `p = V AND (M-1)` for decoded key V and M>0. The selected entry is A+24*p. The helper loads the 4 B state at `0xfffffe000a5ef8a8` and, on the occupied path, the 8 B key at `0xfffffe000a5ef908`. It compares that key with `0x1ee45f68039f9913 + zero_extend32(V)`. The caller reads the payload only when the helper status is `0x31ae0066` and X19 is nonzero. The modeled array extents are 3,072 B and 1,536 B for capacities 128 and 64. The replay supplies bytes for the selected entry only. The archived positive-capacity bound applies beyond these capacities. [Archived result and probe proof](userclient_schema_lookup_result_report.md)

The helper uses a 112 B stack frame. It preserves X19 through X29 and returns at `0xfffffe000a5efa18` to the nominal link `0xfffffe000a69c6c0` with SP restored to F. The executable model represents the incoming unknown X29 and the signed link as separate opaque values confined to the frame spill and restore. This establishes their round trip under a normal authenticated-return premise. The original BLRAA modifier `0x6a0f` belongs to the call. Hardware B-key and SP authentication at RETAB remains unknown.

The caller resumes through the saved C+0x680 and C+0x30 callbacks. At `0xfffffe000a677a3c` it gates on raw helper status. With success, the found-byte gate at `0xfffffe000a677a90` decides whether to read the copied payload. The next branch at `0xfffffe000a677ae4` tests that payload for zero. In the nonzero case, W23 holds the preselected error code `0xce515bda`, while no error publication occurs. The first nonzero-payload target is `0xfffffe000a677ae8`. The replay ends at that entry. The [historical attribute report](userclient_message_attributes_report.md) covers later source processing.

## Outcomes

Each profile was replayed for the synthetic ADID field V=0 with M=128 and the synthetic u32 V=`0x01234567` with M=64. Their first-probe indices are 0 and 39. The null-array profile uses the same nonzero holder and A=0.

| Declared input | Helper status | Index and found | Caller copy | Caller result |
| --- | --- | --- | --- | --- |
| First occupied key, nonzero payload | `0x31ae0066` | p, 1 | Raw u64 -> C+0x440 | Continue to `0xfffffe000a677ae8` |
| First occupied key, zero payload | `0x31ae0066` | p, 1 | Zero -> C+0x440 | Publish `0xce515bda`, then cleanup transfer |
| First empty entry, zero payload fixture | `0x31ae0066` | p, 0 | Zero -> C+0x440 | Publish `0xce515bc4`, then cleanup transfer |
| Null array | `0xce515bbf` | Index remains precleared; found byte untouched | None | Publish `0xce515bbf`, then cleanup transfer |

For each array case, the audit checks that the index read precedes the payload copy and that the copy precedes the found-byte read. Empty-entry payload zero is a modeled input consistent with the recovered table constructor. The helper's selected array path reads no payload. The caller supplies the only entry+16 read. The modeled nonzero payload is an opaque u64 at the replay boundary, and its pointee and ownership remain unknown. [Installed shared constructor](live_fairplay_shared_table_report.md)

The helper also updates two private image globals. From the u64 loads g0 and g1 at `0xfffffe000cd42f38` and `0xfffffe000cd430d8` respectively, set `t = (F - 0x68 + g0 + g1) mod 2^64`, B=`0x4d08a3fb` and K=`0xa41a4d891208c018`. It stores `((t*B) mod 2^64) XOR K` at the first cell and `((t XOR K)*B) mod 2^64` at the second. Both writes occur in the replay state. The selected path adds no Mach send, receive or right transfer. [Mach ports](mach_ports_report.md)

## Scope and verification

The audit compares 433 words across 29 archived spans and the full 334-word installed helper envelope. Twelve helper words differ at relocated controller, bank or pool operands. The other words match their archived counterparts. It resolves 96 authenticated continuation slots and verifies all 256 inputs to the helper's bank selector. The eight suffixes cover 2,818 instruction visits, 134 logical transfers, 154 writes, 16 table reads and 16 controller reads. All 298 retained source counterexample partitions reproduce UNSAT within the 115 s per-query limit. The first-probe cases take O(1) time and auxiliary space with respect to capacity. Other probe paths retain the earlier O(M) source bound. [Installed table helper identity](live_fairplay_table_cleanup_report.md) [Original source audit](userclient_schema_lookup_result_report.md)

| Assumption | Dependent result and falsification probe |
| --- | --- |
| L1. Pinned collection and relocations | The instruction, branch and channel map depend on the pinned image. Rehash and compare both instruction envelopes, resolve slot metadata, and exhaust the bank selector again. |
| L2. Carried scalar and caller epoch | The packet, callback context and index preclear follow the previous replay. Compare the prior requests, verify the two carried frame roots and compare protected bytes, cursor and links after return. |
| L3. Separated readable table environment | The table outcomes use declared occupied, empty or null-array inputs. Vary first entry state, raw payload and key; an additional probe or a different terminal status disproves the stated first-probe profile. |
| L4. Successful logical authenticated return | The caller suffix depends on the restored F, nominal link and saved X19-X29. Check all six paired frame stores and reloads, separate opaque tokens, and RETAB target. Hardware authentication remains unknown. |
| L5. Synthetic ADID representation | The V=0 bytes support the local replay. A correlated transport capture identifying the actual staging subview and table epoch is required for a native daemon/kext identity claim. |

| Impact | Open interface |
| --- | --- |
| High | Bind the nonzero raw payload to an installed producer, its lifetime, and the first message-attribute consumer. |
| High | Identify the staged record and matching holder epoch in a correlated daemon-to-kext transaction. |
| Medium | Trace the raw error and retained container through cleanup. |
| Low | Compare caller ordering under collision and tombstone profiles using the prior general helper bounds. |

QG1 factual scope, QG2 assumption register, QG3 all four stated outcomes, QG4 widths, extents and counts, QG5 helper/client status separation, QG6 pinned provenance, and QG7 bounded continuation pass for this increment. A successful native lookup, native payload ownership and complete selector 26 operation remain unknown.
