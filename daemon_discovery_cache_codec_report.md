# Discovery cache sealing and cleanup

The cache-qualified discovery arm at `0x1005c8428` takes a raw arena address in X10, seals the 552 B context in place, and replaces the raw address with the encoded reference at `0x1005c88b8`. All 13 retained constructor profiles reproduce the sealed backing and published reference byte for byte. The profiles cover two distinct context byte patterns. The discovery arm then decrements the shared control word and requests the final fallback unlock. The saved cleanup continuation reaches a pointer load from S+0x17a0 B whose producer on this route is unknown. [DC1–DC4]

The discovery arm produces the same representation that the earlier network gate consumes at `0x10048192c`. In the retained environment, discovery selects the sealing arm with control 1 and a raw nonzero reference. After publication it leaves control 0 and the encoded reference. The separate network reader accepts those state values under its own caller and backing premises, decodes the reference, restores the raw backing, and publishes the raw address. This establishes a representation and control-state match between the two routes. Native scheduling, lock ownership and a continuous handoff are unknown. [DC2–DC5]

```text
Discovery with control=1 and cache=C
  -> request fallback write lock
  -> transform and permute 552 B at C
  -> cache=encode(C) at 0x1005c88b8
  -> control=0 at 0x10057f70c
  -> request fallback unlock
  -> branch via saved S+0x7448
  -> pending load from S+0x17a0

Separate network-gate replay with control=0 and cache=encode(C)
  -> decode C, restore all 552 B
  -> cache=C at 0x100481d98
```

| Evidence | Source and scope |
| --- | --- |
| DC1 | Pinned thin image SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The replay verifies each visited codec instruction against image bytes and checks selected format-12 fixups. |
| DC2 | [Relock report](daemon_discovery_relock_report.md) and [relock replay](triage_evidence/audit_daemon_discovery_relock.py). These establish the selected gate, the lock-adapter inputs and two shared global roots. |
| DC3 | [Constructor profiles](triage_evidence/daemon_context_lock_profiles.json.zst), [extended success](triage_evidence/daemon_context_lock_success.json.zst), [snapshot](triage_evidence/daemon_context_lock_snapshot.json.zst) and [seal contracts](triage_evidence/daemon_context_seal_contracts.json.zst). These provide the paired raw/sealed bytes, reference-publication events and metadata. |
| DC4 | [Replay](triage_evidence/audit_daemon_discovery_cache_codec.py) and [receipts](triage_evidence/daemon_discovery_cache_codec_audit.json.zst). They check 14 paths, two detached frontier controls and a literal stack-reference census. |
| DC5 | [Network-gate context decoder](daemon_context_unseal_report.md) and [second-allocation failure reseal](daemon_context_state_publish_report.md). These independently locate the inverse and a second writer for the same encoded-reference representation. |

## Inputs, transform and publication

| Instruction or cell | Established role |
| --- | --- |
| `0x1007ca4c4` | Load the u64 shared cache reference through `0x1010c9298`. For the checked control-1 route, X10 carries raw C = `0x6500115b20`. |
| `0x1004c2d30`, `0x1004c2e14` | Separate initializer slices write the root pointers at S+0x858 and S+0x878 B. The selected pool indices are `0x796` and `0x4bc` respectively. |
| `0x1005c8430` through `0x1005c844c` | Metadata word 255 from `0x1010c67d4` selects the u32 at table +200 B. The base held at `0x1010c8268` is `0x6500115d6c` in the retained 512 B table fixture. |
| `0x1005c84a0` through `0x1005c8514` | Eight u32 reads from the pinned image fold the selected table word. The decoded text base is `0x100822058`, the mask is `0x7fff`, and the final fold T is `0xc41c69cd`. |
| `0x1005c8520` | Initialize the scratch pair S+0xb538 and S+0xb540 B to zero and raw C. |
| `0x1005c86d4` through `0x1005c87ac` | Transform 34 vectors of 16 B and two tail words of 4 B, covering all 552 B. |
| `0x1005c87bc` through `0x1005c8808` | Descending swaps at u64 indices 68 through 1. Each selects a strictly lower index. |
| `0x1005c880c` through `0x1005c88b8` | Permute the raw reference bytes, apply the lane arithmetic, and publish u64 `0xe5f6a0000600f0c1` to `0x1010c9298`. |
| `0x1005c88cc` | Dispatch through slot `0x10106ee38`, IA `0x80fa`, to `0x10057f6f0`. |
| `0x10057f70c`, `0x1007fc208`, `0x100208efc` | Store u32 control 0, issue cleanup adapter request with zero primary, and request `pthread_rwlock_unlock` with the fallback value. |

The context seed is `u32(low32(C) * 0xeb36c1ca) XOR T = 0x78396e8d`. At byte index i, the source XORs the low eight bits of `seed XOR ((i+seed)*(i-seed))` into the input, then multiplies by `0x93` modulo 256. For each descending word index i, the swap partner is `u32((u32(seed+i) XOR seed) * 0x01000193) mod i`. The reference applies the corresponding descending byte swaps with key `u32(T * 0xeb36c1ca)` and the two u32 add/XOR lanes detailed in the network decoder report. [DC3–DC5]

The replay matches all ordered context-access addresses and widths to the expected transform. Each profile touches 2,728 B of reads and 2,184 B of writes, including repeated reads and writes during the swaps. The body performs 2,710 instruction visits per profile. Unicorn's configured CPU faults on EOR3, so the replay evaluates 138 visits to five source-checked EOR3 sites as 128-bit bitwise XOR. It executes the remaining codec instructions in Unicorn and compares all output bytes against both the retained constructor and the compact codec. For n context bytes, the codec takes O(n) time and O(1) in-place scratch space. [DC3–DC4]

## Cleanup dispatch and next operand

The replayed cleanup sequence loads slot `0x10103bc58` at `0x10083c1d4`, stores the pointer at S+0x7448 B, reloads it at `0x10075a128`, and takes the IA `0x1910` branch at `0x10075a140` to `0x100577fbc`. The next instruction at `0x100577fc0` needs S+0x17a0 B. The replay stops before that read. No checked instruction wrote the slot in the bounded discovery path. No checked instruction accessed the emitted 16 B interval after the emitter or sent a Mach or IOKit request on this continuation. [DC2, DC4]

Detached controls at this load vary the pointer word while retaining phase `0x6cf4`. The branch at `0x100577fec` uses IA `0x4cdb` and index `u32(phase+0x330f) XOR (pointer_nonzero*14)`. [DC4]

| Declared value at S+0x17a0 B | Index | Slot | Target |
| --- | --- | --- | --- |
| Zero | `0xa003` | `0x101089f08` | `0x10083ea7c` |
| Nonzero | `0xa00d` | `0x101089f58` | `0x1005bfa84` |

The literal A64 u64 SP-relative census finds seven loads and four stores. The stores are candidate producers subject to control flow and frame identity. The scan covers unsigned-immediate encodings. Writes through a computed base, alias, or different-width instruction remain possible. [DC4]

| Literal store to S+0x17a0 B | Immediate value source |
| --- | --- |
| `0x1002aa0e0` | Load from S+0x1998 B at `0x1002aa0dc`. |
| `0x10050690c` | Load from X27+0x98 B at `0x100506908`. |
| `0x100544178` | XZR. |
| `0x100b030a8` | Load from S+0xbf8 B at `0x100b030a4`. |

## Assumption register and bounds

| Premise | Dependent result | Stress test or falsification probe |
| --- | --- | --- |
| DC-A1. The pinned image matches the analyzed daemon build. | Addresses, instruction semantics and fixup labels. | Check the image hash, visited codec words and selected chained fixups. A different hash invalidates the mapping. |
| DC-A2. Detached initializer and constructor state transfers apply in this instance. | Concrete fold, codec inputs and byte identity. | Execute both original root-writer slices, recompute eight text reads, require exact results on all 13 retained contexts, and verify every body access against the declared 552 B backing. Native producer identity is unknown. |
| DC-A3. The modeled pthread returns admit continuation. | Request ordering through cleanup. | Compare bracketed statuses 0 and 35 for the same retained context. Both reach the same publication and cleanup edges. Native exclusion, successful authentication and ownership are unknown. |
| DC-A4. The separately varied pointer at S+0x17a0 B represents an input only to the local null test. | Two successor mappings. | Stop the main replay before its first read and run zero and nonzero controls only to their branch targets. Prove a writing predecessor before joining a successor to a native request. |

High impact. Identify the live producer of S+0x17a0 B and trace the selected descendant into an external call site if present. Identify a runtime instance that correlates daemon cache state, request ownership and an actual transport event. Medium impact. Confirm the fallback lock identity and exclusion across publication. The archived type-0 open still has unknown attribution to this path. [Discovery cleanup and archived-open evidence](daemon_discovery_cleanup_report.md)

Checks cover factual scope, explicit premises, matching byte extents, instruction and fixup provenance, and the two bounded successor controls. Native IPC attribution and the full daemon–kext interaction remain open.
