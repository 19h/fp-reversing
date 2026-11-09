# RPC502 sidecar mapping, copy, cleanup and parser boundary

The selected sidecar path loads the encoded file size into both mmap's 64-bit length and malloc's 64-bit allocation size without truncation. Successful mapping publishes a 32-byte result containing the descriptor, raw mapping and encoded size. Original byte-copy blocks then copy the mapped file into the allocation in descending address order. The next inspected parser operation reads the first four bytes as big-endian and XOR-encodes the word with `0x8b3dc651`; its semantic field identity remains unknown.

The fstat status marker gates mapping after the size load. Early fstat/mapping failures return before descriptor publication on the selected path. Later allocation failure reaches munmap and close; close is followed by clearing the descriptor even for a modeled failed close. Selected failure exits request the saved QoS class with relative priority zero. These are original-instruction and explicitly modeled private-continuation results. No native target filesystem, IPC, mapping, allocation, scheduling or loader operation was executed.

## Provenance and assumption register

Analysis date: 2026-11-01. Original arm64e source SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The available universal source `/Users/___/Downloads/fpx/fairplayd` hashes to `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`. Its 17,668,912-byte slice at offset3,407,872 exactly matches the thin source.

The current live IDB is `6b117c693e3b`. Nine fresh 48-byte readbacks match original source bytes. Its recorded original-input SHA-256 matches the available universal source, but the IDB's recorded locator `/Users/___/Downloads/fairplayd` is now absent. A direct attempt to hash that locator failed; the subsequent readback used IDA's recorded digest and actual database bytes, with the available universal copy independently checked. No IDB mutation or target execution followed from these checks. [Current readback](triage_evidence/rpc502_mapping_ida_readback.json) retains this distinction.

[Contracts](triage_evidence/rpc502_mapping_contracts.json) retain 13 bounded original ranges, seven full-domain arithmetic proofs under explicit register conditions, six exhaustive 256-input selector-bank identities, original import/dispatch fixups and 33 private fixture instances: eleven size seeds, three mapping-result cases, three allocation-result cases, six patterned-copy cases and ten frame/cleanup/QoS cases. Some instances share inputs and corroborate different observations; they are not 33 independent native transactions.

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| M1: source slice and current IDB belong to the intended build | All addresses and source interpretations | Recheck source hash, exact universal slice and live bytes. The missing IDB locator does not attest a runtime executable or prevent byte readback. |
| M2: selected encoded-frame/table/register conditions apply | Guard reductions, length identities, observed record fields and local helper roles | Trace alternate predecessors. Retained frames include the actual selector operands, stack values and original dispatch fixups. |
| M3: earlier private PID-zero, VMM-positive/skip-CoreKE, CSR/BootPolicy, PAC bypass and support-runtime models are adequate for these bounded continuations | All private fixture behavior | Compare native startup, APIs, registers and memory protection independently. No CoreKE code executes; valid native sidecar framing remains unknown. |
| M4: the sole supplied metadata field is the specified st_size bit pattern | Mapping/allocation length and status/size separation | All other stat-output bytes remain unknown and guarded; signed-negative/extreme values are stress seeds rather than asserted native regular files. |
| M5: private mapping/allocation and explicit contents/status seeds represent only the stated test cases | Copy/parser and cleanup continuation observations | Unmodeled data/imports stop execution; private mapping is read-only, allocation extent is guarded and contents are either unknown or explicit patterns. Native API success, actual file contents and native reachability remain unverified. |
| M6: installed arm64e SDK declarations describe the relevant API ABI | PROT_READ/MAP_PRIVATE/MAP_FAILED, widths and QoS terminology | Compile explicit-sysroot assertions and compare the loaded runtime separately. Original register/import identities do not depend on assigning SDK names. |
| M7: the saved original class/relative-priority seeds are 0x15/-2 | Concrete late QoS arguments | Recover original writes/readback and vary query/set status. Current failure cases include query-failed and initial-set-failed variants; native scheduling is never changed. |

Targeted IDA knowledge queries add no verified sidecar semantics. The string query `SC_Info fstat sidecar` returned no facts. A local-address recall returned four unverified/global notes, including earlier MIG work and unrelated instruction-set addresses; they were not promoted to current evidence. [String query](triage_evidence/sidecar_data_memory_0.json) and [address recall](triage_evidence/sidecar_data_memory_1.json) preserve the actual results, excluding automated host suggestions.

## Status guard, length transfer and API emissions

The [preceding report](rpc502_sidecar_report.md) establishes the size read at fstat buffer+0x60 and its encoding `size_bits XOR K64`, where K64=`0xb3800b93c8bcf32b`. At `0x100ca39f8`..`0x100ca3a44`, selected incoming W8=`0x27ae` yields the following full-u32-domain result:

| W28 status marker | Table index / original target | Selected effect |
| --- | --- | --- |
| `0x8b3dc651` | `0x91c8` -> `0x100c85da8` | Prepare mmap |
| Any other u32 | `0x27ae` -> `0x100dcf770` | Store status into file-helper record and return |

Thus reading/encoding size before this guard does not imply mapping after fstat failure. The failure fixture with explicitly seeded size64 returns low32=`0xffff5b82`; ordinary success-marker cases reach mmap. The complete meaning of this error namespace remains unknown.

| Interface | Native emission | Original binding slot | Recovered argument contract |
| --- | --- | --- | --- |
| mmap | `0x100c85e40` | `0x1010a0da8` | X0=0; X1=size_bits; W2=1; W3=2; W4=descriptor; X5=0 |
| malloc | `0x10095b5c8` | `0x10109ff58` | X0=size_bits |
| munmap | `0x1003aaef4` | `0x1010a0f78` | X0=published mapping; X1=decoded size |
| close | `0x1001f19c4` | `0x1010a06d8` | W0=published descriptor |
| free | `0x1008ec710` | `0x10109ff30` | X0=copied-file allocation in the current rejected-pattern cases |
| late pthread_set_qos_class_self_np | `0x1005eeb98` | `0x1010a10e0` | W0=saved class; W1=0 |

All six bind to `/usr/lib/libSystem.B.dylib`. Their authenticated IA discriminators are, respectively, `0xda1c`, `0x6aa4`, `0xda1c`, `0xee56`, `0x46a2` and `0x2a04`. Each selected bank is exhaustively checked across256 selector-byte inputs against original bytes and the exact imported symbol. Static fixup metadata does not establish successful hardware authentication.

The installed SDK identifies protection1 as PROT_READ, flags2 as MAP_PRIVATE and the failed mapping result as all64 bits set. The selected mmap contract is therefore:

```text
mmap(NULL, size_bits, PROT_READ, MAP_PRIVATE, descriptor, 0)
```

Original arithmetic reduces mmap's derived length key to K64, so X1=`encoded_size XOR K64 = size_bits`. The subsequent malloc block similarly derives K64 from its control registers and XORs the stored encoded size into X0. Separate SMT queries prove both identities for every64-bit size bit pattern under M2. Neither calculation truncates to32 bits.

Ten fstat-success size seeds, including0, 1, 8, 64, 4096, 2^20, 2^32-1, 2^63-1, 2^63 and2^64-1, all reach the same mmap boundary with that exact length. This is finite selected-path evidence; it does not prove that every request reaches this branch, that these lengths are valid native files or that mmap succeeds. The selected path does not reject those tested lengths before the call.

The mmap-result guard compares the full64-bit result against MAP_FAILED, selecting `0x528a -> 0x100dcf770` on failure and `0x5287 -> 0x100dacb54` otherwise. The local predicate does not classify pointer zero as MAP_FAILED; downstream zero-address behavior has not been executed. The malloc-result guard separately tests a null pointer, selecting `0x49f3 -> 0x100723af8` or `0x49e5 -> 0x10082c504`. Both predicate/table identities have full-domain proofs and original fixup readback.

## Output record and publication order

These layouts describe two particular epochs; the same stack addresses are reused later for other protected records. Their [compile-only C prefixes](triage_evidence/rpc502_mapping_layouts.c) do not imply one permanent whole-program structure.

| File-helper argument-record offset | Width | Observed field |
| --- | --- | --- |
| +0x00..+0x17 | 24 bytes | Prefix fields not assigned semantics here |
| +0x18 | 8 bytes | Constructed sidecar pathname pointer |
| +0x20 | 8 bytes | Mapping-result output pointer |
| +0x28 | 4 bytes | Encoded status, written at `0x100dcf770` |
| +0x2c..+0x2f | 4 bytes | No initialization guarantee established |

| Mapping-result offset | Width | Observed publication |
| --- | --- | --- |
| +0x00 | 4 bytes | Signed descriptor, initialized to -1 at `0x100d943e4`; set to opened descriptor at `0x100dacb58` |
| +0x04 | 4 bytes | Untouched padding; no validity guarantee |
| +0x08 | 8 bytes | Raw mmap result, stored at `0x100dacb5c` |
| +0x10 | 8 bytes | Encoded size, second qword of the same STP |
| +0x18 | 8 bytes | Opaque auxiliary value, zero in current cases, stored at `0x100dacb60` |

The successful publication block stores the descriptor, mapping, encoded size and auxiliary field, then selects the success marker. In the fstat-error and MAP_FAILED fixtures, this block is absent: the output descriptor remains-1, and the other result fields have no success validity guarantee. Their observed fixture zeros are not valid-output evidence.

Both selected early failures return to the outer RPC fixture without a close call in that recorded continuation. The opened descriptor has not been published through this result. This identifies an unresolved ownership/cleanup edge; a persistent native descriptor leak is not established. Other aliases, native preconditions and any enclosing lifecycle obligation require further recovery.

The [frame/write evidence](triage_evidence/rpc502_mapping_frames.json) watches the full32-byte result and the current48-byte argument-record range. It also records later writes to the reused record address. Those later parser/cleanup records are deliberately not assigned the file-helper layout above.

## Native copy and the next parser operation

Successful private mappings of1 and64 bytes reach malloc of the same extent. With only an allocation result supplied, execution next reads unknown mapped data and stops: offset0 for length1, or offset63 for length64. No file byte is invented in those cases.

The [patterned-content fixtures](triage_evidence/rpc502_sidecar_contents_index.json) explicitly supply `byte[i] = ((73*i) XOR 0xa5) mod256`. Six lengths1, 7, 8, 9, 64 and256 copy exactly, with both source reads and destination writes in order L-1 down to0. Multiplication by73 is a permutation modulo256, so the length256 case exercises every byte value. The bytes are arbitrary synthetic data, not asserted valid sidecar records.

| Original range | Local role |
| --- | --- |
| `0x1005d0314`..`0x1005d0394` | Eight descending byte loads/stores per selected bulk iteration; remaining count decreases by8 |
| `0x10059ccd0`..`0x10059cd04` | Selected one-byte descending remainder loop |
| `0x1009b6eac`..`0x1009b7014` | Four byte loads in big-endian order and mixed arithmetic producing `BE32 XOR 0x8b3dc651` |

Under the recorded copy-register conditions, the unusual third bulk address reduces to remaining-3. The copied byte itself passes directly from LDRB to STRB; this stage performs a byte-preserving copy. The observed behavior is summarized by:

```text
for i = L; i != 0;:
    i = i - 1
    destination[i] = mapping[i]
```

The finite cases cover both bulk and remainder paths. They do not establish every64-bit count, all predecessor states, zero-length copy behavior or overlap semantics. The copy is O(L) time with O(1) auxiliary space; the distinct file allocation is O(L) storage. Native mapping residency, allocator behavior and a valid sidecar's total processing cost remain unknown.

For each patterned length at least4, the subsequent reader accesses offsets0, 1, 2 and3 of the allocation, twice on the reached rejection path. Its four-byte result is XOR-encoded with the same32-bit constant used in earlier payload-parser evidence, as a full32-bit-domain SMT query proves. Equality of the encoding does not establish equal field meaning or equal parser schema. Whether this word denotes a version, length, key or other field is **unknown**.

Length1 reaches a read at allocation+1, PC `0x1009b6ed0`, after its first byte load. The private logical-allocation guard stops there. This is an extent-crossing witness for an explicitly synthetic input; it is not a native page fault, successful disclosure or proof that such input satisfies native caller prerequisites. Lengths7, 8, 9, 64 and256 reach free of the copied allocation at `0x1008ec710`, where these fixtures stop before free executes. Their later cleanup and final parser error remain unmodeled.

## Cleanup and QoS exit contracts

The recovered selected sequence is:

```text
fstat error -----------> store error -> late QoS branch -> return
MAP_FAILED ------------> store error -> late QoS branch -> return
mmap success -> publish result -> malloc
                                +-- NULL -> munmap -> close -> fd = -1
                                |                          -> late QoS -> return
                                `-- allocation -> backward copy -> parser
                                                              -> free boundary
```

Allocation-NULL fixtures first stop at munmap of the published mapping and decoded length. An additional private munmap-success model reaches close of descriptor7. Continuing with modeled close status0 returns low32=`0xffff5bd4`; separately modeling munmap status-1 or close status-1 produces the same pending result in these cases. No errno value is supplied. Native instructions immediately after close store-1 to the descriptor field without checking W0, establishing the local invalidation order independently of resource-retirement success. The other mapping-result fields remain present; their native reuse safety and failure-lifetime policy remain unknown.

On the reached early/allocation-error exits, protected SP+0x344f controls late scheduling. The native `1 & ~flag`, shift/subtract and XOR expression selects table index0x251d when flag bit0 is1, otherwise0x2521. Original targets are `0x1005eeb20` (late setter) and `0x1005faecc` (skip). This predicate is SMT-proved for all flag bit patterns under the recovered W19 condition.

The late setter explicitly loads saved class from SP+0xcec and sets W1=0. Current saved relative priority at SP+0xab0 is-2; it is not forwarded by this call. Thus the selected exit restores the class request while requesting relative priority zero, not the prior relative-priority value. Actual scheduling effects and setter-failure behavior remain unknown. Query-status5 and initial-set-status5 variants both leave change flag0, skip the late setter and retain the fstat-error result. This narrows the earlier open QoS-lifecycle question without establishing every exit path.

## Reproduction, bounded findings and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_rpc502_sidecar_data.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_rpc502_sidecar_mapping.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_rpc502_sidecar_copy.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_rpc502_sidecar_contents.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/capture_rpc502_mapping_frames.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_rpc502_mapping.py
```

The [verifier](triage_evidence/recover_rpc502_mapping.py) checks current generator hashes and explicit seeds, all33 retained fixture instances, source bytes/fixups, seven UNSAT proofs, six exhaustive selector banks, nine current IDB windows and compiled SDK/record assertions. It does not rerun native targets or invoke target APIs. Original inputs and IDBs remain unchanged. Extraction/validation is O(B+E) time/space for retained bytes and bounded evidence; hashing and solver costs are separately recorded. The old sidecar fixtures retain their previous, narrower evidence scope.

| Impact | Bounded finding and next falsification evidence |
| --- | --- |
| High | Local mmap/malloc lengths preserve every64-bit input bit; tested zero/extreme values reach mmap. Recover complete caller guards and all size/count consumers before interpreting resource-exhaustion or bounds consequences. |
| High | Early failure leaves descriptor output-1 without observed close, whereas later allocation failure explicitly unmaps/closes. Complete descriptor aliases and enclosing cleanup before asserting a native leak. |
| High | First-word parsing has an explicit byte-order/encoding contract; the one-byte fixture crosses logical extent before a complete word exists. Establish real framing/minimum-length requirements and branch-specific bounds before any native safety claim. |
| Medium | Cleanup clears the descriptor even after modeled failed close and preserves pending error after modeled failed unmap. Recover retry/error policy and actual resource state; output invalidation alone does not attest retirement. |
| Medium | Saved class is requested again, with relative priority zero. Recover all exits, setter-failure effects and lifecycle invariants; current models cause no native scheduling changes. |
| Medium | Successful copying and parser failure retain both a mapping and separate allocation before the free boundary. Continue through free, unmap and close, and recover valid sidecar parsing plus successful outputs. |
| Low | Current IDB locator is missing while its nine byte windows match the available source. Recorded identity, available-file identity and runtime identity are separate evidence boundaries. |

QG1 factual technical scope. QG2 M1-M7 state dependencies and probes. QG3 this increment covers mapping/result publication, copy, next parser read, selected cleanup and QoS exits; the full interface objective remains active and incomplete. QG4 widths, endian conversion, modulo arithmetic, byte extents, SDK compile assertions and complexity are explicit. QG5 size/status order, mapped/allocated memory, untouched output fields, record reuse, logical extent versus VM, and class versus relative priority are distinguished. QG6 original bytes/fixups, current IDB readback, exact available source, SDK, SMT and synthetic evidence remain separate. QG7 bounded impact-labeled findings and continuation probes are above. [Machine-readable checks](triage_evidence/rpc502_mapping_quality_gates.json) retain the verified increment.
