# RPC502 resource lifetimes and composed error delivery

Two preserved complete worker executions now have independently reconciled resource ledgers. Each worker issues 16 allocation requests, six free requests, two opens, two mappings, two closes and one unmap. The primary mapping is retired in the declared model; the supplemental mapping remains live at worker return. The model also retains eight startup allocations and two later lock allocations. These are bounded lifetime observations; native resource leakage and complete ownership transfer are unknown.

Eight new fixtures of the original receive callback, each independently replayed, compose the observed worker status `0xffff5bd9` with the original MIG502 serializer. They request destruction of the incoming message after clearing its reply-right field and produce a 36-byte simple error reply, ID602. The application body is abstracted at its public entry for these short callback executions. They are separate from the complete worker executions and from native Mach delivery.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| O1 | The supplied thin image is the intended implementation | Addresses, instructions, fixups and static roles | Rehash thin/universal files, compare exact slice and UUID; attest the live executable slice and IDB separately |
| O2 | Frozen retained and distinct fresh journals faithfully record their declared guarded executions | Worker resource ledger and return status | Require complete canonical equality, original instruction bytes and ordered journal hashes; compare native execution separately |
| O3 | Declared API, heap, FD, mapping, PAC and serial-lock models apply | Logical acquisition, retirement and return paths | Reconcile every recorded resource import edge; reject unknown owners or unmatched operations; actual API outcomes and hardware PAC remain separate |
| O4 | Source visit order, rather than observer step counts, defines local event order | Acquisition-before-release and output-publication order | Match each API site to a strictly increasing source-visit index; require source call instructions and independent final snapshots |
| O5 | The observed application error can be supplied at the public application ABI boundary | Composed MIG/callback behavior | Reexecute original callback/stub instructions and compare exact reply bytes; a joined framework-to-worker execution would test the remaining composition boundary |
| O6 | Application callees preserve the ABI state required by the generated stub | Callback continuation after the abstract application return | Preserve the call frame and supply incidental fixed/OOL outputs; inspect other statuses, aliases and callee effects independently |
| O7 | Modeled destroy/send/free requests identify requested actions only | Error cleanup and emission-site associations | Capture native port objects, rights, VM mappings and API results; do not infer those effects from the observer |
| O8 | These two worker cases and eight callback fixtures support finite conclusions | Resource counts, message fields and selected send-result paths | Review other callers, algorithms, statuses, scheduling and concurrency; unknown ownership escapes cannot be excluded by raw-pointer searches |

The [ledger and source readback](triage_evidence/rpc502_ownership_checks.json) retain the exact API sequence, source-visit indices, per-owner accounting, original fixup records and source call-site bytes. The [new callback profiles](triage_evidence/rpc502_error_delivery_profiles.json) and [distinct callback replays](triage_evidence/rpc502_error_delivery_replays.json) retain all original instruction visits, source stores, requested API actions and message bytes. The [preceding block report](rpc502_padding_report.md) supplies the two observed worker inputs and error outcomes. [O1-O8]

## Resource accounting at worker return

All extents below are bytes per complete worker case. Private pointer values identify declared owners only and are not native process addresses. Both preserved cases give the same accounting. [O2-O4,O8]

| Owner class | Count | Total extent | Return state in declared model |
| --- | ---: | ---: | --- |
| Startup allocations | 8 | 91919 | Live |
| Later typed lock allocations | 2 | 400 | Live |
| Temporary worker heap allocations | 5 | 2208 | Freed |
| Primary-file copied buffer | 1 | 64 | Freed |
| Primary-file mapping | 1 | 64 | Unmap requested, modeled result0 |
| Supplemental-file mapping | 1 | 4096 | No recorded unmap request before worker return |
| File descriptors | 2 | Not a byte extent | Both close requests have modeled result0 |

Allocation arithmetic: `91919 + 400 + 2208 + 64 = 94591` requested bytes in 16 allocations. Six retired allocations account for `2208 + 64 = 2272` bytes. Ten live allocations account for `91919 + 400 = 92319` bytes. Mappings are separate resources and are not added to heap totals. Physical analysis pages, allocator overhead and native resident memory are outside these totals. [O3,O8]

| Original allocation call | Extent | Original release call | Established local role |
| --- | ---: | --- | --- |
| `0x100913590` | 56 | `0x10097d444` | Parsed primary-file record |
| `0x100346714` | 1219 | `0x100a81d50` | First temporary certificate-processing allocation |
| `0x100346714` | 893 | `0x10097fa80` | Second temporary certificate-processing allocation |
| `0x100919330` | 8 | `0x100b31264` | Late hash/context carrier |
| `0x100a0a5e8` | 32 | `0x100baa998` | Late digest buffer |
| `0x10095b5c8` | 64 | `0x1008ec710` | Primary-file copied bytes |

The observed temporary releases and file cleanup occur in this order; earlier record/certificate releases are retained in the full JSON ledger. [O4]

```text
late digest/context frees
  -> close(supplemental FD8) at 0x1001f19c4
  -> free(primary copied buffer) at 0x1008ec710
  -> munmap(primary mapping,64) at 0x1003aaef4
  -> close(primary FD7) at 0x1001f19c4
  -> saved QoS-class request
  -> wrapper output stores
  -> decoded worker status ffff5bd9
```

The captured supplemental mapping record at `0x1008b5170` contains FD8 at offset0 and the supplemental mapping pointer at offset8. That owner differs from the primary mapping supplied to the later unmap. Matching the complete recorded resource-import sequence to the independent ledger prevents conflating the two epochs. A source reference may survive through an encoded carrier, another owner or a wider caller lifetime; the current evidence does not close those possibilities. Complete pointer-escape and native lifetime analysis remain unknown. [O3,O4,O8]

The wrapper executes output stores at `0x100023a94`, `0x100023a9c`, `0x100023aa8` and `0x100023ab0` before status decoding at `0x100023ad4`. This order is verified in both complete journals. The values are not thereby established as initialized or useful outputs on error. [O2,O4]

## Error reply, reply-right preservation and cleanup requests

The callback fixtures enter original `0x100425f78`. Its original demultiplexer and MIG502 stub reach the application call at `0x1000051f8`. The model returns exactly the observed error at public entry `0x100422d48`, with incidental fixed-record and OOL output stores. No internal verification state or accepted result is constructed. [O5,O6]

At `0x1000051fc`, the original `CBZ W0` selects the error branch for this value. The stub writes the status at reply+32 and NDR at reply+24, preserving the demultiplexer's 36-byte simple reply. It does not select the 384-byte complex success serialization. [O1,O5,O6]

| Emitted error field | Offset | Extent | Observed value |
| --- | ---: | ---: | --- |
| Header bits | 0 | 4 | Received remote disposition17 or18 |
| Inline size | 4 | 4 | 36 |
| Reply destination | 8 | 4 | Incoming request remote name |
| Local name / voucher name | 12 /16 | 4 each | 0 /0 |
| Reply ID | 20 | 4 | 602 |
| NDR | 24 | 8 | `0000000001000000` |
| Application error | 32 | 4 | `d95bffff`, little-endian u32 `0xffff5bd9`, signed -42023 |

The callback clears request+8 at `0x10006ce34` before requesting `_mach_msg_destroy(request)` at `0x10006ce90`. The exact captured request differs from its initial bytes only in those four cleared bytes. This preserves the selected reply destination in the reply while presenting a null remote field to the destruction request. The incoming OOL descriptor remains present in that requested destruction. Actual descriptor disposal and right consumption are not executed by this model. [O5-O7]

| Fixture condition | Requested sequence after application error |
| --- | --- |
| Nonzero reply destination, modeled send result0 | Destroy request -> send36-byte reply -> free reply buffer |
| Nonzero destination, send result `0x10000003` or `0x10000004` | Destroy request -> send -> destroy reply -> free reply buffer |
| Zero reply destination | Destroy request -> free reply buffer; no send request |

Each row is exercised with received remote disposition17 and18. Disposition17 requests send options1; disposition18 requests options `0x11`. Both supply receive-size0, receive-name0, timeout0 and notify0. The original emission call is `0x100035184`; reply destruction is `0x10003cc98`; heap reply release is `0x1000bcb58`. The API model records each request without native transport or resource effects. [O5-O8]

The 36-byte emitted span excludes the modeled fixed records and OOL address/count output cells. This finite serialization result is independent of whether those incidental application output values would be meaningful. It does not prove every error status or every malformed-output behavior. [O5,O6,O8]

## Validation and bounded continuation

The audit rechecks two retained/fresh worker pairs covering 29969824 original-source visits in each corpus. It verifies 58 resource import edges, 21 distinct resource call sites, snapshot agreement, original-byte journal hashes and acquisition/release ordering. No new complete worker execution is claimed in this increment. Eight distinct fresh callback replays cover 4830 original-source instruction visits, six send requests, eight incoming-message destruction requests and four reply-destruction requests. Original readback covers 65197 distinct instructions across the combined corpus and 1565 fixup/import records. No new solver proof is claimed.

Reproduction from the extracted directory:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_error_delivery.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/audit_rpc502_ownership.py
```

The ledger is linear in recorded visits/events plus the retained input size; indexed site matching adds `O(E log V)` bounded lookup work. Source extraction additionally reads the image and fixups. Space is bounded by the source/pointer tables and the largest decompressed case/journal. No timing conclusion follows from instruction counts. Extents are bytes and statuses/header fields are explicitly u32. There is no native target/API or IDB execution or mutation.

[Preservation](triage_evidence/rpc502_ownership_preservation.json) checks the 1135-artifact baseline, allowing only the six reporting/index/aggregator updates. [Scoped quality gates](triage_evidence/rpc502_ownership_quality_gates.json) include original file/slice identity, producer/dependency pins, readback and report links. All prior analytical producers, profiles, checks and reports remain frozen.

| Impact | Further interface requirement | Evidence needed |
| --- | --- | --- |
| High | Supplemental mapping owner after error return | Complete encoded aliases, caller cleanup/global publication and native VM lifetime; an unmatched local request is insufficient for a leak conclusion |
| High | Actual error delivery and incoming OOL disposal | Join framework/callback/worker state; match native request/reply bytes, port objects, rights and VM mappings |
| Medium | Persistent versus temporary allocation ownership | Global/lock reference chains, teardown, restart and concurrency epochs |
| Medium | Other status and send-result cleanup paths | Complete local partitions and callees, including application output initialization, alternate exits and effective provider behavior |

QG1: factual technical analysis. QG2: O1-O8 and falsification probes. QG3: finite ownership/error-delivery increment covered; the broad interface goal remains active. QG4: resource arithmetic, byte widths and complexity explicit. QG5: two mapping epochs, retained/fresh reuse versus new callbacks, API requests versus native effects and separate execution boundaries distinguished. QG6: original instructions/fixups, ordered journals, canonical replay equality and exact packet readback. QG7: impact-bounded continuation table above.
