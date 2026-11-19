# FairPlay table lookup and payload release on macOS 26C5035r

The installed FairPlayIOKit cleanup continuation uses the shared table to look up the current node's decoded key twice. A confirmed first hit supplies the entry's 64-bit payload. A confirmed second hit enables entry removal and backward reclamation. After either the second lookup's alternate path or a reclamation return, cleanup requests a typed free of the saved payload if the selected status is `0x31ae0066` and the payload is nonzero. The request uses a 120 B `site.FPSecureTunnel` descriptor. The descriptor identifies the requested allocator type. The saved value's producer, allocation identity and actual retirement remain unknown. [Current shared-table bootstrap](live_fairplay_shared_table_report.md)

```text
shared table -> first lookup
  |-- no confirmed hit -> free list node
  `-- confirmed hit -> save entry payload -> second lookup
         |-- confirmed hit -> mark tombstone -> reclaim -> use reclaim status
         `-- other result -> use second lookup status

selected status == 0x31ae0066 and saved payload != 0
  |-- true -> request typed payload free -> free list node
  `-- false -> free list node
free list node -> resume through saved successor
```

## Installed evidence

Addresses are preferred and unslid. The auditor identifies the boot collection by SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`, kernel UUID `90195379-954d-3ca3-baac-327341f14211` and FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. The continuing caller regions and three helper bodies each moved by `0x41190`. Of the 1,174 words in the regions and helpers below, 40 differ at checked data-address operands and 1,134 match exactly. The auditor also verifies the full enclosing `_kratpzs81h` body. [Audit script](triage_evidence/audit_live_fairplay_table_cleanup.py) [Compressed audit receipt](triage_evidence/live_fairplay_table_cleanup_audit.json.zst)

| Region or routine | Installed range, end exclusive | Instruction words | Changed address words |
| --- | --- | ---: | ---: |
| Caller lookup | `0xfffffe000a667f58`–`0xfffffe000a66826c` | 197 | 0 |
| Caller removal and release | `0xfffffe000a66826c`–`0xfffffe000a668590` | 201 | 0 |
| Lookup helper | `0xfffffe000a5ef4e4`–`0xfffffe000a5efa1c` | 334 | 12 |
| Entry writer | `0xfffffe000a5efdb4`–`0xfffffe000a5effa4` | 124 | 12 |
| Backward reclaimer | `0xfffffe000a6579f0`–`0xfffffe000a657ee8` | 318 | 16 |

The audit matches ten 256 B arrays, verifies eight fixup-backed array roots and checks twelve lookup rules over all 256 byte inputs, for 3,072 rule-input checks. It verifies 37 distinct authenticated local branch fixups and their `bti j` landing instructions, plus the call, descriptor and stack guard bindings. It replays 37 historical lookup and 36 historical reclamation source obligations. Their applicability here derives from the installed instruction and binding checks. The auditor uses the boot collection and retained primary receipts. [Historical lookup source](triage_evidence/userclient_hash_table_lookup_checks.json.zst) [Historical reclamation source](triage_evidence/userclient_hash_table_reclamation_checks.json.zst)

## Private record handoffs

| Call | Installed call address | Pointer slot and IA modifier | Selected interface |
| --- | --- | --- | --- |
| First lookup | `0xfffffe000a6680a0` | `0xfffffe0008491288`, `0x6a0f` | X0 points to the 48 B lookup record. Its decoded token is `0x541`. |
| Second lookup | `0xfffffe000a668230` | `0xfffffe0008491288`, `0x6a0f` | Same helper, record extent and token, with distinct index and found-byte destinations. |
| Mark as tombstone | `0xfffffe000a668378` | `0xfffffe00084914a8`, `0x3936` | X0 points to a 48 B writer record with decoded token `0xc28`. |
| Reclaim backward | `0xfffffe000a668484` | `0xfffffe0008491470`, `0xaf1c` | X0 points to a 40 B record with decoded token `0x559`. |
| Clear entry during reclamation | `0xfffffe000a657e38` | `0xfffffe00084914a8`, `0x3936` | The reclaimer constructs a nested writer record in its own frame. |
| Request payload release | `0xfffffe000a668578` | `0xfffffe0008491318`, `0x4d6a` | X0 is the descriptor at `0xfffffe0008492a00`. X1 is the saved payload from caller SP+0x18. |

Both lookup records carry `key32 = node[+4 B] XOR 0x31ae0066` and, under a stable header, the same capacity and array pointer. They reuse caller SP+0x90 with found bytes at SP+0x86 and SP+0x87 and u32 index outputs at SP+0x7c and SP+0x80. The u32 at record +0x18 holds raw lookup status. The writer takes an entry pointer, header pointer and new state, key and payload. It has no status field. The reclaimer takes a header, index, capacity and array, and writes raw status at record +0x20. The earlier source reports give the field offsets and record codecs. [Lookup record](userclient_hash_table_lookup_report.md) [Writer and reclaimer records](userclient_hash_table_reclamation_report.md)

## Lookup and table mutation

For the 128-entry header produced by the installed initializer, the first probe index is `key32 AND 127`. The helper probes forward with wrap and remembers the first tombstone. At entry +0 B, state `0x629f8775` means empty, `0x629f8776` means tombstone, and `0x629f8777` means occupied. An occupied match compares the u64 at +8 B with `0x1ee45f68039f9913 + zero_extend(key32)`. The helper reads states and keys and leaves the array unchanged. [Current initializer](live_fairplay_shared_table_report.md)

| Lookup outcome | Raw status | Supplied found byte | Index output |
| --- | --- | --- | --- |
| Occupied match | `0x31ae0066` | 1 | Matched entry |
| Empty encountered | `0x31ae0066` | 0 | First remembered tombstone or the empty entry |
| Budget exhausted | `0xce515bd9` | 0 | Untouched |
| Null array | `0xce515bbf` | Untouched | Untouched |

The caller compares the first status at `0xfffffe000a6680b4` and reads the first found byte at `0xfffffe000a668110`. Either failed gate enters the node-free implementation at `0xfffffe000a667ab0`. A confirmed hit reads the selected entry's +16 B u64 at `0xfffffe000a66813c` and saves it in the caller frame. The second combined status and found gate runs from `0xfffffe000a668240` through `0xfffffe000a668268`. A confirmed hit enters mutation at `0xfffffe000a66826c`. Its alternate route reaches `0xfffffe000a668498` with the lookup status.

The writer stores the requested key, payload and state, preserving entry bytes +4 B through +7 B. Its u32 counter update at header +0 B is modular. Empty-to-occupied adds one, tombstone-to-empty subtracts one, and other transitions leave the counter unchanged. Cleanup requests a tombstone with key representation `0x1ee45f68039f9913` and zero payload, so a stable occupied entry produces no counter change. The reclaimer checks the following entry with wrap. If it is empty, the reclaimer walks backward from the removal index until an empty or occupied entry or the visit bound. It requests empty state, key-zero representation and zero payload for each cleared entry. A cleared tombstone decrements the counter. The local transitions support a count of used slots including tombstones. Its global invariant and the producers of occupied entries remain unknown. [Historical mutation proofs](triage_evidence/userclient_hash_table_reclamation_audit.json.zst)

For coherent capacity `N` and valid, nonwrapping entry addressing, the three bounded operations visit at most `3*N` entries across two lookups and reclamation, excluding constant-time field stores and allocator work. At `N=128` that is an upper bound of 384 visits across the loops. Time is O(N) and additional state is O(1).

## Typed release and external boundary

The final release gate uses two inputs. It compares the selected u32 status to `0x31ae0066` at `0xfffffe000a6684c4` and checks the saved payload for nonzero. If the second lookup produces candidate success on its alternate route, that raw status still satisfies the final status comparison. A stable table with the same key and header yields the same confirmed hit twice. The native circumstances of a differing second result remain unknown.

On the release arm, the descriptor's name and empty signature resolve through relocated fixups. The descriptor has flags `0x6c` and size 120 B. The installed `_IOFreeTypeImpl` adapter at `0xfffffe000c509988` tail-branches to `0xfffffe000bd46f04` without altering X0 or X1. On ordinary return, cleanup joins the existing node-free implementation and continues through the previously saved successor. The reclaimer checks its stack guard at `0xfffffe000a657ec0` and its failure call at `0xfffffe000a657ee4` resolves through the veneer to `___stack_chk_fail`. [XNU fixed typed free interface](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOLib.cpp#L1182-L1197) [Current node continuation](live_fairplay_context_lifecycle_report.md)

These blocks hand off private kernel records and pointers. They introduce no Mach port transfer, issuance or receiving endpoint. The key's relation to a UID or an external controller remains unknown. An earlier collection has a separate allocation site bearing the same type name and 120 B extent. Payload insertion lineage, shared-table serialization, actual deallocation and correlation with a daemon message remain unknown. [Historical allocation site](secure_tunnel_allocation_report.md) [Mach endpoints and emission sites](mach_ports_report.md)

## Assumptions and coverage

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| C1 | Collection and receipts have the stated identities. The installed addresses and historical proof applicability depend on this. | Rehash the collection and receipts, check UUIDs and rederive function starts, then compare every word. |
| C2 | Current bank roots and chained branch/call metadata support the selected control flow. Record and helper joins depend on it. | Exhaust all rule inputs, decode the relocated operands and resolve the original fixup slots and landing words. |
| C3 | Header, capacity, array extent and saved frame remain coherent for each chosen call. The bounded probe, payload access and backward scan depend on this. | Verify the allocated extent, indexes and tag predicate. Check saved frame separation and audit intervening writers. |
| C4 | The same key and header reach both lookup calls. Equal outcomes additionally require a stable array across the two calls. | Compare both record producers and establish the interval protected by serialization, if any. |
| C5 | The selected calls return normally, with intact saved cells and valid authentication. The final status branch and node continuation depend on this. | Check the status offsets, branch operands, failure veneer and saved successor reload. Native authentication outcomes require runtime evidence. |

High impact applies to the verified handoff from the first entry's payload to the separate typed-free interface. Medium impact applies to the used-slot counter interpretation and its dependency on the producer paths. Low impact applies to naming the key from the local marker transform alone.

QG1 covers factual scope. QG2 records assumptions and falsification probes. QG3 covers both lookup outcomes, mutation, typed release and node continuation. QG4 checks record extents, field widths and bounded loop arithmetic. QG5 accounts for null, candidate and exhaustion outcomes, canary failure and the outstanding native premises. QG6 uses original image words, fixups, pinned receipts and Apple source. QG7 records the bounded implications for producer identity, serialization and IPC correlation. No native target call was performed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_table_cleanup.py "$CURRENT_COLLECTION"
```
