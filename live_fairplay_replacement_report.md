# Installed FairPlay UIDList replacement and table bootstrap

In build `26C5035r`, the existing-node path in `_PRnut72j9` uses the old UIDList marker to find the prior table payload. It conditionally requests table mutation and typed release, then updates the existing node's marker through a separate status gate. On a missing shared table it conditionally allocates, initializes, and publishes the same header type used by teardown. The two callers have different continuations after a null holder reload. [Current node publication](live_fairplay_uidlist_report.md) [Current teardown bootstrap](live_fairplay_shared_table_report.md)

```text
matching node -> old marker -> read shared holder
  |-- ready ------------------------------> lookup path
  `-- missing -> allocate -> initialize
      |-- initializer success -> publish -> lookup path
      `-- allocation failure or rollback -> reload holder
          |-- ready -----------------------> lookup path
          `-- still null -> saved-status gate -> update or error

lookup path -> lookup 1 -> lookup 2 -> retirement-status gate
  |-- success -> saved-payload gate -> update marker in same node
  `-- other status -> error
```

## Build and audit scope

The installed collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. Kernel and kext UUIDs are `90195379-954d-3ca3-baac-327341f14211` and `316464f8-eade-30ca-938e-2f430b1ed5bc`. The audit checks the full compiler-bounded caller hash, then compares 901 replacement and 550 bootstrap instruction words in the selected spans, transfers and def-use ranges. The counts include overlapping ranges and two private decoder spans. Eight distinct relocated words reconstruct the installed pool base. The audit also rechecks the entire table initializer and size helper, eight bank arrays, 15 rules across 256 inputs each, and 38 distinct authenticated branch fixups. It reruns 95 distinct SMT queries from 56 source obligations and 44 predecessor references, after removing five duplicates. Current applicability depends on the checked words, data and bindings. [Historical replacement](userclient_uidlist_replacement_report.md) [Historical bootstrap](userclient_replacement_bootstrap_report.md) [Installed audit receipt](triage_evidence/live_fairplay_replacement_audit.json.zst)

## Missing-holder handling and saved status

Let J denote the existing 16 B list node, O its u32 old marker, M the new marker retained at S+0xd8c, H the module holder at `0xfffffe000cd4e8a0`, and R the private record at S+0x968. The node capture saves J at C+0x410, J+4 at C+0x2c8, and O at S+0xc84. For the selected phase, O equal to `0x31ae0066` enters the marker gate with `0xce515bbf` and selects the error continuation. A differing marker enters the holder route.

| Installed site | Selected operation |
| --- | --- |
| `0xfffffe000a69bde8` | Read the holder, whose address is saved at SP+0x9e0. Nonzero enters processing. Zero enters header allocation. |
| `0xfffffe000a69bee0` | Call `_IOMallocTypeImpl` at `0xfffffe000c509774` through `0xfffffe0008491258`, IA modifier `0xd0c8`. X0 is the 16 B `site.FPHashTable` descriptor at `0xfffffe0008492400`. |
| `0xfffffe000a69bfac` | Call initializer `0xfffffe000a668590` through `0xfffffe0008491578`, IA modifier `0x2bbe`. R+4 carries encoded token `0xabd` and R+8 carries the allocated header pointer. |
| `0xfffffe000a69bfb4`, `0xfffffe000a69bff0` | Read raw initializer status at R+0. Status `0x7cb541a6` admits the header publication to H. |
| `0xfffffe000a69c120` | Other initializer status selects rollback through `_IOFreeTypeImpl` at `0xfffffe000c509988`, slot `0xfffffe0008491318`, IA modifier `0x4d6a`. X0 is descriptor `0xfffffe0008492440` and X1 holds the allocated header. |
| `0xfffffe000a69c140` | A null allocation or ordinary rollback return reloads H. |
| `0xfffffe000a69c194` | Resume through X19 with IA modifier `0xcb79` at `0xfffffe000a69c270`. The resulting holder reaches C+0x420. |

The allocation and rollback descriptor images are byte-identical and name `site.FPHashTable`, signature `21`, flags `0x64`, extent 16 B. The initializer requests 128 entries at 24 B each, or 3,072 B in addition to the header. The holder's eight file bytes are zero. Runtime occupancy and serialization remain unknown. [Installed initializer and entry type](live_fairplay_shared_table_report.md)

Processing reloads W23 from SP+0x9ec at `0xfffffe000a69c2b0`. If the selected holder is still zero, W23 supplies the later marker-update gate. Only `0x31ae0066` permits that update. The routine contains 47 direct u32 loads and one direct u32 store using exactly `[sp, #0x9ec]`. The store at `0xfffffe000a677820` writes `0xce515bb2` on that initialization path. The census leaves the full saved-status domain unknown because it covers one operand form and does not resolve overlapping writes, aliases or frame epochs. The selected teardown caller uses its node release continuation on a null holder reload. [Current teardown null reload](live_fairplay_shared_table_report.md)

## Existing-table path

Both 48 B lookup requests use token `0x541` and key `O XOR 0x31ae0066`. The first call publishes a found byte at S+0xb68 and a u32 index at S+0xa28. The second publishes them at S+0xc80 and S+0xbe0. Both publish raw status at R+0x18. The first raw-success branch can read entry +16 B and save its value at C+0x7a8 before the first found-bit test. The first found-bit test governs progression to the second lookup.

| Operation | Installed call | Slot, IA modifier | Effect |
| --- | --- | --- | --- |
| First and second lookup | `0xfffffe000a69c6bc`, `0xfffffe000a69c974` | `0xfffffe0008491288`, `0x6a0f` | Resolve to `0xfffffe000a5ef4e4` with separate output destinations. |
| Entry writer | `0xfffffe000a69ca9c` | `0xfffffe00084914a8`, `0x3936` | Resolve to `0xfffffe000a5efdb4`. Request tombstone state `0x629f8776`, key-zero representation `0x1ee45f68039f9913`, and zero payload at the second selected entry. |
| Backward reclaimer | `0xfffffe000a69cba4` | `0xfffffe0008491470`, `0xaf1c` | Resolve to `0xfffffe000a6579f0`. The 40 B token-`0x559` record carries header, index, capacity and array, and receives status at R+0x20. |
| Prior payload release | `0xfffffe000a69f7f4` | `0xfffffe0008491318`, `0x4d6a` | Resolve to `_IOFreeTypeImpl`. X0 is descriptor `0xfffffe0008492a00` for a 120 B `site.FPSecureTunnel`. X1 is the saved first payload. |

Second lookup status and found bit jointly gate the writer and reclaimer. The subsequent retirement-status gate uses the reclaimer status when those calls execute and the second lookup status on the alternate route. Raw success then admits the saved-payload check. A zero saved payload skips release. After an ordinary release return the code clears the saved payload cell at `0xfffffe000a69f828`. Both paths reach the join that sets W23 to `0x31ae0066` at `0xfffffe000a69f844`–`0xfffffe000a69f848`. The subsequent update stores M at J+4 through the saved address at `0xfffffe000a69f8c4`. The selected blocks retain J and the existing head linkage. [Installed helper contracts](live_fairplay_table_cleanup_report.md)

With L valid nodes in a stable acyclic list and a coherent table of N entries, search, the two lookups and reclamation take O(L+N) time and O(1) traversal state excluding allocator internals. Missing-table initialization takes O(N) time and requests O(N) entry storage. The new sites pass private kernel records and pointers and introduce no Mach-port transfer or message emission. The native relationship between a request, its prior entry and a new marker remains unknown. [Mach endpoints and emitters](mach_ports_report.md)

## Assumptions and coverage

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| R1 | The checked collection, historical receipts and fixups match their identities. Installed call and data bindings depend on this. | Recover compiler bounds, rehash inputs, compare words, and decode original chained offsets and landing instructions. |
| R2 | Selected blocks use the recorded dispatcher roots and saved frame epoch. Marker, holder and status joins depend on them. | Trace incoming blocks, SP changes, overlapping accesses and all writers to the saved cells. |
| R3 | R, J, the header and the relevant entries remain valid and coherent during selected ordinary calls. Lookup and mutation depend on this. | Compare record extents, status and index outputs, selected entry addresses, and synchronization across the two calls. |
| R4 | Ordinary allocator, initializer and release returns preserve saved roots. Publication and update depend on these returns. | Check the initializer output, typed descriptors, restored continuation and separation of the two raw status channels. |
| R5 | A common native context and entry epoch joins the old marker to the saved payload and the new marker to the write. | Correlate native request, holder, node, lookups and payload identity with a single connection and call. |

High impact applies to the installed update and rollback contracts and the distinct null-holder continuations of replacement and teardown. Medium impact applies to the direct saved-status census and its limits. Low impact applies to inferring the marker's external meaning from its layout alone.

QG1 covers factual scope. QG2 records premises and probes. QG3 covers the old-marker route, construction and rollback, lookup and mutation, release request and update. QG4 checks byte extents and bounds. QG5 covers null outcomes and the independent status channels. QG6 uses original images, exact fixups and replayed proof queries. QG7 bounds conclusions about native serialization, ownership and daemon correlation. No native call was exercised.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_replacement.py "$CURRENT_COLLECTION"
```
