# FairPlay shared-table bootstrap on macOS 26C5035r

The installed FairPlayIOKit `_kratpzs81h` checks a module-level table pointer when a context-list node's marker differs from `0x31ae0066`. An existing table enters the processing continuation. If the holder is empty, cleanup attempts to allocate a 16 B `site.FPHashTable` header and initialize its 3,072 B backing array. It publishes the header only after the initializer returns the expected status in a private record. A failed attempt reloads the holder. If the holder is still empty, cleanup frees the current node and resumes traversal through its saved successor. [Current typed context lifecycle](live_fairplay_context_lifecycle_report.md)

```text
unequal node marker -> load module holder
  |-- nonnull -> table processing
  `-- null -> allocate 16 B header
        |-- header returned -> initialize header and request 3,072 B array
        |     |-- status 0x7cb541a6 -> publish header -> table processing
        |     `-- other status -> free header -> reload
        `-- no header -> reload

reload -> read module holder again
  |-- nonnull -> table processing
  `-- null -> free current node -> continue via saved successor
```

## Installed evidence

Addresses are preferred and unslid. The audit identifies the boot collection by SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`, kernel UUID `90195379-954d-3ca3-baac-327341f14211`, and FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. It checks the full compiler-bounded bodies against the pinned earlier collection receipts. Each start moved by `0x41190`. All 46 changed instruction words are checked data-address expressions. The remaining 1,233 words match byte for byte. [Historical bootstrap](userclient_hash_table_bootstrap_report.md) [Historical initializer](userclient_hash_table_initializer_report.md)

| Routine | Current range, end exclusive | Instruction words | Changed address words |
| --- | --- | ---: | ---: |
| `_kratpzs81h` | `0xfffffe000a6677d8`–`0xfffffe000a668590` | 878 | 18 |
| Table initializer | `0xfffffe000a668590`–`0xfffffe000a6689dc` | 275 | 16 |
| Allocation-size helper | `0xfffffe000a5f4f58`–`0xfffffe000a5f5150` | 126 | 12 |

The audit compares ten 256 B lookup arrays and evaluates 15 rules over 256 inputs each, for 3,840 rule-input checks. It resolves 18 distinct authenticated branch fixups to the current `bti j` destinations and checks the allocator and guard bindings. It also replays 12 historical bootstrap and 21 historical initializer Z3 obligations. Applicability to the installed build rests on the current instruction, data and fixup comparisons. [Audit script](triage_evidence/audit_live_fairplay_shared_table.py) [Compressed receipt](triage_evidence/live_fairplay_shared_table_audit.json.zst)

## Holder, status and rollback

| Event | Current address | Recovered behavior |
| --- | --- | --- |
| Unequal-marker arm | `0xfffffe000a667bcc` | The saved successor is already available to cleanup. |
| Initial holder read | `0xfffffe000a667c34` | Loads the u64 at `0xfffffe000cd4e8a0`. The installed pool slot `0xfffffe0008489700` resolves to holder +4 B, and the code applies −4 B. |
| Allocate header | `0xfffffe000a667d04` | Calls `_IOMallocTypeImpl` at `0xfffffe000c509774`. X0 is the fixed descriptor at `0xfffffe0008492400`. A null result selects reload. |
| Call initializer | `0xfffffe000a667df8` | Slot `0xfffffe0008491578`, IA modifier `0x2bbe`. The private caller record at SP+0x90 carries the keyed u32 token at +4 B and header pointer at +8 B. The token decodes to `0xabd`. |
| Read and test status | `0xfffffe000a667dfc`, `0xfffffe000a667e08` | Loads the record's +0 B u32 and checks it against `0x7cb541a6`. |
| Roll back header | `0xfffffe000a667ed4` | Calls `_IOFreeTypeImpl` at `0xfffffe000c509988` with the descriptor at `0xfffffe0008492440` and the saved header pointer. An ordinary return selects reload. |
| Reload holder | `0xfffffe000a667ef4` | A nonnull result selects table processing. A null result enters the existing node-free implementation at `0xfffffe000a667ab0`. |
| Publish header | `0xfffffe000a667f3c` | Writes the initialized header pointer into the holder, then reaches table processing. |
| Enter table processing | `0xfffffe000a667f58` | The verified continuation starts here. |

The allocation and rollback descriptors occupy different addresses and have identical 64 B image contents. Both resolve `site.FPHashTable`, signature `21`, size 16 B and flags `0x64`. The holder's eight file bytes are zero. Its value in any running kernel and the synchronization governing its writers are unknown. The fallback requests the current node's typed release even though its marker took the unequal branch. When the saved successor is null, the ordinary continuation requests context release and clears the original context cell. [Current typed context lifecycle](live_fairplay_context_lifecycle_report.md)

## Initializer and typed storage

The initializer takes the header pointer from the private caller record and sets the two header u32 fields at +0 B and +4 B to 0 and 128. Its call at `0xfffffe000a668800` uses slot `0xfffffe0008491590` and IA modifier `0x2502` to reach the allocation-size helper. A separate internal record at SP+0x10 carries the size request, which decodes to token `0xed1` and count 128. The helper encodes its size output at record +0x20 at `0xfffffe000a5f5144`. Decoding gives `128 * 24 B = 3,072 B`. [Historical size record and arithmetic](userclient_hash_table_initializer_report.md)

| Interface or operation | Current address | Verified arguments and effect |
| --- | --- | --- |
| Variable typed allocation | `0xfffffe000a66888c` | Uses slot `0xfffffe0008491368` with IA modifier `0x3ff2`. X0 is descriptor `0xfffffe000cd43500` and X1 holds 3,072. The descriptor starts with u32 words 1 and 24 and its name resolves to `site.FPHashTableEntry`. |
| Kernel adapter | `0xfffffe000c509f7c` | `_IOMallocTypeVarImpl` sets bit 0 of X0, preserves X1, supplies W2 = `0x1f1004` and X3 = 0, then tail-branches to `0xfffffe000bd464ac`. |
| Save array pointer | `0xfffffe000a668890` | Stores the returned address at header +8 B. Null selects raw result `0x7cb49d7a`. |
| Initialize entries | `0xfffffe000a668944`–`0xfffffe000a668958` | On the checked normal-address path, each 24 B entry receives the three writes below. |
| Store caller status | `0xfffffe000a66899c` | Writes raw u32 `0x7cb541a6` on completion of the nonnull path or `0x7cb49d7a` on the null path. |
| Check stack guard | `0xfffffe000a6689b4` | A mismatch leads through veneer `0xfffffe000a6e0424` to `___stack_chk_fail`. The ordinary return also depends on return authentication. |

| Entry extent | Width | Initializer write |
| --- | ---: | --- |
| +0 B | 4 B | u32 `0x629f8775` |
| +4 B | 4 B | Retains allocator-provided content |
| +8 B | 8 B | u64 `0x1ee45f68039f9913` |
| +16 B | 8 B | u64 0 |

The loop visits 128 entries under the valid, nonwrapping extent and address-tag premises. It writes `128 * (4 + 8 + 8) B = 2,560 B` and leaves `128 * 4 B = 512 B` without initializer stores. A successful bootstrap requests `16 B + 3,072 B = 3,088 B` of declared storage. Physical allocator footprint is unknown. For an array of `n` entries the loop takes O(n) time and O(1) additional state, excluding allocator behavior. Apple XNU source supplies the public variable typed allocation interface, while the installed image supplies the adapter instructions above. [XNU variable typed allocator](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOLib.cpp#L1199-L1216)

## Interface scope and assumptions

The verified handoffs use kernel pointers and scalar fields in private records. No Mach send, receive or port emission appears in these selected blocks. Later processing, native allocation and table ownership, the meaning of the entry defaults, and a corresponding native `fairplayd` event remain unknown. The audit used the boot collection and pinned receipts.

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| S1 | The installed collection and historical receipts match their pinned identities. All site addresses and cross-build conclusions depend on this. | Rehash the inputs, verify the UUIDs, and derive each function boundary from `LC_FUNCTION_STARTS`. |
| S2 | The relocated data and authenticated jump targets retain the checked bindings for the selected phases. The continuation and historical obligation applicability depend on these bindings. | Decode each changed expression and chained pointer, exhaust the lookup inputs, and verify the authentication metadata and target landing instructions. |
| S3 | The frame, header and saved successor remain live for the selected calls. Allocators and the initializer return normally where the path requires it. The rollback and publication sequence depends on these premises. | Compare the caller's saved cells and ABI arguments along both outcomes. Resolve the canary failure path and check runtime lifetimes if suitable evidence is available. |
| S4 | A nonnull array covers 3,072 B continuously without wrap. Its endpoints share the address bits tested by the initializer guard. The contiguous field writes depend on this. | Check the return pointer and extent against the address predicate and re-evaluate the guard over all 128 entry addresses. |
| S5 | Each holder read supplies the value used by that branch. A module-wide ordering or single-writer interpretation would require separate synchronization evidence. | Enumerate module writers and inspect execution under concurrent cleanup, including a holder change between the two loads. |

High impact applies to the shared holder's separation from per-context node cleanup and the verified fallback. Medium impact applies to the structure extents and separate status/return gates. Low impact applies to naming the entry fields from default values alone.

QG1 covers factual scope. QG2 records dependent results and falsification probes. QG3 covers holder reads, allocation, initialization, publication, rollback, and fallback within the stated boundary. QG4 checks instruction counts, field widths and byte extents. QG5 accounts for both null paths and the guard failure, with native ordering and processing open. QG6 uses original code and fixups, pinned receipts and Apple source. QG7 records the bounded implications for ownership and interface mapping. No runtime experiment was performed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_shared_table.py "$CURRENT_COLLECTION"
```
