# FairPlay typed context construction and teardown on macOS 26C5035r

The installed `_lapsl183ah` constructs and publishes a 24 B `site.IOUCCtx` object through the provider's context cell. The installed `_kratpzs81h` requests its release on the empty-head and selected populated-list paths. The populated path saves each matching 16 B `site.UIDList` node's successor before calling the typed free adapter. On the selected normal return it clears the original context cell. This joins the previous IOService stop handoff to the typed allocator interfaces and cell store in the installed build. [Provider stop handoff](live_fairplay_provider_stop_report.md)

```text
start -> _lapsl183ah(&cell, mode, task)
         -> allocate IOUCCtx(24 B) -> initialize fields -> publish *cell

stop  -> _kratpzs81h(&cell)
         -> load *cell and its head
              |
              +-- each matching node: save successor, free UIDList(16 B)
              +-- unequal marker: separate continuation
              |
              +-- empty head or exhausted matching chain
                    -> free IOUCCtx(24 B) -> clear *cell -> return zero
```

## Installed evidence and cross-build correspondence

All addresses are preferred and unslid. The audit verifies the boot collection hash, both fileset UUIDs and the running kernel UUID for build `26C5035r`. It uses `LC_FUNCTION_STARTS` for the entire current bodies, then compares their raw instruction words to the pinned earlier collection receipts. The two body starts have the same address delta, `0x41190`. Every changed word belongs to a checked data-address expression. The controller words, literal arrays, pointer pool, dispatch table and stack-canary reference all have their current bindings verified.

| Routine | Current range, end exclusive | Instruction words | Changed data-address words |
| --- | --- | ---: | ---: |
| `_lapsl183ah` | `0xfffffe000a5f7470`–`0xfffffe000a5f76f0` | 160 | 16 |
| `_kratpzs81h` | `0xfffffe000a6677d8`–`0xfffffe000a668590` | 878 | 18 |

All eight 256 B arrays match the earlier receipts byte for byte. The auditor checks `x XOR right[left[x] XOR key]` over all 256 byte values for each of twelve recorded lookup rules, including the common free rule used by both cleanup paths. It then verifies the selected targets using original chained pointers from the installed pool at `0xfffffe00084889a0` and table at `0xfffffe00084899c0`. The thirteen distinct path edges retain their branch authentication modifiers and land at the current `bti j` sites. The fifteen Z3 replays check the historical contracts. Current applicability derives from the separate code, array, branch and pointer comparisons. [Historical context analysis](userclient_context_lifecycle_report.md) [Historical node analysis](userclient_uidlist_cleanup_report.md)

## Typed allocator and field ABI

| Request | Call site | X0 type descriptor | X1 and selected adapter |
| --- | --- | --- | --- |
| Allocate context | `0xfffffe000a5f767c` | `0xfffffe0008492300`, `site.IOUCCtx`, 24 B | Current `_IOMallocTypeImpl` at `0xfffffe000c509774`; the lower call supplies W1 = `0x8004` for descriptor flags `0x64`. |
| Free context | `0xfffffe000a667a54` | `0xfffffe0008492d00`, `site.IOUCCtx`, 24 B | X1 is the saved context. Current `_IOFreeTypeImpl` at `0xfffffe000c509988` tail-branches to `0xfffffe000bd46f04`. |
| Free matching node | `0xfffffe000a667b44` | `0xfffffe0008491d40`, `site.UIDList`, 16 B | X1 is the current node. Uses the same typed free adapter. |

The context allocation and free descriptors occupy different addresses and have identical 64 B image contents. The auditor independently resolves their name and signature pointers and confirms the strings `site.IOUCCtx` and `121`. The node descriptor resolves `site.UIDList` and `21`. The context allocator tests flags bit 4. For `0x64 AND 0x10 = 0`, it supplies `0x8004` before branching to the lower allocator at `0xfffffe000bd46a80`. The task is stored into the result object on the success path. [XNU typed IOKit allocator entry points](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOLib.cpp#L1152-L1200)

| Context extent | Width | Successful construction |
| --- | ---: | --- |
| +0 B | 8 B | Stores null head at `0xfffffe000a5f76b4`. |
| +8 B | 4 B | Stores the supplied mode at `0xfffffe000a5f76b8`. |
| +12 B | 4 B | Constructor leaves these bytes at their allocator-provided values. |
| +16 B | 8 B | Stores the supplied task pointer at `0xfffffe000a5f76bc`. |

The constructor publishes the result through the cell at `0xfffffe000a5f76c0` after the field stores and returns zero. Its null-cell branch returns raw u32 `0xffff5bd9`. Its null-allocation branch returns raw u32 `0xffff5bd4` before publication. These are helper results. The enclosing FairPlay `start` writes its own success value after an ordinary helper return. [Current startup wrapper](live_fairplay_provider_stop_report.md)

## Selected release paths

| Test or event | Current location | Effect |
| --- | --- | --- |
| Null cell address or empty cell | `0xfffffe000848ef18` and `0xfffffe000848c6b0` | The null address produces raw u32 `0xffff5bd9`. An existing cell containing null produces zero. Both select the checked epilogue. |
| Empty head in a nonnull context | `0xfffffe000848e5c0` -> `0xfffffe000a6679c8` | Requests the context free. After return, `0xfffffe000a667a60` clears the original cell through its saved pointer. |
| Populated head | `0xfffffe000a667b88`–`0xfffffe000a667bc8` | Saves node +8 B as the successor, reads the u32 at +4 B and checks it against `0x31ae0066` on the recovered phase. |
| Matching marker | `0xfffffe0008490ee8` -> `0xfffffe000a667ab0` | Requests a `site.UIDList` free. The continuation reloads the successor from the saved frame at `0xfffffe000a667b4c`. A nonnull successor continues the loop, and null joins the context free. |
| Unequal marker | `0xfffffe0008490cb0` -> `0xfffffe000a667bcc` | Enters the other arm. Its branch target is pinned on this build. Current shared-table processing and completion depend on separate bindings. |

For a stable, finite, acyclic chain of `n` matching nodes and ordinary returns, the selected sequence requests `n` node frees and one context free. It accounts for `(16*n + 24) B` of declared type extents, then clears the cell. This is an O(n) traversal with O(1) private traversal state excluding allocator costs. The audited constructor and cleanup interfaces exchange kernel pointers and scalar state. Their selected calls introduce no Mach message or port endpoint. Native allocation, final memory retirement, task reference balance and concurrent ownership remain unknown. [Historical unequal-marker continuation](userclient_hash_table_bootstrap_report.md)

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| T1 | The matched collection and historical receipts supply the stated build identities. All addresses and earlier proof applicability depend on this. | Rehash the collection and decompressed predecessors, check both current UUIDs and recompute compiler function boundaries. |
| T2 | The selected path has the observed data roots and authenticated branch bindings. The cross-build ABI match depends on these. | Compare all aligned words, independently decode the changed operands, exhaust the lookup inputs and check the selected chained pointer targets and modifiers. |
| T3 | The context cell, objects and traversal frame are valid for the selected call, and the allocator and free adapter return normally. Publication and clearing depend on these premises. | Recheck the saved-cell and saved-successor proofs, inspect pointer/call arguments, and resolve the stack-canary failure binding separately. |
| T4 | A populated traversal uses a stable matching chain. The complete `n`-node sequence depends on this premise. | Enumerate live writers and synchronization if runtime evidence is available. The unequal-marker branch is a visible alternative path. |

High impact for joining FairPlay's stop callback to specific typed-free requests and a cell clear. Medium impact for distinguishing constructor allocation status from the startup return and for confirming the task-pointer field. Low impact for interpreting the recorded type signatures until their consumers are identified.

QG1 covers factual scope. QG2 covers assumptions and probes. QG3 covers construction, publication, empty and matching release paths and the user-client boundary. QG4 checks decoded instruction counts, byte widths and requested extents. QG5 distinguishes the unequal and native lifetime paths. QG6 uses original code and fixups plus pinned source receipts and Apple source. QG7 records bounded ownership implications. Audit cost is O(B + F + I + 256R) time and space before solver replays for collection bytes B, fixups F, compared instruction words I and checked rules R. The fifteen queries replay previously published obligations with a 45 s solver limit per query. [Audit script](triage_evidence/audit_live_fairplay_context_lifecycle.py) [Compressed receipt](triage_evidence/live_fairplay_context_lifecycle_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_context_lifecycle.py "$CURRENT_COLLECTION"
```
