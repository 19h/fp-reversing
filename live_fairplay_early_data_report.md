# Installed selector 26 early node storage and writer handoff

The installed FairPlayIOKit core stores the decoded body length plus its 10 B header in the early `FPTTLVNode` and requests the same number of bytes from `_IOMallocData`. It stores the returned buffer pointer at node +0x18. A zero buffer result selects typed node retirement. A nonzero result reaches a shared writer with the address of that pointer field in X16. [Installed first TLV decode](live_fairplay_early_header_report.md)

```text
accepted TLV -> typed node allocation -> J
  -> clear J[0..15]
  -> save L+10 at J+0x10
  -> IOMallocData(L+10) -> Z -> save Z at J+0x18
       |-- Z == 0 -> typed retirement request for J
       `-- Z != 0 -> shared writer entry with X16 = J+0x18
                     -> stop before first metadata load
```

## Build and replay evidence

The installed collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. Kernel and kext UUIDs are `90195379-954d-3ca3-baac-327341f14211` and `316464f8-eade-30ca-938e-2f430b1ed5bc`. The audit checks the bounded caller hash and compares 132 node continuation words and 164 data continuation and setup words, including overlapping ranges. Two changed words resolve the installed pool base in the retirement path. Three selection rules check all 256 byte inputs each, and seven distinct authenticated branch fixups resolve to their installed destinations. The audit reruns 13 historical caller and setup proofs. Installed allocator wrappers are checked separately against current source words. [Historical node continuation](userclient_early_node_report.md) [Historical data continuation](userclient_early_data_report.md) [Installed audit receipt](triage_evidence/live_fairplay_early_data_audit.json.zst)

The replay starts at the installed compiler entry for 48 archived cases with u32 provider extents. Four accepted input profiles vary over two private stack placements, three controller fixtures, and zero or nonzero data returns. The node return is nonzero in all cases. Five register-only allocation cuts per case supply the declared results, with zero allocator-model memory writes. The replay checks 94,416 instruction visits and 1,056 logical edges against archived paths, along with private access addresses and widths. Selected source values are checked at the data request and both stopping points. Authenticated transfers execute as logical transfers.

## Node fields and lower allocation ABI

Let L denote the decoded u32 body extent, S the workspace, C the auxiliary region, J the node, and Z the data allocation result. The preceding parser checks that the complete record fits and L+10 is representable in u32. The retained cases request 10, 14, or 18 B.

| Installed site | Destination or call | Selected value |
| --- | --- | --- |
| `0xfffffe000a6a2800` | C+0x58 | Retain J. |
| `0xfffffe000a6a287c` | J+0 through J+15 B | Clear two 8 B words. |
| `0xfffffe000a6a2920` | S+0xca8 | Store `0x622f763938943e93 + zero_extend(L)` as u64. |
| `0xfffffe000a6a2988` | J+0x10 | Store u32 L+10. |
| `0xfffffe000a6a29d8` | `_IOMallocData` | X0=L+10. Slot `0xfffffe0008491240`, IA modifier `0xca0c`. |
| `0xfffffe000a6a29dc` | J+0x18 | Store u64 Z. |

The first 16 B clear, 4 B extent, and 8 B pointer account for 28 of the node's 32 B. The four bytes at J+0x14 through J+0x17 receive no source store in these prefixes. The data region receives no source write. Runtime allocator initialization, usable extent, and ownership remain unknown.

At `0xfffffe000c509774`, `_IOMallocTypeImpl` reads descriptor flags at +0x28 and selects W1=`0x8004` for the verified descriptor flags `0x64`. Its tail target `_kalloc_type_impl` at `0xfffffe000bd46a80` projects W1 through `AND 7` to W10=4 at `0xfffffe000bd46a98`. The bit `0x8000` is absent from that projection. The separately called `_IOMallocData` adapter at `0xfffffe000c509c2c` passes X0=`0xfffffe0007f98788`, X1=L+10, W2=`0x31000`, and X3=0 at its first backend call `0xfffffe000c509c58` to `0xfffffe000bd464ac`. These are current argument preparations. The replay supplies no observation of allocator success or failure rates.

## Retirement and writer dispatch

For Z=0, the 24 replay cases reach the typed retirement request at `0xfffffe000a6a5374`. X0 is descriptor `0xfffffe0008492a40` and X1 is J. The call selects `_IOFreeTypeImpl` at `0xfffffe000c509988` via slot `0xfffffe0008491318` and IA modifier `0x4d6a`. The allocation descriptor at `0xfffffe0008491f40` and retirement descriptor have byte-identical 64 B images. Both name `site.FPTTLVNode`, signature `1121`, flags `0x64`, size 32 B. The retirement call remains pending at the stopping point.

The 24 nonzero Z cases branch to `0xfffffe000a695c64` using index `0x543` and IA modifier `0xdfc5`. The handoff carries S in X3, C in X11, `0x31ae0066` in W1, and the raw tag XOR `0x2502309f` in W23. X16 holds J+0x18, whose contents are Z. The replay stops before the first upcoming metadata load at `0xfffffe000a695c74`. The checked load sequence contains the following cells.

| Cell | Installed load PC | Width | Bytes defined by the replayed source |
| --- | --- | --- | --- |
| C+0x768 | `0xfffffe000a695c74` | 8 B | 0 |
| S+0xd30 | `0xfffffe000a695c80` | 4 B | 0 |
| C+0x458 | `0xfffffe000a695c94` | 8 B | 0 |
| C+0x140 | `0xfffffe000a695c9c` | 8 B | 0 |
| C+0x6b8 | `0xfffffe000a695ca4` | 8 B | 0 |
| S+0xe28 | `0xfffffe000a695cb0` | 4 B | 0 |
| S+0xdf8 | `0xfffffe000a695cbc` | 4 B | 0 |
| C+0x58 | `0xfffffe000a695cc8` | 8 B | 8, J |
| S+0x94 | `0xfffffe000a695cd0` | 4 B | 4, encoded length |
| S+0x110 | `0xfffffe000a695cd8` | 4 B | 4, encoded u32 channel |
| S+0xb90 | `0xfffffe000a695ce4` | 2 B | 0 |
| S+0x1b2 | `0xfffffe000a695cf8` | 2 B | 2, encoded early type |

The table totals 64 B, with 18 B written by the replayed source. It measures provenance in the selected model. The earlier symbolic writer study proves that the selected early phase uses the C+0x58 root for its protected header despite the broader set of syntactic loads. Applying that proof beyond the stopped installed replay needs the same writer phase and record continuity. Native state, payload serialization, container publication, and matched daemon transaction identity remain unknown. This increment establishes no new Mach transfer or emitter. [Historical protected writer phase](userclient_early_writer_report.md) [Mach endpoint map](mach_ports_report.md)

## Assumptions and coverage

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| D1 | The collection and archived cases match their identities. Installed bindings depend on this. | Rehash the inputs and compare compiler bounds, selected words and each chained pointer. |
| D2 | The five source-call boundaries use the declared allocator returns and saved-root epochs. The modeled continuation depends on them. | Check call arguments, clobbers, node zeroing, extent and data-pointer stores in both result branches. |
| D3 | The prior header/body test selects L+10 within u32. The extent projection depends on it. | Re-solve the selected length obligation and compare the data argument with the 4 B node store. |
| D4 | The pending writer starts at the verified entry with the recorded early phase. The field map depends on the indicated operands and roots. | Verify transfer and register values, decode the actual loads, and trace any field producer before extending concrete execution. |
| D5 | Later ownership and native transaction correlation require the same allocation and connection epochs. | Correlate actual caller admission, writer completion, node publication and a matched daemon request. |

High impact applies to the stored node extent, lower allocation ABI, and verified writer handoff. Medium impact applies to the exact source-provenance boundary and matching retirement type. Low impact applies to business meaning inferred from the type name.

QG1 covers factual scope. QG2 records premises and probes. QG3 covers node fields, allocator interfaces, both data-result branches and the writer inputs. QG4 checks L+10 and byte spans. QG5 bounds provenance and native runtime claims. QG6 uses original installed source words, fixups and archived checks. QG7 identifies the remaining source and IPC joins. The replay costs O(V+E) for V instruction visits and E byte events per case. The selected allocation and handoff blocks use fixed additional caller state excluding allocator internals.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_early_data.py "$CURRENT_COLLECTION"
```
