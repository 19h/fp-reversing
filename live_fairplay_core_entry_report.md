# Installed selector 26 core entry and first parser boundary

In the installed FairPlayIOKit collection, the selector 26 provider passes its staging pointer, extent, and context to `_PRnut72j9`. A replay of current instruction bytes follows those three arguments from the compiler entry to four distinct boundaries. With a non-null early container and an initial cursor of zero, an extent of 9 B selects short-header cleanup and 10 B reaches the planned first read at the staging pointer plus 6 B. The replay stops before that read. [Installed provider transfer](live_kext_selector26_transfer_report.md)

```text
selector 26 provider -> I, A, Q -> _PRnut72j9 entry
  -> aligned workspace request -> typed auxiliary request
  |-- I == 0 -> auxiliary release request
  `-- I != 0 -> first FPTTLV allocation request -> fixture H
      |-- H == 0 -> staging allocation request
      `-- H != 0 -> zero 16 B
          |-- A == 0 -> empty-container retirement request
          |-- 0 < A < 10 -> short-header retirement request
          `-- A >= 10 -> first scheduled load at I+6
```

## Evidence and replay

The installed boot collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. Its kernel and FairPlayIOKit UUIDs are `90195379-954d-3ca3-baac-327341f14211` and `316464f8-eade-30ca-938e-2f430b1ed5bc`. The compiler-bounded core is `[0xfffffe000a676398, 0xfffffe000a6a7ac0)`. The audit compares the 1,212 entry and 725 container-boundary words against prior selections and decodes all 28 changed words. The installed words form the replay inputs, including the relocated data address operands. Fifteen dispatch rules check all 256 byte inputs each. Their selected targets and the captured branch destinations resolve through the installed chained fixups. [Historical entry replay](userclient_entry_execution_report.md) [Historical container-boundary replay](userclient_fpttlv_entry_report.md)

The current replay checks 66 archived entry fixtures with the retained integer instruction interpreter. It supplies the current fileset's instruction bytes and resolves pointer loads from its fixup data. Cases use two private stack placements and three controller settings. The extent fits u32, and the staging pointer is either zero or a defined private address. The model supplies 192 allocator register returns and writes no allocator bytes. Authenticated transfers execute as logical transfers. Current visit PCs, logical edge endpoints, and private source access addresses and widths are checked against the archived paths. The audit separately checks selected argument, output, and allocation-field values. Recorded coverage is 92,526 instruction visits, 1,032 logical edges, 1,698 private reads, and 22,350 private writes. [Installed audit receipt](triage_evidence/live_fairplay_entry_audit.json.zst)

## Provider handoff and entry state

Let I be the provider's staging address, A the zero-extended extent, Q the provider context, and F the core frame SP. The provider passes these values at `0xfffffe000a546480`, `0xfffffe000a546484`, and `0xfffffe000a546488`. Its call at `0xfffffe000a54648c` targets the installed core entry. The prologue reserves 128 B for saved registers, calls the stack probe with 4,208 B, then reserves the requested 4,208 B. F is entry SP minus 4,336 B. The original stack probe target is `0xfffffe000a5e2e54`; the replay resolves its address-diverse chained pointer and follows its installed instructions. [Provider task buffer and extent](live_kext_selector26_transfer_report.md)

| Entry value | Installed save | Destination |
| --- | --- | --- |
| Q in X2 | `0xfffffe000a6763dc` | F+0x738 |
| A in X1 | `0xfffffe000a6763e0` | F+0x878 |
| I in X0 | `0xfffffe000a6763e4` | F+0x8f8 |

The core requests a 16,384 B workspace aligned to 64 B at `0xfffffe000a67656c`, then requests a typed 4,096 B auxiliary region at `0xfffffe000a676600`. Their targets are `_IOMallocAligned` at `0xfffffe000c509028` and `_IOMallocTypeImpl` at `0xfffffe000c509774`. Both allocations return declared nonzero addresses in the replay. The auxiliary descriptor at `0xfffffe0008492940` and release descriptor at `0xfffffe0008492500` carry `site.AllocType`, flags `0xe4` and the same 512-character signature. Both unsigned address-order calls use the helper at `0xfffffe000a6c905c`. They validate the numerical order of each modeled endpoint pair. Native allocation extents and lifetimes remain unknown.

On the nonzero pointer path the core retains I at auxiliary region +0x98 and stores `A XOR 0x31ae0066` at workspace +0xb5c for the selected extent range. The first FPTTLV allocation request is at `0xfffffe000a677594`, with descriptor `0xfffffe0008492600` naming `site.FPTTLV`, signature `11`, flags `0xe4`, and extent 16 B. It saves the returned H at auxiliary +0xb0 and zeroes both 8 B words at `0xfffffe000a677858` on the nonnull branch. The replay verifies zeroes through the observed source writes. [Installed context reloads](live_fairplay_uidlist_report.md)

## Four stopping points

The replay starts at the actual installed compiler entry and stops before each listed instruction. The header-fit calculation begins at `0xfffffe000a6a1e14` and selects the fitting-header block when the remaining extent is at least 10 B under the recovered phase. That block forms offset cursor+6, with the cursor zero in these cases.

| Selected condition | Cases | Installed stopping point | Arguments or captured effect |
| --- | --- | --- | --- |
| I = 0 | 6 | `0xfffffe000a6a73f0`, typed auxiliary release request | X0 is descriptor `0xfffffe0008492500`, X1 is the modeled auxiliary result. |
| I nonzero, H = 0 | 24 | `0xfffffe000a682e88`, staging allocation request | X0 is A. Target is `_IOMallocData` at `0xfffffe000c509c2c`. |
| H nonzero, A = 0 | 6 | `0xfffffe000a6a1754`, FPTTLV release request | Status `0x31ae0066`. Auxiliary +0x418 retains H. |
| H nonzero, A = 1 or 9 B | 12 | Same FPTTLV release request | Status `0xce515bb8`. Auxiliary +0x3d0 retains H. |
| H nonzero, A = 10, 16, or 65,536 B | 18 | `0xfffffe000a6a1f5c`, first scheduled input byte load | `LDRB W11,[X10,X9]`, with X10=I and X9=6. |

Both FPTTLV retirement cases request `_IOFreeTypeImpl` at `0xfffffe000c509988` with X0=`0xfffffe0008492880` and X1=H. The release descriptor carries the same type name, signature, flags and extent as the constructor descriptor. The cleanup cell remains distinct by case. The replay reaches the input-byte instruction without consuming its value. No target allocator, release body, complete parser return, or new Mach emission is observed. The 65,536 B fixture supplies an extent value, with backing of that full extent outside the checked prefix. [Mach endpoints and emitters](mach_ports_report.md)

## Assumptions and coverage

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| E1 | Collection identity, archived fixtures and chained pointer resolution apply. The installed source replay depends on them. | Rehash artifacts, check bounds and all fifteen bank selectors, and compare the complete logical PC and edge sequences. |
| E2 | The provider reaches the recorded call, with nominal staging descriptor and an ordinary core entry. The argument interpretation depends on it. | Correlate actual descriptor receiver, copy count, register arguments, and the same native invocation before extrapolating. |
| E3 | The declared allocator returns and private bounds apply. Initialization and first-byte selection depend on them. | Vary the supplied container return and extent around the gate, and compare source stores, retained pointers, and the four stopping points. |
| E4 | PAC transfers and the stack probe match the logical model for the tested epochs. Source continuity depends on this. | Check fixup metadata, visited source words and target PCs. Hardware authentication and native stack state require independent observations. |
| E5 | The modeled pointer and length describe the pre-read header phase. The first scheduled address depends on that phase and cursor. | Check the cursor, retained original pointer, and the instruction operands before attributing any subsequent read to the same buffer. |

High impact applies to the installed handoff from the staging address and extent to the first parser gate. Medium impact applies to the distinct empty and short-header retirement cells. Low impact applies to treating the declared container type name as a business-level input schema.

QG1 covers factual scope. QG2 records premises and probes. QG3 covers argument saves, allocations, gates and all observed frontiers. QG4 checks frame and allocation sizes, u32 extent, and address offsets. QG5 records modeled returns and boundary limits. QG6 uses original collection bytes, fixups, and pinned predecessor fixtures. QG7 bounds inference about format, ownership, and native daemon correlation. The replay is O(V+E) in instruction visits and byte-access events for the retained prefix, with bounded private state.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_entry.py "$CURRENT_COLLECTION"
```
