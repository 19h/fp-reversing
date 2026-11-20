# fairplaydeviceidentityd selector 26 adapter

The installed `fairplaydeviceidentityd` has a record adapter at `0x1001f7e68` that can reach `IOConnectCallStructMethod` with selector 26. It computes the table base in X23 before branching to the call block, and the call block preserves that base through its import load. This resolves the reaching table value left open in the earlier audit. Actual connection identity and a native request from this adapter remain unknown. [Earlier candidate](live_fairplay_additional_clients_report.md) [XPC worker](live_fpdi_xpc_report.md)

## Entry and import binding

| Location | Role on the selected route |
| --- | --- |
| `0x1005e7990` | Original authenticated function pointer to adapter `0x1001f7e68`, discriminator `0x132e`. |
| `0x1001f7e88` | Saves the incoming record address in X19. |
| `0x1001f7fd0`–`0x1001f7ff0` | Decodes a dispatch index and a byte count, loads two record pointers, and initializes the output-count cell. |
| `0x1001f8054`–`0x1001f8078` | Resolves the function table base in X23 and branches with discriminator `0x2c19`. |
| `0x1005e06f8` | Authenticated rebase to `0x100015930` for the selected branch. |
| `0x1000159ac`–`0x1000159c4` | Loads original slot `0x1005e7300` and calls `IOKit/_IOConnectCallStructMethod` with discriminator `0xb0da`. |

On entry to the selected branch, let P denote the adapter record address and let `K = ((low32(P) XOR 0xb4a1a4b0) * 0xcc853e13) mod 2^32`. The original arithmetic computes the dispatch input `u32(P+0) XOR K` in W17. The length is `(u32(P+8) + 0x85785c8b + K) mod 2^32` in W20. X20 is zero-extended. The two pointer fields are loaded from P+16 B and P+24 B. The pair is tested with CMP and conditional CMP, yielding W0 = 0 when both are nonnull.

For dispatch input `0x3f8d`, W22 is `0x2938`. The nonnull pair selects table index `0x3f8f` and the call block starts at `0x100015930`. The other branch for the same input selects `0x3f8d` and reaches the common epilogue at `0x1000101d4`. In each case the branch performs the installed authenticated lookup. The two 256 B banks at `0x1005bc130` and `0x10057a2e0` give `i XOR right[left[i] XOR 0xda] = 0x2a` for every byte i. The addend `0x161` selects pool slot `0x1005e8898`, from which the load and signed adjustment produce X23 = `0x1005c0a80`.

The call block uses a second bank pair at `0x10057a0e0` and `0x1005a5d90`. Its `0xfd` key gives the constant `0xa5` over all 256 inputs. Adding `0x4c6b` gives index `0x4d10` and the verified X23 reaches the IOKit import. The selected record route establishes this binding with original calls and fixups. [Apple dyld fixup inspection](https://developer.apple.com/videos/play/wwdc2022/110362/)

## Driver call and local result

| AArch64 argument | Value at the import |
| --- | --- |
| W0, connection | u32 from `[u64(P+16 B)+4 B]`, loaded at `0x100015948` |
| W1, selector | 26 |
| X2, input buffer | u64 from P+24 B |
| X3, input extent | Decoded u32 extent in X20, zero-extended |
| X4, output buffer | Same pointer as X2 |
| X5, output-count pointer | SP, initially containing the same decoded extent as X3 |

The adapter submits one buffer for input and output. The caller determines its initial extent through the record. On the selected route, the call return W0 is transformed to `S - ((S << 1) AND 0x2cb8bbaa)` modulo `2^32`, where S is the IOKit status. Its zero test is equivalent to S = 0. For a nonzero S the subtracted value has a zero at S's least significant set bit and at every lower bit, so the difference retains that set bit. The branch uses the original authenticated entries at `0x1005d5440` and `0x1005d9630`.

A zero status reaches `0x10009cfb4`. That block compares the returned 64-bit count at SP with the original X20 extent and selects W11 = `0x965c5dd5` on a match or `0x69a30ca9` on a mismatch. It then reaches the common epilogue. A nonzero status reaches the epilogue directly with the transformed status plus `0x965c5dd5`. The epilogue writes W11 to P+4 B at `0x1000101d4`. The null-pointer bypass for the selected dispatch input writes `0x69a30c43` there. These are adapter-record values. The eventual XPC status and caller interpretation remain unknown.

If the record supplies a 16 B extent and the connection names a FairPlayIOKit client, the installed method table matches the call to `ucSendFPMessage`. On that ordinary inline route the framework emits Mach request 2865 at `0x184ebe090` with the connection as COPY_SEND destination and a separate MAKE_SEND_ONCE reply right. The adapter output-count check runs after IOKit returns from the transaction. [Installed method contract](live_kext_selector26_report.md) [Mach request and reply evidence](live_iokit_mach_transport_report.md)

## Candidate caller record

An address-taken block at `0x1000503c4` prepares a record at FP−128 B and passes its address in X0 to an authenticated call at `0x1000504a0`. It writes the encoded dispatch word and extent at record +0 B and +8 B, and pairs the pointer from SP+56 B with X21 at +16 B and +24 B. The return continuation loads the result from +4 B at `0x1000504a8`. Its call modifier `0x132e` is consistent with the adapter's authenticated function slot. A subsequent audit identified the unique ordered pair of file-backed tables compatible with this call at the recovered table base and its candidate producer. The complete reaching path remains unknown. [Caller audit](live_fpdi_selector26_caller_report.md)

For an 8 B-aligned record the original caller arithmetic produces the same address-derived K as the callee. The decoded dispatch input would be the block's incoming W20 plus `0x202`, modulo `2^32`. The decoded extent would be W28 plus `((W20 << 4) XOR 0x6ec5b6ca)` plus `0x85785c8b`, modulo `2^32`. This identifies the upstream definitions needed to establish a particular dispatch and extent. The instructions in this block alone do not determine those inputs.

## Assumptions and next check

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| F1 | The inspected executable matches the running slice. Preferred PCs and bindings depend on its UUID and SHA-256. | Recheck the live slice against the installed arm64e identity and rederive the fixups. |
| F2 | The adapter receives a record with decoded dispatch input `0x3f8d`. The stated two-way dispatch, result normalization and count test depend on this case. | Recover that decoded value from a calling record producer or observe the local branch and its inputs. |
| F3 | The selected pair of pointers is nonnull and represents valid live objects. The local ABI interpretation uses the original record loads. | Track the connection container and common buffer back to their producers. |
| F4 | The connection points to FairPlayIOKit and the extent is 16 B. This qualifies the named cross-layer method and the inline transport. | Match the connection object and the selector's extent in one registered client's method call. |

High impact for resolving the exact IOKit import and the in-place call ABI. Medium impact for identifying the separate IOKit status and returned-count checks. The leading unresolved chain is from the earlier peer worker to a calling record, then from the record's connection container to the corresponding IOKit open. [Live registry corroboration](live_iokit_selector26_task_provenance_report.md)

## Reproduction

The [auditor](triage_evidence/audit_live_fpdi_selector26_route.py) verifies the arm64e image identity, 61 instruction sites and seven original authenticated fixups. It exhausts both 256-input table equations and checks three bit-vector identities for the adapter, the candidate caller's aligned arithmetic and the status test. The [compressed receipt](triage_evidence/live_fpdi_selector26_route_audit.json.zst) retains 262 instruction records and the solver queries. For image bytes B, fixups F and selected instructions I, extraction uses O(B + F + I) time and space. The two table proofs use 512 checks, independent of input image size.

    python3 triage_evidence/audit_live_fpdi_selector26_route.py DAEMON RECEIPT
