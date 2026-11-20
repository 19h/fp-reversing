# Authenticated call targets in the fairplayd RPC 502 environment helper

The authenticated call at `0x100de8540` selects local helper `0x100de1430` through the original dispatch table. Three continuous private replays reach this call and the helper's read-only VMM query, then observe the helper's caller-frame output. A second call at `0x100de7a8c` selects the same helper for the recovered bank pair and canonical dispatch base. Its reaching bank definitions remain conditional. The two genuine `dlsym` calls in this cluster resolve CoreKE exports. This closes one dynamic-lookup ambiguity left by the daemon's IOKit interest-registration census. [Prior transport census](daemon_iokit_retirement_report.md) [IOKit registration evidence](daemon_iokit_interest_link_report.md) [RPC 502 request and reply ABI](live_fairplay_rpc_abi_report.md)

## Original call targets

All addresses are preferred, unslid virtual addresses in the pinned thin daemon. For input byte i, both lookups yield a constant `i XOR R[L[i] XOR key]`. The original additive turns the constant into an index of the 8 B table at `0x1010ab1a0`. The auditor evaluates all 256 input bytes at each call and checks both the authenticated slot word and dyld's interpretation of that slot. The table and site evidence distinguish the target identities that share the same ARM64e modifier.

| Call | Modifier | Table index / slot | Verified or conditional target |
| --- | --- | --- | --- |
| `0x100de1794` | `0xc052` | `0x9a` / `0x1010ab670` | `sysctlbyname` |
| `0x100de189c` | `0xc052` | `0xcc` / `0x1010ab800` | Local comparison-frame helper `0x100ddc63c` |
| `0x100de1a2c` | `0xc052` | `0xcc` / `0x1010ab800` | Same local comparison-frame helper |
| `0x100de1ab0` | `0x19ad` | `0xd3` / `0x1010ab838` | `puts` |
| `0x100de1b58` | `0xc052` | `0xca` / `0x1010ab7f0` | `dlopen`, named CoreKE framework |
| `0x100de1c2c` | `0x19ad` | `0xdb` / `0x1010ab878` | `dlsym`, name `IWvA5fm4IwMS88oQXDANCS` |
| `0x100de1d30` | `0x19ad` | `0xdb` / `0x1010ab878` | `dlsym`, name `JY0DfiUyFiVcNw89R4t` |
| `0x100de7a8c` | `0x19ad` | `0xe7` / `0x1010ab8d8` | Local environment helper `0x100de1430` under the bank-root premise below |
| `0x100de7f7c` | `0xc052` | `0xeb` / `0x1010ab8f8` | Local wrapper `0x100de574c` |
| `0x100de8540` | `0x19ad` | `0xe7` / `0x1010ab8d8` | Local environment helper `0x100de1430` |

The two local comparison calls in the environment helper both pass a frame at SP+0x78 B and read the next control index at SP+0xac B on return. The original `0xc052` call at `0x100de7f7c` enters the wrapper containing the conditional `0x100de7a8c` edge. The prior transport census establishes the explicit `mach_msg` and `mach_msg2_internal` stub sites separately. Across the image, the checked adjacent-modifier form yields these five `0xc052` calls, five `0x19ad` calls and 15 other `0x19ad` tail branches. The remaining tail branches and other call forms require independent resolution. [Comparison-frame semantics and loader names](rpc502_runtime_report.md) [Legacy ADID Mach emission](daemon_adid_mach_fallback_report.md) [Daemon Mach transport census](daemon_iokit_retirement_report.md)

## Helper input, output and reaching definitions

At `0x100de8540`, X0 is X29−0x78 B. The left root is loaded from pool+0x170 B at `0x100de8428`. The right root is loaded from pool+0xb0 B, reduced by 12 B and saved at SP+8 B. The original pool entries decode to `0x101032b70` and `0x101032c7c` before the bias. Key `0x56` produces constant `0x4e`, giving index `0xe7` after addition of `0x99`. The same bank rule minus `0x4c` selects pool index 2 for the biased table pointer at `0x100de8160`. Subtracting 12 B restores the canonical base passed into the wrapper continuation. All three private replays confirm the active table in X22 and the resolved target in X8 at the call.

The `0x100de7a8c` wrapper gets its canonical table from the same original pool entry by a separate rule at `0x100de5978`. Its call loads the left and right bank pointers from SP+0x30 B and SP+0x28 B, respectively. The wrapper contains producers for both bank addresses and stores candidate pairs into those slots. For pair (`0x101032b70`, `0x101032c70`), key `0x2c` gives constant `0x85`; addition of `0x62` selects the same slot. The incoming path through the stack stores and intervening stack adjustments is unknown. The audit therefore retains this edge as conditional on the two live pointers at the call. A follow-up recovered the producer and consumer intervals with the same underlying stack. The natural transition between them remains open. [Wrapper stack and helper dispatch](daemon_rpc502_wrapper_frame_report.md)

In the callee, `0x100de158c` reads the 4 B word at frame+0 B, and `0x100de1598` saves the frame pointer. The exit store at `0x100de1df8` writes a 4 B result to frame+4 B. The callers read that field at `0x100de7a94` and `0x100de8544`. The values below are encoded continuation words. The true query result is the modeled u32 returned through the `sysctlbyname` output pointer, together with the modeled API status.

| Private sysctl result | Output word at helper frame+4 B | Observed continuation |
| --- | --- | --- |
| Status 0, value 0 | `0xd1c48a3f` | Both named CoreKE export queries |
| Status 0, value 1 | `0x2e3bd2ce` | Diagnostic call and return to wrapper |
| Status −1, configured value 1 | `0xd1c48a3f` | Both named CoreKE export queries |

The failure fixture configures value 1 but the sysctl model writes the output only on success. The continuous replays use the existing RPC 502 worker entry and its declared once, lock, allocation, system-query and loader models. They observe the original helper call and caller readback without patching those sites. Native CoreKE execution and effects on the FairPlayIOKit reply remain unknown. The available IDA MCP session exposed an unrelated database. Reproduction uses the original Mach-O bytes and the existing private runner. [Model and API assumptions](rpc502_runtime_report.md) [Audit receipt](triage_evidence/daemon_rpc502_dynamic_dispatch_audit.json.zst)

## Assumption register

| Assumption | Dependent result and impact | Falsification probe |
| --- | --- | --- |
| D1. The recorded Mach-O SHA-256 and UUID identify the source for the table and calls. | High. All call-slot assignments depend on this identity. | Rehash the image, verify the literal instructions and compare the original chained slot words. |
| D2. The two stated bank pointers reach SP+0x30 B and SP+0x28 B at `0x100de7a8c` with the canonical table. | Medium. This conditions the first local-helper edge. | Follow the dominating stack stores across the stack adjustments or capture both pointers and the target at the call in a complete offline replay. |
| D3. The inherited private models describe the three declared worker executions. | High. The second helper edge and frame result are observed within those executions. | Repeat with varied query values and statuses, then compare the original target, input frame and output word against the receipt. An actual daemon query and loader outcome would establish native behavior for that case. |
| D4. The adjacent register-immediate form bounds the call census. | Medium. Direct inference covers the enumerated call sites. | Inspect the remaining tail branches and calls through other register or authentication forms, then trace any resolved IOKit registration transport. |

For binary bytes B, fixup records F, ten calls K and retained replay work E, the audit takes O(B + F + 256K + E) time and O(B + F + E) space excluding tool internals. Run `python3 -B triage_evidence/audit_daemon_rpc502_dynamic_dispatch.py "$ARCHIVED_DAEMON"` with the existing RPC 502 replay dependencies. [Audit script](triage_evidence/audit_daemon_rpc502_dynamic_dispatch.py)
