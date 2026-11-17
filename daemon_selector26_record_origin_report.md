# fairplayd selector 26 result record origins

The source now ties the result field at `0x1000acc50` to a caller-owned stack record. At `0x1001f5178`, the audited bank pair selects `0x1004110fc` and passes `R = caller FP−0x78 B` in X0. The caller reloads `R+8 B` at `0x1001f517c` and compares the 32-bit field with `0x8b3dc651`. The containing routine saves that same record pointer at its SP+0x90 B and saves W28 at SP+0x124 B on its nonnull-context path. [Prior result-record audit](daemon_selector26_status_publication_report.md)

## Record and caller branches

| Location | Field or control effect |
| --- | --- |
| `0x1001f5108`–`0x1001f512c` | Writes a byte at R+0 B, an encoded phase at R+4 B and X20 at R+16 B. The purpose and downstream use of the byte remain unknown. |
| `0x1001f5178` | With bases `0x100fc4230` and `0x101031fa0`, XOR key `0xf3` and additive `0xce5b` select slot `0x1010a13e0`, IA `0x99fc`, to `0x1004110fc`. |
| `0x100411290`–`0x1004112ec` | Loads R+4 B and decodes W28. A solver check proves W28=`0x8934` for the caller's W24=`0x3941` and every 16 B-aligned record address. R+16 B is loaded into X1 and selects the initial route. |
| `0x100411328`, R+16 B null | Index `0x895b`, slot `0x10107e9c8`, IA `0x654e`; the shared writer stores `0x74c29d88` at R+8 B. |
| `0x100411328`, R+16 B nonnull | Index `0x8934`, slot `0x10107e890`, IA `0x654e`; `0x10005be70` saves X1 at SP+0x88 B and R at SP+0x90 B. `0x10005bfa8` saves W28 at SP+0x124 B. |
| `0x1001f517c`–`0x1001f51a4` | After normal return, `R+8 B = 0x8b3dc651` selects index `0xaf7e` and `0x10011c77c`. The selected errors `0x74c29ded` and `0x74c29cd6` select index `0x3941` and `0x1002c99a0`. The branch uses IA `0x595b`. |

The nonnull-context path requests `malloc(16 B)` at `0x10005bf20`, using slot `0x10109ff58` and IA `0x6aa4`. A null result takes `0x100013334`, with encoded status `0x74c29d85` in W16. A nonnull result enters `0x100015c50`, clears both 8 B fields of the allocation and stores its pointer at FP−0xb8 B. The prologue had cleared both cleanup cells at FP−0xc0 B and FP−0xb8 B. The second cell is therefore nonnull after successful allocation. Its state at the selector 26 error continuation remains to be traced through the intermediate constructor path.

The producer at `0x10005bf5c` and `0x10005bf70` installs `0x100fc4130` and `0x101031ea0` at SP+0xb8 B and SP+0xc0 B. Those banks resolve the indirect call at `0x1000dda88` to `libSystem/_free` under the recovered frame composition. Key `0xa3` gives constant `0x72` for all 256 byte inputs, making `0xcb96 + 0x72 = 0xcc08` and selecting original slot `0x10109ff30` with IA `0x46a2`. This call receives the pointer saved at SP+0xa8 B. The proof covers six bank rules over 1,536 inputs and three context/allocation profiles. Each fixed-size record and bank dispatch takes O(1) time and space, excluding the allocator and later constructor work. [Audit script](triage_evidence/audit_daemon_selector26_record_origin.py) [Compressed evidence](triage_evidence/daemon_selector26_record_origin_audit.json.zst)

The supplied `annotated-strace-rax-user.txt` still hashes to `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. The audit independently found 22 sends, ending with open request 2862, and no send with ID 2865. Reply 2962 at lines 1736–1741 has result `0xe00002c2` and a null connection port. This trace documents a transport-successful open failure. Native selector 26 and publication of R+8 B in IPC remain unknown. [Trace and port attribution](zut_trace_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| S1. The pinned image and format-12 fixups supply the table and pool in the audited fragments. | Original targets and bank roots. Decode the original slot words, import ordinals and bank addresses. Test all 256 inputs for each bank pair. |
| S2. The selected caller enters with W24=`0x3941`, a valid 16 B-aligned record and the stated SP+0x40 B and SP+0x38 B banks. | Call identity, caller decode and post-call branches. Recover reaching definitions from the caller's predecessor and evaluate the altered phase or bank pair. |
| S3. `_malloc` returns normally and a nonnull result has 16 writable bytes. | Allocation branches and second-cleanup-cell initialization. Test null and nonnull returns and inspect both zero stores and the pointer save. |
| S4. The later record publication occurs in this same frame with the recovered saved cells live. | Joining selector 26 status to the caller record and resolving the final `_free`. Trace the intermediate constructor and subsequent stores to SP+0x90 B, SP+0x124 B and FP−0xb8 B. |

| Impact | Open join |
| --- | --- |
| High | Join the nonnull constructor path to selector 26 and carry the returned word through the caller's branch at `0x1001f51a4`. |
| Medium | Establish the lifetime and contents of the second cleanup allocation through the constructor and confirm the source of the caller's W24. |

QG1–QG7 apply to the retained static ABI and trace interval. Cross-layer native correlation remains open.
