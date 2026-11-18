# fairplayd selector 26 postprocessing and shared state

After a successful constructor return with bit 7 clear in the context word at C+0x14 B, both class paths call private adapter `0x100902878`. It calls a second constructor that allocates 8 B and then 120 B. Failure of either allocation joins the existing service and iterator release path. With both allocations present, the constructor calls a helper that reads process-wide byte buffers also used by the Arcade subscription path. [Class fallback](daemon_selector26_class_retry_report.md) [Arcade subscription state](arcade_subscription_report.md)

The source is the original arm64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. PCs are unslid. F is the outer SP and R=F+0xc8 B. The replay starts with the actual class lookup and open continuation, supplies ordinary IOKit results, and uses the earlier constructor's success word as the input to this path. [Generator](triage_evidence/audit_daemon_selector26_postprocess.py) [Compressed evidence](triage_evidence/daemon_selector26_postprocess_audit.json.zst)

## Calls, records and returns

| Site | Established handoff |
| --- | --- |
| `0x10028a8b0` → `0x100902878` | X0=R, X1=F+0x80 B. The record holds context C at R+0x10 B. The adapter reads the 8 B value at X1 as D and supplies a private stack cell initialized to D−`0xf0` to the core. |
| `0x100902adc` → `0x10087a590` | Original slot `0x1010a1558`, IA `0xe5f2`. The core reads R+4 B, selects phase `0xb22f` for the replayed record, adds `0xf0` to the private stack cell at `0x10087a700`, and loads C from R+0x10 B. |
| `0x10087a5c0`, `0x10087a848` | Calls `___chkstk_darwin` for the `0x1c00` B local extent and the audited internal byte-fill helper `0x10046faf8` with value 0 and extent 4,097 B. |
| `0x100a62f78`, `0x10063dd40` | Two `_malloc` calls for 8 B and 120 B. Original slot `0x10109ff58` is used for both. Source initializes the first six bytes of the small object to `05 00 00 00 01 01` before requesting the larger object. |
| `0x100a2fe70` | A null 120 B allocation frees the earlier 8 B object. A null initial allocation reaches the same status writer with no free in the selected path. |
| `0x1009e5714`, `0x100902aec`, `0x10028a8c0` | On either modeled allocation failure, the core writes `0x74c29d85` to R+8 B, and the adapter writes zero to F+0x80 B. The outer continuation adds that word to SP and dispatches to `0x1002c99a0` with the original outer SP. |

The adapter derives its output from the core's private stack cell as `16 * u16(u32(cell) - u32(D))`. In the failure replays, the cell contains D on return. The outer release path therefore reads the same F+0xc B service name and F+0x78 B iterator name. The Avp profiles then restore the primary context and look up FairPlayIOKit. The primary profiles proceed to publication at `0x1002bffa8`. [Class fallback and release sites](daemon_selector26_class_retry_report.md) [Compressed evidence](triage_evidence/daemon_selector26_postprocess_audit.json.zst)

## Shared byte-state dependency

Both nonnull allocations lead to the `0x100a2146c` call to `0x100444dfc` via `0x1010a01b0`, IA `0x9a7c`. X0 is a local record at the core's FP−0xa0 B. The established callee body reads process-wide pointers before it uses the result record. [Prior helper analysis](daemon_scalar_field_population_report.md)

| Callee read | Global pointer cell | Backing state in the separately recovered initializer |
| --- | --- | --- |
| `0x100444fcc` into X19, followed by a byte load at X19+0x48 B at `0x100444ff4` | `0x1010c6808` | 101 B allocation, published at `0x1003b43c4`. |
| `0x100444ff0` into X20 | `0x1010c8260` | 58 B allocation, published at `0x1003b42d4`. |

Both pointer cells are in zero-fill storage. The initialized buffers come from the previously recovered startup path. The postprocessing replay stops at this call with both allocations live. The earlier Arcade analysis identifies the same helper and initialized buffers. The downstream values, further IOKit calls and successful native method exchange remain unknown. [Initializer and shared helper](arcade_subscription_report.md) [RAX trace interval](zut_trace_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The pinned original fixups and stack layout identify the logical calls. The modeled stack guard matches and the probe call returns normally. | Check chained words and native return continuity against the original save and restore sites. |
| A2 | The known constructor status and bit 7 clear select this branch. The outer record, context and API outputs remain live. | Correlate `R+8 B`, `C+0x14 B` and F+0x80 B with actual loads in one invocation. |
| A3 | The allocator outputs are modeled disjoint pointers or null. The byte-fill calls complete over their exact local destinations. | Compare each requested extent, initialized prefix and matching free against the original call and store instructions. |
| A4 | Replayed seed cells start from their original or zero-fill bytes. The nonnull case reaches the shared-state call without modeling initialized buffer contents. | Compose the recovered initialization with the two consumers and compare their state identities and synchronization in one capture. |

Six profiles cover both classes and three allocator outcomes. The audit retains 227 source spans and verifies 95 original chained fixups. For I instruction visits, L recorded loads and M modeled byte writes, the replay uses O(I·L+M) time with its explicit fixup candidate search and O(I+L+M) retained space. QG1–QG7 cover factual scope, live premises, allocator outcomes, explicit widths, original provenance and the following evidence gaps.

| Impact | Open evidence |
| --- | --- |
| High | Establish the successful postprocessing return and any subsequent method emission using the original initialized state. |
| High | Correlate a successful native selector 26 exchange with the service right, context and subsequent helper calls. |
| Medium | Identify the synchronization and lifetime shared by both byte-state consumers. |
