# Selector 26 command scalar and installed reader dispatch

All four pinned `fairplayd` selector 26 fixtures encode command `0x88594abe`. On a successful command-node lookup, the installed FairPlayIOKit dispatcher selects the copying-reader route when the saved provider is nonnull. Its next requested key, `0x172ba3a8`, is already present as a 19 B span in each reconstructed daemon aggregate. The separate archived 96 B `adid` selector 26 fixture carries command `0x73eba01e` and selects the other installed branch. [Request framing and custody](daemon_selector26_request_bytes_report.md) [Archived adid selector 26 fixture](adid_iokit_report.md)

## Daemon writer and method input

The prior four cases cover the two caller classes and both upstream comparison histories. All four final aggregate digests, inline digests, record structures and other parent receipt fields reproduce. In each case, the command node occupies aggregate offsets 0–13 B. It consists of BE32 tag `0x744b91e8`, BE16 type `0x9777`, BE32 length 4 B and BE32 command scalar `0x88594abe`. The last store to each byte is the reverse-copy `STRB` at `0x1009166b8`. Original words identify a source byte read at `0x10091667c`, the XOR at `0x1009166a8` and the destination write. The inspected boundary establishes the final value, with its earlier producer beyond this copy still unknown. [Daemon replay and writer source](triage_evidence/daemon_selector26_command_audit.json.zst)

| Daemon case | Command location | Other matching outer field |
| --- | --- | --- |
| Class `0x98`, method call `0x1002069c4` | First record in 272 B or 288 B inline method structure | `0x172ba3a8` header at 232 B or 248 B, respectively |
| Class `0x99`, method call `0x100293074` | First record in 272 B or 288 B task buffer referenced by 16 B inline descriptor | Same offsets and lengths in the task buffer |

The pinned legacy adapter's input count rejects the direct extent on that method binding. The descriptor meets both outer structure counts and supplies the task address and nested extent to the provider. When provider setup succeeds, the installed core receives the staging pointer, the nested extent and the provider context. The core saves the context at SP+0x738 B. The request uses Mach 2865 and the existing connection right, with a separate send-once reply right for 2965. The supplied trace ends at failed open 2862/2962 with a null connection. Native command-node publication and a matched method transaction remain unknown. [Legacy outer counts](daemon_selector26_legacy_admission_report.md) [Installed provider transfer](live_kext_selector26_transfer_report.md) [Mach rights and emission](live_iokit_mach_transport_report.md)

## Installed dispatch

The pinned source proof requires a successful command-tag search, valid node backing, a 10 B header and a 4 B scalar body that fits the retained extent. The installed command lookup sets up the request at `0xfffffe000a697e34`. The key becomes `0x45e5918e` by applying XOR `0x31ae0066` to the raw key, and the raw type becomes `0xa129` by applying XOR `0x365e`. The command store at `0xfffffe000a67be6c` places the scalar XOR `0x31ae0066` in the workspace at S+0xcf0 B. The installed switch at `0xfffffe000a67bed0` loads that u32. The audit executes this switch and the following branch setup in an offline emulator with the encoded scalar and declared private cells. [Pinned lookup and scalar obligations](userclient_command_dispatch_report.md) [Installed source and replay receipt](triage_evidence/daemon_selector26_command_audit.json.zst)

| Decoded u32 | Encoded u32 | Installed decision | Conditional result |
| --- | --- | --- | --- |
| `0x88594abe` | `0xb9f74ad8` | Equality at `0xfffffe000a67bee0` to `0xfffffe000a67eea4` | Nonzero saved provider selects reader setup at `0xfffffe000a67ef10`. Zero selects cleanup at `0xfffffe000a698090`. |
| `0x73eba01e` | `0x4245a078` | Equality falls through `0xfffffe000a67bef0` to `0xfffffe000a67bef4` | Stores the parsed container at C+0x3a8 B and enters the second command phase. |
| Other u32 | Scalar XOR `0x31ae0066` | Inequality at `0xfffffe000a67bef0` | Enters cleanup at `0xfffffe000a698090` with raw status `0xce515bb7`. |

The first command preserves the parsed container at C+0x4b0 B. The branch at `0xfffffe000a67ef0c` uses IA discriminator `0x9fd7` and selects index `0x8c4` or `0x8ed` from the saved provider test. For the reader route, the next window sets W9 to `0x2685a3ce`, the encoded form of the aggregate's `0x172ba3a8` field. It forwards the two saved output addresses in X10 and X11, sets resume index `0x133` and emits the logical transfer at `0xfffffe000a67ef5c`, with IA discriminator `0x73ed`, to `0xfffffe000a6a3bb8`. Original chained slot `0xfffffe000848a358` binds resume index `0x133` to `0xfffffe000a698254` with IA discriminator `0x3aa3`. The replay stops at the transfer. Search, decoded copying of the 19 B span and the resulting hash input remain unknown for these aggregate cases. [Previously recovered copying-reader ABI](userclient_input_reader_report.md)

## Verification and scope

The installed collection is pinned to SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The audit compares 685 words across 37 command windows, verifies 30 unchanged terminal transfer words and resolves 36 authenticated table fixups. Only two compared words change, at `0xfffffe000a6a3cdc` and `0xfffffe000a6a3ce0`, to form the installed callback pool address. The callback's two 256 B banks preserve the result for all 256 inputs. The resolved descriptor at `0xfffffe0008492780` is the 32 B `site.FPTTLVNode` with signature `1121`. The reader request adds 19 source words and two authenticated slot checks. Nine archived source proof queries recheck as unsatisfiable, and six offline dispatch cases cover both recognized scalars and the zero control at each saved-provider state. [Replay script](triage_evidence/audit_daemon_selector26_command.py) [Compressed receipt](triage_evidence/daemon_selector26_command_audit.json.zst)

```sh
uv run --offline --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_command.py "$COLLECTION" "$RECEIPT"
```

The daemon stage uses the existing pinned loader and modeled call results. The installed replay starts at the switch with the encoded scalar in an emulated workspace and resolves pointer-authenticated edges through original format-8 fixups. The selected dispatch and reader setup take O(1) time and auxiliary state for a fixed layout. Evidence collection takes O(I + E) space for I recorded instruction words and E mappings, excluding SMT cost and prior daemon execution.

| ID | Assumption and dependent claim | Falsification probe |
| --- | --- | --- |
| A1 | The two classes and two predecessor histories represent the scoped daemon fixtures. The scalar value and producer refer to these states. | Vary the predecessor input and compare the last 14 writes and command bytes at the IOKit call. |
| A2 | The staged buffer produces a matching command node under the prior parser and lookup premises. The conditional scalar and command selection depend on that result. | Follow one full provider staging buffer through node publication, protected reads and cursor commitment, preserving byte provenance. |
| A3 | The selected reader phase and saved output cells are valid. The request emission follows if the saved provider is nonnull. | Check the earlier parser-caller phase and output-cell stores, then compare their values at the installed transfer. |
| A4 | The pinned image and chained words describe the selected logical targets. Native authentication, task names and object ownership remain unknown. | Correlate a passive verified method transaction with the same image, provider context and subsequent reader execution. |

| Impact | Open evidence |
| --- | --- |
| High | Continuous installed staging-to-command-parser custody for one complete selector 26 aggregate. |
| High | Copying-reader consumption and hash input for the matched 19 B span. |
| Medium | Dependence of the earlier command producer on daemon state beyond the four retained cases. |

QG1–QG3 cover the factual scope, conditional interfaces and continuation decisions. QG4–QG5 cover field widths, six replay cases, and the saved-provider and unsupported-status paths. QG6–QG7 cover original image words, original slot fixups, proof rechecks and the bounded open evidence above.
