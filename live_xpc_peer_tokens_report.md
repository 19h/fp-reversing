# Live XPC peer audit tokens

On macOS build `26C5035r`, the installed XPC receive code copies the 32 B Mach audit token into both the received dictionary and the connection's cached credential. The installed `adid` adapter uses the dictionary getter. In a native control with two verifier processes, both fields matched the sender's independently queried kernel task token in each direction. Creating a reply preserved the token on its source request.

## Installed receive and application paths

The auditor matches the running shared-cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`, `libxpc.dylib` UUID `94e40b03-44c5-3636-aa1a-c64a5d6b6bbb` and the running `adid`'s code identity to its ARM64e slice, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. The addresses below are unslid.

The SDK defines a 24 B Mach header and a 52 B audit trailer. If H is the message header address and n is its u32 `msgh_size`, the installed receiver computes the trailer address T as H + 4 B × ceil(n / 4 B). It zero-extends n before rounding. The token occupies the 32 B from T+20 B through T+51 B, inclusive. The reply name in a received request is a separate u32 at H+8 B, interpreted in the receiver's IPC namespace. [XNU Mach message ABI](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/message.h#L670-L703)

| Operation | Installed sites | Data or control transfer |
| --- | --- | --- |
| Unpack the event or reply | libxpc `0x184bbe3fc` ordinary event, `0x184bbd6cc` synchronous reply, `0x184bc1914` asynchronous reply | Each calls `__xpc_connection_unpack_message` at `0x184bbddfc`. The unpacker checks the peer requirement at `0x184bbde40` before invoking the receiver at `0x184bbdf28`. |
| Copy incoming identity and take the reply name | libxpc `0x184bb816c–0x184bb81c0` | `_xpc_receive_mach_msg` loads the size and name, clears H+8 B, and saves the name in the temporary record at SP+0x10 B. Two 16 B loads from T+0x14 B and T+0x24 B supply the separate record field at SP+0x30 B. |
| Attach identity to the decoded dictionary | libxpc `0x184bb8858–0x184bb8860`, `0x184bb88e8–0x184bb8908` | The context-bearing graph path sets mode 1, moves the 32 B context to dictionary+0x58 B and copies the 32 B token to dictionary+0x78 B. The ordinary callback receives the decoded event in X1 at `0x184bc0024`. |
| Refresh the connection credential | libxpc `0x184bbdf34–0x184bbdf6c` | After the decoder's return passes the check against `-1`, the unpacker copies the same trailer bytes to connection+0x68 B under the unfair lock at connection+0x58 B. |
| Create the outgoing reply | libxpc `0x184bc685c–0x184bc68c0` | The mode-1 request must have a nonzero first context word. A mode-2 reply receives 24 B of that context at reply+0x60 B, and the corresponding 24 B are cleared on the request. The peer reference is handled separately. The request's credential starts 32 B into its original context area and survives these stores. |
| Read the per-dictionary identity | libxpc `0x184bb8b64` | The getter selects on the low two bits at dictionary+0x1c B. Mode 1 reads +0x78 B, mode 3 reads +0x58 B, and modes 0 and 2 return the default token. That token has all 32-bit words equal to `0xffffffff` except PID word 5, which is zero. |
| Read the cached peer identity | libxpc `0x184bc8f58` | The getter reads 32 B at connection+0x68 B under the same unfair lock. The cache can be refreshed by receive, while the dictionary carries metadata from its own delivery. |
| Read the request credential in `adid` | `adid` `0x1000aa4b4–0x1000aa4c0`, authenticated import slot `0x1002d8a18` | The adapter passes the dictionary in X0 and SP+0x60 B in X1 to `_xpc_dictionary_get_audit_token`. The receiver's later Security.framework lookup uses the token-associated task. |

The reply context explains why `adid` can create the reply first at `0x1000aa3f0` and read the request credential afterward at `0x1000aa4c0`. For the installed named synchronous path, libdispatch installs the request's destination send name at `0x1855b45f0`. The server's reply uses the received send-once right preserved by the branch at `0x1855b4580`. Both sends reach `0x1855b487c` and the Mach2 trap at `0x180548c1c`. The static sites establish the right and credential paths. The numeric names and message variant of a native `fairplayd` application transaction remain unknown. [Named XPC transport and emission sites](live_adid_xpc_sync_transport_report.md) [ADID receiver](adid_receiver_report.md) [Live Security entitlement lookup](live_adid_peer_entitlement_report.md)

On the kind-2 peer check, installed instructions at `0x184bda1bc–0x184bda1e0` compare the cached PID and PID version against trailer offsets 40 B and 48 B, respectively. The separate optional requirement path starts at `0x184bda1e4`. The control did not identify which check ran, and the existence of these branches does not establish the result for a named peer. [Archived XPC receive context](xpc_receive_context_report.md) [Live audit-token generation](live_audit_token_generation_report.md)

## Native control

The parent constructs a private Mach receive right and gives the child a send reference in its registered-port array. The child requests an endpoint for the parent's anonymous XPC listener through that private channel. The installed pipe receive code constructs options with audit-trailer bits `0x03000000` at `0x184be8d9c` and calls the common decoder at `0x184be8d20`. The child then opens a connection from the endpoint and makes two sequential synchronous requests, each echoed by an application reply. Both processes independently query the other's running kernel task with `task_name_for_pid` and `task_info(TASK_AUDIT_TOKEN)`. The verifier compares all 32 B each time and requires distinct PIDs. [Registered-port consumers](registered_port_consumers_report.md)

| Exchange | Received dictionaries | Comparison and result |
| --- | ---: | --- |
| Private setup request and endpoint reply | 2 | Each dictionary's token equals the sender's task token. |
| Anonymous connection, sequences 1 and 2 | 4 | Each dictionary's token and the receiver's cached peer token equal the sender's task token. Both request tokens still match after reply creation. |
| Unattached dictionary created in the parent | 1 | Getter returns the exact default token, including zero at word 5. |

The native control exercises ordinary XPC send and receive with verifier-owned endpoints. Its receipt records outcomes and counts. Raw Mach headers, numeric port names and raw token words were not collected. Existing daemon logs corroborate connection lifecycle activity. An original `fairplayd` application message, its credential consumption in `adid`, and its relation to an admitted FairPlayIOKit action remain unknown. [Native daemon XPC observations](fairplay_native_xpc_observation_report.md)

## Assumption register

| Assumption | Dependent result | Falsification check |
| --- | --- | --- |
| A1. The installed bytes correspond to the running images. | Instruction addresses, authenticated import and the `adid` join. | Check runtime and on-disk cache UUIDs, image UUIDs, the running `adid` code identity, the slice hash and the import fixup. Recheck process identity after reading. |
| A2. The selected branch is the ordinary successfully decoded XPC message path. | Dictionary, connection and reply-context transfers. | Check the call edges, peer check, decoder return branch, dictionary mode bits and exact ranges written by context transfer and reply creation. |
| A3. The independent task query refers to the peer sending the control messages. | Equality with the native peer identity in both directions. | Assert distinct PIDs and match the kernel-returned token's PID to each queried child or parent. Compare the full token, check sequence correlation and require clean child exit. |
| A4. Evidence from anonymous endpoints applies to the mapped transport mechanism. | Type and direction of metadata available to the installed consumer. | A receiver-side record of a genuine named request, correlated with its endpoint and transaction, is needed to attribute a credential lookup and downstream result to a specific daemon message. |

**High impact.** The dictionary credential survives transfer of the request's reply right, which accounts for the ordering in the installed `adid` adapter. **Medium impact.** Synchronous reply reception refreshes the connection cache through the same unpacker as ordinary events. A cached connection credential and a credential attached to an individual dictionary have different lifetimes.

Run `python3 -B triage_evidence/audit_live_xpc_peer_tokens.py` with the repository's Python dependencies on the pinned build. The auditor checks the original instructions, the compiler-asserted ABI layout and the native control. For m measured messages the probe does O(m) work with fixed-width token comparisons and O(1) live application requests, excluding transport setup and scheduling. [Auditor](triage_evidence/audit_live_xpc_peer_tokens.py) [Native verifier](triage_evidence/xpc_peer_audit_probe.c) [Compressed receipt](triage_evidence/live_xpc_peer_tokens_audit.json.zst)
