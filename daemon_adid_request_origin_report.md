# fairplayd request origin for the CoreADI OTP command

On the retained clock-success path, `fairplayd` gets the operand for its `com.apple.adid` request from an internal leaf at `0x100001e0c`. The leaf returns the full 64-bit value `-2`. The daemon builds the 20 B XPC `data` field from two local allocations and supplies it to the synchronous send. The command and layout match the original `akd` operation named `requestOTPForDSID:outMID:outMIDSize:outOTP:outOTPSize:`. The installed `adid` dispatch tree maps this command to `0x10016dab8`. The clock-success branch's original upstream transaction, effective provider admission and native delivery remain unknown. [Clock-success entry](daemon_environment_outputs_report.md) [XPC client and listener](live_fairplay_adid_ipc_report.md) [Named akd client](akd_adid_client_report.md)

```text
clock-success cut 0x1007019b0
  -> original leaf returns -2
  -> fairplayd helper 0x100e1e5ec
     -> malloc(24) record -> malloc(4096) byte buffer
     -> write 20 B -> XPC dictionary "data" -> pending sync send 0x100e21718
                                                  |
                                      command correspondence
                                                  v
                               installed adid parser 0x10016dab8
```

## Request bytes and custody

All instruction addresses are unslid preferred virtual addresses. The source saves helper X0 to `SP+0x138` at `0x100e1e610`. In the caller path the original call at `0x100701a78` supplies `-2` from the leaf. The last eight byte stores read the original saved X0 and serialize all 64 bits. The AKADIProxy method gives the wire operand its DSID name. The meaning of the particular value `-2` in `fairplayd` policy remains unknown. [Named argument provenance](akd_adid_client_report.md)

| Request offset | Width | Value | Original writer PCs in byte order |
| --- | ---: | --- | --- |
| 0 | 4 B | BE32 `1` | `0x100e208ac`, `0x100e208c4`, `0x100e208d8`, `0x100e208bc` |
| 4 | 4 B | BE32 `0xcfe0b46a` | `0x100e20b84`, `0x100e20b94`, `0x100e20bc8`, `0x100e20bd4` |
| 8 | 4 B | BE32 `1` | `0x100e20e60`, `0x100e20e78`, `0x100e20e84`, `0x100e20e90` |
| 12 | 8 B | BE64 helper X0 | `0x100e211d4`, `0x100e211e8`, `0x100e211fc`, `0x100e2120c`, `0x100e2121c`, `0x100e2122c`, `0x100e2123c`, `0x100e21248` |

For the clock-success caller, the complete request is `00000001 cfe0b46a 00000001 fffffffffffffffe`. A direct-helper control with X0=`0x1122334455667788` produces exactly the 20 B already captured from the original `akd` OTP producer for that operand. The audit repeats the equality with two stack placements, controller pairs and clobber patterns. That control is separate from the original caller and its fixed operand. [Original akd request/reply profiles](triage_evidence/akd_adid_pair_profiles.json.zst)

The first modeled `malloc` returns record R at `0x100e1ea4c`. The second returns buffer B at `0x100e1eb04`, and `0x100e1eb0c` saves B at R+0. The original instructions at `0x100e1eb48` and `0x100e1eb64` compute and save `SP+0x1c0 = R + 0x7dd5cf10709e5799` modulo 2^64. The setter prefix adds `0x822a30ef8f61a867` and `0x822a30ef8f61a873` to that encoded address, yielding R and R+12. The source loads B and the encoded used length from those addresses.

| Record offset | Width | Checked representation |
| --- | ---: | --- |
| 0 | 8 B | Raw B pointer. |
| 8 | 4 B | Encoded capacity. Initial value `0x1d6d1efe`, then `0x1d6d2efe` after installing 4,096 B. |
| 12 | 4 B | Encoded used extent. Add `0x9aa4ac59` modulo 2^32 for the checked sequence 0, 4, 8, 12, 20 B. |
| 16 | 4 B | Zero written at `0x100e1eab0`. Its semantic name remains unknown. |
| 20 | 4 B | Unwritten in the replayed prefix. |

The setter at `0x100e21448` receives the new dictionary, key `data`, B and count 20. Each supplied byte has a unique original store. In the modeled call sequence the same dictionary is passed to the pending `xpc_connection_send_message_with_reply_sync` at `0x100e21718` with the connection for `com.apple.adid`. When the first allocation returns NULL, the helper returns `0xffff5035` to its original caller. When the second returns NULL, the code reaches pending `free(R)` at `0x100e2507c`. Both failure profiles leave the four initialized output cells zero and reach no XPC setter or send.

## Provider and FairPlayIOKit boundaries

The current arm64e `adid` slice matches all 7,904 B of the prior provider decision-tree window beginning at `0x10016cd58`. That tree takes the BE32 command from request offset 4, adds `0x46d726` modulo 2^32 and selects `0xd0278b90` at `0x10016d454`, targeting `0x10016dab8`. This is the command branch. The selected operation's complete authorization, reply layout and downstream providers remain unknown. [Provider command tree](adid_command_dispatch_report.md)

The recovered request producer starts at the clock-success cut with the caller's five frame roots supplied as premises. The prior scratch-pointer investigation tracks a source-compatible `gettimeofday` predecessor and an independent IOKit continuation. It has no uninterrupted state path from the IOKit continuation to this cut. The current transport evidence therefore locates the application request boundary at the synchronous libxpc call. The actual destination and reply-port names, right dispositions and participating FairPlayIOKit transaction remain unknown. [Scratch and IOKit predecessor boundaries](daemon_scratch_pointer_origin_report.md) [Kernel-side FairPlay request and reply ABI](live_fairplay_rpc_abi_report.md)

## Assumptions and verification

| ID | Premise and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | Pinned fairplayd bytes identify the checked original. The provider comparison uses the previously matched installed arm64e slice. | Rehash both thin images and compare the complete current provider tree against the original window. |
| A2 | The retained clock-success frame roots, cache-miss state and controllers admit the chosen prefix. | Recheck each retained caller prefix down to visits, reads, writes, edges, registers and flags before the first allocation. Compare two stack placements and controller pairs. A prior writer that changes a required root requires a new composition. |
| A3 | The declared allocation, XPC and dispatch outcomes follow ordinary API returns. | Test both allocator NULL alternatives and vary caller-saved general-purpose registers and condition flags. Check the original call opcodes, import targets, discriminators and defined arguments before each modeled return. |
| A4 | The observed scalar-writer registers bind the eight-byte serializer to this request. | Symbolically interpret 51 original instructions with the saved X0 arbitrary. No 64-bit value violates BE64 serialization. The reversed-endian comparison produces a counterexample. |
| A5 | The matching command provides the named wire operation. | Compare the literal command, width and all 20 raw bytes with the named producer for the same operand. Compare the installed provider's decision bytes. Native observation would test policy, lifetime and delivery. |

The audit captures 20 runs, 12 exactly matched retained prefixes, 16 pending sends and 23,958 original instruction visits. Every continuation stops before the synchronous send or at the stated failure boundary. The request bytes are written by original instructions. External API return objects, cache and environment state, logical pointer-authentication effects and the setter's object association are explicit private premises. No native XPC transaction executes. Replay cost is O(B + V + E) in loaded original bytes B, visits V and retained events E, with space O(B + V + E). The bit-vector query has a 30 s cap. [Audit script](triage_evidence/audit_daemon_adid_request_origin.py) [Compressed evidence](triage_evidence/daemon_adid_request_origin_audit.json.zst)

| Impact | Remaining discriminating evidence |
| --- | --- |
| High | Connect the clock-success cut to its original transaction entry, or establish an independent caller path from FairPlayIOKit. |
| High | Follow the OTP-specific provider branch through the input and output adapters. Recover the application reply schema and test its match with the four daemon outputs. |
| Medium | Trace the provider output and request through the actual libxpc peer and Mach reply context under ordinary operation. |
