# Arcade registration dispatch and status reply

On macOS build `26C5035r`, the kernel proper uses its generic Mach Interface Generator (MIG) hash table to dispatch fairplayd request 51471. The generic server takes the reply destination from the request header's local right and initializes a simple status reply with ID 51571. The same Mach send worker that accepted the request hands the reply to the destination queue. The following identifies static call sites in the UUID-matched boot fileset and joins them to the previously matched daemon client. Native delivery remains unknown. [Registration and daemon client audit](live_arcade_registration_report.md)

```text
fairplayd --51471--> kernel registration object
                         |
                  MIG bucket 952
                         |
                  Arcade registration stub
                         |
fairplayd <--51571-- queue send to the original MIG reply port
```

## Boot registration and routine lookup

The compiler-bounded initialization routine at `0xfffffe000c679d60` visits 20 subsystem pointers at `0xfffffe000caff018`. Entry 17 is the relocation at `0xfffffe000caff0a0` to the Arcade subsystem at `0xfffffe0007e748d8`. For each populated 32 B routine record it derives the message ID from the subsystem start plus the routine index. It probes the 1,031-entry table at `0xfffffe0007e68ab8` with 24 B buckets and inserts the message ID, authenticated function pointer, exact internal reply size, reply descriptor count and initial filter index. The file-backed bucket region is all zero before initialization. [Apple XNU MIG table initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_kobject.c#L161-L276)

The audit reconstructs insertion in registry order from 358 nonzero routine pointer slots. For 51471, `51471 = 49 × 1031 + 952`, so probing begins at bucket 952. It is free when Arcade is inserted. The resulting preferred bucket address is `0xfffffe0007e68ab8 + 952 × 24 B = 0xfffffe0007e6e3f8`. The Arcade record supplies 44 B and zero reply descriptors. The runtime lookup reads the ID at internal header +0x1c B and probes the same table. The authenticated call at `0xfffffe000bd3c724` uses the selected bucket's +8 B function pointer and discriminator `0x3a83`, matching the original routine fixup for `0xfffffe000bdda404`. This establishes the generic dispatch path independently of the generated subsystem lookup helper. The initialized runtime bucket and effective filter policy remain unobserved.

## Reply construction and destination

| Stage | Preferred site | Recovered behavior |
| --- | --- | --- |
| Request dispatch | `0xfffffe000bd0f2fc` or `0xfffffe000bd0f364` | The generic send worker calls the kernel-object server on the kernel-space branch. Both call sites converge on the same server. |
| Reply header | `0xfffffe000bd3c654` through `0xfffffe000bd3c688` | Initializes 44 B internal size, copies the received local disposition into the reply's remote disposition and moves the request local port object into the reply remote slot. Clears the reply local and voucher fields and adds 100 to the request ID. |
| Registration result | `0xfffffe000bdda4a4` and `0xfffffe000bdda4a8` | Calls the application and writes its 32-bit return status after the 8 B NDR record. The same response has 36 B in the daemon's user layout. |
| Reply handoff | `0xfffffe000bd0f3b4` or `0xfffffe000bd0f448` | The worker takes the returned message, initializes its trailer with a null task argument, and reloads the reply destination from the new header. |
| Destination queue | `0xfffffe000bd0f208` | Calls the queue send routine at `0xfffffe000bd0fbf0` with the destination object plus 0x28 B, the returned reply message, options and timeout. |
| Daemon consumer | Client `0x1000043b4` | Validates the reply family and reads the status from its MIG reply buffer. |

The 51471 client's MIG reply name supplies a send-once right when Mach imports the request. The kernel-object server frees the received request buffer on success, leaving the application-owned descriptor available to the endpoint publication path. A nonzero ordinary status takes the generic request destruction route with both header rights excluded, after the destination has been released and the reply right assigned. Before returning a reply, the server discards one with an invalid destination or a destination in kernel IPC space. The queue call is the static reply submission boundary. A native observation would distinguish a message handed to a waiting receiver from one enqueued or destroyed. [XNU kernel-object server and reply ownership](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_kobject.c#L603-L709) [XNU send and reply continuation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_kmsg.c#L4894-L4946) [XNU queue send](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_mqueue.c#L388-L425)

## Assumption register and verification

| Assumption | Dependent result | Falsification check |
| --- | --- | --- |
| A1. The extracted fileset identifies the selected kernel build. | All preferred addresses and table contents. | Match kernel UUID, rehash the fileset and verify instruction operands and chained fixups. |
| A2. The startup replay begins from the observed empty buckets and follows registry order. | Bucket 952 and its dispatch metadata. | Replay each insertion, check for duplicates, and compare the Arcade slot with the original lookup arithmetic and authenticated pointer. |
| A3. A request reaching the handler carries the daemon's expected reply right and passes generic and Arcade admission. | The registration status flows to the daemon's queue. | Correlate object identity, application result, queue submission and receiver in a native observation of an ordinary transaction. |

High impact applies to identifying the kernel's actual status reply submission and connecting it to the daemon's reply name. Medium impact applies to boot-time table population and the split between generic message disposal and Arcade endpoint publication. The audit reads the kernel image, asserts instructions at the dispatch and reply sites, and reconstructs the table in O(R + P + H) time with R routine slots, P collision probes and H buckets. Table reconstruction uses O(H) working memory in addition to the input image and parsed metadata. Native policy, queue outcome and transaction correlation remain unknown. [Audit script](triage_evidence/audit_live_arcade_registration_reply.py) [Compressed audit receipt](triage_evidence/live_arcade_registration_reply_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_arcade_registration_reply.py "$BOOT_FILESET"
```
