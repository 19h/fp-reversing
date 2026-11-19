# Selector 26 outer structure admission

The pinned legacy selector 26 method requires a 16-byte input structure and a 16-byte output capacity. The two positive daemon PID-path fixtures produce 272- or 288-byte buffers. The daemon can put that extent in the outer IOKit call or inside a 16-byte descriptor. The placement determines whether the request reaches the nominal member of this legacy method.

| Daemon fixture and call PC | Outer input / output capacity (bytes) | Nested extent (bytes) | Pinned legacy method result |
| --- | ---: | ---: | --- |
| Class 0x98, 0x1002069c4 | 272 / 272 or 288 / 288 | No descriptor in this call form | Input count mismatch, 0xe00002c2 |
| Class 0x99, 0x100293074 | 16 / 16 | 272 or 288 | Both structure counts match |

The rows are conditional on a live connection selecting the pinned legacy method and on the request reaching its argument adapter. Class tags are the modeled daemon values. See the [PID-path branch report](daemon_selector26_pidpath_paths_report.md) and [field report](daemon_selector26_pidpath_fields_report.md) for the construction of the two extents and their model provenance.

## Framework and kernel count checks

The pinned framework compares input extent X5 against 4096 bytes at `0x184e77d98` and output capacity X11 against the same cutoff at `0x184e77e28`. Both forms use inline Mach structure fields. At zero scalar input, the MIG client computes the request length as `84 + align4(input_extent)` bytes at `0x184e77ffc`. The user request lengths are 356 and 372 bytes for the direct form and 100 bytes for the descriptor form. The kernel view adds eight bytes to those lengths. The framework copies a send right for the existing IOKit connection and requests a send-once right for its separate reply port through the Mach header dispositions. The call to the Mach trap veneer is at `0x184e78090`. See the [structure argument report](iokit_structure_arguments_report.md).

The selector 26 method record at `0xfffffe000846b710` contains flags `3` at offset `0x18` and 64-bit counts of `16` at offsets `0x20` and `0x28`. In the kernel adapter, `0xfffffe000c565170` reads the input count from the record. The comparison at `0xfffffe000c565180` uses the actual 32-bit input count zero-extended in X19. The branch at `0xfffffe000c565184` takes the input mismatch path for both direct extents. That arm loads `0xe00002c2` and returns it through `0xfffffe000c5652c0` under ordinary diagnostic return. The original collection names the logger at `0xfffffe000c4babac` as `_IOLog`. The call at `0xfffffe000c565238` supplies the diagnostic string at `0xfffffe00070e0596`, which identifies an input-count mismatch, and the embedded routine label `shim_io_connect_method_structureI_structureO` at `0xfffffe00070e05dd`. The adapter address has no exact nlist entry. The output-capacity comparison at `0xfffffe000c5651a4` and the nominal member are downstream of the taken branch. With the descriptor form, the two 16-byte counts pass both comparisons. The handler at `0xfffffe000a504034` forwards the nested address in X1, the zero-extended 32-bit extent in X2 and the stored task identity to the nominal provider. That provider uses these values at the descriptor factory call `0xfffffe000a5051d4`. The count checks leave provider acceptance unknown. [Structure and task provenance](iokit_structure_arguments_report.md)

## Reply and daemon continuation

The kernel's ordinary nonzero-status reply for request 2865 is short reply 2965. Its status occupies offset 40 in the 44-byte kernel message and offset 32 in the 36-byte userspace message. This reply carries no output structure. The kernel copies the reply object from the request at `0xfffffe000bcf4778` and hands the reply to the common send path. That path reaches the queue helper call at `0xfffffe000bcc724c` under its destination and option gates. The kext member does not run on the mismatch path. [Kernel reply send](kernel_reply_send_report.md) The framework preserves the submitted output capacity in the public size cell on this path. The [short-reply reconstruction](iokit_sync_error_reply_report.md) establishes the reply format and status propagation. The [daemon return report](daemon_selector26_return_report.md) establishes the status encoding and dispatch model. The direct helper writes `0xe00002c2 XOR 0x8b3dc651 = 0x6b3dc493` at record offset 24 from `0x10020e6b0`. Both daemon replays take table slot `0x101047988` to `0x10065f430`. After the modeled framework return and before the caller gate, the direct helper neither reloads the public size nor accesses the aggregate bytes.

The supplied RAX trace records `0xe00002c2` at the earlier service-open reply 2962. The open request and reply are on lines 1726 and 1736. The reply carries a null connection, and none of the trace's 22 sends has request ID 2865. The selector 26 mismatch above is a reconstruction from the pinned method and the modeled daemon request sizes. See the [trace report](zut_trace_report.md).

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | A live connection selects this method record. The count outcomes and reply prediction depend on that identity. | Correlate the successful open with the concrete user client and recover the method record from the same loaded kernel build. |
| A2 | The positive PID-path fixtures reach their documented IOKit call sites with the recorded arguments. The outer and nested counts depend on these fixtures. | Compare the recorded registers and stack arguments with the call site in a successful execution. |
| A3 | Normal diagnostic return and ordinary short-reply delivery occur. Userspace status and size predictions depend on these conditions. | Check the returned kernel status, request and reply IDs, and public size cell for one correlated call. |
| A4 | The pinned kernel and retained framework apply to the modeled request. Wire lengths and status propagation depend on these selected components. | Compare both image UUIDs and the actual call and request path in the same run. |

## Verification

The [audit](triage_evidence/audit_daemon_selector26_legacy_admission.py) checks both original chained pointers, five input-count cases, four output-capacity cases, three framework request lengths and two satisfiable short-reply premises with unsatisfiable violation queries. Two daemon replays check original instructions and independently resolve three original dispatch fixup words. The retained trace check independently ties the status to the open reply. The audit compares the kernel slices with the pinned collection and reads framework instructions from the retained capture. The pinned kernel UUID is `9b65bd6e-027b-34d1-a22b-ac03dccffc84`, and the retained framework cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. The audit performs no native IPC. The fixed legacy count comparison and short-reply fields take O(1) local time and storage, excluding diagnostics and transport. Source lifting and replay scale with the number of inspected instructions and recorded memory accesses, excluding solver time.

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_legacy_admission.py
```

## Scope and impact

- High. The positive direct-buffer success models cannot be attributed to this fixed-size legacy member under A1 and A2.
- Medium. The 16-byte descriptor is compatible with both count checks. Whether it reaches the expected provider and succeeds there is unknown.
- Low. An older direct-call profile also uses 16 outer bytes. The interpretation and provenance of those bytes as a descriptor remain unknown.

## Quality gates

- QG1–QG3. The count, status, reply and continuation claims specify their premises and falsification probes.
- QG4–QG5. Byte counts, status widths and kernel/user header layouts agree with the inspected instructions. Boundary cases cover 15 B, 16 B, 17 B and a capacity with only its low 32 bits equal to 16.
- QG6–QG7. The pinned source checks and replay commands establish the scoped result. Native connection ownership, provider behavior and the origin of successful reply bytes remain open.
