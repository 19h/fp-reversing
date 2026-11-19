# Current selector 26 inline reply backing

The synchronous method places the 16-byte selector 26 output in the reply backing itself. The MIG stub passes a pointer to that storage into the IOKit method. The kext handler writes the returned address and extent on success. The scalar scratch zeroing in the method wrapper affects a separate stack allocation. [Current kernel and IOKit transport](live_iokit_mach_transport_report.md) [Provider and handler writes](live_kext_selector26_transfer_report.md)

Let H be the start of the expanded kernel reply header and B the output body pointer supplied to the MIG stub in X4. The ordinary non-complex reply represents B at logical offset 32 B from H. At `0xfffffe000be81650`, X20 preserves B. At `0xfffffe000be81654`, X24 becomes B+12 B, the inline structure count pointer. Two words at `0xfffffe000be8168c` and `0xfffffe000be816b0` pass structure data B+16 B and count B+12 B to the kernel method. The method saves the structure pointer at SP+0x88 and the count at SP+0x90 at `0xfffffe000c5c0124`–`0xfffffe000c5c0134`. This joins the MIG output backing to the IOKit arguments record without an intermediate inline structure copy at that boundary.

| Output | Kernel offset from H | Packed user message offset |
| --- | --- | --- |
| Returned structure count | +44 B | +36 B |
| Returned address | +48..55 B | +40..47 B |
| Returned extent | +56..59 B | +48..51 B |
| Last four inline bytes | +60..63 B | +52..55 B |

The call to `_bzero` at `0xfffffe000c5c0120` uses the output-scalar pointer from the first stack argument and eight times its current count. The stub initializes that separate scalar stack staging at `0xfffffe000be81620`–`0xfffffe000be81630`. The inline result uses the separate reply body backing.

## Reply backing and byte ownership

The current MIG subsystem record for request 2865 carries the maximum reply size 4,284 B and zero output descriptors. The regular dispatcher reads both fields at `0xfffffe000bd3c2fc` and calls the message constructor at `0xfffffe000bd3c310` with `(4284, 0, 0, 0xb)`. The constructor's ordinary size path adds 68 B to the reply envelope and selects its split backing through the zero-descriptor case. It passes flags `0x8004` and length 4,320 B to the data-backing allocation at `0xfffffe000bd0a590` and separately requests the message object at `0xfffffe000bd0a620` with flags `0x8004`. The dispatcher obtains the body backing from the object's authenticated +0xf0 slot at `0xfffffe000bd3c388`–`0xfffffe000bd3c398` and passes it in X4 at `0xfffffe000bd3c71c`. The kernel offsets above describe the logical message. The body pointer and header pointer can refer to separate allocations.

The typed allocator sends this size to its zone-selection path at `0xfffffe000bd46564`–`0xfffffe000bd465cc`. On the ordinary cache-hit path, the zone allocator reads the element size from zone offset 0x34, pops the element into X20 and calls `0xfffffe000bce59c0` with the base and that size. Flag bit 14 is clear and the check executes on this path. The helper OR-reduces vectors from the first and last 64 B and the intervening blocks. It reduces the final vector to its maximum byte at `0xfffffe000bce5a44`. The allocator diverts a nonzero result at `0xfffffe000bdbdc14`. An ordinary successful checked cache return therefore supplies a zero-filled element. Where the returned inline span lies within that element, this accounts for its initial bytes. The current evidence leaves the allocator path and returned output of any particular transaction unknown.

On the successful zero-scalar path, the stub writes NDR at B+0 B, the count at B+32 B and the final 8 B field at B+36 B. The kext stores cover B+16..27 B. Taking the represented 16 B size, these selected writes leave B+28..31 B unchanged. The kernel declares a logical 76 B reply. The corresponding packed reply is 68 B. The IOKit framework reads the returned count, checks the reply length and copies 16 B starting at packed offset 40 B to a caller with room for 16 B. The copy call is at `0x184ebe200` and the count publication is at `0x184ebe204`. [Success envelope and kext stores](live_kext_selector26_transfer_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The ordinary request reaches MIG record 2865 and the allocated reply uses the indicated split layout | Body pointer and the size/flags derivation | Correlate the routine record, allocator arguments and authenticated body pointer |
| The element takes the checked cache return and the inline span stays within it | Initial values within B+16..31 B | Check the selected extent and returned pointer against the element base and size |
| The selector returns success with a 16 B structure and zero scalars | Logical offsets and selected copyout | Observe the post-handler count, return status and received Mach message |
| The receiver packs the expanded kernel header into its simple 24 B user layout | Eight-byte offset adjustment | Compare the pre-copyout body extent with the emitted packed message |

The backing check has medium impact on the provenance of the last four bytes. A matched ordinary live exchange has high impact on confirming the body selection, method result and final caller-visible span. The cache-miss/refill initialization path and native output remain open.

The [audit script](triage_evidence/audit_live_iokit_selector26_inline_reply.py) checks the image identities, record fields and selected instructions. The [compressed receipt](triage_evidence/live_iokit_selector26_inline_reply_audit.json.zst) retains the original words for each cited span.
