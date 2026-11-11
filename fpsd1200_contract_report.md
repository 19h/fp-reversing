# FPSD1200 application record, reply contract and cleanup

The reference CoreFP request1200 and fairplayd handler agree on the64-byte request and212-byte success reply. The daemon wrapper stages a104-byte protected-call payload from14 application arguments, invokes shared dispatcher`0x10065ffd8`, and copies seven returned fields into the MIG reply. The original CoreFP parser consumes the128-byte inline block, OOL address/count, three additional scalar words and a returned send-right name. This closes the local serializer/wrapper/parser contract; the protected operation, certificate policy, output allocation and actual kext interaction remain unknown. [FC1-FC8]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FC1 | The pinned daemon slice and retained CoreFP bytes define this increment's reference versions. All addresses and cross-image mappings depend on this identity. | Rehash original daemon bytes, compare seven live IDA ranges, and compare four CoreFP IDA ranges against retained reference bytes. The installed CoreFP has a different hash; do not transfer these offsets to it. |
| FC2 | Original format12 words, slot membership and256-entry banks select the stated targets. Routine-role recovery depends on these constants. | Enumerate all256 inputs for each of six bank uses and independently decode15 original fixup words/imports. Native rebasing and authenticated pointer validity remain separate. |
| FC3 | Private executable/data/stack pages and explicit import fixtures supply the modeled environment. Finite control-flow and cleanup observations depend on this environment. | Stop at unreviewed PCs, unknown imports and system instructions; retain visits and PAC bypasses. Native PAC, stack mappings, scheduling and library resolution are untested. |
| FC4 | The protected dispatcher returns the declared status, zero stack delta and complete controlled output tuple. Successful replies and client output transfer depend on this fixture. | Replace the fixture with a source-backed dispatcher path and determine its delta/output definedness. Current results do not establish native acceptance or ordinary successful return. |
| FC5 | Received header names/bits and the OOL address are explicit private receive-conversion inputs. The client fixture additionally converts outgoing port disposition19 to received17. Paired parser acceptance depends on these transformations. | Preserve IDs and all other body bytes, vary the disposition conversion, and compare original client predicates. Native object identity, right movement, memory transfer and completion are unknown. |
| FC6 | The received audit-trailer storage is readable through byte115. Audit propagation depends on that extent, beyond the stub's local trailer-size check. | A size32 fixture with supplied backing bytes passes the local guard; recover the receive callback's allocation/options and native trailer production before inferring actual available extent. No out-of-bounds or exploitability claim follows. |
| FC7 | Mach descriptor constants are interpreted according to the retained ABI context; descriptor fields are not application object identities. Port-role nomenclature depends on this distinction. | Track the producer of the returned name and native received descriptor. A numerical task-local name or an output-cell store cannot establish a kext connection or remote receiver. |
| FC8 | Fresh original-instruction replay and a separately written scalar oracle validate the retained finite cases only. Generalized protocol claims are limited to directly inspected predicates/stores. | Compare full104-byte payloads,14 argument positions, modular state updates, reply bytes, output padding and independent parser decisions; perturb request/reply/status fixtures. Arbitrary pointer aliases, payload semantics and native ownership remain unknown. |

## Evidence and identity [FC1-FC3]

| Primary object | Identity / comparison |
| --- | --- |
| Original fairplayd arm64e slice | SHA-256`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base`0x100000000` |
| Live daemon IDA input metadata | Basename`fairplayd`; input SHA-256`4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; seven selected byte ranges equal the original slice. The input hash differs from the thin slice hash; selected-byte equality is the evidence used here. |
| Reference CoreFP | Universal SHA-256`68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; selected slice SHA-256`8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; preferred base0 |
| Live CoreFP IDA | Input metadata matches the reference universal hash; complete608-byte builder/parser and three16-byte cleanup stubs equal the retained reference bytes. No IDB mutation. |
| Installed CoreFP observation | SHA-256`94e00fac067f28543a969b14f1d463e623e624b32cae1a9367e14131e64f99cb`, different from the reference. The existing full-image reference reader rejects this installed file. No new full-image CoreFP emulation is claimed. |

The initial references already cover message construction and MIG dispatch. Live IDA was used for the remaining version/byte correspondence, with federated historical memories treated as leads only. The matching selected bytes, not the memory labels, corroborate the recovered interface. Evidence: [read-only IDA capture](triage_evidence/fpsd1200_ida_readback.json.zst), [source spans, selectors and35 private cases](triage_evidence/fpsd1200_contract_checks.json.zst), [generator](triage_evidence/recover_fpsd1200_contract.py), [independent oracle](triage_evidence/audit_fpsd1200_contract.py). Prior endpoint/certificate provenance remains in [CoreFP client paths](corefp_client_paths_report.md), [lookup/protocol comparison](corefp_lookup_report.md), [CoreFP exports](corefp_exports_report.md) and [receive routing](daemon_receive_interface_report.md).

```text
reference CoreFP builder 0x8ae0
  -> mach_msg call 0x8ba8: request1200, send64 B, receive capacity220 B
  -> [explicit private receive conversion; no actual IPC]
  -> daemon demux 0x100004b80 -> stub 0x100004530
  -> application wrapper 0x100007b28
       14 arguments -> payload104 B + address-encoded carrier
       -> shared dispatcher 0x10065ffd8 [stopped; controlled outputs]
       <- status decode + seven output-field copies
  -> mig_deallocate call 0x10000468c [modeled]
  -> request OOL address/count cleared; success reply212 B / error reply36 B
  -> [explicit private receive conversion; no actual IPC]
  -> original CoreFP parser 0x8bac..0x8d08
       success: eight caller output regions
       failure: message destruction or reply-port handling
```

The earlier client-path cases associate this64-byte builder with lookup`com.apple.fpsd` and a756-byte DER input. This increment uses the prior builder fixture's8-byte input to establish the ABI; it does not replay the complete certificate caller or establish its policy result. The separate56-byte request1200 builder`0x1590824` remains a different interface and is outside this pairing.

## Original daemon acceptance and application ABI [FC1,FC3,FC6]

Request offsets are from the received message header. The stub tests the complex bit, descriptor count1 and size64, returning-304 on failure. It then tests OOL descriptor type1 at+39 and equality of descriptor count+40 with repeated count+60, returning-300 on failure. Trailer type+64 must be0 and reported trailer size+68 greater than31; otherwise it returns-309. These are local predicates, not a complete validation or backing-storage proof. The stub copies32 audit bytes from request+84..115 after these guards. NDR bytes and the application words are not semantically validated in this stub. The existing [CF receive analysis](cf_receive_report.md) separately establishes3072-byte initial capacity and requested68-byte AV trailer in its installed-cache path; that context supports the normal receive extent, without turning the size32 local fixture into a native observation.

At`0x10000467c`, the direct call to application wrapper`0x100007b28` supplies the following AArch64 argument positions. Offsets in the payload are relative to P=wrapper post-prologue SP+`0x48`.

| Position | Original value / pointed cell | Payload offset and width |
| --- | --- | --- |
| X0 | Received local port name, request+12 |+0x00 u32 |
| X1 | Application word, request+52 |+0x04 u32 |
| X2 | Local32-byte audit copy |+0x08..+0x27 bytes copied by original helper |
| X3 | Pointer to request word+56 |+0x28 u32 loaded from pointer |
| X4 | Request OOL address+28 |+0x30 u64 |
| W5 | Request OOL count+40 |+0x38 u32 |
| X6 | Pointer to reply+68,128-byte inline output |+0x40 u64 pointer |
| X7 | Pointer to reply+28, OOL output-address cell |+0x48 u64 initial cell value; copied back |
| Stack+0 / argument8 | Pointer to reply+196, OOL-count output scratch |+0x50 u32 initial value; copied back |
| Stack+8 / argument9 | Pointer to local deallocate-output scratch |+0x54 u32 initial value; copied back |
| Stack+16 / argument10 | Pointer to reply+200, scalar output |+0x58 u32 initial value; copied back |
| Stack+24 / argument11 | Pointer to reply+204, scalar output |+0x5c u32 initial value; copied back |
| Stack+32 / argument12 | Pointer to reply+208, scalar output |+0x60 u32 initial value; copied back |
| Stack+40 / argument13 | Pointer to reply+44, port-name output cell |+0x64 u32 initial value; copied back |

Payload bytes+0x2c..+0x2f and+0x3c..+0x3f are gaps in this wrapper's stores. The104-byte extent ends at+0x67. The stub zeros reply+196 before the call, but several other output cells and gaps are read without initialization by this local wrapper/stub prefix. The private experiment intentionally poisons them; this establishes seed propagation, not a native uninitialized-output disclosure. Definedness depends on actual dispatcher stores and receive-buffer initialization. The inline128-byte region is accessed through its pointer, separately from the104-byte payload.

## Obfuscated selectors, carrier and returned fields [FC2-FC4,FC8]

All six selectors are constant over their256 possible byte inputs. Each row retains its two original banks, arithmetic, original slot word and independently decoded format12 provenance.

| Selected role | Bank output | Original selected slot | Decoded effective target |
| --- | --- | --- | --- |
| First mutable state cell |0x48 |`0x1010a56e0` |`0x1010b8078` after bias |
| Second mutable state cell |0x19 |`0x1010a1e00` |`0x1010c4670` after bias |
| Shared target table |0xff |`0x1010a6230` |`0x101039ef0` after bias |
| Source-to-destination copy helper |0x14 |`0x10109fc88` |`0x10046f89c`; IA diversity`0x34a1`, address diversity0 |
| Nested-record seed cell |0x58 |`0x1010a85b8` |`0x1010c4d68` after bias; initial word`0xcbfeb095c4fbe881` |
| Shared protected dispatcher |0xbb |`0x1010a0638` |`0x10065ffd8`; IA diversity`0xea64`, address diversity0 |

The copy call at`0x100007d8c` supplies X0=source audit pointer, X1=P+8 and count32. Original helper instructions, including byte/word stores, execute privately and copy those32 bytes in all six accepted cases. This is a local copy-helper role; arbitrary overlap and other helper callers are untested. The protected call at`0x100007f18` supplies X0=C=FP-`0x80`, X1=FP-`0x90`, modifier`0xea64`. The experiment stops at its selected target before any dispatcher instruction executes.

Let N=C-32 and k=`((low32(C) XOR 0xeaae0ac9)*0x7398180b) mod2^32`. The carrier's wrapper-defined fields are:

| Location | Width | Original expression / role |
| --- | --- | --- |
| C+0 |64 bits |`N XOR 0x1c0b9f7ce10f2255` |
| C+8 |32 bits |`k XOR 0x6cf4` |
| C+12 |32 bits |`k XOR 0xad952088` |
| C+16 |64 bits | P payload pointer |
| C+24 |32 bits | Returned status cell; not initialized by the wrapper before dispatch |
| N+0 |32 bits |`low32(N)+0xea06b394 mod2^32` |
| N+8 |64 bits | N self pointer |
| N+16 |64 bits | Initial seed loaded from`0x1010c4d68`; this is also X1's returned stack-delta cell |

The constants`0x6cf4` and`0xad952088` are encoded labels in this carrier; their actual backend decoding and operation semantics remain unknown here. The wrapper reads the returned delta at`0x100007f20` and adds it to SP before copying the seven payload output fields. Zero delta is an explicit fixture, not an established native invariant. It then returns `stored_status XOR 0x8b3dc651`. Neither the nested seed nor returned stack delta is promoted to an ordinary function pointer or high-level type.

The wrapper also mutates two64-bit state cells. With r=`oldG1+oldG2+(C-8) mod2^64`, the observed original stores are:

```text
G1 = r*0x0a5cd4cf + 0x8c2fb9df71512e5a          mod2^64
G2 = (r XOR 0x73d046208eaed1a6)*0x0a5cd4cf     mod2^64
```

Zero, nonzero and all-one initial states agree with the independent scalar oracle. State purpose, synchronization and concurrent interference remain unknown.

## Reply bytes, incoming/outgoing ports and ownership boundary [FC3-FC7]

| Source emission / copy site | Established field or call |
| --- | --- |
| Daemon demux`0x100004b8c..0x100004ba0` | Response destination+8 comes from received request remote name+8; response local name+12=0; reply ID=request ID+100=1300. This prepares a buffer; it is not the actual send syscall. |
| Stub`0x10000467c` | Application's incoming port argument is the received local name+12. This is a task-local fixture name, not a globally meaningful endpoint identifier. |
| Wrapper`0x100007f34..0x100007f60` | Copies OOL address/count/deallocate, three scalar outputs and port-name output from payload to their pointed cells. Port-name store reaches reply+44; actual name/right producer remains inside the unexecuted core. |
| Stub`0x100004628..0x10000462c` | Initializes the port descriptor tail from original literal`00 00 00 00 00 00 13 00`: outgoing disposition19, descriptor type0. |
| Stub`0x1000046c8..0x1000046d4` | Copies deallocate low byte to reply+36 and OOL count scratch+196 to descriptor count+40. |
| Stub`0x1000046f0..0x100004704` | Marks reply complex, sets size212 and descriptor count2. |
| Stub`0x10000468c` | Calls authenticated import`mig_deallocate(input_OOL_address,input_count)` after every application return, including nonzero status. The result is ignored locally. No native deallocation executes in this increment. |
| Stub`0x100004690..0x100004694` | Zeros request OOL address+28 and count+40 after the deallocation call. Structural rejection exits before this call/clearing. Outer failure cleanup remains a separate responsibility. |

| Successful reply offset | Width / content | Original client consumer |
| --- | --- | --- |
|+28 | OOL address u64 | Caller X6 output cell |
|+36..+39 | Deallocate/copy/pad/type bytes | Parser checks type byte+39=1 |
|+40 | OOL count u32 | Caller X7 output cell; must equal repeated count+196 |
|+44 | Port name u32 | Fourth stack output pointer, argument11 |
|+48..+55 | Port descriptor tail | Parser checks received disposition17/type0 at+54..55 |
|+56..+63 | NDR bytes | Retained; no explicit conversion in this parser |
|+64 | Echo of request word+56 | Writes through caller X2 |
|+68..+195 |128-byte inline output | Writes through caller X5 |
|+196 | Repeated OOL count u32 | Equality guard against+40 |
|+200/+204/+208 | Three scalar u32 outputs | First/second/third stack output pointers, arguments8/9/10 |

The client parser tests size212, descriptor count2, received remote name0, OOL type1, port disposition/type17/0 and equal OOL counts before publishing any of its eight output regions. The adapter's19-to17 disposition conversion is explicit. Retaining outgoing19 causes-300 and message destruction. No right transfer, descriptor copyout, port allocation, OOL ownership transfer, received-pointer validity or output-buffer allocation is observed natively. Successful parsing itself performs no cleanup import and only copies the address/name to caller outputs; actual caller retirement remains unknown.

## Client failure partition [FC3,FC5,FC8]

The inspected parser continuation is`0x8bac..0x8d08`; it stops at the original epilogue before stack-canary/return execution. Import stubs are identified from retained original format12/import evidence and matching current IDA bytes, then intercepted as explicit cleanup fixtures.

| Trigger | Original status / cleanup branch |
| --- | --- |
| Nonzero transport status in`{0x10000002,0x10000003,0x10000010}` | Preserve transport status;`mig_put_reply_port` at callsite`0x8bdc` |
| Other nonzero transport status | Preserve transport status;`mig_dealloc_reply_port` at`0x8c2c` |
| Reply ID71 |-308;`mach_msg_destroy` at`0x8d04` |
| Reply ID other than1300/71 |-301;`mach_msg_destroy` |
| Malformed complex reply predicate above |-300;`mach_msg_destroy` |
| Simple reply size36, remote name0, nonzero status+32 | Return that status;`mach_msg_destroy` |
| Other simple reply, including zero status |-300;`mach_msg_destroy` |
| Matching successful complex reply |0; publish eight output regions; no cleanup import in the inspected parser |

The finite transport controls exercise all three selected statuses and one outside status. The bitmask expression in original instructions defines this partition for W0; no native reply-port caching or actual destruction behavior is inferred. All failed private parser cases preserve poisoned caller output regions. The controlled application statuses`0x1234` and`0xffffffff` propagate through the daemon's36-byte reply and the client error branch.

## Verification, quality gates and bounded continuation

Reproduce from the repository with an analysis Python providing Capstone and Unicorn:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence "$PYTHON" -P triage_evidence/recover_fpsd1200_contract.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence "$PYTHON" -P triage_evidence/audit_fpsd1200_contract.py
PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/verify_fpsd1200_contract_publication.py
```

The generator replays the retained IDA attestation; a fresh live attestation is a separate read-only operation. It rehashes the original daemon and verifies the recorded CoreFP bytes against retained reference artifacts. It does not reopen the changed installed CoreFP as the reference. JSON outputs use compressed canonical storage after round-trip verification.

The independent oracle passes13 server cases and22 client cases, including seven request guards, six full104-byte payload comparisons and four successful controlled replies. It replays3025 original daemon instructions and522 original parser instructions across these finite cases; these are visit counts, not unique instructions or native timing. Six bank uses exhaust1536 byte inputs,15 original fixup words/imports are independently decoded, and11 selected IDA ranges match their source references. The new exact publication audit verifies the manifest delta, original inputs, owned paths and metadata hygiene. No solver, compiler, native daemon, Mach transport, protected dispatcher body or kext code is newly executed. Static recovery costs O(B+F+R+256N); finite replay costs O(C(B+F+K)), space O(B+F+C*K+R), for image bytes B, fixups F, retained bytes R, bank uses N, cases C and bounded instruction visits K. Arithmetic uses explicit32-/64-bit modular widths; byte counts are exact, with no statistical or performance inference.

| Gate | Scoped result |
| --- | --- |
| **QG1** | Pass: factual interface analysis; no normative conclusion required. |
| **QG2** | Pass: FC1-FC8 identify dependencies and falsification probes. |
| **QG3** | Pass for this increment: request,14-argument payload, dispatcher boundary, reply/port fields and client cleanup are covered. The full multi-level investigation remains active. |
| **QG4** | Pass: exact byte extents, offsets, visit counts and modular arithmetic reproduce in the independent oracle. |
| **QG5** | Pass within stated scope: changed installed-image identity, seed definedness, trailer backing extent, disposition conversion and controlled core outputs remain explicit boundaries. |
| **QG6** | Pass: original daemon bytes/fixups and retained CoreFP bytes agree with selected read-only IDA ranges; publication rechecks dependencies and preserved original inputs. |
| **QG7** | Pass: impact-ranked continuation below preserves unresolved architectural questions. |

| Impact | Further discriminating evidence |
| --- | --- |
| High | Recover dispatcher`0x10065ffd8`'s actual carrier decoding, stack delta, status and complete output writers for this payload. Follow request words+52/+56 and input OOL into provider/IOKit/Mach calls. This is the next direct daemon-to-kext frontier. |
| High | Establish the returned OOL allocation and port-name/right producers, all failure paths and caller retirement. Neither a written name nor descriptor19 identifies FairPlayIOKit. |
| High | Match a native version/credential/service instance to the reference request and response, including audit trailer, endpoint identity and actual output result. The installed CoreFP differs; its ABI requires a separate identity-based comparison. |
| Medium | Recover nonzero stack-delta behavior and all payload-definedness/aliasing conditions before treating the controlled104-byte snapshot as a complete backend schema. |
| Medium | Tie request1200 input deallocation and reply-error destruction to the outer receive loop's cleanup and restart behavior, and verify exact kernel receive disposition/memory conversion for a matched environment. |
| Low | Compare the separate56-byte request1200 interface and other FPSD parsers without unifying endpoints by numerical request ID. |

This report is one completed increment. The full investigation remains active and incomplete.

## FPSD1200 original admission prefix

The [original admission-prefix recovery](fpsd1200_admission_report.md) extends this contract through adapter `0x10065ffd8`, core `0x10061a2d0`, decoded phase `0x6cf4` and operation `0xad952088`. Original marshalling reaches the `fairplay-client` numeric/text helper, with `com.apple.private.fpsd.client` Boolean fallback. Sixteen controlled failures now establish status `0xffff5bbb`, a 36-byte error reply and zero adapter delta through original instructions; the successful 212-byte replies in this contract remain protected-output fixtures. Eleven other cases stop before `audit_token_to_au32` at `0x100581f2c`. No native admission or successful kext operation is established.
