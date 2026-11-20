# mobileactivationd certificate issuance and reply

The installed arm64e `mobileactivationd` builds an XML property-list request for the DeviceIdentity certificate method and starts an `NSURLSession` task. Its response worker turns a successful HTTP response into the certificate-array and date fields consumed by DeviceIdentity. The non-VM request builder also contains a public-key query to the AppleKeyStore user client. The confirmed upstream caller of DeviceIdentity in this analysis is `fairplaydeviceidentityd`. Direct use of this activation method by `fairplayd` and a link from this method to FairPlayIOKit remain unknown. [Upstream DeviceIdentity RPC](live_deviceidentity_activation_report.md)

## Server dispatch and network transport

All addresses below are unslid in the pinned server slice.

| Site | Control and data transfer |
| --- | --- |
| `0x100021228`–`0x100021240` | The public XPC method calls the internal method at `0x10001c024` with X2 set to the caller process name, X3 the request's retained reference-key data argument, W4=0, X5 the options, and X6 the reply block. W4 records the initial argument. The options parser separately reads a `CertType` value. |
| `0x10001c0f4`, `0x10001c778`, `0x10001c890` | The server asserts its XPC queue, conditionally tests network reachability, and dispatches the creation worker at `0x10001cad4` on its creation queue. The pre-dispatch error path invokes the reply with a null result at `0x10001ca04`. |
| `0x10001cb5c`–`0x10001cc98` | The worker calls `create_baa_info_macos`; it requires data under `RKCertification`, decodes `RKProperties` as a property list and checks its dictionary type. It obtains a string `UniqueDeviceID`. X0 at `createXMLRequest` is the BAA-info dictionary. |
| `0x1000466cc`–`0x1000467b8` | The XML helper serializes that dictionary with property-list format 100, sets POST, adds content-type and content-length headers, and supplies the serialized data as the body. |
| `0x10001cd20`–`0x10001ce64` | The worker writes User-Agent and the device-ID header, then selects the standard or VM BAA URL stored in the image. It applies a provided timeout. An internal-build branch consults a persistent defaults domain for a string URL override. |
| `0x10001d280`, `0x10001d414` | The worker enqueues the transport block at `0x10001d2c0` on a global queue. That block passes the request and response-header, status and error out slots to `talkToServerWithError`, with W1=0, W2=0 and X3=null. |
| `0x100042604`, `0x1000426e0`, `0x10004271c` | The helper creates the session and task, then calls `resume` on the task. This is the application-level network start. It waits on a semaphore at `0x10004272c`. The captured task completion at `0x100042b7c` reads the HTTP status and header fields at `0x100042bd0` and `0x100042be4`. |

Two file-backed CFString fixup chains bind the URL selection at `0x10001cd58` to the standard BAA and VM BAA endpoints on `humb.apple.com`. The receipt records the strings as embedded in this slice. Actual endpoint selection, connections and HTTP responses for a live invocation are unknown.

## Conditional AppleKeyStore public-key query

The creation worker's `create_baa_info_macos` helper has a path through Security reference-key operations and local system-key attestation. At `0x100007d00` it calls `create_baa_info`. On that builder's non-VM route, the branch at `0x1000051b8` requires a nonzero stack-held value before the first `libaks_system_key_get_public` call at `0x1000051cc`. A zero result branches to the error path. A successful result and the false boolean branch at `0x100005200` reach a second call at `0x1000055f8`. The first two arguments at these sites are `(1, 1)` and `(2, 2)`, respectively. The incoming options and host state for any specific client invocation are unknown.

| Site | Interface |
| --- | --- |
| `0x100029230`, `0x10005beac` | The local public-key wrapper calls `aks_system_key_get_public` with two null optional arguments. Its request builder encodes the public-key operation and numeric arguments, then calls the common AKS operation. |
| `0x10005b77c`, `0x100048488` | The operation obtains the cached AKS connection. The uncached branch opens by `IOService:/IOResources/AppleKeyStore` first, with a fallback to matching the class `AppleKeyStore`. |
| `0x100048524`, `0x100048568`, `0x1000485a4` | Both open sites use user-client type 0. The code tests the resulting connection with selector 0 and all counts and data pointers zero. It closes the connection on a failed probe. |
| `0x10005b7e4` | The common AKS operation uses `IOConnectCallMethod` selector 43 on that connection. This is the application-level IOKit emission site for the encoded public-key lookup. A missing connection branches away before the call. |

This identifies an AppleKeyStore connection and a conditional IOKit path within server-side request preparation. The pinned evidence extends through the userspace IOKit call. The numeric port, the kernel handler and the hardware operation for a particular invocation remain unknown.

## Response and XPC completion

| Site | Result transfer |
| --- | --- |
| `0x10001d4b8` | HTTP status 200 selects the certificate-response path. Other nonzero statuses enter server-error handling. Zero enters the network-error path. |
| `0x10001d910`, `0x10001d954`, `0x10001d980` | The worker parses the `Date` header, decodes the response body as PEM certificates and requires exactly two decoded elements. |
| `0x10001de10`–`0x10001e068` | The ordinary trust branch selects a root, builds the two `SecCertificate` objects and checks the chain. The discriminator at `0x10001def0` sends value 1 to accessory trust at `0x10001df14` and other values to BAA trust at `0x10001e054`. The binary also contains internal-build and device-state branches. |
| `0x10001e0e4`, `0x10001d768` | The worker constructs the two-key dictionary `RKCertification`, `ServerResponseDate` from the decoded array and date. The completion call uses the captured block in X0, the result dictionary in X1 and the byref error in X2. DeviceIdentity's remote reply block consumes both keys. |

## Assumption register

| ID | Dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Unslid offsets and fixups describe the installed UUID and digest recorded below. | Re-read the arm64e slice, compare its identity and digest, and regenerate the record windows. |
| A2 | The two authenticated dispatch invocations execute the recovered block entries under ordinary queue semantics. That premise links receiver, creation worker and transport worker. | Correlate ordinary dispatch and invoke events against the captured block entries. |
| A3 | The selected non-VM branch reaches the public-key query only when its earlier inputs and checks permit it. | Trace the normal branch decisions and correlate an admitted request with the public-key call and same-process IOKit connection. |
| A4 | The potential XPC return follows the block captured on the admitted path. | Correlate a normal server completion with the provider's reply block and validate its argument classes and key names. |

High impact for locating the network handoff and correlating the server response with DeviceIdentity's reply fields. Medium impact for identifying AppleKeyStore as an additional, conditional IOKit interface. The remaining cross-layer evidence needs a matching live invocation or a static join through Foundation, libxpc and the kernel. The earlier FairPlayIOKit method route is a separate connection. [FPDI FairPlayIOKit connection provenance](live_iokit_selector26_task_provenance_report.md)

## Reproduction

Primary evidence is the arm64e `mobileactivationd` slice UUID `828906ff-d325-3bc9-9f28-0b3a8fd7af5b`, SHA-256 `d6c33e737346613383570a14f5be5ff87e27cfabf87a955b2cfaaf210f7f658d`, from the same target build used in the DeviceIdentity RPC report. The audit checks the slice identity, named branch targets, selected instructions and file-backed string fixups. For an image of B bytes, total disassembly and fixup text of D bytes, and C named call checks, the verification uses O(B + D) memory and O(B + C times D) time outside the external disassembler. [Auditor](triage_evidence/audit_live_mobileactivation_certificate.py) [Compressed receipt](triage_evidence/live_mobileactivation_certificate_audit.json.zst)

    python3 -B triage_evidence/audit_live_mobileactivation_certificate.py MOBILEACTIVATIOND
