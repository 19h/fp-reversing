# Exact produced requests through CoreFoundation source dispatch and the daemon

Four exact kernel-produced extended-trailer requests now execute the original
CoreFoundation DoSource1, source-call bridge and CFMachPort perform bodies before
entering the original daemon callback. Both RPC502 cases continue through the
MIG stub, application records and original selected libbsm body to the pthread
identity boundary. Both RPC700 cases return through CF with handled=true and a
null generic reply. Source handling is therefore distinct from daemon recognition
or application acceptance. [CC1-CC8]

These private executions start at DoSource1. Actual receiver selection, voucher
processing, registration/cache history, native objects and native image pairing
remain unknown. The full interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| CC1 | Pinned daemon/kernel/cache sources form the selected implementation corpus | Addresses and cross-image composition | Rehash source and six cache files; verify original CF function bounds and actual loaded-image pairing separately |
| CC2 | Prior kernel primitive/context contracts produce the recorded USER/OOL bytes | Exact request and trailer inputs | Freshly replay all four selected kernel deliveries; compare complete observation bytes with their final RAM |
| CC3 | Post-receive bytes are supplied unchanged to DoSource1 with the shown source/runtime fixtures | Framework-to-daemon forwarding | Compare every original read/write and call frame; attest actual receive/voucher hooks, source selection and buffer provenance separately |
| CC4 | Declared private CF fields and initialized global flags describe this bounded path | Valid-source admission and selected callback/context | Verify source+8 guard, source+0x70/+0xa8 and port+0x10/+0x30/+0x40; recover native object construction, registration/cache history and concurrency separately |
| CC5 | CF lock, retain/release, boost/observer and stack helpers obey only the declared models | Source/perform progression and return | Check all50 original helper-entry contracts, arguments, volatile clobbers and source stores; execute matching implementations for native state/lifetime claims |
| CC6 | Logical PAC and selected CF/libbsm bindings describe private control transfers | Authenticated source/perform/callback and library edges | Decode original pointers, compare all42 CF authentication-input records, attest hardware PAC/loader state separately |
| CC7 | Existing daemon malloc/stack and normal string/token premises apply | RPC502 application record and PID-zero continuation | Freshly replay both preceding application components; compare whole records, source traces and rebased control records |
| CC8 | Pthread entry and DoSource1 return delimit the observations | Return values, ownership and emission scope | Complete original downstream APIs/run-loop handling and actual disposal before claiming application success, native release or reply emission |

## Primary provenance and executed scope

The [original daemon](</Users/___/Downloads/zut/fairplayd.arm64e>) SHA-256 remains
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
The selected cache UUID is2bd06591-e751-3e84-963f-b08dab6af23a; CoreFoundation
UUID is7fe5392e-ff16-31e1-8552-3a45c6b68224. Addresses are preferred unslid
virtual addresses. Runtime rebases, interposition and image pairing are separate
requirements. [CC1,CC6]

| Original CF boundary | Address | Complete captured instructions |
| --- | --- | ---: |
| DoSource1 | 0x184758bc8..0x184758ec0 | 190 |
| Source perform-call bridge | 0x184758ec0..0x184758f10 | 20 |
| CFMachPort perform | 0x184784050..0x1847841ec | 103 |

[Source](triage_evidence/cf_daemon_request_source.json) retains these313
instructions,13 original cache pages, nine lower helper boundaries, three
original cache-pointer chains and six complete cache-file hashes. It also
retains the prior53 daemon ranges /3808 instructions and35-instruction libbsm
body. Range counts do not imply complete-function counts for flattened daemon
code. [Profiles](triage_evidence/cf_daemon_request_profiles.json) retain every
source/read/write journal and CF/daemon/API frame.
[Independent checks](triage_evidence/cf_daemon_request_checks.json) recapture
sources, freshly replay producers and verify independent byte/ABI/record oracles.
No IDB access or modification was needed.

```text
original kext/kernel producer -> exact USER/OOL observation bytes
                                      |
                           explicit post-receive/task premise
                                      |
                    CF DoSource1 [private runtime/source fields]
                         -> original source-call bridge
                         -> original CFMachPort perform
                         -> original daemon callback
                              |
             +----------------+---------------------+
             |                                      |
          RPC502                                  RPC700
          MIG -> application -> libbsm            callback return
          stop before pthread_self                CF perform returns NULL
          CF call frames remain active            bridge stores NULL reply
                                                  DoSource1 returns true
```

## Exact framework and callback ABIs

All four inputs have80 inline bytes, a68-byte trailer and29 OOL string bytes.
The request IDs are502 or700; local service names are0x303 or0x403; the delivered
reply name is0x207. USER=0x6500001000 and OOL=0x6500004000. Complete8192-byte
USER and16384-byte OOL observations are imported unchanged. No kernel register,
thread, right object or address-space ownership is transferred into the CF CPU
model. See [kernel delivery](kernel_request_delivery_report.md). [CC2,CC3]

| Boundary | Registers / established values |
| --- | --- |
| DoSource1 entry | X0=run-loop fixture0x65000a0000; X1=mode fixture0x65000a4000; X2=source0x65000a8000; X3=USER; X4=80; X5=generic-reply output0x65000ac000 |
| Source bridge entry | X0=CF perform0x184784050; X1=USER; X2=80; X3=generic-reply output; X4=CFMachPort fixture0x6500090000 |
| CF perform entry | X0=USER; X1=80; X2=allocator fixture0x65000b0000; X3=CFMachPort fixture |
| Actual daemon callback | X0=CFMachPort fixture; X1=USER; X2=80; X3=context info0 |

The source's+0xa8 perform pointer is authenticated with the original
storage-address discriminator0xc0b6, stripped/compared, then passed through the
source bridge. Logical authentication is explicit in the private executor.
The CF object supplies the actual callback through+0x30 and context info through
+0x40. Context retain/release are null in this fixture. CF forwards the inline
size80, while the entire148-byte message/trailer remains available and unchanged
at every captured CF-to-daemon frame. It does not pass148 as callback size.
[CC3,CC4,CC6]

Only consumed CF fields are represented. The source validity-bit predicate and
port invalidation-word predicate take their normal admitted branches; that does
not establish complete native CF objects, a service-name registration or a
matching kernel port object. Registry caching can preserve an old callback or
context, as established in [CF registration/reception](cf_receive_report.md).
[CC4]

The original source routine clears source+0x58 with STLR at0x184758c88 in every
case. Source, mode and run-loop synchronization helpers are modeled. The boost
creator returns null with an initially null port boost field, selecting the
direct callback call at0x18478416c. Source retain/release are observed call
boundaries; native reference counts and disposal are not established. [CC5]

## Cache/runtime pointer boundaries

Original v5 chain membership and raw words are independently checked before
declaring the private runtime cells. The private targets below describe only
the explicit fixture; native targets are not rewritten. [CC5,CC6]

| Cache cell | Decoded original target | Private fixture target/value |
| --- | --- | --- |
| 0x1e01c88a8 | 0x1ed84eea0 | Private guard storage0x65000b2000 |
| 0x1e0261ea0 | 0x1e232cea8 | Private allocator token0x65000b0000 |
| 0x1e21210e0 | 0x180587cd4 | Explicit stack-preservation trampoline0x60000f0000 |
| 0x1ed891742, one byte | Scalar flag, not a pointer | Initialized-path flag2 |

The CF stack helper receives W9=0x1040 bytes. Its original target identity is
recovered; its implementation is not executed in this increment. The daemon's
separate stack-check import remains its earlier declared preservation contract.
The selected original libbsm body still executes on RPC502. [CC5-CC7]

## Control results, outputs and ownership

| Produced request | Cases | Original visits per case | Terminal observation |
| --- | ---: | ---: | --- |
| RPC502, extended trailer | 2 | 3103 | Original application/libbsm reaches pthread identity entry; CF frames remain active |
| RPC700, extended trailer | 2 | 416 | Actual daemon returns; CF stores null generic reply; DoSource1 returns1 |

Each RPC502 daemon/application instruction sequence remains identical to the
prior2967-visit component; the added CF prefix is136 visits. Original CF frames
consume96+4160+32+80=4368 bytes =0x1110 bytes before callback entry. Application
SP therefore shifts by0x1110, with16-byte alignment retained. The whole120-byte
argument record still matches the incoming values; the32-byte control record
is independently rebuilt using its new address. No application-entry reset or
record overlay occurs. See [application/libbsm composition](daemon_request_application_report.md).
[CC6,CC7]

For RPC700, the223-visit original callback returns a residual X0 value that CF
does not interpret as acceptance. CF perform writes X0=0 at0x1847841d0. The
source bridge stores that null through the generic-reply pointer at0x184758efc.
DoSource1 subsequently returns1 with entry SP and saved callee registers
restored. Its Boolean reports source handling; RPC700 still reaches no daemon
MIG family. This does not identify RPC700's actual receiver. [CC4,CC8]

The RPC502 generic-reply output retains itsA5 initial pattern because the held
CF call has not returned. It is not a valid reply value. Both RPC700 generic
reply outputs become zero. Their daemon reply-allocation observations remain
untouchedA5 because no allocation occurs. Incoming USER/OOL bytes and complete
daemon reply buffers match their independent oracles in all cases. [CC7,CC8]

No Mach receive/send, native voucher transition, application completion,
incoming OOL/right destruction or native CF deallocation executes. Full run-loop
reply/cleanup, kernel port identity and successful FairPlay output remain
unknown. The earlier daemon emission site0x100035184 remains downstream.

## Verification and bounded continuation

Independent replay checks7038 visits:658 CF,6342 daemon and38 libbsm. It checks
1434 reads /7408 bytes,836 writes /5830 bytes,178 saved CPU frames,30 CF/daemon
object/message frames and42 CF logical authentication-input records. Final
private-memory comparisons cover6291456 bytes; complete observed buffer/object
comparisons cover101536 bytes. Fifty CF primitive/stack contracts remain
explicit. Four fresh kernel delivery replays check10380 visits, and two fresh
prior application-component replays check5934 visits.

The consumed daemon fixup union has160 words: the earlier157 plus three original
out-of-range callback continuation slots exercised by RPC700, at0x10106fbe8,
0x101076268 and0x101086268. Every word/import and each added target is checked
against the original image. An initial aggregate-count expectation of157 was
corrected after deriving this exact union; the execution/byte oracles did not
fail.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_daemon_request.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_daemon_request.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_daemon_request.py
```

Extraction/replay costs O(B+H+V+J+F) time and O(B+R+J+F) space for source bytes B,
streamed cache-hash bytes H, visits V, journal bytes J, fixups F and private RAM R.
Observed byte totals count repeated private fixtures, not distinct native maps.

| Impact | Remaining requirement / opportunity | Completing evidence |
| --- | --- | --- |
| High | Actual receive/voucher/source handoff | Original service/voucher/run-loop selection composed with the exact produced buffers |
| High | Effective endpoint and callback | Native namespace/object identity plus original registration/cache history |
| High | Environmental processing and real outputs | Continue the held RPC502 state through original thread/QoS/environment and output producers |
| Medium | CF helper implementations | Matching lock/reference/boost/stack/observer bodies and initialized runtime epochs |
| Medium | Complete run-loop reply/cleanup | Original callers after DoSource1 and concrete buffer/OOL/right lifetime |
| Medium | RPC700 endpoint | Actual slot34 publication and a matching server remain unknown |

[Preservation](triage_evidence/cf_daemon_request_delivery.json) and
[quality gates](triage_evidence/cf_daemon_request_quality_gates.json) retain the
baseline and reporting/index changes.

QG1: factual interface analysis. QG2: CC1-CC8 with dependent results and probes.
QG3: produced-buffer/CF-source/actual-daemon composition covered; full goal active.
QG4: bytes,32/64-bit fields,16-byte alignment, counts and complexity explicit.
QG5: source handling, recognition, held output cells, generic null replies and
native identity remain distinct. QG6: original daemon/cache bytes, three pointer
chains, six cache hashes,160 fixup/import words, independent fresh execution and
whole-object/packet/control-record oracles. QG7: bounded continuation table above.
