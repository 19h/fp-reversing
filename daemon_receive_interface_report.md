# fairplayd receive routing, reply emission, and ownership

Subsequent cross-image finding:the [CoreFP lookup/protocol report](corefp_lookup_report.md) recovers a client that resolves `com.apple.fpsd` but emits a simple24-byte request1203. This daemon's1203 stub requires a complex100-byte request and returns-304 for that form;metadata is1204 with a52-byte reply containing76/9/0/42. Private execution of the original demultiplexer and client parser reproduces the local mismatch. Effective native pairing and service-to-handler history remain unverified.

The shared callback at `0x100425f78` routes all five recovered MIG families. RPC502 has a complete local callback-to-demultiplexer-to-stub edge: callback -> continuation `0x10006d214` -> `0x100264b4c` -> demultiplexer `0x100005274` -> stub `0x1000050c8` -> implementation `0x100422d48`. This closes the previous callback-routing gap, conditional on normal arm64e control transfers and the original table contents. It does not prove delivery from a specific live Mach port.

The callback's native reply emission is `0x100035184`, through `_mach_msg`. Its input/reply destruction and heap-release paths are recovered below. RPC700 does not enter any family in this callback; the actual receiver of the kext's alternate RPC700 remains unknown.

## Scope, provenance, and assumption register

Analysis date: 2026-11-01. Original thin daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Its exact relationship to the original universal file, current native executable, and loaded IDB is documented in [interface_abi_report.md](interface_abi_report.md). All addresses here are preferred static virtual addresses.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| R1: original thin bytes correspond to the intended live IDB | Native address associations | Recheck image hash and original/live snapshots. Three fresh live ranges match; prior section-wide identity remains separately recorded. |
| R2: the original relocated tables and ordinary arm64e calling convention apply | Flattened edges, inherited registers, post-call states | Compare original chained words, dyld fixups, full predecessor register writes, callee preservation, runtime rebases and hardware PAC. No target execution or PAC check was performed. |
| R3: the callback receives a valid Mach message buffer | Header reads and generated MIG validations | Available installed-cache CF options/capacity/forwarding are now recovered in [cf_receive_report.md](cf_receive_report.md); attest actual runtime pairing, post-voucher-hook bytes and complete message-body ownership. The callback does not preserve/use the framework size argument for these checks. |
| R4: public XNU definitions supply conventional constant/API names | `MIG_BAD_ID`, `MIG_NO_REPLY`, send options/error names and timeout units | Compare exact installed source/build. Native raw values and offsets remain authoritative. |
| R5: opaque application implementations obey the shown stub output contract | Semantically formed replies and ownership after successful dispatch | Recover every implementation, allocation/output bound and ownership action. Callback recovery alone does not prove valid application outputs or successful native execution. |
| R6: wrappers are used for a specific published receive port | A service-name-to-effective-callback assignment | Five original local check-in/wrapper/source chains are now recovered in [daemon_registration_report.md](daemon_registration_report.md); attest actual namespaces, CF cache history and effective callback. Plist declarations alone remain insufficient. |

[Native ranges and proof results](triage_evidence/daemon_receive_contracts.json), [live wrapper/callback bytes](triage_evidence/daemon_receive_wrappers_native.json), [fresh callback pseudocode](triage_evidence/daemon_receive_callback_decompilation.json), and [original dyld fixup output](triage_evidence/daemon_receive_fixups.txt) retain provenance. IDA knowledge-store [recall results](triage_evidence/daemon_receive_ida_recall.json) were used as locators, then checked against original/live bytes. Accepted memory confidence and existing function names/comments are not independent proofs. Automatic model diagnostics were excluded from the saved decompilation result.

## Registration ABI and service identity

| Wrapper | Native call | Established registration |
| --- | --- | --- |
| `0x100001f50` | `0x100001f8c`, `_CFMachPortCreate` | Null allocator; authenticated pointer to callback `0x100425f78`; zeroed 40-byte context; address of Boolean temporary initialized false |
| `0x100001f9c` | `0x100001fdc`, `_CFMachPortCreateWithPort` | Incoming port name forwarded to the port argument; same callback and zeroed context; null allocator |

Both wrappers form the callback address and use `PACIZA`. Each returns the framework result without inspecting its `shouldFreeInfo` Boolean output. The zeroed context includes null info/retain/release/copy-description fields. This does not assign a service-specific object through callback context.

The conventional callback ABI is `(CFMachPortRef port, void *message, CFIndex size, void *info)`. The native callback saves X1 at SP+`0x10`, loads its message ID at+`0x14`, and does not use the other incoming callback parameters in the recovered family decisions. All family decisions below depend on the ID; the opaque global mutations do not alter those choices because their selector banks reduce to constants for all byte inputs. No recovered family choice checks the original CFMachPortRef or context info.

The existing IDB callback comment assigning it specifically to `com.apple.fpsd` is not sufficient: the native body demonstrably routes all five families. The later [registration recovery](daemon_registration_report.md) establishes five named local chains requesting this callback: unfreed, fairplayd, fpsd, arcade.fpsd and fpsd.sim, with main/default-mode source insertion and exact stored CF fields. Effective callback identity still depends on cache history, and application service-to-family policy remains unknown under R6. [Current launchd services](triage_evidence/native_fairplayd_services.json) remain separate publication evidence. Most application stubs receive the destination's local receive name from request+`0x0c`, so deeper implementations retain an input that can distinguish services even though this callback does not select the family by it.

The later [installed-cache CF recovery](cf_receive_report.md) verifies the callback ABI from original instructions,3072-byte initial capacity, requested68-byte AV trailer, inline-size forwarding and normal grown-buffer cleanup. All eleven fixed request sizes fit with that trailer. Successful incoming OOL/right disposal remains separate. It also establishes constructor caching: `CFMachPortCreateWithPort` can return an old object's callback/context rather than the newly passed ones, so R6 requires actual registration/cache history.

For separately versioned context, Apple's [CFMachPort implementation](https://github.com/apple-oss-distributions/CF/blob/CF-1153.18/CFMachPort.c#L532) passes the received buffer, size and context info to the callout. That historical source is not established as the installed version; its receive-helper signature differs from the available installed-cache implementation.

## Complete recovered ID routing

Ranges are inclusive. Maximum reply sizes are **bytes**, read from subsystem-header+`0x10` and passed to `_malloc`.

| Callback ID range | Header | Reply capacity | Demultiplexer | Non-null routine IDs / behavior |
| --- | --- | ---: | --- | --- |
| 1000..1002 | `0x101038128` | 200 | `0x100005004` | 1000,1001,1002; indirect stub call through the descriptor array |
| 1200..1204 | `0x101038040` | 212 | `0x100004b80` | 1200..1204; indirect stub call through the descriptor array |
| 500..502 | `0x1010381c0` | 384 | `0x100005274` | Only502; 500/501 have null stub pointers |
| 41471..41472 | `0x101038258` | 36 | `0x1000053c8` | Only41471; demultiplexer inlines its validation and directly calls `0x100006944` |
| 61471..61472 | `0x1010382a0` | 40 | `0x1000055ac` | Only61471; demultiplexer inlines its validation and directly calls `0x1000057c0` |
| Everything else | None | No allocation | None | Returns through `0x100073b34`; no callback reply send |

The last two callback ranges are wider than their single-ID table ranges. IDs41472 and61472 therefore allocate a reply buffer and reach a demultiplexer, which returns false with a `-303` error reply. IDs500/501 do the same through their null entries. The callback then frees that reply buffer without sending the `-303` message. There is no explicit request `mach_msg_destroy` on these local false-demux paths. Caller/framework ownership remains separate; this is not a resource-leak conclusion.

The first dispatcher branch is unsigned `(id-1000) < 3`. The default continuation implements the 1200..1204 test using a mixed 32/64-bit expression. A full-domain SMT check proves its exact range, including wrapped/negative message-ID bit patterns. Later tests reduce to unsigned `(id-500)<3`, `(id-41471)<2`, and `(id-61471)<2`.

The return value of each demultiplexer is a Boolean indicating recognition, not the application's status. A recognized request with malformed contents still returns true and encodes an error in the reply. The generated demultiplexers initialize reply size36, copy request remote disposition (`bits & 0x1f`) and remote port into the reply, clear reply local/voucher fields, and set reply ID to request ID+100. Consequently RPC502's ordinary reply ID is602 and its reply destination originates in request+8.

For the three array-driven families, the generated demultiplexer directly invokes the stored stub; it does not call the separate table lookup function first. The two single-ID demultiplexers inline the stub logic. The [earlier eleven-stub catalog](interface_abi_report.md) remains a contract catalog; it must not be read as eleven direct callback-to-stub calls.

## Native control and ownership recovery

```text
CF callback receives request
  |
  +-- ID outside five ranges ------------------------------> return
  |
  +-- malloc(max_reply) == NULL ---------------------------> return
  |
  +-- demux(request, reply) == false -----------------------> free(reply)
  |
  +-- simple reply:
  |     retcode == -305 -----------------------------------> free(reply)
  |     retcode != 0 -> request.remote = 0 -> destroy(request)
  |
  +-- reply.remote == 0:
  |     complex -> destroy(reply)
  |     then ---------------------------------------------> free(reply)
  |
  +-- mach_msg(reply, options, reply.size, 0, 0, 0, 0)
        result in {0x10000003,0x10000004} -> destroy(reply)
        then ---------------------------------------------> free(reply)
```

The compact model below describes the recovered local callback, with all application work abstracted behind `demux`. Buffer validity, reply correctness and callee preservation remain assumptions R2/R3/R5.

```c
family = classify_u32(request->msgh_id);
if (!family) return;
reply = malloc(family->max_reply_bytes);
if (!reply) return;
if (!family->demux(request, reply)) goto done;
if (!(reply->msgh_bits & 0x80000000u)) {
    int32_t rc = reply_error_code_at_0x20(reply);
    if (rc == -305) goto done;
    if (rc != 0) {
        request->msgh_remote_port = 0;
        mach_msg_destroy(request);
    }
}
if (reply->msgh_remote_port == 0) {
    if (reply->msgh_bits & 0x80000000u) mach_msg_destroy(reply);
    goto done;
}
options = ((reply->msgh_bits & 0x1fu) == 18) ? 0x11 : 1;
mr = mach_msg(reply, options, reply->msgh_size, 0, 0, 0, 0);
if (mr == 0x10000003 || mr == 0x10000004) mach_msg_destroy(reply);
done:
free(reply);
```

| Action | Native site | Exact resolved target / operands |
| --- | --- | --- |
| Reply allocation | `0x100203aec`, `0x10020a418`, `0x10006d2b4`, `0x1000eee48`, `0x1000a6f30` | `_malloc`; capacities200,212,384,36,40 respectively |
| Preserve reply right before destroying failed request | `0x10006ce34` | Zeroes u32 at saved request+8; does not clear local receive name+`0x0c` |
| Destroy failed request | `0x10006ce90` | `_mach_msg_destroy(request)` |
| Reply send / emission | `0x100035184` | `_mach_msg(reply,options,reply_size,0,0,0,0)`; source import slot `0x1010a1288`, IA diversity`0x67eb` |
| Destroy unsent complex reply or selected send failure | `0x10003cc98` | `_mach_msg_destroy(reply)`; source slot `0x1010a0e98`, IA diversity`0xc429` |
| Release heap reply buffer | `0x1000bcb58` | `_free(reply)`; source slot `0x10109ff30`, IA diversity`0x46a2` |

The raw option values correspond to `MACH_SEND_MSG` and, when low disposition is18, `MACH_SEND_MSG | MACH_SEND_TIMEOUT`. The timeout argument is0 milliseconds; otherwise the timeout option is absent. Error values `0x10000003`/`0x10000004` conventionally name `MACH_SEND_INVALID_DEST`/`MACH_SEND_TIMED_OUT`; the native arithmetic is proven to select exactly those two values over all 32-bit results. See pinned [Mach definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/message.h#L1007). `-303`/`-305` conventionally name `MIG_BAD_ID`/`MIG_NO_REPLY` in [MIG error definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/mig_errors.h#L78). [Source hashes](triage_evidence/daemon_receive_public_sources.json) are retained; installed-version identity is not assumed.

No general request destruction occurs in this callback after a successful complex reply or a simple zero-status reply. `MIG_NO_REPLY`, no-allocation, unrecognized-ID and false-demux paths also lack explicit request destruction here. Combined with the prior stub catalog, the ownership distinction is now sharper: five stubs explicitly deallocate/zero incoming OOL data, failed recognized requests can enter the callback's generic destruction, and successful RPC502/61471 requests require deeper application/framework ownership analysis.

The send options depend on the received reply-right disposition. This is an externally supplied header input with observable control-flow effect; it is not an authorization result. Audit-token copying and receiving-service-name inputs remain available to deeper application implementations. No policy bypass, installed-framework leak, native timeout, or reachable malformed-reply conclusion is inferred from the callback alone.

## Reproduction, validation, and bounded extensions

```sh
xcrun dyld_info -fixups fairplayd.arm64e (reference input) \
  > triage_evidence/daemon_receive_fixups.txt
$PYTHON triage_evidence/recover_daemon_receive.py
```

Current results: 35 original native ranges, three fresh live/original comparisons, 22 exhaustive 256-input selector-bank reductions, 34 original branch-slot checks, 65 independent original fixup-word/import checks, and six SMT queries returning `unsat`. The latter cover the opaque1200 range, both two-ID ranges, demultiplexer Boolean selection, simple-status sign selection, and the exact pair of send errors requiring reply destruction. Constant route states converge to the same common post-demultiplexer frame with W24=0. Manual native-to-formula lifting remains reviewable in the saved script and report; the checks do not substitute for native execution or PAC validation.

The callback prologue has a 128-byte stack frame and no receive loop of its own. Its continuations lie at widely separated addresses outside the nominal IDA function bounds. They are analyzed as inherited-register/frame fragments, not called as standalone functions. Routing/control overhead is O(1) time/space, excluding opaque demultiplexed work, framework reception, allocation and Mach operations. Evidence extraction uses O(B+F+D) time/space for image bytes B, fixup records F and captured instructions D, plus finite bank checks and solver-dependent proof cost.

| Impact | Additional finding / remaining boundary |
| --- | --- |
| High | A complete local path connects the shared callback to the compatible RPC502 implementation; port delivery and service-specific registration are still separate proof obligations. |
| High | RPC700 is excluded by every recovered callback range, so locating its receiver requires another endpoint/callback/image or evidence of a different effective table. |
| High | Callback cleanup depends on recognition, reply complexity, application status, reply destination and send result. A uniform ownership rule would be incorrect. |
| Medium | IDs41472/61472 and null500/501 allocate a reply but have no recognized stub; the generated error reply is dropped locally. |
| Medium | Reply-right disposition selects timeout-enabled0 ms versus a send without the timeout option. |
| Medium | A zeroed CF context and shared callback do not justify assigning one service name to one MIG family; deeper implementations can still inspect the receive name and audit input. |

Next source leads are per-service registration/cache histories, actual runtime CF/voucher/monitor behavior, RPC502's successful incoming OOL lifetime/authorization, and the kext destination-port object's acquisition/forwarding/release aliases. The installed-cache normal receive/capacity/inline cleanup contract is now recovered in [cf_receive_report.md](cf_receive_report.md). These remain active work within the original objective.

QG1 factual analysis with no normative content required. QG2 R1-R6 and probes explicit. QG3 this increment recovers all five callback routes, reply emission and local ownership; the full investigation remains active. QG4 widths, modulo arithmetic, timeout units, capacities and complexity specified. QG5 callback ranges versus recognized IDs, Boolean versus status, inline versus indirect demux and local versus framework cleanup are distinguished. QG6 original bytes, fixups, live readback, locator memories and pinned public source are separated. QG7 bounded findings and continuation boundaries listed above.

## Kernel-side delivery and audit context (2026-11-01)

The subsequent [native user-copyout investigation](kernel_user_copyout_report.md) recovers the matching kernel receive-results path, namespace/header roles, receiver-map OOL mapping and trailer packing. On the inspected null-task kernel RPC path the audit template has eight zero words; under the stated no-replacement/delivery assumptions these reach MIG502's copied audit argument. This does not establish how the application interprets them. Scalar receive can truncate trailer delivery while retaining its requested advertised extent, making installed CF receive options/capacity/allocation and callback/status handling concrete remaining requirements. The synthetic delivery witness is not evidence of a native out-of-allocation read or faulty CF behavior.

## RPC502 application predicate and private ABI (2026-11-01)

[daemon_rpc502_report.md](daemon_rpc502_report.md) now recovers the application edge beyond0x100422d48: a filename scan, 120-byte private argument prefix, protected tag0xbc84919b and a local audit-PID-zero predicate. Nonzero PID returns0xffff5bbf (-42049), which the generated stub serializes through its error form. The wrapper publishes OOL output words before returning status; useful output initialization on every failure is not established, and error-form serialization remains distinct. Full authorization, service registration, CF receive behavior and successful incoming OOL lifetime remain unknown.

## User-library packet and trap layer (2026-11-01)

[arcade_subscription_report.md](arcade_subscription_report.md) now follows61471's application0x1000057c0 to a process-path copy,80-byte record,nested tagged serialization and synchronous CoreFP XPC request. It initializes output1 and copies the path before checking the received local name against the anonymous CF object. Selected mismatched-service cases return5;count/opaque variations do not alter the pre-reply serialized request. Actual CoreFP response,event handling,final decision and successful OOL disposal remain open.

The subsequent [arcade handshake recovery](created_port_report.md) resolves the application route behind41471:service-name gate against the arcade CF field,new anonymous CF cell0x1010c4d10,make-send insertion and synchronous kernel51471 registration. The matching kernel supplies the registration kobject through a one-way41471 sent to host special slot31,then uses the registered endpoint for61471 subscription validation. A prepared41571 status buffer does not imply an emitted reply because this kernel trigger has no reply port. Local errors/replacement and nested-client response checks are established; effective policy,CF/kernel ownership and subscription application0x1000057c0 remain open.

[user_trap_interface_report.md](user_trap_interface_report.md) connects the recovered reply API to available original libsystem_kernel: mach_msg -> mach_msg_overwrite -> packed mach_msg2_internal -> SVC0x180547c1c/X16=-47. Port-name/header fields, descriptor count, runtime-selected vectors/class flags and library interruption retry masks are established separately from actual IPC delivery. The callback's options1/0x11 are SEND_MSG or SEND_MSG|SEND_TIMEOUT; selected destroy statuses are INVALID_DEST/TIMED_OUT in the checked SDK.

The supplied trace's PC0x180547c20 equals RET after this cache's SVC. Its27 printed trap observations include five identical-packet RESTART/resume pairs rather than five newly printed sends. Current RAX source explains the pattern conditionally on historical producer equivalence. Installed CF receive/trailer allocation, runtime callback data and actual port objects remain unknown.

## FPSD1200 application and reply contract increment

FPSD1200 now has a recovered14-argument application ABI and104-byte protected-call payload. Original selectors resolve copy helper0x10046f89c and shared dispatcher0x10065ffd8; input OOL deallocation/clearing and212-byte reply descriptors are traced to exact source sites. The protected core remains a declared output fixture. See [FPSD1200 contract](fpsd1200_contract_report.md) and [source/private evidence](triage_evidence/fpsd1200_contract_checks.json.zst).

## FPSD1200 original admission prefix

The [FPSD1200 admission-prefix report](fpsd1200_admission_report.md) follows the same original received carrier through protected dispatch into Security callsites. The original 32-byte audit token is copied into first and fallback `SecTaskCreateWithAuditToken` calls; modeled entitlement results select direct PID extraction, Boolean fallback or original error return. All 27 prefixes avoid reading the input OOL payload. Sixteen failures reach original input deallocation/clearing and 36-byte reply construction; eleven other cases stop before PID extraction. This establishes finite local ordering and explicit cleanup calls, without native credentials, endpoint access or transport completion.

## FPSD1200 PID and FPDI identity path

The [FPSD1200 identity-path report](fpsd1200_identity_report.md) preserves the received carrier through 25 original libbsm calls and 250 complete audit-token copies. A separate FPDI entitlement dictionary supplies selected client-identifier/capabilities inputs. The subsequent local record result and process-local buffer transformations precede once/lock and allocation boundaries. No input OOL byte is read in these prefixes and no complete reply is produced; audit bytes and API objects/results remain explicit private fixtures.

## FPSD1200 pool and application-word continuation

The [pool continuation](fpsd1200_arena_report.md) carries that original path through a 50-slot allocation and process-local publication. Request+52 controls the sampled later branch independently of OOL count8/756: words1/2 reach a scalar-atomic boundary and, with its explicit model, `arc4random`; word3 and reference `0x11223344` return zero through the original wrapper. Five complex reply returns retain seeds in the inline block and output cells. All 12 profiles read no input OOL bytes and reach no new IOKit call or Mach emission. Status zero is distinct from established output definedness, native admission or successful transaction (FA1-FA8).

## FPSD1200 environment and OOL-input continuation

The [context report](fpsd1200_context_report.md) joins admitted FPSD1200 processing to original seed/time material, readiness/arena/self-text prerequisites and all756 reference-certificate bytes. Five original simple error replies restore the selected slot marker and retire the incoming OOL through the recorded MIG call; the DER routes reach a process-local atomic gate and one explicit continuation reaches malloc(1219). No new send, right producer or IOKit call is established (FX1-FX8).

## FPSD1200 certificate and local inline result

The [certificate report](fpsd1200_certificate_report.md) joins the incoming CoreFP DER to actual Root/AAA signature arithmetic and source-built representative exponentiation under its leaf public modulus. Original stores at0x1002212a0 define reply[68,196),128 bytes matching the complete big-endian public-exponent result. The staged 104-byte payload, including output OOL/name cells, remains unchanged. The later vm_deallocate call at0x10049e114 is an unexecuted API boundary, not receive/send completion. One first-certificate NULL case returns original 36-byte status0xffff5bd4 and retires the input through record-only MIG cleanup. Native output ownership and completion remain unknown (FV1-FV8).

## FPSD1200 VM output and shared-callback creation edge

The [VM/output report](fpsd1200_vm_report.md) establishes original consumers of staged OOL address/count, deallocation at 0x10049e114, allocation at 0x10049e17c and a complete 719-byte copy of the embedded daemon leaf into a private VM owner. Original count store 0x100543d3c precedes certificate retirement and helper0x100001f50's CFMachPortCreate request at 0x100001f8c. This connects FPSD1200 to the previously recovered shared callback 0x100425f78 with source-defined zero 40-byte context. CF object/name extraction, output-address publication, registration and actual transport remain unresolved. Allocation failure returns original 36-byte status0xffff5bd4 (VM1-VM8).

## FPSD1200 endpoint return and original reply construction

The [CF endpoint report](fpsd1200_port_report.md) joins the shared receive callback to a per-slot CF object, main-loop source registration and one-shot audit-PID exit-watch request. Explicit opaque CF/mode/kevent results allow original code to publish all seven staged outputs and construct212 bytes with two descriptors/status0; no protected output tuple is injected. Port/source NULL controls return36-byte errors; kevent=-1 stops at __error. The separate callback send0x100035184 is outside this demultiplexer-entry replay, so native transmission, right conversion and client acceptance remain unknown (FP1-FP8).

## FPSD1200 failed process-watch cleanup

The [lifetime/queue report](fpsd1200_lifetime_report.md) follows kevent=-1 through the __error call without an errno read, CF invalidation/release requests, slot clearing/marker reset and original36-byte status -1 reply. NULL and unmapped accessor-result controls have identical original sequences and retained terminal state. Explicit descriptor7 composition still reaches212-byte success; the prior descriptor0 word was an original image value, not proof that retained startup executed kqueue initialization. Native callback send, right conversion and input/output-owner effects remain unknown (FL1-FL8).

## FPSD1200 session retirement through the process-event callback

The [process-event report](fpsd1200_process_report.md) connects the successful FPSD1200 pool to descriptor callback `0x10044f23c` through an explicit source-snapshot composition. The callback's `kevent` output ident is compared with encoded slot+140, then matching eligible slots receive exact reset stores and CF invalidation/release requests. Eight independently replayed cases cover44440 original callback visits; the preceding session prefix is pinned rather than freshly repeated. Native callback delivery, CF effects and transport remain unknown (FP1-FP8).

## FPSD1201 session selection and failure-state continuation

The [session report](fpsd1201_session_report.md) recovers the simple164-byte request,16-byte protected payload, marker4b/name selection, original failure reset to marker49 and reply construction. Ten complete request profiles and a separately composed process-event callback are independently replayed. Nonzero tail stores are source leads; native right ownership, reclamation and successful request1201 processing remain unknown.

## FPSD1202 control endpoint and OOL continuation

The [request1202 report](fpsd1202_ool_report.md) joins the registered fpsd CF field to the control-name comparator, recovers the marker4d session selector and establishes the OOL input/deallocation/reply ABI. Fifteen independently replayed profiles distinguish original failures, declared application-return controls and explicit stop boundaries. Source-produced marker4d ownership, successful processing and native transport/reclamation remain unknown.

## FPSD1202 selected-session continuation

The [selected-session report](fpsd1202_session_report.md) extends the marker4d stop through the session CF-name comparison and complete13-case original return interval. Words A=1/2 reach shared digest/block-transform code and original status8 with diagnostic session bytes; tested other words return0 with zero OOL count and retained output seeds. The reply layout/status distinction, input deallocation call and absence of native send/IOKit effects are retained explicitly.

The [tail cleanup report](fpsd_tail_retirement_report.md) extends process-event handling through declared nonzero pointers without consuming opaque object bytes. The +888 path stops after object+24 is zeroed; the +880 path reaches its first pending read after session CF cleanup requests. These are callback intervals, with no new receive/reply message or native transport claim.

The [CoreFP1201 round trip](fpsd1201_client_report.md) matches the reference client scalar/inline128 serializer to the daemon164-byte request and returns the original daemon statusffff5b37 through the client36-byte parser. Header/name conversion is declared separately in each direction; native delivery and namespace identity remain unknown.

The [CoreFP1201 caller increment](fpsd1201_caller_report.md) identifies the parent call and scalar guard, while keeping the client returned-name handoff conditional on stack epochs and cell preservation. No additional daemon receive or native client/server identity is established.

The [CoreFP1201 protected-record continuation](fpsd1201_record_report.md) remains on the client side:16 complete original rejection paths write zero stack adjustments,while eight cases stop before the next unresolved call. No additional daemon receive,transport or native endpoint identity is established.

The [CoreFP1201 byte-import report](fpsd1201_import_report.md) identifies0x17bbb8 as a big-endian byte-to-encoded-limb importer,with selected unsigned length0..256 B and normalized limb counts. Eight nested prefixes import128 bytes from diagnostic context C,leave candidate P+0x880 untouched and stop before0x98189c ->0x14fac64. Sixty-eight independently audited cases and matching reference-file corroboration establish this local ABI; complete protected processing,native port lineage and daemon/kext pairing remain unknown.

The [CoreFP1201 operand-preparation report](fpsd1201_operand_report.md) resolves the selected negative-inverse coefficient, separates three descriptor identities and follows the original scalar-one initializer. Eight unchanged-context cases stop before an unbacked payload read; 28 explicitly backed prefixes stop before 0x14f9408 -> 0x5a600c. Forty source obligations, independent replay and odd/even controls support this local contract. Native context production, complete arithmetic, port lineage and daemon/kext pairing remain unknown.

## CoreFP1201 signed-shift continuation

The [CoreFP signed-shift increment](fpsd1201_shift_report.md) recovers a local caller arithmetic stage and zero/sign queries through complete private primitive returns. Eight continued caller cases stop before 0x649430; 136 isolated cases supply separate arithmetic controls. These results add no receiver invocation or matching native endpoint/right identity. Complete request1201 processing and daemon/kext lineage remain unknown.

## CoreFP1201 working-copy and comparison continuation

The [CoreFP comparison increment](fpsd1201_comparison_report.md) establishes local working-context copy and signed-comparison contracts, including per-call record reuse and seed-dependent frame geometry. Eight caller cases advance to the unexecuted 0x5e8158 boundary. This adds no daemon receiver invocation or native endpoint/right identity; complete request1201 processing and daemon/kext lineage remain unknown.

## CoreFP1201 subtraction continuation

The client-side [subtraction continuation](fpsd1201_subtraction_report.md) establishes a further local arithmetic return in eight private caller profiles. No native receive, reply-right identity or daemon/kext pairing follows from this local contract.

## CoreFP1201 complete precomputation continuation

The client-side [complete precomputation return](fpsd1201_reduction_report.md) establishes twelve positive local child/wrapper returns and a later unexecuted consumer. Native receive continuity, reply-right identity and daemon/kext pairing remain unknown.

## CoreFP1201 post-precomputation consumer handoff

The client-side [consumer handoff](fpsd1201_consumer_report.md) establishes a further local arithmetic-record boundary. Twelve private continuations stop before 0x114245c -> 0x74fd0c. No native receive, reply-right or daemon/kext identity is established by this increment.

## CoreFP1201 complete product continuation

The client-side [complete product increment](fpsd1201_product_report.md) establishes complete local arithmetic/wrapper returns and a later auxiliary-record boundary. Its canonical results and retained counterexamples remain distinct from native receive, reply-right and daemon/kext identity; those joins remain unknown.

The client-side [auxiliary/exponentiation continuation](fpsd1201_auxiliary_report.md) completes 16 private arithmetic consumer returns, then reaches an unexecuted output dependency at 0x981bc8 -> 0x32f628. Fourteen odd-modulus results match modular exponentiation. Root status, native receive/reply rights, endpoint identity and daemon/kext pairing remain unestablished; a local arithmetic return supplies no native receive join.

The client-side [export continuation](fpsd1201_export_report.md) establishes complete private output production and local helper return. It separates exporter status, root marker, nominal modulus width and stack adjustment; two altered short exports demonstrate local status nonpropagation. No daemon receive, native transaction, reply right or daemon/kext join is executed or established.
