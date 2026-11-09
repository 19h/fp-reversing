# Platform IORPC construction, local dispatch and power-output ABI

Original AppleARMIODevice capitalized clock/power/PSD wrappers construct kernel-form IORPC packets. Under an explicit local class-hierarchy premise, original OSMetaClassBase::Invoke dispatches them through AppleARMIODevice::Dispatch, _Dispatch, the selected Invoke adapter and an Impl thunk into the previously recovered lowercase device/controller methods. Nominal controller unsupported results return without reply construction. Declared backend success instead lets original reply construction and caller validation complete. This establishes a conditional local ABI chain, not a native Mach exchange or actual hardware activation. [IR1-IR8]

```text
capitalized wrapper: original request + 32-byte IORPC context
  custom callback supplied -> callback outcome/reply model -> caller validator
  callback NULL
    -> original OSMetaClassBase::Invoke
    -> declared local hierarchy -> clear thread+0x378 temporarily
    -> original Dispatch -> _Dispatch(method ID)
    -> original method_Invoke -> original method_Impl thunk
    -> original lowercase device wrapper -> nominal controller method
       unsupported: return register propagates; no generated reply
       declared success: original generated reply -> caller validator
    -> restore thread+0x378

native remote routing / Mach endpoint / actual platform effects: unknown
```

[Source, constants, imports and SDK layout probes](triage_evidence/platform_iorpc_source.json), [18 profiles](triage_evidence/platform_iorpc_profiles.json), [independent replay/oracles](triage_evidence/platform_iorpc_checks.json), [preservation](triage_evidence/platform_iorpc_delivery.json) and [scoped quality gates](triage_evidence/platform_iorpc_quality_gates.json) retain evidence. This extends the [platform gate report](aes_platform_gate_report.md); original [zut trace evidence](zut_trace_report.md) remains unchanged and contains no transaction through this interface.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| IR1 | The pinned collection supplies captured source, exact symbols and fixups. | Rehash collection; recapture 88 retained/new functions, 7533 instructions, 24 retained/new bindings and constant bytes. Different runtime builds require remapping. |
| IR2 | Source-produced platform objects/globals transfer exactly; nominal device/controller vptrs and previous table/count fixtures carry forward. | Match actual startup, registry ancestry, class/vptr, table resources and owner extents. No native controller identity or valid hardware gate is established. |
| IR3 | AppleARMIODevice's superclass chain is explicitly terminated; the local routing debug byte is supplied as file value 1. | Capture initialized native hierarchy, remote-capable object relationships, debug epoch and runtime dispatch. Different class/flag state may take a remote route. |
| IR4 | Emulated TPIDR_EL1 points to a private 1024-byte thread reservation, with a declared +0x378 word. | Match actual current-thread association, field meaning, nested calls and concurrency. Local clear/restore proves neither native scheduling nor the field's complete semantics. |
| IR5 | Four success cases substitute controller return zero; power supplies one explicit four-byte output. | Execute the actual controller override and observe its output, side effects and status. The nominal original base stubs instead return unsupported. |
| IR6 | Custom OSDispatchMethod outcomes are declared models. Five clock cases transfer the exact source-produced reply buffer from case 3, optionally substituting one field. | Establish a real registered callback/transport and preserve authentic reply provenance. These are private caller-validation cases, not native send/receive observations. |
| IR7 | SDK declarations/layout compiles corroborate structures and constants but are not the matched kernel source revision. | Match the collection build's headers and generated IIG interfaces. Compare kernel internal ports/pointers with user namespace names before decoding packets. |
| IR8 | Logical PAC and private CPU execution remain conditional; real remote transport, ports, platform effects and IDBs are untouched. | Establish native call reachability, authentication, actual remote route, right conversion and runtime observations before claiming end-to-end daemon interaction. |

## Primary source and dispatch identities

Collection: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Twelve functions / 807 instructions are added to the previous 76-function capture. Exact compiler bounds, complete bytes/disassembly and nlist definitions are retained. No IDB is changed.

| Method | Builder | Invoke adapter | Impl thunk | 64-bit IORPC method ID |
| --- | --- | --- | --- | --- |
| EnableDeviceClock | 0xfffffe0008cfa1e8 | 0xfffffe0008cf98e8 | 0xfffffe0008cb47c0 | 0x98ae300572af31c2 |
| EnableDevicePower | 0xfffffe0008cfa2e4 | 0xfffffe0008cf9994 | 0xfffffe0008cb47f4 | 0xd33e8303066fa5d3 |
| EnablePsdService | 0xfffffe0008cfa5fc | 0xfffffe0008cf9b9c | 0xfffffe0008cb4890 | 0x9817bbdfffd2803c |

Default Invoke import slot 0xfffffe0008012bc8 targets OSMetaClassBase::Invoke at 0xfffffe000c5957d4 through stub 0xfffffe0008cfede8. Device vptr+0x60, slot 0xfffffe0007ff2540, targets AppleARMIODevice::Dispatch at 0xfffffe0008cf9500, which copies the 32-byte IORPC and calls _Dispatch at 0xfffffe0008cf9530. Both new slots are authenticated IA, address-diversity=1; Dispatch diversity is 0x9209 and the import diversity is zero. Source _Dispatch signs each exact Impl callback with its signature discriminator before passing it to the Invoke adapter. Hardware PAC remains unexecuted.

The three source-selected callback discriminators are clock 0xfee3, power 0x629a and PSD 0x3b24. Optional OSDispatchMethod calls use 0xed39. These 64-bit method IDs and signature discriminators are distinct from the Mach header's 32-bit version/message ID; no numeric value is assigned a daemon RPC502/700 identity. [IR1,IR8]

## Kernel packet layout versus user wire representation

Two syntax-only arm64e SDK compiles independently check public user headers and Kernel.framework headers. Kernel.framework include paths select kernel port types even without -DKERNEL; the probes therefore use distinct public and kernel header search paths. Recorded commands, source, header hashes and fresh validation preserve the distinction. No compiled target executable runs. [IR7]

| Structure/field | Kernel header result | User header result |
| --- | --- | --- |
| sizeof(mach_msg_header_t) | 32 bytes | 24 bytes |
| offsetof(msgh_id) | 28 bytes | 20 bytes |
| sizeof(mach_msg_port_descriptor_t) | 16 bytes | 12 bytes |
| sizeof(IORPCMessageMach) | 36 bytes | Not compiled in the user-only probe |
| sizeof(IORPC) / kernelContent offset | 32 bytes / 24 bytes | Not compiled in the user-only probe |
| sizeof(IORPCMessage) | 24 bytes | Not compiled in the user-only probe |

Kernel headers define mach_port_t as an ipc_port_t pointer. The source builders below use this internal representation; they do not directly construct user task-local port names. In particular, applying the zut user header offsets would misidentify fields.

The 32-byte IORPC context is two u64 pointers (message and reply), u32 sendSize, u32 replySize capacity and a u64 kernelContent pointer. Every source builder aliases message and reply to the same stack buffer, and kernelContent points to message+0x34.

| Request offset | Width | Source value |
| --- | --- | --- |
| +0x04 | u32 | Logical request size: 92 bytes for clock/power; 100 bytes for PSD. |
| +0x1c | u32 | 0x4da2b68c, SDK kIORPCVersion190615. |
| +0x20 | u32 | Descriptor count 1. |
| +0x24 | 16 bytes | Zeroed port-descriptor reservation. No actual right is supplied by these builder stores. |
| +0x34 | u64 | Method ID. |
| +0x3c | u64 | Flags 0x80, SDK SimpleReply. |
| +0x44 | u64 | objectRefs=1. |
| +0x4c | u64 | Receiver object reference. |
| +0x54/+0x58 | u32/u32 | First and second scalar inputs: enable and index. |
| +0x5c/+0x60 | u32/u32 | PSD additional scalar inputs; absent from clock/power logical requests. |

Reply capacities are 128 bytes for clock/PSD and 132 bytes for power. Logical reply sizes are 60/64/60 bytes. Capacities, request sizes and reply sizes are separate quantities. Power's caller output pointer is retained in a register; the request serializes only enable/index, not that pointer. The tested scalar inputs match the prior platform cases: enable=1, index=0, PSD's remaining inputs=0xffffffff.

## Local routing, adapter guards and callback ABI

On the selected default path, original OSMetaClassBase::Invoke ORs Kernel bit 4 into content flags, yielding 0x84. The declared terminating hierarchy prevents the checked remote-class matches. Source temporarily clears emulated current-thread+0x378, calls the object's Dispatch virtual, then restores the exact prior word after return. Seven complete local cases verify one zero/store and one restoration/store around the selected adapter. The field is reported by offset; complete native meaning and remote routing are unknown. [IR3,IR4]

_Dispatch reads kernelContent->msgid and selects the corresponding adapter and Impl function. Each adapter clears DeepSerialization bit 0x100 in content flags before its validation. The source guards require message descriptor count=1, content objectRefs=1, sendSize >= the method request size and replySize capacity >= the method reply size. The new full-chain cases use original valid constructed packets and larger capacities; separate negative request-boundary cases are not supplied.

| Adapter | Callback arguments after receiver |
| --- | --- |
| Clock | u32 enable, u32 index |
| Power | u32 enable, pointer to reply+0x3c for a u32 result, u32 index |
| PSD | Four u32 scalar inputs |

Original Impl thunks dispatch through the lowercase device virtuals recovered previously: clock +0x8a8, power +0x8b0 and PSD +0x8c8. Device wrappers then select the table-derived controller gate arguments. Thus this is a concrete source connection between the previously inventoried IORPC surface and the direct platform interface. It remains conditional on the declared class/table epoch and does not demonstrate that the native accelerator caller uses this route. [IR2,IR8]

## Return status, reply construction and power-output lifetime

The original nominal base controller methods execute their four-instruction unsupported bodies in cases 0-2. Nonzero W0 makes the Invoke adapter return before reply-header construction. The capitalized caller returns that same 0xe00002c7 without parsing a reply. Kernel bit publication and thread clear/restore have nevertheless occurred. An error return does not imply unchanged request memory.

Cases 3-6 replace the controller body with a declared zero return. Power additionally supplies u32 0x12345678 through the actual reply+0x3c pointer. Original adapter source then writes the reply:

| Reply offset | Width | Source value |
| --- | --- | --- |
| +0x04 | u32 | Exact size: clock/PSD 60, power 64 bytes. |
| +0x1c | u32 | 0x4da2b68d, SDK version reply. |
| +0x20 | u32 | Descriptor count 0. |
| +0x24 | u64 | Same 64-bit method ID. |
| +0x2c | u64 | Flags 8. |
| +0x34 | u64 | objectRefs=0. |
| +0x3c | u32 | Power result, written by the declared backend through the adapter-supplied pointer. |

Request and reply alias, so the response layout overwrites the request prefix. Bytes beyond the logical reply size can retain prior request data in the allocated capacity; those bytes are not claimed to be transmitted reply content. All current final-buffer snapshots intentionally retain the whole capacity for state verification.

On a zero dispatch result, the original caller requires exact reply size, matching method ID, descriptor count zero and objectRefs zero. Failure yields 0xe00002bf, named kIOReturnIPCError by the separately versioned IOReturn header. The observed caller interval does not validate the reply version word or flags; prior/lower validation and native transport handling remain separate questions.

Power copies exactly four bytes from reply+0x3c to the original caller pointer only after those guards pass and only when the pointer is non-NULL. The non-NULL success case changes just the first four bytes of a 16-byte caller reservation; the NULL case leaves it unchanged while the internal reply output still exists. The pointer is a synchronous caller output, not a serialized pointer, port or retained remote reference.

Custom callbacks have distinct cases: declared nonzero returns propagate directly; zero without replacing the request fails the exact reply-size check; transferring the original case-3 clock reply succeeds; changing only size, method ID, descriptor count or objectRefs rejects it. These substitutions establish caller field contracts under declared callback outcomes, not real remote delivery or backend success. [IR5,IR6]

## Verification, scope and continuation

The case set contains three original unsupported local chains, four declared backend-success local chains (including NULL power output), three custom nonzero returns, three zero returns without reply replacement and five source-reply-transfer/field cases. All prior 158 object images and two source-global images transfer exactly into each case and remain unchanged; only the new caller output, private thread epoch and stack packets participate in this increment. No jobs or DMA objects are allocated.

Fresh independent replay verifies 2967 original instruction visits, 852 writes / 6528 bytes, 714 reads / 5336 bytes, 119 logical authentication steps, 81 indirect edges, 18 boundaries, 2880 final object images, 36 source-global images and 108 environmental-global images. It checks 18 RPC contexts/buffers, 14 Dispatch entries, seven adapters/thunks/device/controller frames and seven thread-context frames. Fifteen declared API models contain seven memory effects / 648 bytes, separated from source writes. All 2844 prior-object comparisons pass.

The independent checker recaptures original bytes/disassembly and 24 bindings, repeats both SDK layout compiles, checks complete request/reply buffers and frame arguments, replays every original A64 instruction, read/write, indirect edge, logical PAC step and declared model effect, and verifies full private RAM plus object/global snapshots. Exact totals are retained in the linked checks JSON. Run: `PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_platform_iorpc.py`.

Complexity is O(image bytes + visits + journal events + object bytes) time and O(image bytes + journals + private RAM) space. Offsets/addresses are hexadecimal; sizes are exact integer bytes; one byte is 8 bits. No native duration, scheduling, hardware power or transport measurement is inferred.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Actual native hierarchy/controller and real callers of capitalized methods | Determines whether the established local route is exercised or remote dispatch applies. |
| High | Remote Invoke routing, kernel/user representation conversion and object/right publication | Connects this local kernel form to actual IPC endpoints and user-visible packets. |
| High | Actual controller overrides, registry tables and register resources | Replaces the conditional backend success with real activation/output evidence. |
| High | Historical RAX UserClient-open cause and effective host-task identity | The supplied trace ends with BadArgument/null connection before selector26 and reverse RPC. |
| Medium | Other _Dispatch method IDs, request-guard boundary cases and nested thread contexts | Extends the finite three-method ABI coverage without generalizing local-context behavior. |
| Medium | Reply-version/flag validation at other layers and error serialization on remote routes | Distinguishes caller checks from complete native RPC validation and status transport. |

QG1: Descriptive technical evidence is sufficient for this increment.

QG2: IR1-IR8 state premises, dependent results and falsification probes.

QG3: This increment covers three complete local IORPC chains, exact kernel packets, callback routing, selected status/reply/output behavior and thread clear/restore. The full daemon/kext/native investigation remains active.

QG4: Kernel/user widths, packet offsets, logical sizes/capacities, four-byte output and exact buffer transfers are explicit and reproducible.

QG5: Local dispatch, custom outcome, controller result, constructed reply, allocated capacity and transmitted content are separated. Native identities, remote paths and untested request boundaries remain unknown.

QG6: Original collection bytes/symbols/fixups, compiler ranges, SDK provenance, source-produced packets, independent CPU replay and preserved snapshots support the bounded claims. No native IPC/platform/PAC operation executes and no IDB is changed.

QG7: Impact-labelled continuation identifies remaining native caller, remote representation, right/publication, platform and daemon joins. Scoped gate passage does not establish a complete FairPlay transaction.
