# RPC502 BootPolicy backend: filesystem, IOKit, kernel and SEP interfaces

RPC502's BootPolicy inquiry has a concrete second user/kernel path. In the inspected local cache, `bootpolicy_get_security_mode` resolves the default root-volume identity, reads local-policy data, and sends command `0x11` through the IOKit class `BootPolicy`, user-client type 0, selector 0. The matching kernel collection contains its entitlement gate, command validator and SEP transport. The daemon subsequently partitions the returned mode into three marker classes; complete FairPlay policy remains unknown.

This increment uses original daemon/cache/kernel bytes and static arithmetic proofs. It executes neither a native target nor synthetic target instructions. Runtime cache selection, actual port objects, filesystem/registry values and a successful SEP exchange remain unverified.

## Provenance and assumption register

Analysis date: 2026-11-01. Daemon arm64e SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The source cache is `/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`, UUID `2bd06591-e751-3e84-963f-b08dab6af23a`; `libbootpolicy.dylib` UUID is `c7262dd7-f07d-35f3-a130-3cfa5a10289a`. The matching supplied kernel collection remains SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, containing `com.apple.security.BootPolicy`, UUID `cd49af0a-e1ab-3506-98e6-9f04b09314dd`.

[Native contracts](triage_evidence/bootpolicy_backend_contracts.json) retain 12 BootPolicy functions, five IOKit functions, 19 shared-cache stubs, 13 kernel functions, nine kernel stubs, five endpoint virtual bindings, seven daemon continuations and two SMT queries. Exact export/nlist names, original function-start bounds, page-chain membership and seven source-cache file hashes are retained. The [cache reader](triage_evidence/bootpolicy_cache_reader.py) reads original unslid cache ranges; it does not load or call a dylib.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| B1: this installed cache supplies the daemon's library implementation | Cross-process end-to-end interpretation | Match the daemon's actual loaded cache/library UUID and bytes. Current filesystem/cache identity does not attest the running process's selection. |
| B2: original native code, read-only tables and pointer metadata represent the intended builds | Static call targets, layouts and branch reductions | Recheck hashes, cache/subcache UUID correspondence, export tries, nlist records and chain membership; compare live pages separately. |
| B3: native custom-frame state agrees with the previously recovered RPC502 route | Daemon mode-marker classification | Recheck W24=0x6cf4, prior branch constants, table base and aliases at each predecessor. Do not treat isolated continuation entries as independent C functions. |
| B4: runtime objects have the declared IOKit/SEP classes and standard API contracts | Virtual method roles, volume-property conversion and library interpretation | Trace construction/casts and vptr address points; inspect concrete runtime objects and PAC. Static bindings do not establish hardware authentication. |
| B5: filesystem, registry, local-policy and SEP operations satisfy their own contracts | Successful security-mode output | Observe statuses, actual extents and content, root-volume identity and firmware response. All actual environmental values and successful execution remain unknown here. |
| B6: embedded XML entitlement declarations correspond to the selected executable's effective entitlement state | Compatibility with the kernel open gate | Verify code-signature trust, DER/XML consistency, selected slice and effective task entitlements. This increment establishes the original XML declaration only. |

The extracted [analysis dylib](triage_evidence/libbootpolicy.arm64e.macho) has rewritten headers/support data. Its entire 248,488-byte `__text` section matches original cache bytes, SHA-256 `b50b270a519c55fdc0ba9015532b4c0f74cd7186962113c185deeeec190aa224`. All behavior claims below are based on original cache ranges, not reconstructed headers or normalized pointer contents. The current SDK [header manifest](triage_evidence/bootpolicy_backend_header_sources.json) is separately versioned ABI context.

## Cross-layer flow

```text
FairPlayIOKit -- Mach RPC502 --> fairplayd protected context operation
                                      |
                                      +--> CSR configuration
                                      |
                                      +--> libbootpolicy: get_security_mode(path, uuid, out)
                                             |
                                             +--> root mount / I/O Registry VolGroupUUID
                                             +--> local-policy file input
                                             |
                                             +--> BootPolicy IOUserClient, selector 0
                                                     |
                                                  command 0x11
                                                     |
                                               kernel BootPolicy
                                                     |
                                           SEP endpoint "sep-endpoint,pnon"
                                                     |
                                             firmware semantics unknown
```

The two kernel interfaces have different roles: FairPlayIOKit originates the compatible daemon request; the daemon's BootPolicy library opens another user client to inquire about environment state. The endpoint matching string is an IOKit name, not an established bootstrap/Mach service name. Actual exchange and object identity remain conditional on B1-B6.

## Imported data now resolved in the original cache

The prior [environment report](rpc502_environment_report.md) proves original daemon bind addends and the two cell loads. The cache resolves the cells further:

| Original exported symbol cell | Decoded cache target | Established representation / behavior |
| --- | --- | --- |
| `_bootpolicy_default_policy_volume_path_value`, `0x1e1770ab0` | `0x1b7e77819` | NUL-terminated `/System/Volumes/iSCPreboot` |
| `_bootpolicy_root_volume_uuid_value`, `0x1e1770ac0` | `0x1ee340af0` | Private initially zero storage used as a default-volume UUID sentinel and later UUID output |

Both pointer values come from original slide-v5 page chains, with membership checked before decoding. Their concrete runtime values are not read from a process.

`_handle_default_volume_uuid` at `0x1b7e3b118` compares **pointer identity** with `0x1ee340af0`. A different pointer containing identical zero bytes does not trigger that default-object path. A synthetic model must preserve this alias relationship; replacing the imported value with an arbitrary zero buffer changes semantics.

On the unresolved default-object route, this helper:

1. Calls `statfs("/", ...)` at `0x1b7e3b1c4`.
2. Passes a name derived from that result to `IOBSDNameMatching`, then obtains a matching service.
3. Reads the I/O Registry property `VolGroupUUID`; if absent, tries the direct parent in plane `IOService` and reads it there.
4. Calls `CFStringGetCString` with 37-byte capacity and then `uuid_parse` into the private default storage.
5. Marks the cached-resolution flag only after the inspected conversion succeeds.

This establishes root-mount and I/O Registry dependencies. Actual mount-device spelling, property value, cache freshness and behavior under concurrent resolution are unknown. The code provides no basis for treating the original zero storage as a literal UUID string.

## BootPolicy command and local-policy file boundary

`bootpolicy_get_security_mode` at `0x1b7e48f44` forwards its first two values and output pointer to `bootpolicy_get_security_mode_ex` at `0x1b7e49170`, adding argument value 1. Logging surrounds that call and does not replace its status.

On the inspected successful preparation path, the extended API allocates zero-filled request/reply buffers, prepares local-policy data through `_input_local_policy`, and calls `_sep_command_with_fixed_output` with:

| Field | Value / site |
| --- | --- |
| Command | `0x11`, prepared at `0x1b7e492b8` |
| Request extent | `0x4028` bytes = 16,424 bytes |
| Reply capacity and required final extent | `0x24` bytes = 36 bytes |
| Local-policy extent field | u16 at request+0x20 |
| Local-policy bytes | request+0x28, maximum `0x4000` bytes = 16,384 bytes |
| Mode output | u32 at reply+0x20, copied at `0x1b7e492dc` after successful command processing |

The local-policy reader uses `open`/`fstat`/`read`/`close`, rejects file size at least `0x10000` bytes and rejects size exceeding the supplied maximum. It stores the accepted size as u16 and loops over reads until that size is satisfied; a nonpositive read takes an error path. It does not treat the file body as a NUL-terminated string.

The path-construction code retains formats `%s/%s/LocalPolicy/%s.img4` and `%s/%s/LocalPolicy/%s.recovery.img4`, with selection based on its kind argument. The complete metadata/hash derivation of every substituted component is not recovered in this increment; no concrete policy filename or content is asserted.

`_sep_command` at `0x1b7e470b4` writes request magic `0x42506368`, command at +4 and zeros the rest of the 32-byte header. After transport success it requires an actual response extent of at least 32 bytes, response magic `0x42507268`, and extent no larger than the caller capacity. It records returned extent and reads status from response+4. The fixed-output wrapper additionally requires exact extent 36 bytes before mode output is used. Header magic, command/status and mode are distinct fields; complete firmware enum meanings remain unknown.

## BootPolicy user-client port and exact Mach emission

The lazy connection initializer is block invoke `0x1b7e3a41c`, reached through original block pointer `0x1e66a88f0` and `dispatch_once`.

| Event | Library call site | Exact target / arguments |
| --- | --- | --- |
| Class matching | `0x1b7e3a440` | `IOServiceMatching("BootPolicy")` |
| Obtain service | `0x1b7e3a44c` | `IOServiceGetMatchingService` |
| Open user client | `0x1b7e3a470` | `IOServiceOpen(service, current-task value, type 0, &global_connection)` |
| Release service object | `0x1b7e3a47c` | `IOObjectRelease(service)` |
| Submit structure call | `0x1b7e3a3cc` | `IOConnectCallStructMethod(connection, 0, request, request_extent, reply, &reply_extent)` |
| Open Mach emission in current IOKit | `0x184e77c6c` | `_io_service_open_extended` -> exact `_mach_msg2_internal`; IDs 2862/2962 |
| Structure-call Mach emission in current IOKit | `0x184e78090` | Exact `_mach_msg2_internal` via original authenticated shared stub `0x188088a80`; IDs 2865/2965 |

The connection-name cell is `0x1ee340b00`; the once-state cell is `0x1ee340b08`. The inspected sender returns an error when connection is zero and does not retry initialization after the observed once check. Other writers/reset/close paths outside these functions and complete lifecycle remain unproved. The service object's release does not itself close the separately returned user-client connection.

Original shared-cache pointer/export checks identify the task-value source as `_mach_task_self_` and the matching-port default as `_kIOMainPortDefault`. Their actual runtime name values remain unknown. The open request is complex, 80 bytes, with two descriptors; this caller supplies the task port and a zero-length/null properties region. The inspected successful reply must be complex, 52 bytes, with one port descriptor of disposition 17/type 0. The stub publishes the returned connection name from reply+0x1c and the separate driver result from reply+0x30; `IOServiceOpen` combines transport and driver status. This establishes where the connection right enters user space under successful delivery, not an observed successful open.

For this command, `IOConnectCallMethod` sees input size `0x4028 > 0x1000`, so it sends the **user virtual address and u64 extent as inline scalar fields**. It does not place the 16,424-byte request in the Mach inline body or establish a Mach OOL descriptor. The 36-byte output uses the in-band reply path.

| IOKit Mach field | Offset in this 84-byte request | Value / role |
| --- | --- | --- |
| Header bits | +0x00 | `0x1513`, complex bit clear |
| Destination / reply names | +0x08 / +0x0c | Cached connection name / MIG reply name; actual numeric names unknown |
| Request / expected reply ID | Header +0x14 / reply check | `0xb31` = 2865 / `0xb95` = 2965 |
| NDR / selector | +0x18 / +0x20 | Native NDR / 0 |
| Scalar input / structure in-band counts | +0x24 / +0x28 | 0 / 0 |
| Input user address / extent | +0x2c / +0x34 | request VA / `0x4028` |
| Output in-band capacity / scalar capacity | +0x3c / +0x40 | `0x24` / 0 |
| Output user address / extent | +0x44 / +0x4c | 0 / 0 |

The native Mach call passes raw option word `0x200000003` and maximum receive extent `0x10bc` bytes = 4,284 bytes. These are caller-observed constants, not an actual captured exchange. This new port is separate from RPC502's service destination and its kernel-thread reply endpoint.

## Matching kernel entitlement, dispatch and validation contracts

`BootPolicyUserClient::initWithTask` at `0xfffffe000a3382d8` calls exact `_IOTaskHasEntitlement` for:

```text
com.apple.private.security.bootpolicy
com.apple.private.security.bootpolicy.readonly
```

Either declaration permits the inspected path to proceed to superclass initialization; neither present selects failure. The full-entitlement predicate is retained in client+0xe8, the task in client+0xe0, and client+0xe9 is initially zero. Further framework/task/signature requirements remain separate.

The original daemon's [embedded XML entitlement blob](triage_evidence/bootpolicy_daemon_entitlements.plist) contains `com.apple.private.security.bootpolicy = true`. The extraction checks the original LC_CODE_SIGNATURE superblob and XML slot; it does not verify signature trust, effective task state or XML/DER consistency.

`externalMethod` at `0xfffffe000a3386d0` passes a one-entry `IOExternalMethodDispatch2022` table at `0xfffffe0008429f58` to the exact framework dispatcher. This is a **40-byte** record, rather than the older 24-byte dispatch prefix: action `extPerform` at `0xfffffe000a33809c`, zero scalar counts, variable structure counts, `allowAsync=0`, null per-entry entitlement pointer. The open-time entitlement checks remain present despite that null per-entry field.

`validateSEPCommand` at `0xfffffe000a338734` maps the input descriptor, requires at least 32 bytes and verifies request magic `0x42506368`. Depending on the full-entitlement/context flags, it either bypasses or invokes the command predicate at `0xfffffe000a337f80`. The complete meanings and later mutation of client+0xe9 remain unresolved.

The exact nlist name of the predicate is `_boop_command_is_read_only`. Its accepted u32 command set is:

```text
0b 0c 0d 0e 0f 10 11 18 26 2a 2d 36
3a 3b 3c 3d 3e 3f 43 44 46 47 4c 5a
```

All values are hexadecimal. A full 32-bit SMT check proves the native bit-mask/range predicate equivalent to this 24-element set, including wraparound and large inputs. Command 0x11 therefore passes this predicate independently of the bypass condition; that does not establish open permission or later success.

## Kernel provider, shared memory and SEP endpoint

After validation, `extPerform` adapts inline or descriptor-backed structure buffers and calls `BootPolicy::performCommand` at `0xfffffe000a338e60`. Its gated continuation maps/prepares input and output descriptors and calls `sendSEPCommand` at `0xfffffe000a339278`. The caller copies response bytes and updates output counts after successful provider status. Complete framework copying/error guarantees are not inferred from these local adapters.

`getSEPEndpoint` at `0xfffffe000a339c68` uses `IOService::nameMatching("sep-endpoint,pnon", ...)` and `waitForMatchingService`, then the exact `AppleSEPDeviceService::getEndpoint` interface. It installs callback `BootPolicy::handleSEPMessage` at `0xfffffe000a3397b0`. The inspected initialization obtains SEP page size and send/receive OOL page limits and allocates visible memory for both directions. These are SEP shared-memory buffers, separate from Mach OOL descriptors and from FairPlayIOKit's VM-copy objects.

Original endpoint vtable chains establish the following static bindings, conditional on the concrete object class/address point:

| Vptr-relative slot | Exact target | Role |
| --- | --- | --- |
| +0x170 | `0xfffffe0009de8c4c` | `AppleSEPEndpoint::enable` |
| +0x180 | `0xfffffe000c51bd70` | `IOEventSource::isEnabled` |
| +0x1e8 | `0xfffffe0009de8d18` | `AppleSEPEndpoint::sendMessage` |
| +0x200 | `0xfffffe0009de8e34` | `AppleSEPEndpoint::setSendOOLBuffer` |
| +0x208 | `0xfffffe0009de8f2c` | `AppleSEPEndpoint::setReceiveOOLBuffer` |

`sendSEPCommandMessage` builds a 64-bit message value `((u64)request_extent << 32) | 0x200` and invokes the endpoint send slot at `0xfffffe000a339c20`. The asynchronous callback requires `(message & 0xff00) == 0x200`, extracts an 8-bit status from bits 16..23, and uses the upper 32 bits as response extent before its checked buffer read/copy and waiter wakeup. The outer sender also checks the caller's reply capacity before copying the response and updating its u32 size. Firmware contents, complete endpoint mailbox protocol, all lock/timeout transitions and native PAC remain unknown.

Open transport status, open driver status, IOKit method status, the SEP callback's 8-bit status, the response header's u32 status and the final u32 mode are separate values. In particular, zero IOKit transport status alone is not a successful security-mode result: response framing/status and exact output extent are checked later. No shared symbolic error namespace is inferred across these layers.

## Daemon use of the returned mode

The successful API result enters `0x100592a00`, loads mode as u32 and reaches signed comparisons in `0x100461da8`, `0x1005750d4` and `0x1004cdba4`. Under B3, all inspected mode partitions converge at `0x1005bbb20` with:

| API result / mode bits | W9 marker entering the shared continuation |
| --- | --- |
| Success, mode 1 or 2 | `0x693d4f62` |
| Success, mode 3 | `0x693d4f65` |
| Success, any other u32 word | `0x693d4f68` |
| API failure | `0x693d4f68` on the prior recovered failure edge |

The signed native tests reduce to the three exact numeric cases above for all 32-bit inputs, including negative bit patterns. The common continuation retains the marker at protected SP+0x9b90 and combines it with the CSR indicator and a mutable state word. This is recovered control/data flow, not a complete policy rule. No public security-mode enum labels, unconditional acceptance/rejection or final crypto effect are assigned.

## Reproduction, bounded findings and quality gates

```sh
/Users/___/dev/dylex/target/release/dylex extract \
  /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
  -i /usr/lib/libbootpolicy.dylib \
  -o triage_evidence/libbootpolicy.arm64e.macho
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_bootpolicy_backend.py
clang -target arm64e-apple-macos13.0 -std=c11 -fsyntax-only \
  triage_evidence/bootpolicy_backend_layouts.c
```

The extraction command operates only on cache files. The recovery script hashes selected original sources, verifies original code/metadata and runs static SMT checks; it makes no target library, filesystem-policy, IOKit, Mach or SEP API call. Analyst file reads/writes are distinct from executing target file operations. The [layout assertions](triage_evidence/bootpolicy_backend_layouts.c) cover the request/reply, 40-byte dispatch and 84-byte Mach request contracts. Complexity is O(B+F+S+D+H) extraction time for kernel bytes B, fixups F, symbols S, retained instructions D and hashed source bytes H, with O(B+F+S+D) retained working space and streamed hashing; SMT cost is solver-dependent.

| Impact | Additional finding / remaining obligation |
| --- | --- |
| High | RPC502's environment inquiry crosses back into the kernel through a different IOKit user client and then a SEP endpoint. This is an additional architectural dependency, not evidence of a second bootstrap service. |
| High | Default-volume behavior depends on imported pointer identity and root-mount/registry state; substituting equivalent bytes at a different address changes the observed path. |
| High | The large request travels as inline address/extent fields in a simple Mach message, then descriptor/shared-memory adaptations. Treating every layer as Mach OOL would conflate different ABI contracts. |
| High | The command predicate, embedded entitlement declaration and mode partition have concrete static evidence, while actual authorization, policy state and successful exchange remain separate. |
| Medium | IOExternalMethodDispatch2022 is 40 bytes here; interpreting only the older 24-byte form loses async/per-entry entitlement fields. |
| Medium | Lazy connection/default-UUID state introduces initialization, invalidation, restart and concurrency obligations beyond the first-call path. |

QG1 factual technical scope. QG2 B1-B6 and falsification probes are explicit. QG3 this increment covers the BootPolicy dependency across daemon, library, filesystem/registry, IOKit, kernel and SEP caller interfaces; the full goal remains active. QG4 widths, units, extents, layout assertions and complexity are explicit. QG5 pointer identity, distinct OOL meanings, 40/24-byte dispatch forms, signature declaration/effective state and numeric marker/policy distinctions are separated. QG6 original ranges, export/nlist records, checked pointer chains, source hashes, full-text comparison and SMT artifacts retain provenance. QG7 impact-labeled expansions and unresolved downstream interfaces are listed above.

[Machine-readable delivery checks](triage_evidence/bootpolicy_backend_quality_gates.json) retain current counts and verification boundaries.
