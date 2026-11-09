# CoreADI adid: request persistence, filesystem control and reply errors

Original requests now continue from the retained listener/peer state through concrete persistence paths, lock-file setup, filesystem-type discrimination, setup-marker checks, unlock/close and an emitted four-byte error. All six client selectors share these prerequisites in the tested states. Successful selector semantics and the opaque 64-bit request field remain unknown. The broad daemon/kext/deeper-interface investigation remains active.

## Evidence identity and assumption register

Addresses are original preferred virtual addresses in the provider arm64e image, base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. The universal executable, slice selection, fixup format and imported symbols are pinned by the [receiver report](adid_receiver_report.md). The [startup report](adid_startup_report.md) establishes the earlier source-produced checkpoint and callback chain. These addresses do not belong to CoreFP, fairplayd or the kext.

Original bytes and SDK headers were read. Analyst code was compiled to assembly; bounded source instructions ran in private Unicorn memory under explicit fixtures. No native target, loader, IPC, persistence, environment or synchronization operation was executed. Original supplied inputs and IDBs remain preserved.

| Assumption | Dependent results | Stress test / falsification boundary |
| --- | --- | --- |
| R1: the pinned image and SDK declarations describe the inspected reference objects | All addresses, imports, widths and named constants | Fresh original instructions, compiler ranges, chained pointers, dyld_info output and SDK compilation agree. Native executable selection and exact runtime implementation remain unknown. |
| R2: the retained private startup/peer state and declared PAC/vector/API models permit the stated continuations | All finite request paths | Three fresh source replays match complete instruction digests, events and mutable models. They use the same declared execution model; they are not a second emulator or native validation. The prior uninterrupted-versus-checkpoint startup check remains separately retained. |
| R3: explicit metadata, owned descriptors and API statuses describe each virtual filesystem case | Path, permission, open, type-query and lock observations | Descriptor zero, open failure, mode subsets/supersets, fchmod/getpath/statfs failures and lock errors are varied. Selected stat fields are populated; other fields are zero. Full inode identity, links, path replacement, native filesystem contents and durability remain unknown. |
| R4: one private errno cell, initial values 2/0/13 and declared failure updates describe the stated thread-local state | Errno-sensitive branches and EINTR retry | `___error` returns the same cell without resetting it; original stores remain effective. The zero/13 cases differ from the value-2 prefix. Native successful APIs may affect errno differently; native branch prevalence or defect is not inferred. |
| R5: captured control constants and the original encoded reference apply to the local predicates | Permission and filesystem-type reductions | Original bytes, branch slots, reference bytes and four full-domain local SMT obligations are checked. Other control states and whole-program behavior remain outside those proofs. |
| R6: the exact request bytes represent the stated selector/opaque-value experiments | Common-prefix comparisons | Six client selectors, six counterfactual selectors and multiple 64-bit field values are retained. Sharing a prefix does not prove server acceptance, selector equivalence or a semantic type for that field. |
| R7: opaque CF/XPC objects and the explicit prior 40-byte block copy represent their declared roles | Incoming handler and outgoing reply linkage | Original callback, audit/data adapter, wrapper return and reply calls are connected. Native block retention, bootstrap namespace, Mach port objects/rights, libxpc emissions and legacy Mach compatibility remain unknown. |

Primary artifacts: [request profiles](triage_evidence/adid_request_profiles.json), [static contracts and proofs](triage_evidence/adid_request_contracts.json), [fresh checks](triage_evidence/adid_request_checks.json), [quality gates](triage_evidence/adid_request_quality_gates.json), [producer](triage_evidence/probe_adid_requests.py), [SDK model](triage_evidence/adid_request_layouts.c), [assembly](triage_evidence/adid_request_layouts.s) and [independent validator](triage_evidence/validate_adid_requests_delivery.py). Full compressed source-visit and event streams are retained.

## Request-to-persistence flow [R1-R4,R6,R7]

```text
source-created peer block -> handler 0x100029fc8
  -> reply/audit/data adapter -> entitlement/header checks
  -> private context /var/db/fpsd/adi
  -> adi-gb metadata -> adi-gb.lck open/metadata/mode
  -> F_GETPATH -> statfs -> encoded comparison with "nfs"
       match:       advance without the observed lockf acquisition
       nonmatch:    lockf(F_LOCK,0) -> optional EINTR retry
  -> record discovery -> setup-marker queries
  -> observed completed error continuation
       unlock -> close -> later record query -> core wrapper return
       -> XPC data ff ff 50 1f -> send reply
```

The baseline uses the earlier admitted entitlement-number fixture, root audit EUID zero, PID 1234, NULL `__OSINSTALL_ENVIRONMENT`, and the retained initialized state. It initializes private errno to 2; separate cases use zero and 13. The declaration `_fpsd` UID/GID 265 is configuration context from the preceding report, not the audit identity of this client fixture.

| Original boundary | Callsite | Recovered argument / observed role |
| --- | --- | --- |
| Private directory metadata | `0x10010b178` | `lstat("/var/db/fpsd/adi", stat144)` |
| Additional context path metadata | `0x100110474` | `lstat("/var/db/fpsd/adi/adi-gb", stat144)`; file-format/semantic expansion of `gb` unknown |
| Lock-file open | `0x10010ae2c` | `/var/db/fpsd/adi/adi-gb.lck`, flags `0x01000201`, variadic mode `0666` |
| Descriptor metadata | `0x10010cd5c` | `fstat` of the opened lock descriptor |
| Conditional permission request | `0x10010ce98` | `fchmod(fd,0666)` |
| Descriptor-to-path query | `0x10010d100` | `fcntl(fd,F_GETPATH,output)`; command 50, pointer in the first variadic stack slot |
| Filesystem query | `0x10010d190` | `statfs` of the returned path; 2168-byte structure |
| Lock acquisition request | `0x10010d3ec` | `lockf(fd,F_LOCK,0)`; command 1 and signed 64-bit extent zero |
| EINTR-case retry | `0x10010e480` | Same descriptor/command/extent in the retained retry case |
| Initial record discovery | `0x1001088fc` | Queries include private `adi.pb` and `/Users/Shared/adi/adi-00000000.pb` |
| First setup-marker query | `0x1001097cc` | `/var/db/.AppleSetupUser` |
| Fallback setup-marker query | `0x10010986c` | `/var/setup/.AppleSetupUser`, reached after the declared first-query failure |
| Later record query | `0x1001237dc` | Shared `adi-00000000.pb` in the completed fixtures |
| Unlock request | `0x1001239e8` | `lockf(fd,F_ULOCK,0)`; command 0 |
| Lock-descriptor close | `0x100123ac4` | Same owned descriptor in the completed fixtures |

The lock-file flags are `O_WRONLY | O_CREAT | O_CLOEXEC`. The observed call does not include `O_NOFOLLOW`; the actual path/ownership consequences require native namespace and race evidence. Source calls temporarily request umask zero and restore the saved mask around open and the conditional mode update. The private model tracks the changing mask; its baseline value `0x12` is a fixture, not a measured process property.

The original code consumes a 144-byte stat layout, including mode at +4 and size at +96. The SDK compile additionally verifies device, inode and link-count widths/offsets; those declarations do not establish that every such field is tested on this path. Descriptor zero reaches fstat and lock acquisition. A modeled open result -1 avoids those descriptor-dependent calls.

## Permission and filesystem-type predicates [R1,R3-R5]

At `0x10010cdbc`, `BICS WZR,W9,W8` uses requested mask `0x1b6` (0666) and a zero-extended 16-bit mode. The retained branch requests fchmod when:

```text
missing = (0x01b6 & ~mode16) != 0
```

This tests whether all requested permission bits are present. It is not equality with 0666. Modes 0666 and 0777 both skip the observed normalization; 0600 and 0640 reach it. The captured encoded indices are `0x1925` for no missing bits and `0x192e` otherwise. Original authenticated slots `0x1002d09e8` and `0x1002d0a30` resolve to `0x10010cf08` and `0x10010cde0` respectively. A full 16-bit-domain proof checks the mask reduction.

The filesystem-type loop reads offset 72 of the returned statfs object, the SDK's 16-byte `f_fstypename` field. Original reference bytes at `0x1002b44c0` begin `6a 62 77 04`; XOR 4 gives `6e 66 73 00` (`nfs\0`). Source instructions sign-extend input/reference bytes and compare their XOR against 4, with an explicit loop bound and reference terminator.

The later arithmetic equality uses unsigned 32-bit modular arithmetic:

```text
d = (sign_extend(reference_byte) XOR 4) - sign_extend(input_byte)
C = 0xfbf9d5cf
t = (d XOR C) + ((d << 1) & 0xf7f3ab9e)  (mod 2^32)
t == C  iff  d == 0
```

The source prefix supplies shift 1, and `0xf7f3ab9e = 2*C mod 2^32`. Separate proofs cover the full 32-bit fold, signed-byte equality and the fixed four-byte `nfs\0` predicate. They do not assert arbitrary loop safety or whole-request correctness.

| Controlled type/result | Retained continuation |
| --- | --- |
| `apfs`, `hfs`, `smbfs` | Reaches acquisition at `0x10010d3ec` |
| `nfs` | Advances without that observed acquisition call |
| F_GETPATH returns -1 | No statfs or observed acquisition in this continuation |
| statfs returns -1 | No observed acquisition in this continuation |
| fchmod returns -1 | This fixture still reaches getpath/statfs/lockf; native error-state equivalence is unproved |
| lockf returns -1, errno 13 | One acquisition attempt, no modeled lock acquired |
| lockf returns -1, errno 4, then success | Retry at `0x10010e480`, followed by the recorded discovery boundary |

These are exact finite fixture observations. No native filesystem type, successful lock, blocking duration or concurrent exclusion was measured.

## Errno and environmental control [R2-R4]

The provider reads `___error` after the `adi-gb` query. In the retained prefix, `0x100110484` compares the lstat result against zero and `0x100110518` compares the errno-cell value against 2. Keeping one mutable errno cell exposes a control difference that a model resetting errno on every accessor would erase.

Initial errno zero and 13 take a longer continuation than the value-2 baseline. The initial-zero cases additionally vary the `adi-gb` mode between regular file, directory and symbolic link. All reach the retained record-discovery boundary with different source streams. This establishes a private state dependency; it does not establish the native frequency, cause or security effect of any branch.

The source explicitly clears the errno cell before the acquisition call. The EINTR fixture then supplies errno 4 on failure, and the retry preserves the original source's cell writes and subsequent accessor reads. Native thread-local storage, API errno side effects, interruption, contention and scheduling remain open.

Both setup-marker paths are separately retained. First-marker success, fallback-marker success, both absent, and both absent with initial errno zero all reach the same completed payload error for every tested selector. Thus this evidence does not assign the error to the presence of a setup marker. Nonroot audit EUID 265 and 501 fixtures encounter the setup-marker gate earlier, before the root fixture's persistence path.

## Selector limits and IPC response [R2,R6,R7]

The client constructs a 28-byte big-endian request: three 32-bit header words, a signed 64-bit selector and an opaque 64-bit argument. The six client-accepted selectors are `-8,-6,-5,-4,-3,-2`. Counterfactual selector values `-9,-7,-1,0,1,4294967288` share the first inspected persistence boundary; they are not classified as accepted server operations.

Opaque-field variants include 0, 265, 4294967295, 4294967296 and `0x7b000100`. None changes the observed shared record path in the advanced fixtures. Its meaning remains unknown; address-shaped or account-shaped values do not establish a pointer or identity type. The origin of the zero field in `adi-00000000.pb` also remains unknown.

| Response layer | Original site | Observed completed value |
| --- | --- | --- |
| Core record return | `0x1000aa910` | Wrapper status zero, output extent 4 bytes |
| XPC dictionary payload | `0x1000aa9fc` | Key `data`, bytes `ff ff 50 1f` |
| Reply emission request | `0x1000aaa70` | `xpc_dictionary_send_reply` on the created reply object |

Interpreting the payload as big-endian signed 32-bit gives `0xffff501f - 2^32 = -45025`. It is distinct from the earlier entitlement-denial payload `ffff4ff2` (-45070). The zero wrapper status does not mean that the payload reports success. The precise symbolic name and underlying cause of -45025 are unknown.

In the completed fixtures, acquisition at `0x10010d3ec` precedes unlock at `0x1001239e8` and close at `0x100123ac4`; the final private descriptor/lock models are empty and the mask is restored. Prefixes deliberately stopped at unknown file metadata retain an owned descriptor when appropriate; they do not prove native leaks or complete error cleanup.

No deeper IOKit provider/selector call is reached in this case set. Those imports remain static evidence and pending continuation targets. Native incoming Mach rights, outgoing libxpc Mach emission, actual peer credentials and compatibility with CoreFP's legacy Mach request remain unresolved.

## Verification and bounded continuation

The increment passes **29443 assertions** across **124 private cases**, **4 full-domain local proofs**, 16518 unique original instruction records and 13 compiler-bounded ranges. All 4586940 source visits and 6083 source API boundaries are retained. Three independent private replays total 118933 hooks; the fresh SDK compile returns zero.

Fresh checks cover every retained original instruction, complete ordered source-visit digests, compiler-bounded ranges, selected chained import/branch pointers, encoded reference bytes, dyld_info readback, SDK headers/assembly and preserved supplied inputs. Three fresh replays cover a completed reply/retirement path, the NFS bypass and the EINTR retry; they compare all retained events and mutable filesystem/descriptor/lock/mask models.

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_requests.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_requests.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_requests_delivery.py
```

Readback is O(B+F+R+V) time/space for image bytes B, fixups F, unique source instructions R and visits V. Each private case has a 300000-hook cap; retained hooks and visits are distinct counts because imported API/sentinel hooks are not source instructions. SMT cost is separate, capped at 30 s/query. Byte extents and integer domains are exact; no native performance measurement is asserted.

| Impact | Further discriminating evidence |
| --- | --- |
| High | Recover the exact producer and prerequisite for payload -45025, then pass the common initialization path to successful selector-specific semantics and the first concrete IOKit provider/selector call. |
| High | Trace all consumers and caller provenance of the opaque 64-bit field and the filename's zero field; recover valid persistent-record grammar and identity binding. |
| High | Pair actual client/provider credentials, bootstrap/Mach endpoint identity and underlying libxpc transport with the kext-facing path. |
| Medium | Establish native errno/TLS effects, stat metadata predicates, inode/path identity, symlink handling, umask concurrency and replacement/durability behavior. |
| Medium | Recover complete acquisition/retry/unlock/close behavior for all errors, contention, interruption and shutdown/reentrancy; private sequential locks do not establish exclusion. |

QG1-QG7 apply to these stated claims and assumptions. The full interface objective remains active and incomplete.
