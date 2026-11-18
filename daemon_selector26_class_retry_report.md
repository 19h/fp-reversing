# fairplayd class fallback, object release and result publication

In phase `0xe8d`, `fairplayd` can look up `AvpFairPlayDriver` and then `com_apple_driver_FairPlayIOKit` in the same invocation. The first attempt's saved continuation identifies the primary-context check after release. The primary attempt writes a different continuation that returns through the caller-record status path. The same frame carries the two different selector 26 control words. [Initial class decision](daemon_selector26_class_gate_report.md) [IOKit open handoff](daemon_selector26_open_report.md)

The evidence uses unslid PCs from the original arm64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. F is the outer SP after allocation and R=F+0xc8 B is its private record. The Avp and primary contexts are `0x1010b5d90` and `0x1010b63a0`. [Audit generator](triage_evidence/audit_daemon_selector26_class_retry.py) [Compressed evidence](triage_evidence/daemon_selector26_class_retry_audit.json.zst)

## Saved continuation and two-lookups path

At `0x100281654`, incoming W8 indexes the original authenticated table. The store at `0x100281658` saves the selected pointer at F+0x70 B before the main-port call. The release sequence reaches `0x1001ce7b8`, which reloads that pointer, then branches through it at `0x1001ce7c0` with IA modifier `0x0cba`.

| Attempt | Incoming W8 / control at F+0x4c B | Saved continuation and effect |
| --- | --- | --- |
| Avp | `0xe8d` / `1` | Slot `0x101041358` → `0x10014ebf0`. With primary context byte `0x70`, the check selects the primary predecessor at `0x100289e64`. Other byte values select `0x1002bfecc`. |
| FairPlayIOKit | `0xe5e` / `0` | Slot `0x1010411e0` → `0x1002bfecc`, which publishes the result to the original caller record. |

| Outcome of the current attempt | Context update and outer continuation |
| --- | --- |
| Main-port or matching failure, null dictionary, or zero `IOIteratorNext` return | `0x1000bd85c` writes `0x20` to C+0x18 B and zeros 8 B at C+0x28 B. The path checks the iterator and continues through F+0x70 B. |
| Nonzero open return, or constructor return with `u32[R+8] != 0x8b3dc651` | `0x1002c99a0` makes the same context stores, releases the service, checks and releases the iterator, then continues through F+0x70 B. |
| Constructor return with `u32[R+8] == 0x8b3dc651` and bit 7 set in `u32[C+0x14]` | `0x10011c77c` selects the same `0x1002c99a0` sequence. The file-initial word is `0x382d2cea` for both contexts. The branch uses the word read after the constructor. |
| Same constructor status and bit 7 clear | `0x10011c77c` selects `0x10028a774`. The call at `0x10028a8b0` reaches private helper `0x100902878` with X0=R and X1=F+0x80 B. The subsequent result and continuation fall outside this replay. |

The constructor entry evaluates W28=`0x8934` with the live layout R=F+0xc8 B. Two bit-vector checks extend the earlier 16 B-aligned proof to every 8 B-aligned R. The adjusted dispatch byte is `u8(2*U + (U XOR 0xef) + 0x3e)` for the 32-bit control U. The two recovered control words yield `0x2d` and `0x2e`, preserving the descriptor and direct structure choices in this layout. [Prior constructor and dispatch proof](daemon_selector26_constructor_join_report.md) [Compressed evidence](triage_evidence/daemon_selector26_class_retry_audit.json.zst)

## Object-name lifecycle and RAX comparison

| Name | Producer and daemon consumer | Recorded RAX evidence |
| --- | --- | --- |
| Service send right | Returned by `IOIteratorNext` and saved at F+0xc B by `0x100176a00`. The release call at `0x1001dcab8` reads that 32-bit name. | Guest `0x1903`, returned at lines 1720–1724. `_kernelrpc_mach_port_deallocate_trap(0x203, 0x1903)` returns 0 at line 1743. |
| Iterator send right | Matching API output at F+0x78 B. `0x1001bb4e4` loads the 32-bit name and the branch skips the release when it is zero. The nonzero path calls at `0x100205980`. | Guest `0x1803`, returned at lines 1709–1713. `_kernelrpc_mach_port_deallocate_trap(0x203, 0x1803)` returns 0 at line 1745. |
| Connection name | Type-0 open output at C+4 B. The selected release sequence leaves this slot intact after a modeled successful open. | Open reply 2962 returns a null connection and `0xe00002c2`. |

Both daemon release sites bind `IOKit/_IOObjectRelease` through original slot `0x1010a0240`, IA `0xbe7e`. The code uses neither release call's return value to choose its successor. At `0x1001bb510` it restores the primary context from F+0x50 B before the iterator release or continuation. The recorded deallocation trap PC is `0x180547ad0` for both names. The observed task-local names and release order corroborate the static lifecycle. Their direct attribution to the unslid daemon PCs remains unknown. The interval ends after this primary attempt with no method request 2865. [RAX trace](zut_trace_report.md)

## Result record

`0x1002bff74` calls the same cached-byte adapter used by the entry at `0x100438530`. If the returned byte is `0x99`, `0x1002bff84` selects the primary context. Otherwise it selects the Avp context saved at F+0x10 B. At `0x1002bffa8`, a 4 B store to the original X0 record writes `0x74c29dee` when the selected context's first byte equals `0x70`, or `0x8b3dc651` otherwise. This is a private record field. The final branch and restored registers follow the stack guard check. [Initial query and cache](daemon_selector26_class_gate_report.md) [Compressed evidence](triage_evidence/daemon_selector26_class_retry_audit.json.zst)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The original image and phase define F, R and the logical branch targets. Live stack and context storage are disjoint. | Check original chained words, the exact stack slot widths and both nonvacuous solver obligations with `R & 7 == 0`. |
| A2 | IOKit calls return normally with the declared opaque names and output stores. Error cases retain the modeled contents of the initialized outputs. | Record the iterator and connection outputs at each corresponding return. Check whether a failed call writes either slot on the matched framework. |
| A3 | The query helper and constructor return normally and preserve the caller's live frame slots. The helper-byte fixture represents the earlier audited local query path. | Join live cache, C+0x14 B and returned private record bytes to both branch loads. Test the second lookup with the same frame and a distinct iterator/service pair. |
| A4 | The retained RAX interval establishes the order of guest names and traps with the supplied capture hash. | Correlate the framework release, trap PC and unslid daemon caller in one capture, then observe the right's final kernel lifetime separately. |

The audit replays 12 profiles, verifies 117 original source spans and 53 chained fixups, enumerates 1,280 bank inputs and checks two alignment formulas. It verifies the two captured deallocation calls against the hashed source trace. For I audited instruction visits, B bank inputs and T trace lines, evaluation uses O(I+B+T) time and O(I+T) retained space plus the fixed-size banks, with separate solver resources. QG1–QG7 cover factual scope, the premises, the outcome routes, the address and field sizes, source and trace provenance, and the open interfaces below.

| Impact | Open evidence |
| --- | --- |
| High | Recover the bit-clear continuation through `0x100902878` and identify any additional IOKit calls, releases or class lookup on that path. |
| High | Attribute writes to the context state and connection fields across initialization, successful method return, and close. Correlate a native method exchange with the specific service and right. |
| Medium | Trace the outer status word into its caller and identify where it leaves the daemon, if it does. |
