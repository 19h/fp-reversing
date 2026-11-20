# lskdd selector 19 service acquisition

The installed arm64e image resolves the fresh-acquisition branch from the shared FairPlayIOKit flag through matching, iteration, and type-zero `IOServiceOpen`. Successful open sets the same flag and joins the continuation that reads the shared selector 18 and 19 connection cell. The open's output pointer is live in X20 on entry to the acquisition path. Its upstream definition remains unknown, so the evidence still leaves a gap between this open's output and the shared cell. [Shared connection cell](live_lskdd_selector19_connection_report.md)

## Flag and acquisitions

For the recovered frame, the publisher at `0x1009c7d7c` and `0x1009c7d90` provides banks `0x100d06670` and `0x100d3f920` to S+0x5bc8 B and S+0x5bc0 B. When X21 carries the published left bank, the selection at `0x1004db1d4` gives pool index `0xab` under key `0x25` and bias `0xa7`. Slot `0x100e74478` rebases to the shared flag `0x100e82ab4`. Zero enters the acquisition branch. The selector 18 matching branch independently reads this same flag. [Selector 18 matching](live_lskdd_selector18_connection_report.md)

| Daemon site | Resolved role and ABI |
| --- | --- |
| `0x100455b1c` | `IOMainPort(0, &main)`, where main is a 4 B output at S+0xc784 B. W0 = 0 continues to matching. |
| `0x10051476c` | `IOServiceMatching` receives the constructed `com_apple_driver_FairPlayIOKit` string in X0. A nonnull dictionary continues to `0x100436224` through slot `0x100e4d708`. |
| `0x1004362a8` | `IOServiceGetMatchingServices(main, dictionary, &iterator)`. W0 reads S+0xc784 B, X1 holds the dictionary, X2 names S+0xbf64 B. |
| `0x1003f2f7c` | `IOIteratorNext` reads the 4 B iterator name from S+0xbf64 B. W0 returns the service name. |
| `0x10046f98c` | `IOServiceOpen(service, mach_task_self_, 0, output)`. W0 retains the iterator's nonzero return, W1 loads the task name through the ordinary symbol bind, W2 is zero and X3 is the incoming X20 pointer. |
| `0x10046f9f8` | `IOObjectRelease` receives the saved service name. The open result remains in W20. |
| `0x1005996dc` | `IOObjectRelease` receives the iterator name from S+0xbf64 B. The no-service continuation also reaches this release. |

The matching-dictionary branch uses W21 = `0x40c1`. The matching-service result test simplifies to W0 = 0 under that frame state. It tests `(W0 XOR A) + ((W0 << 1) AND (A << 1)) == A`, with A = `0x7d854ffe` and arithmetic modulo 2^32. The left side is W0 + A. Success selects slot `0x100e68d28` and `0x1003f2ef0`. A zero service name selects the iterator-release block at `0x100599664`. The open result is tested against zero after releasing the service. Success selects slot `0x100e3a288` and `0x1005409d4`, which writes 1 to the shared flag through X23 at `0x1005409e0` and sets W24 = `0x2ee02eab`. It then reaches the iterator release via `0x100e3a400`. After that release, the preserved W24 flows to the predecessor status store at `0x100404254`.

The saved RAX trace shows the related 2881/2981 binary matching exchange, 2802/2902 iteration exchange, and 2862/2962 open exchange for `fairplayd`. The installed-image open transport site is `0x184ebdc6c`. The trace's guest port names and failed open belong to that run. Native `lskdd` names and outcomes remain unknown. [RAX exchange](zut_trace_report.md) [Installed Mach open transport](live_iokit_mach_transport_report.md)

## Class-string clearing and rejoin

On the status-store route through `0x10040423c`, `0x100404284` and `0x100404288` set X4 to `0x2f87da69`. The compared X8 is `0x2f87da8a`. The difference is 33 B, so this route takes slot `0x100e56338` to `0x100454898`.

The target writes zero to `[X19 + X9]` and increments X9. It starts at X9 = 0 and loops through slot `0x100e6b420` while X9 is below 33. X19 still points to the class string. The last write is at +32 B, within the 48 B reserved from the frame cursor. When X9 reaches 33, slot `0x100e6b3c8` selects `0x100a45f20`, which reloads X10 from S+0xe420 B and uses index `0x45b9 + 0xd1e = 0x52d7` to reach `0x10087de14`. The latter block loads the shared connection-cell address and dispatches to `0x100562ce8`. This recovers the clearing continuation between the previously reported endpoints.

## Assumptions and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| The pinned image and reconstructed frame tables supply the listed banks. | Recompute the slice digest, enumerate 256 inputs per bank equation and compare the original slot, target and authentication metadata. |
| The frame begins with P = `0x45b9` and the matching route retains the expected registers. | Observe the entry registers and verify the branch targets, W24, and X19 through service acquisition and the 33 B clearing loop. |
| Open receives a valid inherited output pointer, and its success populates that pointer. | Trace X20 to its reaching definition and compare the open's X3 with `0x100e82af8` and the later load at selector 19. |

High impact for the flag's success semantics, the service-acquisition ABI and the complete local clearing detour. Medium impact for the service and iterator release order. The fresh-open output address, native port names and native invocation remain unverified. [Instruction and fixup receipt](triage_evidence/live_lskdd_selector19_open_audit.json.zst)

The follow-up identifies the authenticated entry slot for the acquisition block and rules out two proposed ways for the known frame route to reach it. The incoming X20 remains unresolved. [Open output pointer](live_lskdd_selector19_open_output_report.md)

The follow-up establishes the fresh open output pointer as the shared selector 18 and 19 connection cell on the recovered buffer-preparation route. [Selector 19 open copyout](live_lskdd_selector19_open_copyout_report.md)
