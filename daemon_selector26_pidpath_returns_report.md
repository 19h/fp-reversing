# fairplayd selector 26 returns after the process-path query

The direct and descriptor forms of `IOConnectCallStructMethod` return through different private records and converge at daemon gate `0x100873c28`. In the process-path replay, a zero API status with matching sizes continues at `0x1009d9118`. The selected nonzero API status and the size-mismatch marker enter `0x10065f430`, the same block previously reached after a nonpositive `proc_pidpath` result. The status words remain distinct at the gate. [Process-path continuation](daemon_selector26_pidpath_paths_report.md) [Earlier selector 26 return analysis](daemon_selector26_return_report.md)

## Helper return and buffer ownership

All addresses refer to the pinned `fairplayd.arm64e` image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The replay continues from both process-path IOKit calls using their recovered stacks and the 272 B and 288 B aggregates. It injects the API status and returned sizes at the import boundary. In the descriptor profiles the returned address remains equal to the submitted aggregate pointer.

| ABI | API return control | Private result word | Daemon access to the aggregate during the helper return |
| --- | --- | --- | --- |
| Direct | Zero status, returned u64 size equals submitted extent | `0x8b3dc651` | Zero reads and writes |
| Direct | Zero status, returned u64 size one byte short | `0x74c29fc9` | Zero reads and writes |
| Direct | Status `0xffff5bbc`, returned u64 size one byte short | `0x74c29ded` | Zero reads and writes. The helper skips the size load. |
| Descriptor | Zero status, outer u64 size 16 B, inner u32 extent unchanged | `0x8b3dc651` | Copies all 272 or 288 bytes in descending order to the same addresses |
| Descriptor | Status `0xffff5bbc`, both sizes unchanged | `0x74c29ded` | Performs the same descending copy before storing the status |
| Descriptor | Zero status, outer u64 size `0x100000010` | `0x74c29fc9` | Zero reads and writes |
| Descriptor | Zero status, outer size 16 B, inner extent one byte short | `0x74c29fc9` | Zero reads and writes |

The direct helper stores the u32 result at record+24 B at `0x10020e6b0` and returns at `0x10020e6c8`. The descriptor helper stores the u32 result at record+8 B at `0x1001f48bc` and returns at `0x1001f48d8`. Both restore the saved caller link and stack. The 272 B and 288 B lengths are multiples of eight, so both run the eight-byte-group loop at `0x1002bfadc` without a remainder. The replay checks every address in the copy and verifies that the aggregate contents survive from API return to the helper’s epilogue. The later lifetime of the aggregate is unknown. [Earlier 14-byte descriptor replay](daemon_selector26_return_report.md)

## Caller status gate

The direct caller reloads the record result into W5 at `0x100943d44`, and the descriptor caller does so at `0x100915e84`. The instructions at `0x100943d50` and `0x100915e90` both dispatch to `0x100873c28`. With the recovered W22 phase `0x1b53`, the gate computes `u32(((W22 - 0x5b9) xor 0x9e12) + 0x8b3d3ac9)`, which equals `0x8b3dc651`. The branch compares W5 with this value at `0x100873c40`.

| Compared value | Table index and chained slot | Destination |
| --- | --- | --- |
| `0x8b3dc651` | `0x8b23`, slot `0x10107f808` | `0x1009d9118` |
| `0x74c29ded` or `0x74c29fc9` | `0x1b53`, slot `0x101047988` | `0x10065f430` |

The common failure entry establishes a control-flow join. The earlier process-query failure replay has a different allocation history, so its free sequence alone does not establish which objects the selector 26 failure subsequently releases. The earlier transport analysis identifies framework request 2865, reply 2965 and the Mach rights for that interface. This replay observes no native IOKit transaction and does not link the injected status to an actual provider response. [Mach transport and reply](iokit_sync_error_reply_report.md)

## Assumptions and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| R1 | The process-path fixture reconstructs the caller with its original stack, record and helper slots. Both aggregate lengths and the common phase depend on the fixture. | Check those fields at both call sites during an ordinary request on the image with the recorded digest. |
| R2 | IOKit is modeled as returning normally with the injected status and size fields. The descriptor pointer stays equal to the supplied aggregate. The byte-preserving result depends on address equality. | Compare the output-size cell, descriptor, status and buffer before and after the same native call. |
| R3 | Pointer authentication is modeled through the chained targets and restored links. The helper return and gate reachability depend on logical authentication and ordinary register preservation. | Compare the two return PCs, restored stack pointers and gate branch under matching native execution. |

The audit uses three direct and four descriptor return profiles at each of the two lengths. It verifies the authenticated branch slots against original chained fixup words. Copy work is O(N) for an N-byte aggregate and O(1) auxiliary storage in the daemon. The audit records O(J) events for J replayed loads, stores and branches. [Replay audit](triage_evidence/audit_daemon_selector26_pidpath_returns.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_pidpath_returns.py
```

| Impact | Open evidence |
| --- | --- |
| High | Establish which provider continuation generates a native returned status and whether the daemon’s output buffer changes before the helper resumes. |
| High | Follow the gate’s two destinations to the aggregate’s next consumer or release and the outer response status. |
| Medium | Compare the recovered frame phase and aggregate sizes with other process paths and requests. |
