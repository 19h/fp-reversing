# fairplaydeviceidentityd protected DeviceIdentity callers

Two protected call sites in the installed arm64e image supply storage for the key and both certificates. Each conditionally resolves to the DeviceIdentity wrapper at `0x100001130` through authenticated table entry `0x4e04`. The matching byte-table pairs select that entry for every possible lookup byte. The live provenance of the table pointers and the request path into these blocks remain unknown. [Completion and output ABI](live_fpdi_deviceidentity_completion_report.md)

## Call and destination

The instruction census finds ten aligned pairs of `MOVZ X17, #0xf447` and `BLRAA X8, X17` in `__TEXT,__text`. It establishes two call sites with the wrapper's six-argument shape. `LC_FUNCTION_STARTS` places both inside the compiler range `[0x100002784, 0x1001f40fc)`. The table contains authenticated entries into the two call blocks at `0x1000c8e20` and `0x1001742e0`. The range and entries identify code locations. Semantic ownership and an incoming XPC request path are still unknown.

| Call PC | Pointer-table base | Left byte bank | Right byte bank | Key | Bias | Constant XOR term |
| --- | --- | --- | --- | --- | --- | --- |
| `0x1000c8eb0` | X12 | `0x1005b1b40` | `0x1005bc230` | `0xd6` | `0x4d61` | `0xa3` |
| `0x100174364` | X1 before assignment of the key out pointer | `0x10057a1e0` | `0x1005a5e90` | `0xdb` | `0x4dd6` | `0x2e` |
| `0x100174364` | Same | `0x1005b3cf0` | `0x1005542d0` | `0xdb` | `0x4dd6` | `0x2e` |

For lookup byte `b`, the instruction sequence computes `i = bias + (b XOR right[left[b] XOR key])`. At the first site, the bank pointers come from SP+312 B and SP+184 B. At the second site they arrive in X24 and X20. All three pairs yield `i = 0x4e04` on the full 256-value domain. With base `0x1005c0a80`, the effective slot is `0x1005c0a80 + 8 * 0x4e04 = 0x1005e7aa0`. The slot rebases to `0x100001130` with IA diversity `0xf447` and address diversity disabled.

The census covers 469,313 contiguous 256 B windows in the selected 469,568 B `__TEXT,__const` section. A fixed XOR term over all 256 inputs requires a permutation on each side. The 523 permutation windows yield one ordered pair for the first call and two for the second among all in-range fixups with the matching authentication parameters. This uniqueness applies to fixed-slot compositions in the file-backed section and with the stated table base. The first pair matches the banks used by the earlier selector 26 candidate. One pair for the second call matches the one used in its 32 B allocation predecessor. The shared bank addresses establish reuse of lookup tables across these interfaces. A continuous control-flow path between the certificate and IOKit calls remains unknown. [Selector 26 caller evidence](live_fpdi_selector26_caller_report.md)

## Output frames and candidate consumers

Both protected calls pass mode 0 and five nonnull stack addresses. The scheduled caller passes no output addresses. Stack offsets below are relative to SP at each call.

| Output | First call SP offset | Second call SP offset |
| --- | ---: | ---: |
| X1, `SecKeyRef` | 1152 B | 584 B |
| X2, certificate 0 buffer | 544 B | 928 B |
| X3, certificate 0 length | 516 B | 1092 B |
| X4, certificate 1 buffer | 376 B | 632 B |
| X5, certificate 1 length | 1140 B | 944 B |

The block at `0x1000106a4` zeros all five locations of the first layout at `0x1000106b8` through `0x1000106c8`. The block at `0x1001528ec` zeros all five locations of the second layout at `0x10015290c` through `0x10015291c`. The store widths match the wrapper's 8 B references and 4 B lengths. The same-frame paths from those initializers to their respective calls remain unverified.

| Return branch | State that selects candidate | Candidate and observed reads |
| --- | --- | --- |
| `0x1000c8f04` | With W25=`0x3b29` and the restored X30 as the original table base, every wrapper status 0 through 4 selects slot `0x3b29`. | `0x100220ff8` reads all five fields at `0x10022101c`, `0x100221020`, `0x100221028`, `0x100221050`, and `0x100221058`. It transforms both lengths and tests the key and both buffers for null. |
| `0x1001743c8` | With W23=`0x3ba3` and the reloaded X1 as the original table base, statuses 1 through 4 select slot `0x3ba3`. | `0x10022c3dc` reads the key, certificate 0 pointer and certificate 0 length at `0x10022c448` through `0x10022c450`. |

The first branch transforms the status as `status - ((status << 1) & 0x2cb8bbaa) + 0x965c5dd5`, modulo 2^32. At the specified W25, its comparison is unequal across the five wrapper statuses. The second uses a variable shift whose low five bits equal 19 at the specified W23. It subtracts the masked shifted status from the original. Status 0 yields equality and takes the alternate index calculation, which also depends on W20. The return analysis is conditional on the stated register values and frame continuity. It identifies candidate uses of the wrapper's results. The eventual key or buffer consumer and any mapping into a Mach or XPC reply remain unknown.

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| C1 | The file being interpreted is the pinned arm64e image. All locations and bindings depend on this identity. | Verify `LC_UUID` and the selected slice SHA-256. |
| C2 | The call edge receives one of the enumerated byte-bank pairs and the recovered pointer-table base. The wrapper target depends on these reaching values. | Trace both bank pointers and the table base through an incoming branch into each call block. Compare their effective address with `0x1005e7aa0`. |
| C3 | Candidate initializers and consumers address the same live SP frame as their respective calls. The output correlations depend on that identity. | Track SP and the five storage locations through the intervening branches, preserving the 8 B and 4 B store widths. |
| C4 | The return branch receives the stated W25 or W23 and the stated base. The conditional consumer targets depend on this state. | Verify the register reaching definitions and compare an ordinary return against the computed slot and destination. |

High impact for recovering a caller-side use of the DeviceIdentity wrapper with result buffers and locating the point where the results may enter daemon processing. Medium impact for correlating lookup-bank reuse with the separate selector 26 analysis. Native call execution, daemon-to-driver reachability from these blocks, and provider-side Mach transport are unobserved.

## Reproduction

Primary evidence is the installed arm64e slice, UUID `0a404c50-4901-312f-9e36-04565d30f305`, SHA-256 `f73ababfd9265e1bdacde11467d5a3701cec634c49ce3a65f5769cf5ccd843f0`. The audit checks 59 named instruction anchors plus the argument setup at each call, the 10-site instruction census, the containing range for each site against `LC_FUNCTION_STARTS`, the table compositions, and the status arithmetic. It records 384 decoded instructions. For B input bytes, F fixups, P permutation windows, K eligible slots, alphabet size A=256 and I retained instructions, time is O(B + F + PKA + I) and space is O(B + F + PA + I). [Auditor](triage_evidence/audit_live_fpdi_deviceidentity_callers.py) [Compressed receipt](triage_evidence/live_fpdi_deviceidentity_callers_audit.json.zst)

    python3 -B triage_evidence/audit_live_fpdi_deviceidentity_callers.py DAEMON
