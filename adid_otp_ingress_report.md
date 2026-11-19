# CoreADI OTP ingress and reply emission

The `adid` handler for CoreADI command `0xcfe0b46a` reads a big-endian 64-bit operand at request offsets 12–19, stages it in an XOR-encoded frame cell and calls the VMM environment helper. Two retained callbacks with distinct operands reach a later zero-operand test, return four reply bytes `ffff4ffb` and request XPC reply emission at `0x1000aaa70`. Both use modeled VMM query success with value 0. Neither visits the known primary FairPlayIOKit or Avp call sites. The clock-success `fairplayd` request uses the same wire layout with operand `0xfffffffffffffffe`. The provider execution for that operand and the native cross-layer transaction remain unknown.

## Request and data flow

```text
akd named OTP operation       fairplayd clock-success request
            |                 |
            +------ data -----+
                      |
            com.apple.adid peer callback 0x100029fc8
                      |
            data getter 0x1000aa598
                      |
            command equality 0x10016d454 -> 0x10016dab8
                      |
            BE64 at offsets 12..19 -> XOR -> [SP+0x16e8]
                      |
            VMM helper 0x10002ba5c -> result byte at record+4
                      |
            [SP+0x16e8] -> [SP+0x1e90] and zero-operand test
                      |
            retained reply: data (4 B) -> XPC send 0x1000aaa70
```

The `fairplayd` producer and synchronous-send boundary come from the [CoreADI request-origin report](daemon_adid_request_origin_report.md). The method name `requestOTPForDSID:outMID:outMIDSize:outOTP:outOTPSize:` comes from the original `akd` client. It supports the interpretation of the scalar as a DSID in that client API. The current provider code establishes a 64-bit field and a zero test. Its complete business semantics and any reserved-value interpretation are unknown. [Named akd client and paired callback](akd_adid_client_report.md)

| Offset (B) | Width (B) | Observed wire field | Consumer |
| --- | ---: | --- | --- |
| 0 | 4 | BE32 1 | Common first-word gate |
| 4 | 4 | BE32 `0xcfe0b46a` | Adds `0x0046d726` modulo 2^32. Encoded value `0xd0278b90` selects `0x10016dab8`. |
| 8 | 4 | BE32 1 | Common reader consumes this word. Its global meaning is unknown. |
| 12 | 8 | BE64 operand | Eight `LDRB` instructions from `0x1001af0ec` through `0x1001af140` feed shifts 56, 48, 40, 32, 24, 16, 8 and 0. |
| 20 | 8 in one fixture | Zero-filled suffix | The 28 B callback terminates with no reads at or above offset 20. Full length grammar remains unknown. |

The current operand reader reloads the input pointer from frame+0x2728 at `0x10016e460`. The archived XPC getter and byte-read records tie that pointer to the same `data` bytes in both cases. At `0x1001af170`, the result is `x + K - ((2K) & (2x))` modulo 2^64 for decoded scalar `x` and `K = 0xda8ca8cae5dfbd2d`. Since `x + K = (x XOR K) + 2(x AND K)` and `(2x) AND (2K) = 2(x AND K)` modulo 2^64, the result is exactly `x XOR K`. The store at `0x1001c0250` stages this result. The observed continuation reloads it at `0x100219ec0`, copies it to frame+0x1e90 at `0x100219eec` and compares it against `K` at `0x100219f04`. Equality therefore means `x == 0` over the full 64-bit domain. Both recorded operands are nonzero and the dispatch at `0x100219f38` reaches `0x10024d5f8` in both callbacks.

| Evidence | Length (B) | BE64 operand | Derived staged word | Provider output |
| --- | ---: | --- | --- | --- |
| Retained named `akd` callback | 20 | `0x1122334455667788` | `0xcbae9b8eb0b9caa5` | `ffff4ffb` |
| Retained command-tree callback | 28 | `0xfffffffffffffff8` | `0x257357351a2042d5` | `ffff4ffb` |
| Retained `fairplayd` clock-success producer | 20 | `0xfffffffffffffffe` | `0x257357351a2042d3` by source equation | Unknown |

## Environment and external interfaces

| Site | Corroborated local role | Boundary |
| --- | --- | --- |
| `0x1001c0308 → 0x1001c0314` | Passes a local record at caller FP-0xa8 as X0 into `0x10002ba5c`. | Selected branch under the archived initial state. |
| `0x10002bd94 → 0x10002bdac` | Requests `kern.hv_vmm_present` with a 4 B output extent. Writes 10 at record+4 exactly when query status is zero and its output is 1. Otherwise writes 9. | Each callback models status 0 and value 0, yielding byte 9. Earlier isolated controls establish the helper predicate. [Helper analysis](adid_startup_report.md) |
| `0x1001c0318` | Caller reads record+4 and carries it into subsequent record setup. | The complete OTP branch for byte 10 is unknown. |
| After environment query | The callbacks record modeled `lstat`, `open`, `fstat`, `fchmod`, `statfs`, `lockf`, `close` and `unlink`. | These events establish filesystem and lock interfaces in the retained continuation. Native effects and their causal relevance to the reply code remain unknown. |
| `0x1000aa910` | Core callback returns wrapper status 0 and provides a 4 B output. | The wrapper status and the BE32 payload status are distinct. |
| `0x1000aa9fc → 0x1000aaa70` | Sets the reply dictionary's `data` from the core output, then calls `_xpc_dictionary_send_reply`. | The payload is signed BE32 `-45061` in both cases. The numeric Mach port name and native delivery are unknown. [Current XPC bindings](live_fairplay_adid_ipc_report.md) |

The complete retained callbacks contain no IOKit, raw Mach-port or notification-post API events. They avoid the documented primary acquisition and selector-26 sites `0x1000208fc`, `0x10001f908` and Avp acquisition or call sites `0x10002af70`, `0x10004967c`, `0x100058a1c`. The demonstrated Avp method-100 path belongs to raw command `0x76e89210` at `0x10016db8c`. This separates the recorded OTP callbacks from that established route. Other provider states, the zero-operand branch and the relation to an upstream FairPlayIOKit request remain unknown. [Provider IOKit sites](adid_iokit_report.md), [Avp method-100 command](adid_command_dispatch_report.md)

## Assumptions, provenance and validation

| ID | Claim scope | Verification or falsification condition |
| --- | --- | --- |
| A1 | Current instruction addresses and disassembly identify the installed arm64e slice. | Pin its SHA-256 and byte-compare every recorded instruction against the corresponding archive. A different image or any mismatched address or word invalidates this comparison. |
| A2 | Retained observations apply to two private callbacks with declared model state and APIs. | Independently recheck the order and next destinations of 12 edges per callback, the XPC pointer and byte records, and the complete PC-and-instruction digests. Native PAC, audit, permissions and dispatch behavior remain unknown. |
| A3 | Operand byte order and the zero predicate apply to the inspected instructions. | Check the original shift widths and frame transfers, use the full-width modular identity, and check zero, all ones, each single-bit operand and the three listed values. No callback using a zero operand is asserted. |
| A4 | The `fairplayd` payload shares the observed command and field layout. | Recheck the producer bytes and the named `akd` comparison against the retained audits. Equality of format gives a derived staged word. A matched provider execution would be required to assign the producer's actual reply. |
| A5 | The absence of known IOKit call sites applies to the two complete retained callbacks. | Recheck the full recorded PC sequences and API events. A different environment or path requires independent coverage. |

Primary evidence is the installed `adid` arm64e Mach-O, SHA-256 `b9e0043fbbc4525ad1a78545155c6c096422688de2ce3a3fc0144ab6adab9895`, and the two retained original-code callback profiles from archive SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`. All 88,807 recorded visits match the current 4 B instruction words at the same unslid addresses. Separately, 37 source anchors and 69 scalar controls pass. The matched code words corroborate the archived instruction evidence on the installed slice; their environment and API outcomes remain modeled. The audit sends no messages. Run it with the installed universal image as the sole argument. [Auditor](triage_evidence/audit_adid_otp_ingress.py), [audit results](triage_evidence/adid_otp_ingress_audit.json.zst), [paired archive](triage_evidence/akd_adid_pair_profiles.json.zst), [command archive](triage_evidence/adid_command_dispatch_profiles.json.zst)

The environment branch has high impact on any daemon-to-kext attribution because both retained callbacks take the same modeled value-0 continuation. The distinct wrapper and wire statuses have medium impact on interpreting trace evidence because a wrapper status of zero accompanies a negative payload. The unread 8 B suffix has low impact on the recovered request format and leaves the complete extent grammar unresolved. Correlation across the actual `fairplayd` request, provider state and a native kext call remains open.
