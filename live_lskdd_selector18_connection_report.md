# lskdd selector 18 connection provenance

An offline replay of the installed arm64e slice follows a successful IOKit open for `com_apple_driver_FairPlayIOKit` to the selector 18 call. `IOServiceOpen` at `0x1003e8ff8` takes `0x100e82af8` as its output address. The method block loads the same 32-bit cell at `0x100584c9c` and passes the returned word to `IOConnectCallStructMethod` at `0x100584cc8`. The current kernel table identifies selector 18 as `ProcessEncryptedData`. The test substitutes ordinary IOKit results in emulator memory. Native port names and a matched transaction remain unknown. [Installed method table](live_kext_selector26_report.md)

## Connection and service lineage

| Operation | lskdd call site | Observed argument or result in the offline replay |
| --- | --- | --- |
| `IOMainPort` | `0x1006521e0` | Bootstrap argument zero. Publishes the main port through SP+0x88. |
| `IOServiceMatching` | `0x1005c48c4` | The preceding block at `0x10098d968` constructs `com_apple_driver_FairPlayIOKit`. |
| `IOServiceGetMatchingServices` | `0x100404584` | Main port and matching dictionary in, iterator through SP+0x8c. |
| `IOIteratorNext` | `0x1006154c0` | Iterator in, service name returned in W0. |
| `IOServiceOpen` | `0x1003e8ff8` | Service in W0, `mach_task_self_` value in W1, type zero in W2, connection output pointer `0x100e82af8` in X3. |
| `IOObjectRelease` | `0x1003e9058`, `0x1005e3c98` | Releases the service and then the iterator. |
| `IOConnectCallStructMethod` | `0x100584cc8` | Open's connection in W0, selector 18 in W1, distinct input and output buffers, input size and initial output capacity both 3,096 B. |

The lookup at `0x1009e9100` selects the same rebase for every possible low byte i. With byte banks at `0x100d06370` and `0x100d3f620`, `i XOR right[left[i] XOR 0xe2]` equals `0x50`. Adding `0x636` gives pool index `0x686`. Slot `0x100e77350` rebases to `0x100e82af8`, within writable `__DATA,__common`. The same banks with key `0x1e` yield `0xd7`, selecting open and service release with table biases `0x8c20` and `0x8c25`.

The earlier replay entered `0x100654a48` with a null X15. The matching branch from `0x1009e9120` instead reaches `0x10098d968`, which constructs the class string and loads X15 with `0x100e82ab4`. Its zero-initialized byte takes the open branch. The block also passes the connection cell through X1 to SP+0x20, which the open call loads into X3, and through X13 to SP+0x40, which the method call dereferences. The successful route clears the temporary class string before calling the method. [Earlier selector 18 audit](live_lskdd_selector18_binding_report.md)

## Mach boundary on the recovered route

| RPC | Installed framework transport site | Outgoing rights | Incoming reply |
| --- | --- | --- | --- |
| 2862 open, 80 B | `0x184ebdc6c` | Service destination COPY_SEND, local reply MAKE_SEND_ONCE, task descriptor COPY_SEND. | 2962, 52 B on the complex path. On success the connection send descriptor becomes a task-local name and is written to the open output cell. |
| 2865 method, 3,180 B | `0x184ebe090` | Connection destination COPY_SEND, local reply MAKE_SEND_ONCE. | 2965, 3,148 B with the full 3,096 B output, or 36 B on the ordinary short error path. |

The Mach mapping follows the installed framework and kernel sources for those argument shapes. The replay ends at the daemon's method import. [Mach transport](live_iokit_mach_transport_report.md) [Open status and envelope](live_fairplay_iokit_open_report.md) [Connection copyout](live_fairplay_connection_report.md)

## Assumption register

| ID | Premise and dependent result | Falsification check |
| --- | --- | --- |
| LC18.1 | The pinned arm64e image describes the installed executable. Addresses and chained fixups depend on that identity. | Recompute its SHA-256 and UUID and compare original fixup targets and discriminator values. |
| LC18.2 | The modeled frame begins with initial dispatch index `0x6a8e`, a nonnull context object and a context byte selecting the matching branch. This establishes a continuous route for the fixture. Native initialization of those context values is unknown. | Observe the caller's context and test whether its initialized frame selects the same branch. |
| LC18.3 | IOKit returns successful results and provides the associated output values. The shared connection flow depends on these outcomes. | Repeat with distinct synthetic connection values and compare the value written at open with the value loaded into W0 at selector 18. |
| LC18.4 | The system uses the pinned IOKit image and the synchronous inline transfer. The Mach envelope depends on those premises and the returned byte count. | Correlate the task-local service, task, reply and connection names in a passive native open and method transaction. |

High impact for the connection producer and consumer join. Medium impact for understanding the first-use matching branch and temporary string lifetime. Native invocation frequency and connection reuse remain unknown.

## Reproduction and verification

Set `LSKDD_IMAGE` to the unmodified fat executable. Run the auditor with Python, Capstone, Unicorn and Apple `dyld_info`.

```sh
python3 triage_evidence/audit_live_lskdd_selector18_connection.py "$LSKDD_IMAGE"
```

The auditor checks 768 byte inputs across three lookup equations and matches 6,214 authenticated transfers against original fixups in each of two runs. The runs use distinct synthetic connection words and verify the same-cell load, the service class, the release order and the six method arguments. The replay uses O(E) time for E executed instructions and O(M + B) storage for the mapped image and stack M plus B distinct recorded branch edges. The fixed bank equations each use O(256) time and storage. [Auditor](triage_evidence/audit_live_lskdd_selector18_connection.py) [Compressed receipt](triage_evidence/live_lskdd_selector18_connection_audit.json.zst)
