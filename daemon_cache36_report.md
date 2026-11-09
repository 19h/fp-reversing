# Daemon cold-cache hardware-property and formatting interfaces

The cold-cache prefix queries four obfuscated MobileGestalt keys, converts the `UniqueChipID` answer through `CFNumberGetValue`, and prepares a five-object `CFStringCreateWithFormat` call. This establishes a hardware-property formatting role for the recovered blocks. The contents of the 36-byte cache, its consumers, its association with a driver request, and the native caller remain unknown. The full daemon/kext/deeper-interface investigation remains active.

This increment continues the matching-table paths in the [clock/value-lookup report](daemon_object_clock_report.md). It restores 24 retained boundaries, runs 432 declared continuations covering 205,008 original instruction visits, checks every case again, and proves 11 source-local obligations. No native property query, allocation, CoreFoundation operation, Mach message, IOKit call, or hardware pointer authentication executes. `analysis.md` and the supplied kext files are preserved. The earlier RAX strace remains historical emulation evidence; this increment adds no native trace correlation.

## Evidence and identity

| Item | Verified scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Live IDB | `fairplayd`, target `6b117c693e3b`; 12 ranges / 1,279 bytes |
| Original source | 12 selected spans, 707 distinct executed opcodes, 52 original fixups |
| Restored parent evidence | 24 contexts; 1,804,820 retained instruction visits / 427,656 memory effects reconstructed |
| Source proofs | 11 original/simplified proof pairs, 22 SMT files; 78 lifted instructions |
| Conditional cases | 432 persisted and freshly recomputed; 43,152 source reads / 7,536 source writes |
| Declared API models | 3,744 total: 432 allocation, 1,440 MobileGestalt, 240 number conversion, 192 chip formatting, 1,440 release requests |

The IDB resolves chained pointers in constant strings. Its opcode/string-byte ranges match original bytes directly; constant-string metadata matches after explicitly accounting for the ISA and character-pointer fixups. No equality between raw on-disk chained words and IDB-resolved pointer words is claimed. The original ISA binding is `CoreFoundation/___CFConstantStringClassReference`, key DA, diversity `6AE1`, address diversity enabled. The observed IDB ISA value is `0x1010CA4D8`; its native runtime address is unknown.

Evidence: [contracts and original spans](triage_evidence/daemon_cache36_contracts.json), [restored contexts](triage_evidence/daemon_cache36_context.json), [conditional journals](triage_evidence/daemon_cache36_profiles.json), [proofs](triage_evidence/daemon_cache36_proofs.json), [independent checks](triage_evidence/daemon_cache36_checks.json), [primary key reference](triage_evidence/daemon_cache36_mgkeys_reference.json), [SDK source](triage_evidence/daemon_cache36_sdk.c), and [generated ARM64 assembly](triage_evidence/daemon_cache36_sdk.s).

## Recovered routine roles and property queries

All addresses below are daemon virtual addresses. Hexadecimal offsets and byte counts are explicit; `u32` and `u64` arithmetic wraps modulo 2^32 and 2^64 respectively.

| Original call PC | Key CFString | Literal key bytes, length 22 | Corroborated property name |
| --- | --- | --- | --- |
| `0x100BAB21C` | `0x1010B1AF8` | `VasUgeSzVyHdB27g2XpN0g` | `SerialNumber` |
| `0x100C9941C` | `0x1010B1AB8` | `gI6iODv8MZuiP0IA+efJCw` | `WifiAddress` |
| `0x100A42444` | `0x1010B1A38` | `k5lVWbXuiZHLA17KGiVUAA` | `BluetoothAddress` |
| `0x100B2C150` | `0x1010B1B38` | `TF31PAB6aO8KAbPyNKSxKA` | `UniqueChipID` |

Each call resolves original slot `0x1010A0DC8` to `_MGCopyAnswer` in libMobileGestalt, authenticated IA diversity `8E26`, address diversity disabled, total addend zero. Source sets X0 to the indicated constant and X1 to zero. This establishes observed register arguments; the private API's exact target-version prototype and arity remain unknown. Returned objects are checked for presence along this prefix; their native types and contents remain unknown. Later use through `%@` does not establish that an answer is a native CFString.

For each candidate name, independently recomputed `base64(MD5(UTF8("MGCopyAnswer" + name)))[:22]` exactly equals the original key bytes. The selected entries and algorithm are pinned to MGKeys commit `db9cf77fa9d5330070b3dcb73fc1fd6a271fc421`; this corroborates the names without identifying the target libMobileGestalt version. Sources: [pinned mapping](https://github.com/PoomSmart/MGKeys/blob/db9cf77fa9d5330070b3dcb73fc1fd6a271fc421/mapping-gestalt.h), [pinned algorithm](https://github.com/PoomSmart/MGKeys/blob/db9cf77fa9d5330070b3dcb73fc1fd6a271fc421/obfuscate.py). The recorded source hashes and selected rows permit independent comparison; the mapping's historical platform comments are not target-version evidence.

| Source block | Established conditional role |
| --- | --- |
| `0x1009C0148` / `0x1009C0154` | Request 36 bytes, then publish the full allocation return through global `0x1010C6840` before the NULL dispatch |
| `0x100BAB1A4` onward | Prepare first hardware-property query |
| `0x100C993B4` | Save serial answer in X21 and query Wi-Fi property |
| `0x100A42410` onward | Preserve Wi-Fi answer in X22 and query Bluetooth property |
| `0x100B2C128` | Save Bluetooth answer in X23 / SP+3288 and query chip property |
| `0x1009BA800` onward | Request signed-64 conversion into SP+2B70 |
| `0x1009B4254` onward | Format converted chip value using `%qi` |
| `0x100AD6F88` onward | Prepare five-object identity formatting |
| `0x100BB15D0` | Read an unresolved saved base pointer at SP+3050 on the checked missing/failure paths |

These are block roles within obfuscated control flow; no new compiler function boundaries or native entry prototypes are assigned.

## Allocation, conversion, and variadic ABI

Let F denote the restored source SP and C the declared non-NULL allocation return. The checked prefix requests `malloc(36)` at `0x1009C0148` through slot `0x10109FF58`, IA `6AA4`. Source store `0x1009C0154` writes C to `0x1010C6840`. Every one of the 432 cases publishes C before its first property query. The static all-u64 store proof also covers a zero return; these dynamic cases supply only non-NULL returns. Native allocation failure behavior beyond the previously recovered dispatch is unknown.

The entire 36-byte allocation is marked undefined after allocation. Source reads cannot consume the A5/5A backing patterns as allocator output. Zero cache bytes are source-defined at either checked frontier. Publishing a pointer before filling its contents is observed source order; native concurrent visibility, synchronization, and any erroneous reader are unknown.

At `0x1009BA810`, original slot `0x1010A0B28` resolves `_CFNumberGetValue`, IA `8642`, addend zero. X0 is the opaque chip answer, X1 is 4, and X2 is F+2B70. The installed SDK defines type 4 as `kCFNumberSInt64Type`, with an 8-byte signed output and a 1-byte `Boolean` result. Original source initializes F+2B70 to zero earlier. The declared conversion model writes an independent 8-byte value even for a failure return; no native failure-output preservation is assumed.

Under the source phase W20=AB4E, W19=471C, W25=8F46, instructions `0x1009BA818..834` select table index 8F46 when W0==0 and 8F4B otherwise. The proof covers every u32 W0. Upper X0 bits are ignored by this branch. Native normalization of the Boolean return register is unknown; the finite cases declare W0 as 0, 1, or 01000001 and vary the upper 32 bits of X0 independently.

At `0x1009B42D4`, `_CFStringCreateWithFormat` receives `(NULL, NULL, CFSTR("%qi"), ...)`, slot `0x1010A0008`, IA `FE9E`. Source loads the full converted 64-bit word and stores it at `[SP]` at `0x1009B42C0`. On the checked non-NULL formatted-answer path, the next call at `0x100AD6FCC` uses the same import and `CFSTR("%@%@%@%@%@")` at `0x1010B1A98`.

| Variadic location at `0x100AD6FCC` | Source argument | Meaning bounded by evidence |
| --- | --- | --- |
| F+00, 8 bytes | X21 | Opaque serial answer |
| F+08, 8 bytes | X27 | Empty constant CFString `0x1010B1A18` |
| F+10, 8 bytes | X0 from preceding formatting call | Opaque formatted chip answer |
| F+18, 8 bytes | X22 | Opaque Wi-Fi answer |
| F+20, 8 bytes | X23 | Opaque Bluetooth answer |

X0/X1 are NULL; X2 points to the five-`%@` format. GPR X3..X7 are caller-clobbered values and are not the variadic arguments here. A source-local all-u64 proof establishes the five store positions/order. Compiling the [SDK probe](triage_evidence/daemon_cache36_sdk.c) for Apple ARM64 emits matching stack positions for one signed-64 and five object arguments. This validates local ABI layout; it does not execute either formatting call or establish exact resulting string bytes, MAC notation, encoding, digest, cache representation, or identifier stability.

```
36-byte allocation -> publish C6840 -> serial -> Wi-Fi -> Bluetooth -> chip
                                                                  |
                                          signed64 output at F+2B70
                                                                  |
                                         %qi, argument at F+00
                                                                  |
                          %@%@%@%@%@, arguments at F+00..F+20
                                                                  |
                                          stop before native call

first missing answer / conversion zero / formatting NULL
  -> source CFRelease requests -> stop before reading F+3050
```

## Conditional paths, releases, and unresolved caller state

The cases combine 24 restored clock/lookup contexts, two heap placements/backing patterns/volatile-register patterns, and nine outcome classes. Four classes stop at the first missing answer; unqueried subsequent answers have no effect on these sequential prefixes. The all-present class covers conversion zero and two nonzero W0 values, each with NULL/non-NULL formatting outcomes when applicable. This is 24 * 2 * 9 = 432 declared cases. It is not exhaustive over native library states or returned object contents.

| Checked frontier | Cases | Established limit |
| --- | --- | --- |
| Before `0x100AD6FCC` | 96 | Five ordered stack arguments and formatting import established; result not supplied |
| Before `0x100BB15D0` | 336 | Required 8-byte SP+3050 value is not fully defined by retained inputs/effects |

Release requests use `_CFRelease` through slot `0x1010A02E0`, IA `1883`. The 1,440 modeled calls include conditional requests for earlier successful answers and the empty constant. Calls are recorded as requests only. No reference count, deallocation, immortality, ownership correctness, or native library side effect is inferred from the opaque model. The original source sites include `0x1009D5168` (serial), `0x1009E0C28` (Wi-Fi), `0x100A05408` (Bluetooth), `0x100B9F658` (chip), and empty-constant requests at `0x100B24140` / `0x1009B7640` on applicable paths. Their exact sequences are retained per case.

A full original-text census for the single encoding `STR Xn,[SP,#0x3050]` finds three sites:

| Direct writer | Stored expression or register | Context still unknown |
| --- | --- | --- |
| `0x1007CFA88` | SP+C070+u64(SP+16D0) | Producer of SP+16D0 and continuity to this prefix |
| `0x100ACE980` | X13 | Upstream X13 provenance and applicable phase |
| `0x100BDB268` | X20 | Upstream X20 provenance and applicable phase |

The first expression is proved modulo 2^64. These sites are candidates from other source contexts, not a joined caller chain. The census does not exclude computed, paired, alias, or non-immediate writes. The consumer derives offsets 32C, 11C, 20F, and E4 from the missing base; these expressions are proved without inventing its pointer value. Its owner and relation to the 872-byte object remain unknown.

## IPC, environment, and bounded continuation questions

No additional incoming/outgoing Mach right, message ID, disposition, IOKit selector, or emission site is established in this increment. No checked source call enters Mach or IOKit. MobileGestalt's internal implementation and possible IPC remain unknown. The previously saved `_kIOMainPortDefault` value is not used to establish any transfer here. This distinguishes a newly recovered environmental-property interface from transport evidence.

| Impact | Next bounded question | Falsifiable evidence sought |
| --- | --- | --- |
| High | What does the five-object string feed? | Continue from AD6FCC with separately declared CF return/bytes; recover exact CF consumers and subsequent cache stores |
| High | What is the 36-byte cache representation? | Establish every store/read width and consumer before assigning digest, key, identifier, or wire role |
| High | Which caller produces SP+3050? | Join one actual producer/frame epoch to BB15D0 with defined-byte provenance |
| High | Does this path feed the kext? | Join a native caller/data owner to a known Mach or IOKit emission, without treating phase471C as a transport selector |
| Medium | Which target MobileGestalt supplies these answers? | Match exact image UUID/hash/import exports; establish object types and internal IPC from that image |
| Medium | How is the published cache synchronized? | Recover readers, initialization state, locking and lifetime; current publication order alone establishes no concurrent behavior |
| Low | Does native formatting use signed decimal chip text? | Match the actual CF implementation/ABI and compare returned string bytes; current evidence is format literal plus signed64 request |

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| C36-1 | Binary and live IDB identities match / all source claims | Rehash thin input and compare raw code and normalized chained-pointer fields |
| C36-2 | Retained parent premises remain applicable / all continuation claims | Rebuild all 24 contexts from ordered source and declared API effects; native AEE caller remains unknown |
| C36-3 | Restored F is the current frame / stack arguments and failures | Check entry/boundary SP and actual producer/frame continuity; do not join distinct epochs by equal offsets |
| C36-4 | malloc returns declared valid 36-byte owners / dynamic cache paths | Two placements/patterns; reject every read until source-defined; native failure path not dynamically modeled |
| C36-5 | Four supplied answer pointers are opaque / property presence paths | Use NULL at each first missing query; reject any unmodeled object-memory access |
| C36-6 | Pinned key convention applies / clear property names | Independently hash all four names; match target MobileGestalt version to establish native interpretation |
| C36-7 | CF conversion outputs are declared, including full W0 / conversion paths | Zero/nonzero/upper-bit variants; universal u32 source-gate proof; do not assume failure preserves output |
| C36-8 | Formatting return is an opaque declared pointer / second-call frontier | NULL and non-NULL models; original variadic stores and SDK assembly must agree |
| C36-9 | Public SDK types/layout apply to the observed calls / public ABI labels | Compile exact signatures/widths; target library/version mismatch would limit runtime conclusions |
| C36-10 | Modeled APIs preserve callee state and have only declared memory effects / finite source continuation | Clobber X1..X17, X0/X30/NZCV as declared; no native reentrancy or source-global side effect established |
| C36-11 | Logical chained targets model source dispatch / executed block edges | Verify original slots, modifiers/addends and pointer origins; native PAC feasibility remains unknown |
| C36-12 | Direct SP3050 encoding census is bounded / writer candidates | Search computed/paired/alias writers and join real control flow; stop at undefined byte reads |
| C36-13 | Recovered source order has no implied native concurrency or transport semantics / architectural claims | Recover cache readers/locks and actual send/IOKit caller; new emission remains unknown |

## Reproduction and quality gates

Use `/Users/___/Downloads/zut/.venv/bin/python -P` with `PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages` and `Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime`. The ordered producers are `capture_daemon_cache36.py`, `probe_daemon_cache36.py`, `recover_daemon_cache36.py`, `prove_daemon_cache36.py`, and `validate_daemon_cache36.py` in `triage_evidence`. The SDK compile command is retained in the contracts. Algorithms and complexity are documented in each script: replay/byte checking is linear in visited instructions plus effects/defined bytes; the direct writer census is linear in original text bytes; SMT solving is resource-bounded rather than assigned a polynomial bound. All numeric counts concern this finite source/model corpus; they have no sampling error interpretation.

QG1 passes for factual source/ABI analysis. QG2 passes with C36-1 through C36-13 and probes. QG3 passes for this increment; the full objective is incomplete. QG4 passes for explicit byte widths, modular equations, case counts and compiled ABI checks. QG5 passes with unresolved caller/cache/type/PAC/native states explicitly bounded. QG6 passes for original bytes/fixups, live-IDB readback, rebuilt proofs, fresh cases, independent byte ledgers and pinned key provenance. QG7 passes with the impact-bounded continuation table. [Preservation checks](triage_evidence/daemon_cache36_preservation.json) and [scoped delivery gates](triage_evidence/daemon_cache36_quality_gates.json) record final delivery validation.
