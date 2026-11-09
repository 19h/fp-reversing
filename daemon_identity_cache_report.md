# Daemon identity string: UTF-8 and SHA-1 preparation interfaces

The five-object formatting result reaches a UTF-8 conversion, an actual converted-byte count, and a 100-byte context with the encoded SHA-1 IV. Short declared inputs produce the expected first padded SHA-1 block after decoding the source's byte representation. Longer inputs prepare their first 64-byte input block and enter compression through a different branch. No completed digest or initialized byte of the separately allocated 36-byte cache is established. The full daemon/kext/deeper-interface investigation remains active.

This continues the [hardware-property formatting report](daemon_cache36_report.md). The new evidence restores 96 retained formatting boundaries and records 768 declared continuations / 4,034,496 original instruction visits. Each case is freshly recomputed and its ordered memory effects are checked independently. Native caller continuity, object contents, CoreFoundation execution, allocator execution, hardware PAC, and transport remain outside these conditional claims.

## Evidence boundaries and reproducibility

| Evidence | Scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Live IDB | `fairplayd`, target `6b117c693e3b`; 10 matching original-byte ranges / 1,404 bytes |
| New original-source coverage | 14 selected spans; 1,250 distinct executed opcodes; 63 verified original fixups |
| Parent reconstruction | 96 contexts; 33,120 retained instruction visits / 8,832 effects reconstructed |
| New conditional execution | 768 cases; 4,034,496 source visits; 336,672 reads / 157,824 writes |
| Source proofs | 12 original/simplified pairs; 24 SMT files; 86 lifted instructions |
| API boundary models | 5,856 explicit requests/results; no native target/library/IPC operation executes |

[Contracts and original spans](triage_evidence/daemon_identity_cache_contracts.json), [restored contexts](triage_evidence/daemon_identity_cache_context.json), [conditional journals](triage_evidence/daemon_identity_cache_profiles.json), [source proofs](triage_evidence/daemon_identity_cache_proofs.json), [independent checks](triage_evidence/daemon_identity_cache_checks.json), and the [SDK probe](triage_evidence/daemon_identity_cache_sdk.c) contain the reviewable evidence. Earlier [RPC502 certificate evidence](rpc502_certificate_report.md) establishes another use of the shared helper and context representation; it does not establish a caller or transaction relationship between these paths.

All addresses are daemon virtual addresses. F denotes the restored outer SP; B denotes the separately declared temporary byte-buffer return. Offsets are hexadecimal, extents are bytes, `u32`/`u64` arithmetic wraps modulo 2^32/2^64, and source frame epochs are distinguished explicitly.

## External ABI and byte-unit recovery

| Original call PC | Resolved import | Original slot / IA diversity | Observed contract |
| --- | --- | --- | --- |
| `0x100AD6FCC` | `_CFStringCreateWithFormat` | `1010A0008` / `FE9E` | Five object arguments in serial/empty/chip-text/Wi-Fi/Bluetooth order; opaque result |
| `0x100BAB080` | `_CFStringGetLength` | `1010A0E88` / `8E26` | X0=formatted object; returns CFIndex length in 16-bit Unicode code units |
| `0x100BAB0D0` | `_CFStringGetMaximumSizeForEncoding` | `1010A01B8` / `F08F` | X0=that length; W1=`08000100`, the SDK UTF-8 encoding value |
| `0x100BAB11C` | `_malloc` | `10109FF58` / `6AA4` | X0=returned maximum M plus one, modulo 2^64 |
| `0x100B90F78` | `_CFStringGetCString` | `1010A12A8` / `7208` | X0=object, X1=B, X2=M+1, W3=`08000100` |
| `0x100915450` | `_strlen` | `10109FFA8` / `FE9E` | X0=B; returns bytes before the first NUL |
| `0x100B03B68` | `_free` | `10109FF30` / `46A2` | X0=B on the checked conversion-failure cleanup path |

All listed bindings have addend zero and address diversity disabled. Exact slots, encoded chained words, import ordinals and library paths are retained in the contracts. `_CFRelease` requests additionally use original slot `1010A02E0`, IA `1883`.

At `0x100BAB100`, source computes X24=M+1. At `0x100BAB120`, it saves the allocation return into F+3308. A source byte loop at `0x100ACCC38` zeroes the complete declared non-NULL allocation before `CFStringGetCString`: one zero store per byte, with no skipped or duplicate address in the checked cases. This loop is distinct from initialization of the 36-byte cache.

The SDK probe verifies 8-byte CFIndex, 4-byte CFStringEncoding, 1-byte Boolean, UTF-8 value `08000100`, and the public function signatures. Compilation checks declarations and layout; it executes no target function. The target CoreFoundation image/version remains unknown. The private formatting object and its native contents are opaque.

For the cases, the capacity-bound result is independently declared as M=3*L, with L in 0, 1, 64, or 256 UTF-16 code units. This is an input fixture, not a recovered implementation of `CFStringGetMaximumSizeForEncoding`. Successful output fixtures are ASCII or U+00E9; they are supplied independently of the opaque preceding property objects. Their feasibility as the actual five-object formatting result is unknown. In particular, these tests establish source behavior under their declared outputs, not a complete native library chain.

| Declared converted text | UTF-16 code units | UTF-8 bytes before NUL | M+1 allocation bytes |
| --- | --- | --- | --- |
| Empty | 0 | 0 | 1 |
| `A` | 1 | 1 | 4 |
| U+00E9 | 1 | 2 | 4 |
| 64 ASCII characters | 64 | 64 | 193 |
| 256 ASCII characters | 256 | 256 | 769 |

The conversion model invalidates the entire buffer before defining its successful output plus NUL. Its remaining capacity is undefined; conversion failure defines no output bytes. This avoids inferring preservation from the preceding source zero fill. The `strlen` model scans only a verified defined prefix ending in NUL. It does not scan or infer the undefined tail.

Instructions `0x10091545C..4D4` reduce the returned byte length N to:

```text
W5 = (low32(N) + 0x1AD72F12) mod 2^32
```

The source proof covers every u64 N under the recorded phase W19=9930. Upper 32 bits do not survive this expression. This establishes a representation width; it does not establish native feasibility, safety, or downstream behavior for strings exceeding the finite corpus. NUL is excluded from the byte count. The U+00E9 case verifies that the downstream count is two bytes despite the one-code-unit CF length.

## Context, input encoding, and short/long control flow

At `0x1009153B4..3F0`, source initializes the context at F+3C70. A source-local proof verifies these exact fields:

| Context offset | Width | Source value / role supported here |
| --- | --- | --- |
| +00..+3F | 64 | Encoded input/padding buffer; initialized later by source writes |
| +40 | 4 | Counter word, initially zero |
| +44 | 4 | Counter word, initially zero |
| +48 | 4 | `93BC0EF6` |
| +4C | 4 | `1B34867E` |
| +50 | 4 | `6C43F109` |
| +54 | 4 | `E4CB7981` |
| +58 | 4 | `372BCC07` |
| +5C | 4 | Output size 20 |
| +60 | 4 | Algorithm selector 2 |

XOR of the five state words with `F4F92DF7` gives `67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0`, matching the SHA-1 IV in [FIPS 180-4 section 5.3.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). This identifies the initialized context convention. Complete compression and final digest bytes are not established on these continuations.

The byte-store expression at `0x10095EB08..18` reduces in its low eight bits to input_byte XOR98, proved independently for every input word. For short inputs of 0, 1, and 2 converted bytes, the final 64-byte context buffer decodes exactly as:

```text
input[N] || 80 || zero[55-N] || BE64(8*N)
```

Here N is in bytes and 8*N is in bits. This matches the one-block SHA-1 padding rule in [FIPS 180-4 section 5.1.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). All 288 short-input blocks are checked byte-for-byte. The two longer fixtures produce the first 64 input bytes XOR98 and stop before the missing compression frame field; all 192 such blocks are checked. No SHA-1 output is substituted for source execution.

```
five-object formatting result
  -> CF length (UTF-16 units)
  -> UTF-8 maximum M -> malloc(M+1) -> source zero fill
  -> CFStringGetCString -> strlen (bytes before NUL)
  -> encoded low32 byte count -> initialized 100-byte SHA-1 context
       +-> short: shared helper -> encoded padding -> missing SP+2E50
       `-> long: first 64 input bytes -> compression -> missing SP+2C8C

NULL formatting / NULL allocation / conversion failure
  -> release/free requests -> missing SP+3050

36-byte cache: zero source-defined bytes at every checked frontier
```

The short-input path constructs a stack record at F+DE90 and calls `0x100440BE4` from `0x100BD9B9C`, through a source-authenticated rebase with IA `EC9D`. The record points to F+3C70 at +8. This helper is also present in the earlier certificate path. Sharing implementation and context format establishes an architectural touch point; it does not establish that hardware-identity data is a certificate or that both paths share transport, policy, or callers. The long-input path enters compression without this helper call. The independent check caught and corrected an initial assumption that both branches called it.

## Runtime state and unresolved frame producers

The short helper's first unknown runtime scalar is u64 `0x1010B69D0`. To continue its source prefix, cases explicitly declare that initial word as zero or all ones according to their parent placement/pattern. This does not replace a pointer, phase, or branch target. Its native initial value, producer, synchronization, and semantic purpose remain unknown.

Let S be that word, G the retained u64 at `0x1010C4670`, and F the outer frame. The helper subtracts 16 from SP, so its local address is F-8. Source proves:

```text
T = (F-8) XOR S XOR G
B69D0' = (T * 0x0A5CD4CF) XOR 0x73D046208EAED1A6
C4670' = (T XOR 0x73D046208EAED1A6) * 0x0A5CD4CF
```

These are modulo-u64 source updates. The subsequent bank identity is exhaustively checked for all 256 byte inputs and reconstructs dispatch base `0x101039EF0`; no desired internal branch target is forced. The long paths do not read this helper scalar before their frontier.

| Frontier / cases | Missing state | Direct source writer evidence |
| --- | --- | --- |
| `0x100BB15D0` / 288 | u64 F+3050 | Prior report lists `7CFA88`, `ACE980`, `BDB268`; caller continuity remains unknown |
| `0x100ABEE7C` / 288 | u64 F+2E50 | `0x1005F51C8` stores X28+100; `0x100926EA4` stores X4 |
| `0x100ABEE84` / 192 | u32 F+2C8C | `0x100AEE3B8` stores W2 |

The new censuses scan the entire original text for the direct unsigned-immediate `STR Xn,[SP,#2E50]` and `STR Wn,[SP,#2C8C]` encodings. They do not exclude paired, computed, alias, overlapping, or other-width writes. Each listed store expression is proved. These are static producer candidates, not a recovered caller chain. In particular, the earlier address of AEE3B8 relative to the retained AEE5C8 cutpoint is not evidence that a single straight-line predecessor supplies the current W2.

The 768 cases combine 96 restored contexts with eight outcome classes: NULL identity result; empty/one-character ASCII/one-character U+00E9 outputs; NULL allocation at L=64; failed conversion at L=64; successful L=64 conversion; successful L=256 conversion. These classes cover the chosen source boundaries and units, not every native property, Unicode string, CF state, allocation size, or failure behavior.

## IPC, control, and bounded continuation questions

No new incoming/outgoing Mach right, message ID, disposition, IOKit selector, or emission location is established. No checked source call in this increment enters Mach or IOKit. CoreFoundation and MobileGestalt internals remain external and may have behavior not represented by these declared contracts. The local buffers, dispatch indices, digest selector, and cache pointer are not assigned Mach-port semantics.

| Impact | Next bounded question | Evidence required |
| --- | --- | --- |
| High | Recover compression's missing frame inputs | Join actual SP+2E50/SP+2C8C producers and native frame epoch, then continue original instructions |
| High | Complete the hardware-identity digest and cache writes | Compare actual source digest sinks against independent standard SHA-1 outputs for exact converted bytes; recover every cache field/store |
| High | Recover the native caller and transport use | Join object/cache ownership to known Mach or IOKit emission and driver-side consumer |
| Medium | Resolve the temporary buffer lifetime on success | Continue source cleanup beyond compression; failure free request alone does not establish success lifetime |
| Medium | Establish target library behavior | Match exact CF/MobileGestalt images and returned types/contents; current fixtures are conditional |
| Medium | Resolve helper-state ownership and concurrency | Trace B69D0/C4670 producers, readers, synchronization and native persistence |
| Low | Broaden encoding examples | Distinguish surrogate pairs, combining sequences and embedded NUL using exact source byte-count consumers; current ASCII/U+00E9 cases are finite |

## Assumption register and quality gates

| ID | Premise and dependent claims | Falsification / stress probe |
| --- | --- | --- |
| IC1 | Thin source and IDB identity / every source address | Rehash input and compare all selected original-byte ranges/fixups |
| IC2 | Prior conditional inputs remain applicable / all continuations | Reconstruct all 96 contexts from retained ordered effects and reject undefined reads |
| IC3 | F and stack epoch are valid / record and context offsets | Join native frame producer; do not equate source phases by equal numeric offsets |
| IC4 | Formatting result is opaque / length/conversion path | NULL/non-NULL outcomes; no invented native object bytes |
| IC5 | Length, capacity, conversion text are independently declared / finite unit examples | Enforce internal UTF-16/UTF-8/capacity consistency; do not claim feasibility as the actual five-object result |
| IC6 | Allocation owners are bounded / buffer access claims | NULL/non-NULL outcomes; reject undefined or retired-owner reads; source zero-fill census |
| IC7 | Conversion can modify any byte within capacity / output provenance | Invalidate the whole buffer before explicit successful output; failure preserves no bytes by assumption |
| IC8 | Public SDK matches observed ABI shape / names and widths | Compile signatures and encoding/width assertions; native target library/version remains unknown |
| IC9 | API callee state and explicit effects are preserved / source continuation | Vary volatile values, invalidate outputs/lifetime, stop at unknown interfaces; native reentrancy unknown |
| IC10 | B69D0 has a declared initial u64 / short helper continuation | Zero/all-ones values; universal source update proof and exhaustive bank identity; native state producer unknown |
| IC11 | Logical authenticated targets model dispatch / recorded edges | Verify chained slots, diversities and pointer origins; native PAC is not proved |
| IC12 | IV and padding identify preparation / SHA-1 context label | Compare standard IV and exact decoded blocks; require completed source digest sinks before a full hashing claim |
| IC13 | Direct store censuses are bounded / frame-writer candidates | Search paired/computed/alias writers and join actual control flow rather than supplying guessed pointers |
| IC14 | This increment has no inferred transport or full-object lifecycle / architectural limits | Recover actual emission, successful cleanup, cache publication consumers and deeper driver association |

Reproduce with `/Users/___/Downloads/zut/.venv/bin/python -P`, `PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages`, and `Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime`. Run the new capture, probe, recovery, proof, and validation scripts named `*_daemon_identity_cache.py` in that order. Exact SDK compilation and header hashes are retained in the contracts. Replay and byte-ledger algorithms are linear in visits/effects/known bytes; full-text censuses are linear in original text bytes. SMT resource use is bounded to 30 seconds per query and has no claimed polynomial bound. Counts describe finite software evidence, not a sample of native executions.

QG1: factual technical scope. QG2: IC1-IC14 with probes. QG3: increment coverage passes; full objective remains incomplete. QG4: byte/code-unit/bit widths and modular arithmetic are explicit and reproducible. QG5: short/long branches, opaque objects, helper state, frame gaps and unfinished digest/cache are separated. QG6: original bytes/fixups, fresh IDB ranges, source proofs, rebuilt contexts, fresh cases, independent byte/padding checks and primary IV/padding reference support the scoped claims. QG7: impact-bounded continuation table supplied. Final [preservation](triage_evidence/daemon_identity_cache_preservation.json) and [delivery gates](triage_evidence/daemon_identity_cache_quality_gates.json) record the sealed checks.
