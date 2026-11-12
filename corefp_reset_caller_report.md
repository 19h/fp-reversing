# CoreFP reset caller, ProductVersion reader and tuple-cache contract

Original caller `0x9a6454` now reaches the [slot reset](corefp_optional_reset_report.md) continuously through its own record stores and authenticated call at `0x9aa74c`. Under decoded entry operation `0x84ee`, it invokes a `SystemVersion.plist` reader, constructs reset operation `0xf7a5` in the same stack record and, with its original null state pointer, selects reset. Seventeen private configurations complete the outer return; two stop at the previously established token/free boundaries. No child record, source PC or parent frame is patched.

The reader at `0x316a98` obtains `ProductVersion`, uses direct UTF-8 access or a 20 B conversion allocation, parses three unsigned 64-bit components and copies a 24 B global tuple to its caller. Its cache-hit condition requires all three components to be nonzero. Marker `0x40` does not establish three successful scanf conversions. This supplies environmental and lifecycle context; native caller admission, actual file contents, valid preparation objects and daemon/kext pairing remain unknown. The full goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_reset_caller.py), [checks archive](triage_evidence/corefp_reset_caller_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_reset_caller.py), [audit archive](triage_evidence/corefp_reset_caller_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_reset_caller_publication.py) retain the evidence. The pinned CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets. Offsets are hexadecimal; extents use bytes (B). Original image bytes, imports/fixups and current SDK declarations are primary sources. No new live IDA claim is made.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RC1 | The pinned image, compiler bounds and frozen readers identify the analyzed source. All source results depend on them. | Compare four complete source bodies totaling23376 B, every executed byte and reaching authenticated pointer row. Recheck the frozen reset obligations and preserve the three supplied inputs. |
| RC2 | The aligned private caller record and cursor cell describe the analyzed entry. Caller continuity depends on this diagnostic entry. | Independently reconstruct19 initial CPU/touched-RAM states; decode entry `0x84ee`; check the original cursor advance and source-created child records. An actual incoming caller to `0x9a6454` remains unknown. |
| RC3 | Declared CF references, return values, UTF-8 bytes, scanf writes and allocator effects delimit the environmental interface. Reader behavior depends on them. | Exercise URL/stream/open/plist/key failures, cache hit/miss, direct/copy strings, allocation/conversion failures and partial/zero conversions. Verify arguments, all effects, releases and current arm64e SDK types. No native file or API executes. |
| RC4 | The version tuple, parent state pointer and reset state retain separate identities and epochs. Cache and branch claims depend on their declared/original values. | Compare all three u64 tuple words, the all-nonzero CCMP partition and zero-component controls. Verify the parent pointer at image+`0x1d45f80` remains zero. No preparation-object or selector activation is supplied. |
| RC5 | PAC, sequential CASAL and private retirement retain the frozen reset models. Cleanup claims depend on them. | Check one null slot, one distinct backed slot with volatile-register clobber, one busy-token prefix and the original raw-slot stop. Verify full original returns only on completed paths. Native atomic ordering and ownership remain unknown. |
| RC6 | Marker bytes and record words receive meanings only from their source definitions and consumers. ABI interpretation depends on these bounds. | Check record reuse, exact address-key reductions, all24 tuple-output bytes and the post-scanf X0 def/use chain. Separate marker `0x40`, tuple readiness and conversion count. Residual outer X0 has unknown semantic meaning. |

## Continuous source flow and reused record [RC1-RC6]

```text
0x9a6454, decoded entry0x84ee
  -> cursor cell +=64 B
  -> source construct version-reader record at R=FP-0xb8
  -> 0x9a66e4 -> 0x316a98, decoded operation0x9a6b
       -> cache test / SystemVersion CF reader -> tuple copy / marker
  -> original parent state pointer at image+0x1d45f80 is NULL
  -> 0x9aa688: W19 :=0x84ee+0xfff =0x94ed
  -> 0x9aa700: overwrite R[0..3] with encoded reset operation
  -> 0x9aa74c -> 0x1f530c, decoded operation0xf7a5
       -> token / selector / selected slot reset
  -> original return to0x9aa750
  -> separate parent flag image+0x1d44420 is zero -> outer return
```

The parent SP is `0x62017d40`; its reusable child record is `R=0x62017f38` and its version output is `0x62017e90`. Initial entry record address is `0x63000100`; its cursor cell at `0x63000300` advances from0 to64 and is not restored on these paths. The entry's address-derived operation is `load_u32(entry+8) + ((low32(entry) XOR 0x341dc0b1)*0xdb676c6f)`, modulo2^32. The other entry word declares zero decoded displacement for its local workspace anchor. These supplied entry fields do not establish a native public signature or input origin.

| Child record field / phase | Source-produced value and use |
| --- | --- |
| `R+4`, version call | Encoded operation `0x9a6b =0x84ee+0x157d` |
| `R+8`, version call | Output pointer `0x62017e90` |
| `R+0`, version return | One-byte marker `0x3f` or `0x40`; remaining three bytes retain fill |
| `R+0`, store at `0x9aa700` | Encoded u32 operation `0xf7a5 =0x94ed+0x62b8` replaces the marker |
| `R+4..31`, reset entry | Retained bytes from the earlier record epoch; not reset arguments on these paths |
| Reset return | Record unchanged by the reset routine |

The version-reader key is `K_v(R)=(low32(R) XOR 0x542fbf9b)*0x4386951d`. Both original caller and callee pre-multiply expressions reduce to that same u32 XOR. The reset constructor reduces to `K_r(R)=(low32(R) XOR 0x341dc0b1)*0xdb676c6f`, matching the reset reader. Four new UNSAT obligations cover those three reductions and the cache partition. The fixed multipliers preserve equality modulo2^32; no whole-caller symbolic proof is claimed.

At the reset call, original W30 is `0x1030f` and the dispatch base is image+`0x1c81940`. Independent enumeration of all256 table inputs proves `x XOR B[A[x] XOR7] =0x61`, with A at `0x18ac070` and B at `0x1ac18c0`. Therefore index `0x1030f+0x61+0x351 =0x106c1` selects original row `0x1d04f48`, targeting `0x1f530c` with IA diversity `0x30ae`. Every retained execution takes this edge. The row/modifier alone was previously a candidate; the complete entry-to-call source trace now supplies the incoming caller and record producer under RC2-RC5.

## Environmental interface and cache [RC1,RC3,RC4,RC6]

The original path literal is `/System/Library/CoreServices/SystemVersion.plist`,48 B. The CFString key at image+`0x1d1c288` points to the14 B literal `ProductVersion`. The scanf format at `0x1685dc0` is `%llu.%llu.%llu`,14 characters plus a NUL. These are target-defined interface bytes.

| Original callsite | Imported interface | Source arguments / effect boundary |
| --- | --- | --- |
| `0x316de8` | `CFURLCreateFromFileSystemRepresentation` | Allocator NULL, literal path, length48, directory Boolean0 |
| `0x1f9dfc` | `CFReadStreamCreateWithFile` | Allocator NULL, declared URL reference |
| `0x1f9ec0` | `CFReadStreamOpen` | Declared stream; Boolean result controls parsing |
| `0x1f9f84` | `CFPropertyListCreateWithStream` | Allocator NULL, stream, length0, options0, format/error outputs NULL |
| `0x1fa008` | `CFReadStreamClose` | Reached after both open-false and parse paths |
| `0x1fa050` | `CFRelease` | Stream reference |
| `0x316fa4` | `CFDictionaryGetValue` | Plist reference and original `ProductVersion` key |
| `0x317098` | `CFStringGetCStringPtr` | Borrowed value, `kCFStringEncodingUTF8 =0x08000100` |
| `0x317188` | `malloc` |20 B fallback buffer if direct UTF-8 pointer is NULL |
| `0x317254` | `CFStringGetCString` | Borrowed value, fallback buffer, capacity20 B, UTF-8 |
| `0x317314` / `0x317410` | `sscanf` | Converted/direct C string, original format, three stack-passed destination pointers |
| `0x317398` | `free` | Distinct20 B fallback allocation |
| `0x31748c` / `0x31750c` | `CFRelease` | Plist / URL references |

Current SDK syntax-only assertions check all eleven relevant function types, eight-byte pointers/CFIndex/unsigned long long, one-byte Boolean and four-byte u32. Source passes the three variadic output pointers at SP,SP+8,SP+16. They address image+`0x1d444c8`,+`0x1d444d0`,+`0x1d444d8`; each successful `%llu` conversion writes8 B. No native CF objects, parser or scanf execute. Model objects are opaque backed private identities; retain counts and actual CF runtime type/admission are unknown.

The tuple's original three words are zero. In the observed operation phase, `CMP` followed by two conditional `CCMP` instructions implements `major!=0 && minor!=0 && patch!=0` across the full u64 domains. A complete nonzero tuple bypasses all CF calls and receives marker `0x40`. A zero component selects the reader. This cache rule is separate from the marker and from whether the tuple represents an actual installed system version.

| Control | Initial tuple | CF / scanf result | Marker | Copied tuple |
| --- | --- | --- | --- | --- |
| Cache hit | `[17,8,9]` | No CF call | `0x40` | `[17,8,9]` |
| Zero minor | `[17,0,9]` | Declared URL NULL | `0x3f` | `[17,0,9]` |
| Zero patch | `[17,8,0]` | Declared URL NULL | `0x3f` | `[17,8,0]` |
| Direct full parse | `[0,0,0]` | `14.3.1`, three conversions | `0x40` | `[14,3,1]` |
| Direct partial parse | `[0,8,9]` | `26.0`, two conversions | `0x40` | `[26,0,9]` |
| Direct invalid text | `[0,8,9]` | `bad`, zero conversions | `0x40` | `[0,8,9]` |
| Copy parse | `[0,0,0]` |20 B allocation, conversion true, three scanf conversions | `0x40` | `[14,3,1]` |

Every selected helper return copies the current24 B global tuple through stores `0x317524`, `0x31752c`, `0x317534`, then writes the marker at `0x317544`. URL/stream/open/plist/key failures, malloc NULL and string-copy false retain marker `0x3f`; they still copy the current tuple. The parser path writes marker `0x40` without consuming the scanf return count. Independent def/use scans check X0 is redefined before any source use on all five retained scanf returns. Partial and invalid controls therefore establish retained-word behavior and the marker distinction, without asserting native malformed-input exposure or a native fault.

## Reset composition, lifetimes and port bounds [RC1-RC6]

All19 configurations reach the original reset entry with the source-produced `0xf7a5` record. The original parent state pointer at image+`0x1d45f80` is zero; its nonzero branch and upstream producer remain unestablished. That field is separate from the version tuple, reset selector at image+`0x1d44409` and post-reset parent flag at image+`0x1d44420`.

| Profile group | Cases | Source outcome |
| --- | --- | --- |
| URL failure / volatile-clobber control |2 | Complete caller return |
| Stream, open, plist and key failure |4 | Complete caller return with matching source cleanup calls |
| Cache hit / zero minor / zero patch |3 | Complete caller return; only cache-hit case bypasses CF |
| Direct full / partial / invalid parsing |3 | Complete caller return with independently checked tuple and marker |
| Copy malloc NULL / copy false / copy parse |3 | Complete caller return; two allocations and matching20 B frees |
| Selected null slot |1 | Source-produced reset performs80 B common slot reset and returns |
| Selected backed slot with clobber |1 | Version read/parse, reset private retirement,88 B slot reset and return |
| Busy token |1 | Stop before second CASAL; no outer return |
| Original raw slot with selector1 |1 | Stop before `_free(0x614a2fa7)` effect; no outer return |

The CF model records29 creations and29 matching releases. The dictionary value is borrowed and receives no separate release on these paths. Three20 B malloc attempts include one NULL result and two matching frees. Reset free at `0x1f5854` remains a distinct allocation and callsite. Opaque CF references, fallback backing and reset slots do not establish shared native ownership. Source-driven closes/releases are API requests; native reclamation is unknown.

No Mach send, receive, port allocation or descriptor transfer is reached. This increment establishes an internal CoreFP caller/state/environment interface, adding no native daemon endpoint or right identity. Source-produced reset records close the earlier local incoming-call gap; an incoming caller to `0x9a6454`, selector activation and a valid slot+0x48 preparation-object producer remain unknown.

Independent replay checks19 initial CPU frames,3776512 B of initial touched RAM and the same final extent;20854 original visits,5219 reads,2038 writes,459 authenticated edges,134 declared effects,60 reset checkpoints and186 caller checkpoints. Four complete source bodies total23376 B. Four new and four freshly rechecked frozen obligations are UNSAT;56 exact instruction assertions,33 literal-reset lifts and2304 bank inputs pass. Arm64e SDK assertions pass with no output artifact. No native target/API/file/IPC or IDB mutation executes.

Conservative replay/enumeration cost is `O(C*(B+P*F+V*J+R)+256*K)` time/space, including inherited per-page fixup and reaching-load scans. C denotes profiles, B source bytes, P touched pages, F fixups, V visits, J journal size, R retained state and K=9 banks. Each execution is capped at12000 visits. Solver cost is separate, capped at30 s/query. Complete retained function bodies do not imply complete branch coverage.

| Impact | Bounded continuation / discriminating evidence |
| --- | --- |
| High | Resolve an original upstream caller to `0x9a6454`, its encoded displacement and cursor epoch. The diagnostic aligned entry does not establish native admission. |
| High | Establish the producer and valid nonzero layout of parent state image+`0x1d45f80`; preserve its distinction from the preparation slot and version tuple. |
| High | Recover selector-set-to-1 and valid slot+0x48 object construction, then join successful root processing to a matched daemon/kext epoch. |
| Medium | Trace downstream consumers of the version tuple and marker, including partial tuples and zero-component re-entry. Actual file/runtime values and cross-call timing remain unknown. |
| Medium | Resolve the other discriminator-matching reset-call candidates through their own table roots and record epochs. The established `0x9aa74c` edge does not validate them. |

**QG1** passes: factual technical analysis. **QG2** passes: RC1-RC6 register assumptions and probes. **QG3** passes for this increment; the full objective remains incomplete. **QG4** passes: record/key widths, cursor advance, tuple/format/string extents and bounded costs are explicit. **QG5** passes: cache hit versus parse, marker versus conversion count, record epochs, distinct state fields, private ownership and stopped paths remain separate. **QG6** passes: original bytes/fixups, independent CPU/RAM replay, literal/field oracles, def/use checks, symbolic reductions and SDK declarations support the claims. **QG7** passes: impact-ranked continuation covers admission, state production, environment, successful processing and cross-level identity.
