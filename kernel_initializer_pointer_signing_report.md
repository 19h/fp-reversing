# Collection traversal, module-pointer signing and FairPlay class lineage

The helper previously retained as an early-registration no-RAM leaf walks collection and fileset segment commands and re-signs nonzero module initializer/terminator pointers. It does not call those pointers. In the pinned collection, a separate logical-PAC CPU case returns after 1845 segment-helper calls and 6362 pointer stores, including all six FairPlayIOKit entries. Original FairPlay initializer bodies separately corroborate three metaclass constructor ABIs and authenticated vtable stores. Native signatures, initializer invocation and integration into the retained continuous startup remain unknown. [IP-A1-IP-A7]

```text
original main -> collection-header bank -> helper 0xfffffe000c47cce0
  root LC_SEGMENT_64 ---------------------------+
  LC_FILESET_ENTRY -> child LC_SEGMENT_64 -------+
                                                v
                            segment signer 0xfffffe000c656ca4
                              section type 9 or 10
                              each complete nonzero u64 pointer
                                XPACI -> PACIA(modifier 0x4a27) -> store
                                                |
                          FairPlay initializer / terminator pointer tables
                          later callback invocation: not executed here
                                                |
                          initializer source -> OSMetaClass constructor ABI
                                             -> PACDA vtable store (0xcda1)
```

Primary evidence is original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, [captured source/headers/tables](triage_evidence/kernel_initializer_pointer_signing_checks.json.zst), [proofs and CPU journals](triage_evidence/kernel_initializer_pointer_signing_audit.json.zst), and the supplied [kext decompilation](com.apple.driver.FairPlayIOKit.c). Original symbol-table names and recovered helper roles are distinguished; both helper symbols are absent. Apple SDK loader definitions retained with their source digest identify LC_SEGMENT_64=0x19, LC_FILESET_ENTRY=0x80000035, SECTION_TYPE=0xff and module initializer/terminator section types 9/10. No IDB was queried or changed.

| Source | Established role / boundary |
| --- | --- |
| `0xfffffe000c47cce0..0xfffffe000c47ce2c` | 83-word collection/fileset segment walker; X0 root header |
| `0xfffffe000c47cd24` / `0xfffffe000c47cd8c` | Direct-root / child-segment calls to the signer; X0 selected segment command |
| `0xfffffe000c656ca4..0xfffffe000c657040` | 231-word segment signer; X0 nullable segment command; no callback call instruction |
| `0xfffffe000c656d7c` / `0xfffffe000c656d8c` / `0xfffffe000c656d98` | Scalar XPACI / PACIA1716 / final pointer store |
| Eight unrolled tails ending at `0xfffffe000c656e00` through `0xfffffe000c657030` | Equivalent strip, sign and store sequence for each admitted nonzero pointer |
| `0xfffffe000c639a94` / `0xfffffe000c639a98` | Original main loads the primary collection-header bank, then calls the walker; inherited continuous model still declares a leaf here |

Compiler start metadata places the signer's next recorded boundary at `0xfffffe000c65c000`. The retained executable closure ends immediately after its sole RET at `0xfffffe000c65703c`; every direct branch target in that closure stays inside it. The excluded 20416 B contain seven nonzero bytes, including a separate `MSR SPSel,#1; RET` stub, and are digest-retained. They are not classified wholesale as padding. There are 314 captured helper words, 1256 B; a separate 75 words cover the six FairPlay callback wrappers. [IP-A1-IP-A2]

The walker reads u32 ncmds at header+16, starts commands at header+32 and advances by u32 cmdsize at +4. A root segment is passed directly to the signer. A fileset entry supplies its child-header pointer from command+8; the walker visits that child's segment commands without recursively following child fileset commands. After a child segment returns, it rescans command positions from the child's first command to recover the remaining count. For R root commands, child counts C_i and P complete pointer entries, worst-case work is O(R + sum(C_i^2) + P + section records), rather than a universal linear traversal. Valid finite command extents and stable records are declared premises. No malformed-image admission, concurrent mutation safety or native mapping protection is established. [IP-A3-IP-A4]

The signer reads u32 nsects at segment+64 and 80 B section records beginning at segment+72. It tests only the low byte of section flags at +64. For types 9/10 with nonzero u64 address at +32 and u64 size at +40 of at least 8 B, it processes floor(size/8) complete pointers. Null values receive no final table store. Nonzero values flow through instruction-pointer stripping and IA signing with X16=0x4a27, then return to their original slots. Eight-entry blocks precede a remainder of floor(size/8) mod 8 entries; trailing bytes are untouched. The scalar slot expression selects the signed-32-bit byte offset when it equals the full u64 offset, otherwise a pointer whose upper 16 bits are 0x2bad. That source relation is proved without asserting native admission of oversized tables. [IP-A3-IP-A5]

The original collection contains 363 captured headers: the root and 362 fileset images. Its 674 eligible sections contain 6362 pointers, 50896 B; all are nonzero in the resolved logical image. The full case returns after 306644 source visits and 1845 segment calls, writing each expected pointer once in independently parsed order. All newly mapped image pages remain byte-identical under the explicitly declared identity projection for PAC operations. This projection preserves logical target identities; native signing generally changes stored pointer bits, whose values are unknown. The original chained-fixup encodings, resolved targets and signing events are retained separately. [IP-A1-IP-A4]

FairPlayIOKit's header is at `0xfffffe000790a7d0`. Its two 24 B tables are in __DATA_CONST: __mod_init_func at `0xfffffe000846a5b0` and __mod_term_func at `0xfffffe000846a5c8`. Their original format-8 fixups have auth=0. All six pass through the scalar signer and store at `0xfffffe000c656d98`; no target is invoked in this CPU case. Ordinals below are zero-based among the original case's nonzero pointer stores.

| Slot | Logical target | Original symbol | Store ordinal |
| --- | --- | --- | ---: |
| `0xfffffe000846a5b0` | `0xfffffe000a5039a4` | `__GLOBAL__sub_I_FairPlayMemoryDescriptor.cpp` | 3482 |
| `0xfffffe000846a5b8` | `0xfffffe000a504d58` | `__GLOBAL__sub_I_FairPlayIOKitUserClient.cpp` | 3483 |
| `0xfffffe000846a5c0` | `0xfffffe000a50ac60` | `__GLOBAL__sub_I_FairPlayIOKit.cpp` | 3484 |
| `0xfffffe000846a5c8` | `0xfffffe000a5039f8` | `__GLOBAL__D_a` | 3485 |
| `0xfffffe000846a5d0` | `0xfffffe000a504dac` | `__GLOBAL__D_a` | 3486 |
| `0xfffffe000846a5d8` | `0xfffffe000a50acb4` | `__GLOBAL__D_a` | 3487 |

Each initializer's first 12 words forwards X0=metaclass, X1=class-name pointer, X2=superclass and W3=class size to stub `0xfffffe000a69f174`. Its authenticated pointer at `0xfffffe000847c3e8` resolves to original `__ZN11OSMetaClassC2EPKcPKS_j` at `0xfffffe000c441ec0`. The destructor wrappers tail-branch to stub `0xfffffe000a69f184`, whose pointer at `0xfffffe000847c3f0` resolves to `__ZN11OSMetaClassD2Ev` at `0xfffffe000c442ad0`. These import slots have auth=1, address_diversity=1, key=0 and diversity=0; they are distinct from the module-table pointers being re-signed. The constructor/destructor implementations are not executed in this increment. [IP-A1-IP-A5-IP-A6]

| Class-name literal | Metaclass X0 | Superclass target / original symbol | W3 class size | Metaclass vtable address point |
| --- | --- | --- | ---: | --- |
| `FPMemoryDescriptor` | `0xfffffe000ccc77f8` | `0xfffffe000cb5bfc0` / `__ZN8OSObject10gMetaClassE` | 48 B | `0xfffffe000846a750` |
| `com_apple_driver_FairPlayIOKitUserClient` | `0xfffffe000ccc7820` | `0xfffffe000cb5b9c8` / `__ZN12IOUserClient10gMetaClassE` | 248 B | `0xfffffe000846b288` |
| `com_apple_driver_FairPlayIOKit` | `0xfffffe000ccc7878` | `0xfffffe000cb5c060` / `__ZN9IOService10gMetaClassE` | 136 B | `0xfffffe000846c328` |

These source arguments corroborate the supplied C listing's 0x30/0xf8/0x88 sizes and class lineage. Each initializer's seven-word post-call block signs its vtable address point with PACDA using `(returned_object & 0x0000ffffffffffff) | 0xcda1000000000000`, then stores it at returned_object+0. The user-client listing's apparent `"T:P\n"` label is used in that pointer publication; it does not establish string use. Original `__ZTVN40com_apple_driver_FairPlayIOKitUserClient9MetaClassE` is at `0xfffffe000846b278`, 16 B before the computed address point; the address point's first entry is an authenticated fixup. The source distinguishes IA module-pointer signing, DA vtable signing and authenticated import dispatch. [IP-A1-IP-A5-IP-A6]

There are 21 nonvacuous QF_AUFBV source obligations over 159 instruction instances at 159 PCs: six section/size/index relations, nine nonzero strip/sign/store tails and six FairPlay constructor-argument/vtable-store relations. Stripping and IA/DA signing are uninterpreted functions in these proofs. They establish data/control dependence and modifiers, not a cryptographic algorithm, a native signature or universal loop correctness.

The CPU matrix has 29 separate callers: one original collection, 19 signer cases and nine synthetic walkers. Sizes 0/1/7/8/9/56/63/64/65/72/127/128/136 B cover complete-pointer truncation, the eight-entry threshold and remainders. Null segment/address, ignored types, type 10, high flag bits, zero pointers, empty/ignored/direct/fileset commands, first/middle/last/multiple child segments and ignored nested filesets are covered. All 311801 visits, 60467 reads, 27977 writes, 12998 PAC envelopes and 1872 signer entries replay independently. All 31 final GPRs, SP, NZCV, 30408704 private bytes and 3362816 mapped image bytes are compared across cases. The oracle supplies 14004 assertions. NOP controls remove a scalar store, an unrolled store or a root-segment call; all retain identical initial fields and fail the independently derived event sequence even where logical identity leaves final pointer bytes unchanged. [IP-A3-IP-A5]

The earlier [collection-header contract](kernel_collection_header_publication_report.md) and [continuous logging case](kernel_early_logging_execution_report.md) remain unchanged. Source recovery now qualifies the role and finite effects of the earlier leaf; composing a new startup case still requires source-produced header custody through the intervening boot fixups and an explicit choice of logical versus native authentication semantics. Neither these pointer stores nor the metaclass wrapper source establishes an incoming/outgoing Mach right, message ID, daemon request or port-emission site. Native callback execution and matched daemon/provider/kernel epochs remain unknown. [IP-A6-IP-A7]

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_initializer_pointer_signing_checks.json` | `98c811d542eb29095a69efb7a65ad582ecc940e89a8df9fdaa95edde1d8808b0` |
| `kernel_initializer_pointer_signing_audit.json` | `af03096161bfaa208ec0346951ead56826ba5f96af7346960ab5bbee02d27aa2` |

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| IP-A1: Pinned collection and original symbols define source/records | All role, pointer and class claims | Rebuild source, 363 headers, table fixups, literals and exact symbols; reject image drift |
| IP-A2: Branch-closed bounded signer is the relevant executable body | Signer extent and absence of callback calls | Verify sole RET, every direct target and digest of excluded trailing bytes; do not infer a universal compiler boundary |
| IP-A3: Stable bounded command/section layouts define the cases | Traversal, pointer order and loop limits | Independent parser, synthetic boundary matrix and exact original-table sequence; native malformed-input admission unknown |
| IP-A4: Resolved pointers and logical PAC identity define CPU projection | Unchanged logical bytes and returned cases | Preserve original fixups, compare every PAC operand/event and fresh replay; native signature values unknown |
| IP-A5: Architectural model and opaque strip/IA/DA functions bound source proofs | Source relations and modifiers | Rederive 21 nonvacuous obligations, independent CPU/oracle checks and three rejected source mutations |
| IP-A6: Callback source and separate helper cases do not establish startup invocation | Class lineage and continuous-state limits | Source-produced boot-state handoff, callback caller/return and actual constructor state; unknown |
| IP-A7: Loader pointer custody does not establish FairPlay transport | Mach and daemon/kext limits | Pair native rights, endpoints, payloads, statuses and PCs across matching epochs; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Compose boot-produced header state with qualified signing traversal | Explicit producer handoff and retained poisoned regression; source logging return |
| High | Establish actual module initializer invocation and class registration | Caller PC, table-slot authentication, constructor state/return and metaclass lifecycle |
| High | Continue CPU/Mach startup and pair FairPlay IPC | Actual rights, message/selector ABI, endpoint ownership and matching daemon/provider/kernel epochs |
| Medium | Qualify native PAC and mapping permissions | Actual IA/DA keys, authentication outcomes and writable-table epoch |
| Medium | Audit other decompiler labels at authenticated vtables | Original symbol bases, fixups and pointer-use source rather than apparent string labels |

**QG1**: Factual technical analysis; no normative content required. **QG2**: IP-A1-IP-A7 list dependencies and falsification probes. **QG3**: Walker/signer roles, full pinned-table traversal, FairPlay pointer/class lineage, source ABI and continuous/Mach limits covered for this increment; full goal active. **QG4**: u8/u32/u64 widths, byte extents, truncation, ordinals, separate query/CPU counts and quadratic rescan complexity explicit. **QG5**: Source body/compiler boundary, stored fixups/logical/native signatures, table signing/callback invocation and IA/DA/import roles distinguished. **QG6**: Original bytes/headers/fixups/symbols and SDK digest, source queries, independent parser/replay and source mutations retained. **QG7**: Impact-ranked bounded continuation included.
