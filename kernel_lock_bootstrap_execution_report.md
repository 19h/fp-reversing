# Original phase-three lock bootstrap and compact group IDs

Original main returns from all 627 phase-three (`locks`) callbacks in two private startup cases: defaults and the original `lcks=0xb` boot-option path. Both cases retain 392 phase-one and ten phase-two returns, for 1029 actual callback returns. No new callback-result model or call-frame epoch is introduced. Execution stops before the direct BL at `0xfffffe000c639e3c`, target `0xfffffe000bd64ea4`. Native execution, authentic PAC, later startup and a matched FairPlay transaction remain unknown. [LK1-LK7]

```text
original main and 402 preceding callback returns
  -> phase-three gate word = 2
  -> compatibility group, compact ID 0, table slot cleared
  -> 290 named groups + 63 attributes
  -> three registry mutexes
  -> 268 descriptor-driven locks
  -> fixed global mutex
  -> global late initializer, thread-creation branch bypassed
  -> phase-three dispatcher returns, gate word = 3
  -> STOP before original main BL to 0xfffffe000bd64ea4

static group bank: 1024 IDs -> 291 consumed -> 733 free
                   ID 0 reserved; 290 live table bindings
later phase-14 mach_ipc / native FairPlay transaction: unknown
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| LK1 | All 627 phase-three registrations and descriptor fixups are captured; 11 constructor families account for the phase | LK-A1, LK-A2 |
| LK2 | 291 group objects and compact IDs are produced by original source; static storage suffices | LK-A1-LK-A4 |
| LK3 | Boot `lcks` flags, group flags, attribute clear masks and selected lock tags/counts have independent contracts | LK-A1-LK-A5 |
| LK4 | Destination aliases, per-callback outputs, bitmap/table state and full CPU journals agree with independent checks | LK-A1-LK-A5 |
| LK5 | All 1029 callbacks return through the original dispatcher and phase three returns to original main | LK-A1-LK-A5 |
| LK6 | Source mutations of the reserved-slot clear and RW attribute store are rejected | LK-A1-LK-A5 |
| LK7 | The next direct helper and its timeout/wait-queue source are captured but unexecuted; this increment establishes no Mach-port emission | LK-A1-LK-A7 |

Primary evidence is the pinned original kernel collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, and [startup registry](triage_evidence/kernel_startup_registry_abi_checks.json.zst), [phase-one option descriptors](triage_evidence/kernel_tunable_batch_execution_checks.json.zst), [new source/descriptor capture](triage_evidence/kernel_lock_bootstrap_execution_checks.json.zst) and [new execution audit](triage_evidence/kernel_lock_bootstrap_execution_audit.json.zst). The normalized FairPlayIOKit input remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. No IDB mutation or live target operation was used. Earlier [phase-two conclusions](kernel_timeout_execution_report.md) describe their original boundary; this report extends that boundary.

| Original callback | Registrations | Recovered function and output |
| --- | ---: | --- |
| `0xfffffe000c62d618` | 1 | Rank 0: map boot flags; construct compatibility group; reserve ID 0 |
| `0xfffffe000c62d698` | 290 | Rank 1: destination pointer, embedded 64 B name, u32 flags at descriptor +0x48; tail group constructor |
| `0xfffffe000c62d5e8` | 63 | Rank 1: destination pointer, u32 set/clear masks; three sequential u32 stores to destination |
| `0xfffffe000bceb154` | 3 | Rank 2: initialize mutex at registry argument +0xc0 |
| `0xfffffe000c62e678` | 179 | Rank 3: mutex destination, group and optional attribute pointers; 16 B output |
| `0xfffffe000c62e720` | 42 | Rank 3: same three-pointer descriptor; tail `0xfffffe000bd0622c` for RW output |
| `0xfffffe000c62e734` | 32 | Rank 3: destination/group descriptor; two u64 words 0 and 0x11; optional group count |
| `0xfffffe000c62e788` | 4 | Rank 3: 16 B ticket-form output, u32 tag 0x44000000 and u64 second word 0x144 |
| `0xfffffe000c62e7a8` | 11 | Rank 3: destination only; two u64 words 0 and 0x11 |
| `0xfffffe000c631e44` | 1 | Rank 0x7fffffff: fixed mutex `0xfffffe000cb2a5e0`, group `0xfffffe000caaf868` |
| `0xfffffe000bd37dc0` | 1 | Rank 0xffffffff: global argument selects local state/list initialization; no thread-creation call executed |

The callback names above are functional recovery labels. Exact nlist lookups for these callbacks and the four newly captured bodies are empty. Group-ID recovery has additional original diagnostic evidence: `compact_id.c` at `0xfffffe000704adcf`, and the compact-ID exhaustion diagnostic at `0xfffffe000704ada8`. Group constructor `0xfffffe000bd037e0` calls original `_strlcpy` and compact-ID allocator `0xfffffe000bceb1d0`. These observations support the roles without claiming recovered original symbol spellings. [LK1-LK3]

Group initialization clears exactly 0x148 B, including unaligned vector stores beginning at object +4, writes reference word 1 at +0, copies the name to +0x18 with capacity 64 B, optionally initializes statistics words, and publishes `id | flags` at +4. All 290 embedded descriptor names fit: maximum 32 bytes before NUL. All 290 descriptor-local flag words are zero. Group destinations are distinct; the compatibility object at `0xfffffe000cb60590` adds the 291st object. [LK2-LK4]

| Group byte offset | Width | Recovered contract |
| --- | ---: | --- |
| +0 | 4 B | Initial reference word 1; conditional increments when flag bit 31 is set |
| +4 | 4 B | Compact ID OR flags |
| +8 | 4 B | Spin-form lock count |
| +0x10 | 4 B | Mutex count |
| +0x14 | 4 B | RW count |
| +0x18 | 64 B | Bounded NUL-terminated name |
| +0x60,+0x78,+0xa8,+0xc0,+0xf0,+0x108,+0x120,+0x138 | 4 B each | Set to 1 when group flag bit 16 is set |
| +0x90,+0xd8 | 4 B each | Set to 1 when group flag bit 17 is set |

The registry at `0xfffffe000ca90368` has twelve bank pointers at +0 and twelve bitmap pointers at +0x60. Its original format-8 bank-0 pointer resolves to `0xfffffe000cb606d8`, an 8192 B zero table; bitmap-0 resolves to `0xfffffe000ca902e8`, 128 B of ones. Thus bank 0 has 1024 free bits and 1024 pointer slots. Original allocator source selects the lowest set bit, clears that bit, stores the object at `bank + 8*id`, increments u32 count at registry +0xdc and publishes `id+1` at +0xe0. Both runs consume IDs 0 through 290 without entering the expansion helper. The rank-0 callback then zeros table slot 0 while leaving its bit consumed and its compatibility object initialized. Final count and high-water words are both 291; 733 bits remain free and 290 table entries bind named groups. This is initialization state, not a concurrency or allocation-lifetime proof. [LK2-LK4]

The first callback reads the original u32 `lcks` destination at `0xfffffe0007e63698`. Let `f` be that word and `c` the prior common flags at `0xfffffe0007e635c8`. All following operations are u32:

```text
combined = c | ((f << 15) & 0x10000)
             | ((f << 14) & 0x20000) | ((f & 1) << 18)
if f & 0xb: common_flags = combined
global_attribute = f & 1                  # 0xfffffe0007e63610
attribute_output = (global_attribute | set_mask) & ~clear_mask
```

The compatibility group receives `combined` even when the common-flag store is bypassed. All 63 attributes have set mask zero; 60 have clear mask zero, three clear bit 0. Both concrete runs execute the original phase-one `lcks` parser rather than seeding the flags after the earlier checkpoint. Five nonvacuous QF_AUFBV source queries cover the bit mapping, common-store admission, attribute publication, plain-lock output and RW attribute halfword. Query coverage is 34 instruction instances at 34 distinct PCs, with 29 linked-edge obligations. The full constructors are checked by finite formulas and fresh CPU replay, not proved universally by those five queries. [LK3-LK4]

Mutex output is u32 `0x22000000 | (group_flags & 0xffffff)` at +0, zero u32 at +4 and zero u64 at +8; attribute byte bit 0 changes u32 +8 to 0x80000000. RW output starts with the original 8 B constant at `0xfffffe000700dd08` (u32 tag 0x33000000 followed by zero), zero u16 at +8, selected flags at u16 +0xa and zero u32 at +0xc. The selected halfword is `(attribute & 0x10000 ? 0 : 2) | (attribute & 0x20000 ? 0 : 0x40)`. The group count updates use original LDADD instructions. Conditional reference increments and their diagnostic branch are retained; no parallel interleavings or reference-overflow fixture is claimed. Spin and ticket labels describe the recovered layout families. [LK3-LK4]

The registry mutex family uses group `0xfffffe000caad718`; the fixed global mutex uses group `0xfffffe000caaf868`. The late callback receives `0xfffffe000cac6e18`, compares it with that same global and bypasses calls to `0xfffffe000bd55878`, `_snprintf`, `0xfffffe000c36bea8` and `0xfffffe000bd57a48`. It initializes state at `0xfffffe000cac4200`, including argument custody, flags and self-referential lists. At every phase-three group constructor the phase-minus-one word `0xfffffe0007f8b5f0` is 2, so the constructor's `>=4` CASA/CASL lock path is bypassed. After all callbacks the dispatcher publishes 3 and returns to main. These are observed source branches under the recorded environment. [LK4-LK5]

Validation receipts: **965589 source visits, 5146 distinct executed PCs, 2750 static checks, 8896 lock-semantic checks, two complete replays and two rejected source mutations**. The capture contains 188 original functions, 15533 words / 62132 B; four newly captured bodies comprise the group constructor, ID allocator, RW initializer and unexecuted next helper. The default phase-three entry preserves the previously published phase-two journal, register/vector/system state, private RAM, prior mutable intervals and every previously mapped page hash. Additional eagerly mapped pages are checked against original logical bytes. Original pages containing incidental forbidden path strings are published by exact logical-page SHA-256 reference and hydrated only against the pinned collection; target bytes are not edited. Two NOP controls mutate `0xfffffe000c62d68c` (reserved table slot) and `0xfffffe000bd06270` (RW attribute halfword); identical initial states reach the same final boundary and their formulas reject the altered result. The independent replay checks every recorded instruction, read, write, logical operation, callback output, final register/vector/system state, private RAM and mapped-page digest. [LK4-LK6]

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_lock_bootstrap_execution_checks.json` | `7cff5ee38d8420d37223f05a841758feafa59279fce25f7321391a5518e26a29` |
| `kernel_lock_bootstrap_execution_audit.json` | `9093e22d92869a1bbb8be69f77e796dcfe57f23a6ef6754673a7f526ea32af75` |

The new boundary is a direct main call, not a later registry callback. Original helper `0xfffffe000bd64ea4..0xfffffe000bd65380` is 311 words / 1244 B. Its captured source parses the `longterm` option, uses the timebase word at `0xfffffe000ca8c000`, initializes list/lock fields, installs a PACIA-protected function pointer and publishes timeout-related state. None of those helper instructions has executed in this increment. Exact native ownership and lifecycle of its objects remain unknown. The report therefore adds foundational control/data-flow evidence for the lower kernel, without adding an incoming or outgoing Mach right, send site, message ID or fairplayd/provider pairing. Phase-14 MIG initialization remains unexecuted. [LK7]

| Assumption | Dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| LK-A1: Pinned collection and normalized input identify this case | LK1-LK7 | Recheck original SHA-256, body bytes, symbols and registry records; reject image drift |
| LK-A2: Logical format-8 pointers define private initialized storage | LK1-LK7 | Decode raw slots independently; verify bank/table/bitmap bytes; native loader lifetime remains unknown |
| LK-A3: Earlier startup state and static registry admit this continuation | LK2-LK7 | Compare the published default prefix, every known page hash and all prior checkpoint bytes; reject a substituted epoch |
| LK-A4: Logical PAC/system operations and retained three leaf contracts bound the CPU environment | LK2-LK7 | Recheck operands, modifiers, SP/LR and all retained model effects; native authentication/concurrency unproved |
| LK-A5: Two configurations and concrete allocation order define finite formula admission | LK3-LK6 | Per-callback aliases, group IDs, bitmap/counts, full replay and two source mutations; other boot flags/interleavings need new checks |
| LK-A6: Captured next-helper source identifies a continuation frontier only | LK7 | Execute original helper with explicit output and callback custody; current instruction-visit set must exclude its entry |
| LK-A7: Kernel bootstrap alone does not establish FairPlay IPC correspondence | LK7 | Match daemon, user-client, provider and kernel epochs, rights, payloads, statuses and message PCs; presently unknown |

| Impact | Next discriminating work | Evidence sought |
| --- | --- | --- |
| High | Execute original next helper and later startup phases | Actual timeout/wait-queue prerequisites and phase-14 MIG initialization |
| High | Match one daemon/provider/kernel transaction | FairPlay relevance, Mach-right custody and actual emission sites |
| High | Recover the original initialized-section/fixup producer | Replace the pre-entry logical-data premise with loader provenance/lifetime |
| Medium | Follow lock-group and attribute consumers | Verify runtime meanings of flag bits and lock tags beyond initialization |
| Medium | Establish compact-ID expansion/freeing and concurrency | Exhaustion, reuse, capacity growth, ownership, locking and publication order |
| Low | Compare group-name inventory across pinned versions | Separate stable layout families from build-specific names/counts |

**QG1**: Factual technical analysis; no normative content required. **QG2**: LK-A1-LK-A7 list dependencies and falsification probes. **QG3**: Finite phase-three source, descriptors, control/data flow, boot input, ABI and Mach limits covered; full goal remains active. **QG4**: Exact byte extents, widths, modular arithmetic, counts and complexity are explicit. Source, journal and RAM construction are linear; interval sorting is O(N log N); SMT search is separate. **QG5**: Static/live table entries, reserved IDs, phase gate, aliases, observed branches and native lifetime distinguished. **QG6**: Original bytes, independent source queries/formulas, fresh replay, prefix comparison and controls retained. **QG7**: Impact-ranked continuation included. Gates apply to this increment; native startup and matched FairPlay IPC remain unknown.
