# Managed-app to AMS FairPlay context bridge

Both original managed-app arm64e executables contain a concrete `AMSKeybag sharedInstance` -> `fairplayContextWithError:` call chain. The AMS implementation forwards to `fairPlayContext` -> `AMSFairPlayContext fairplayContextIDWithError:`. The returned value is a u32 context identifier; it is not established as a Mach port name or pointer. Three callers per executable retain that result in X21 and have calls into a local obfuscated context/buffer adapter. A fourth, small wrapper exposes a separate Swift error-register path. The bodies and incoming ABI are recovered; the buffer operation, runtime dispatch identity, native processing and any connection to RPC700 remain **unknown**.

This resolves the locator left in the [RPC700 candidate report](rpc700_namespace_report.md) and [publication snapshot](rpc700_publication_report.md). It connects those candidates to the previously recovered [AMS protected context ABI](appstore_events_report.md), [AMS core creation record](ams_core_report.md) and [CoreFP client paths](corefp_client_paths_report.md). It does not assign RPC700's receiver.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| MB1 | Pinned original slices and cache are the intended corpus | All addresses, imports and routine roles | Rehash universal files, selected slices, consumed cache files and original dependency artifacts |
| MB2 | Original chained fixups and compiler starts describe the inspected static layout | Class/import bindings and body boundaries | Walk all format12 chain members and compare targets with dyld_info; reject non-start entries |
| MB3 | Direct original calls and selected local instruction chains delimit the reported graph | Four direct selector callers per image and adapter call sites | Scan every aligned32-bit word in each __text section for B/BL encodings and validate each hit in its original body; indirect/computed calls remain outside this count |
| MB4 | Objective-C messages use the statically selected class and its recorded implementation | Conditional AMS forwarding and singleton roles | Establish actual runtime classes, interposition, subclasses and dispatch targets separately; selectors alone do not attest native IMP identity |
| MB5 | Original register writes and consumers determine the stated widths | u32 context ID, adapter entry and error channel | Check W-register writes, X-register stores and caller error-cell loads; do not substitute pointer64 or port ownership semantics |
| MB6 | Call-site preparation describes its inspected route, not every predecessor | Buffer arguments and NSError handling | Audit intra-function branch predecessors and indirect entries before asserting a global initialized-value or bounds invariant |
| MB7 | Exact symbols identify the retained reference AMS methods | Named forwarding, context validation/creation | Re-read original cache nlist values and bytes; optimized Objective-C method-list type encodings are not decoded here |
| MB8 | Previous protected-core recovery applies within its declared scope | Context creation continues into the existing CoreFP investigation | Revalidate the referenced artifacts; no new end-to-end protected processing, service ownership or RPC700 exchange is established |

## Source identities and exact mappings

The [source artifact](triage_evidence/managed_fairplay_bridge_source.json) pins both original universal-file hashes and selected slice offsets/hashes. Their previously established UUIDs are unchanged. Both slices have their own complete compiler boundaries, instruction decoding and pointer checks [MB1-MB3].

| Image | Original arm64e UUID | Selected-slice SHA-256 |
| --- | --- | --- |
| managedappdistributiond |2ed78e46-6ca7-3ebe-88d3-191d006e1384 |87f3b859aed9690982d9f51f456816dfcb8c03238baac16817b206abe168b3f6 |
| managedappdistributionagent |e1409c36-ae4b-35af-9e0e-265ab4e5c5d5 |26ed3362f6264d00c4e1bd7dc890f6ee377d017490c8797c73c78be016596f88 |

Paths are `/System/Library/Frameworks/ManagedAppDistribution.framework/Support/managedappdistributiond` and the adjacent `managedappdistributionagent`. The AMS image is `/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices`, UUID `1b464993-f0e2-3804-b412-a6cc8091798c`, in cache UUID `2bd06591-e751-3e84-963f-b08dab6af23a`. These static identities are not new attestations of the live mapped processes.

| Recovered role | Daemon body start / selector call | Agent body start / selector call |
| --- | --- | --- |
| First larger context consumer |0x1001a29cc /0x1001a3008 |0x1001a29c8 /0x1001a3004 |
| Second larger context consumer |0x1001a3620 /0x1001a3bf4 |0x1001a361c /0x1001a3bf0 |
| Third larger context consumer |0x1001a42e4 /0x1001a4a90 |0x1001a42e0 /0x1001a4a8c |
| Small context/error wrapper |0x1003c9fc8 /0x1003ca018 |0x1003c9fc4 /0x1003ca014 |
| Obfuscated context/buffer adapter |0x10040c2dc |0x10040c2d8 |

All five corresponding function byte strings differ between the two images. The four-byte address difference is an observed mapping, not a rule for other functions. Runtime import stubs also move; the recovery resolves them by their decoded target symbol rather than copying a daemon address into the agent [MB2].

The common selector stub at `0x10047ddc0` loads the verified selector reference at `0x100547638` and tail-dispatches through `_objc_msgSend` at chain slot `0x100539148`. The common accessor stub at `0x1004808e0` resolves selector `sharedInstance` through slot `0x100548100`. Both source images bind class slot `0x10053ba18` to `_OBJC_CLASS_$_AMSKeybag`, library AppleMediaServices, with total addend0. Selectors have different original string addresses in the two slices; their decoded texts match.

## Cross-layer context and ownership requests

```text
managedappdistributiond              managedappdistributionagent
      | four direct sites                  | four direct sites
      +-------------------+----------------+
                          v
                   AMSKeybag.sharedInstance
                          |
             fairplayContextWithError:(NSError **)
                          |
              AMSKeybag.fairPlayContext [object+16]
                          |
             AMSFairPlayContext.fairplayContextIDWithError:
                          |
                context ID u32 [object+8]
                          |
        +-----------------+-----------------+
        v                                   v
 small wrapper: X0 value,              larger callers: X21 value
 X21 error-state handling             -> local opaque buffer adapter

Actual native message/port delivery and RPC700 receiver: UNKNOWN
```

The managed callers first invoke the bound `_objc_opt_self` stub with the class reference, call `sharedInstance`, request `_objc_retainAutoreleasedReturnValue`, prepare a zero-initialized error-output cell in X2, and call the context selector. They save the returned value separately and request `_objc_release` for the singleton result. These are original call requests; balanced native reference counts and object lifetimes are not proven [MB4,MB5].

| Reference AMS routine | Address | Original behavior relevant to this bridge |
| --- | --- | --- |
| +[AMSKeybag sharedInstance] |0x19c1ecfcc | Tests once token against -1; otherwise requests bound dispatch_once; returns singleton cell through an ObjC return helper |
| Singleton block |0x19c1ed06c | Reads captured class at block+32, requests bound objc_alloc_init and replaces singleton cell |
| -[AMSKeybag init] |0x19c1ed0a8 | Requests allocation/initialization of class at0x1eed15f68 and stores returned object at self+16 |
| -[AMSKeybag fairPlayContext] |0x19c6491c8 | Tail-calls bound objc_getProperty with offset16 and atomic flag1 |
| -[AMSKeybag fairplayContextWithError:] |0x19c1ed14c | Preserves X2 error-output address, obtains fairPlayContext, forwards X2 into fairplayContextIDWithError:, preserves returned value, requests property-object release |
| -[AMSFairPlayContext fairplayContextIDWithError:] |0x19c6000e4 | Reads contextID u32 at self+8; calls existing validation/creation routines on its guarded paths |
| -[AMSFairPlayContext contextID] |0x19c6006fc | LDR W0,[X0,+8]; RET |

The context class is identified by original nlist `_OBJC_CLASS_$_AMSFairPlayContext`; it is not claimed as an exported symbol. Its validation call remains `0x19ca0d0e4`; its creation call remains `0x19c9e12a0`, with X0=NULL, X1=stack+32, X2=the previously recovered SC Info path, X3=contextID cell. This turn rechecks the current original caller bytes and links the existing protected-core analysis; it does not rerun a context operation [MB7,MB8].

The normal return paths load W19 from the contextID cell before moving X19 into X0. W19 loads zero-extend the u32 value. A nonzero NSError cell is a separate condition, not a proof that the contextID equals0. No connection-port right, Mach-name namespace, provider reference or kernel object is assigned to this number [MB5].

## Small wrapper: value versus Swift error register

For each small wrapper in the mapping table, the original code saves incoming X21 in X19, initializes an eight-byte local error cell to0, passes its address in X2 and saves the selector result in X20. After releasing the singleton result, it loads the error cell into X22:

| Error-cell condition | Original requests/register writes | Interpretation limit |
| --- | --- | --- |
| NULL | Restores incoming X21 from X19 | Preserves caller's incoming error-register value; does not independently prove that incoming value was0 |
| Non-NULL | Moves error to X21; calls bound swift_willThrow; requests objc_retain; restores X21 to the error value | Statically recovered Swift error path; native throwing/ownership and caller catch behavior are unobserved |
| Both ordinary exits | Moves saved selector result X20 to X0 | Value result and X21 error state are distinct |

This is a caller-established private register contract, not a complete exported Swift signature. Function names and type encodings of these stripped managed-app routines remain unknown.

## Obfuscated adapter and selected buffer call sites

The adapter is4956 B in each image. The source retains both complete bodies, including their state arithmetic, byte-bank/table accesses and indirect dispatch, without assigning their complete semantics. At entry, the caller's arguments are stored as follows [MB5]:

| Incoming register | Original stack offset from post-prologue SP | Store width | Caller-established role |
| --- | --- | --- | --- |
| W0 |+0x20 |4 B | Context-ID input consumed as u32 |
| X1 |+0x18 |8 B | Buffer/address input; exact buffer contract unknown |
| W2 |+0x14 |4 B | Count/extent-shaped scalar; unit and full constraints unknown |
| X3 |+0x08 |8 B | Output-address argument; pointee schema unknown |
| W0 on return at selected callers | n/a |4 B consumption | Zero/nonzero status branch; complete status domain unknown |

The three larger context consumers contain nine direct adapter calls per image. The source artifact lists all eighteen. Some calls have immediate preparations W2=0 and an initialized cell behind X1; other branches enter shared call tails with prepared values. Those local instruction windows do not establish a universal zero count, empty input or whole-buffer bounds invariant [MB6]. The context value is held in X21 after the selector call and copied into X0 on the inspected adapter routes. Whole-loop value provenance and the obfuscated operation remain unresolved.

The string `FairPlayDecryptionSession` remains a locator. It is insufficient by itself to label this adapter as decryption, identify its cryptographic primitive or associate it with kernel RPC700.

## Verification and bounded continuation

[Recovery](triage_evidence/recover_managed_fairplay_bridge.py) rehashes original sources, walks format12 fixup chains and compares all37622 members/targets with Apple's read-only `dyld_info -fixups` for temporary exact slices. Temporary filenames are replaced by a fixed placeholder only for deterministic tool-output hashing; original bytes are unchanged. It scans every aligned32-bit word of both __text sections for B/BL encodings targeting the selector stub and validates all eight hits within their complete original compiler bodies. This avoids a linear decoder stop and excludes indirect/computed dispatch; structural hits alone are not reachability proofs.

[Validation](triage_evidence/validate_managed_fairplay_bridge.py) independently checks113 selected instruction assertions and original bytes, exact class/accessor/runtime bindings, error paths and u32 consumers. Eight alterations to class, selector, buffer width, error address, context width, property offset, reference agreement or execution scope are rejected. Seventeen complete bodies contain7735 instructions/30940 B, excluding separately captured stubs; ten managed bodies contribute7442 instructions/29768 B and seven AMS bodies contribute293 instructions/1172 B. Fourteen managed stubs, seven AMS stubs and six consumed cache-file hashes are retained. These counts describe evidence coverage, not complete semantic recovery of7735 instructions.

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_managed_fairplay_bridge.py
python3 triage_evidence/verify_managed_fairplay_bridge_publication.py
```

Extraction/validation is O(B+F+I+S) time and space in original bytes B, fixups F, decoded instructions I and selected symbol data S; cache-file hashing is linear in consumed file bytes. Widths are explicit byte extents and bit-vector widths. No target code, emulation, account/network operation, FairPlay message or service mutation is introduced.

| Impact | Remaining gap | Discriminating continuation |
| --- | --- | --- |
| High | Local adapter's operation and transitive endpoint unknown | Recover compact table/state semantics and bind its real external dispatch targets before assigning an IPC contract |
| High | RPC700 receiver and alternate-mode producer unknown | Recover original host-special setter/caller linkage; preserve this AMS bridge as a separate established path |
| Medium | Runtime ObjC IMP identity and Swift callers unknown | Recover actual call-site class constraints and small-wrapper callers; do not equate a static selector with observed invocation |
| Medium | Error/value consistency and buffer extents unknown | Track predecessor definitions into shared call tails, scalar conversions and output ownership |
| Low | Optimized cache method-list type encoding unresolved | Decode its exact format independently if a formal ObjC signature becomes necessary; current u32 result follows original register loads |

QG1: Factual interface recovery; no normative conclusion.

QG2: MB1-MB8 register assumptions, dependencies and falsification probes.

QG3: Both managed-app locators now have concrete class/selector/body/caller mappings and a linked AMS context ABI; full IPC investigation remains active.

QG4: u32 versus pointer64, byte extents, instruction counts and extraction complexity are explicit; count/extent units remain unknown.

QG5: Per-image address shifts, nonidentical bodies, inherited runtime dispatch, value versus error, shared call tails and absent receiver attribution are separated.

QG6: Original source hashes/UUIDs, compiler starts,37622 independent fixup comparisons, original nlist and exact cache exports supply provenance; no native path execution is claimed.

QG7: Impact-labeled continuation targets unresolved interface links and bounds.

[Delivery checks](triage_evidence/managed_fairplay_bridge_delivery.json) and [quality metadata](triage_evidence/managed_fairplay_bridge_quality_gates.json) apply to this increment only. Original inputs and prior evidence are preserved except for explicitly owned report/index/publisher updates.
