# Discovery record initializer and unlock adapter call

The daemon's null cleanup branch tests an initialized record field at Q+0x20 B. The original initializer publishes its address at S+0x6fb8 B and clears the full pointer-sized field. Two source-backed offline replays test the initialized zero and a nonzero control. Both reach the conditional unlock adapter at call site `0x10057b484` with the same decoded operation and distinct paths through the record checks. [Prior cleanup dispatch](daemon_discovery_cleanup_report.md) [Audit](triage_evidence/audit_daemon_discovery_record.py) [Receipt](triage_evidence/daemon_discovery_record_audit.json.zst)

## Record initialization

S is the enclosing SP and Q is the object address in X9 at `0x100530250`. The original block publishes the record and individual field addresses. It initializes the pointer-sized fields at Q+0 B, Q+0x10 B, Q+0x20 B, Q+0x30 B and Q+0x40 B to zero. It also clears 4 B at Q+8 B. The common 32-bit input W10 is stored at Q+0x18 B, Q+0x28 B, Q+0x38 B and Q+0x48 B.

| Frame field | Value | Writer |
| --- | --- | --- |
| S+0x55e8 B | Q | `0x100530254` |
| S+0x2828 B | Q+8 B | `0x10053026c` |
| S+0x8588 B | Q+0x10 B | `0x10053027c` |
| S+0x6fb8 B | Q+0x20 B | `0x1005302ac` |
| S+0x27f0 B | Q+0x28 B | `0x1005302b8` |
| S+0x73c8 B | Q+0x30 B | `0x1005302c4` |
| S+0x11c8 B | Q+0x40 B | `0x1005302f0` |
| S+0x2120 B | Q+0x48 B | `0x1005302fc` |

Two other publications in the same block add 64-bit biases to field addresses. `0x1005302a0` writes `Q+0x18+0x3a4df5cf0c34df65` to S+0x8af0 B. `0x1005302e4` writes `Q+0x38+0x695fbe98a16c25e4` to S+0x45c8 B. The arithmetic wraps at 64 bits.

One original predecessor, `0x1007fd788`, saves X20 to S+0x7908 B at `0x1007fd798`, reads [X20], and checks the pointer at S+0x5478 B and the word at S+0x1314 B. In the tested setup both pointers checked are nonzero and the word differs from `0x8b3dc651`. With W12=`0xbc5f`, `0x1007fd7e0` then selects slot `0x1010981e8`, IA `0x1a03`, and enters the initializer with W10=`0x8b3dc651`. The corresponding equality index is `0xbc80` and its original slot targets `0x100586dc8`. Native reaching values for X9, X20 and W12 at this predecessor remain unknown.

## Record test and convergence

The earlier continuation reaches `0x10080a4d4` with W9=`0x25e9` and W19=`0xabf8`. `0x10080a4d0` loads the address from S+0x6fb8 B and `0x10080a4d4` reads the 8 B field at that address. In this setup the index used at `0x10080a4fc` is `0x25e9 XOR (0x17 * (u64[Q+0x20] == 0))`.

| Q+0x20 B | Index | Slot, IA `0xb819` | First target |
| --- | --- | --- | --- |
| Zero from initializer | `0x25fe` | `0x10104cee0` | `0x1004cfca0` |
| Nonzero control | `0x25e9` | `0x10104ce38` | `0x1005b1320` |

The nonzero arm reads Q+0x28 B via S+0x27f0 B at `0x1005b1334`. In the initialized record the word is `0x8b3dc651`. This selects `0x1004cfca0` at `0x1005b1378`, joining the zero arm. The common block reads Q+0x30 B via S+0x73c8 B at `0x1004cfcc0`. A later block reads through S+0x5900 B at `0x100586de8`. The replay obtains that field's address from the producer instructions at `0x1006171b0..0x1006171b4` with an explicitly supplied X19 and a zero backing word. Eleven and twelve transfers respectively reach the next request preparation at `0x10057b3c4`. The receipt preserves both sequences.

## Lock adapter request

The separate producer at `0x100606554` forms X28+8 B and `0x1006065d8` publishes the address to S+0x1888 B. At `0x10057b3e0` and `0x10057b3e4`, the daemon follows that pointer and reads the 8 B value. It stores that value at P+0 B at `0x10057b408`, with P=S+0x10cb8 B. In both replays the value is a synthetic lock pointer supplied in the producer's backing.

`0x10057b418` stores `W27 + 0x7413 - K` at P+8 B, where `K = low32((P XOR 0xeaae0ac9) * 0x7398180b)`. Adding K back modulo 2^32 recovers `0xa293` at W27=`0x2e80`. Both replays pass X0=P to `0x10057b484`. The ordered banks from S+0x968 B and S+0x960 B with key `0xa3` select index `0xcba3`, slot `0x10109fc08`, IA `0x6aa4`, and target `0x1004423f8`. Independent analysis of that routine identifies the same cleanup operation `0xa293` and the conditional `pthread_rwlock_unlock` path. Here the replay stops before the adapter runs. [Synchronization ABI](daemon_iokit_sync_report.md) [Bank producers](daemon_shared_roots_report.md)

The observed continuation has zero reads or writes to the 16 B emitter output. Native lock identity, lock release, output-byte use and linkage to Mach or IOKit remain unknown.

## Assumptions and verification

| Assumption | Dependent finding | Falsification probe |
| --- | --- | --- |
| A1. The pinned image supplies the original instructions, authenticated slots and banks. | Exact data and control locations and adapter identity. | Compare the digest and 17 original fixup words. Enumerate the bank transformation for all 256 input bytes. |
| A2. The record initializer, two auxiliary producer slices and the cleanup continuation share the modeled frame. | Reachability of the lock adapter from the two record controls. | Preserve the consumer CPU context across producer replays, verify each published address, and vary Q+0x20 B independently. The original producers for the incoming object bases and their native execution order remain unknown. |
| A3. The private state backing includes the explicit word and pointer values used by the test. | The two branches converge and pass the supplied lock pointer. | Check W10, W27, the actual request record and the destination slot at the call boundary. The producer-to-consumer identity of the native lock remains unknown. |

Run `python3 -B triage_evidence/audit_daemon_discovery_record.py` in the existing Unicorn, Capstone and Z3 setup. The receipt includes 15 bit-vector checks and two replays. Time is O(n) in replay instruction visits excluding solver work, and receipt space is O(t) in recorded transfers.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Reaching lock identity | High | Recover the native producer of X28 and the field at X28+8 B. Match it to the earlier acquisition and the same lock epoch. |
| Adapter return and discovery output | High | Continue after `0x10057b484` with explicit lock-call premises and trace the next reads of the saved output pointer. |
| Actual FairPlayIOKit IPC | High | Correlate this caller frame with a captured daemon-side IOKit send and its matching reply. |
