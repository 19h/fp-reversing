# Discovery unlock, reacquisition, and cache dispatch

Two consecutive calls reuse the discovery request at P=S+0x10cb8 B. The first requests conditional unlock. The second clears the primary lock pointer and requests write-lock acquisition through the fallback cell. The resulting control flow tests the signed word in the network control cell and, for a positive word, the associated cache pointer. A control word of 1 and a nonnull cache reach a distinct continuation. The other tested cases reach a second cleanup call. [Prior record handoff](daemon_discovery_record_report.md) [Audit](triage_evidence/audit_daemon_discovery_relock.py) [Receipt](triage_evidence/daemon_discovery_relock_audit.json.zst)

## Lock requests and pointer identity

| Site | Target or field | Observed contract |
| --- | --- | --- |
| `0x10057b484` | `0x1004423f8`, slot `0x10109fc08`, IA `0x6aa4` | X0=P. P+0 B contains the first cleanup pointer and P+8 B encodes operation `0xa293`. |
| `0x100442650` | `pthread_once` | X0=`0x1010b8cd0`, X1=`0x10040ebd4`. |
| `0x100208efc` | `pthread_rwlock_unlock` | Uses the record pointer when nonnull. Otherwise the adapter reads the fallback cell `0x1010b9638` and uses its contents when nonnull. |
| `0x10057b4d8`, `0x10057b4dc` | P+0 B control, P+8 B pointer | Rebuild the record for acquisition. The new pointer is zero. The adapter decodes the control as W27+`0x2abd`, or `0x593d` at this caller phase. |
| `0x10057b530` | `0x10043e280`, slot `0x10109fe88`, IA `0x6aa4` | X0=P. Bank roots from S+0x870 B and S+0x868 B with key `0x81` select index `0xcbf3`. |
| `0x10043e508` | `pthread_once` | Same control and callback as the unlock adapter. |
| `0x100361df4` | `pthread_rwlock_wrlock` | With P+8 B zero, the callee reads the fallback cell and passes its contents in X0 when nonnull. |

A nonzero caller pointer and a different nonzero fallback pointer produce different unlock and write-lock arguments. Supplying a zero caller pointer with a nonzero fallback selects the fallback in both calls. When both pointers are zero, the two once calls still occur and both lock primitives are bypassed. These traces establish argument selection under the declared backing values. Native allocation ownership, lock state, and synchronization outcome remain unknown. [Independent adapter recovery](daemon_iokit_sync_report.md)

## Network control and cache cells

Two bounded initializer slices recover the same addresses as the earlier network-record path. At `0x1004c2bfc` the original rebase at `0x1010a2ac8` plus the source bias resolves to `0x1010c5760`, placed at S+0x570 B at `0x1004c2c0c`. At `0x1004c2f70` the rebase at `0x1010a9c88` plus its source bias resolves to `0x1010c9298`, placed at S+0x568 B at `0x1004c2f88`. The former cell holds the 32-bit control word and the latter holds the 64-bit cache pointer. The earlier network-record path uses these same cells and increments the control on its own branch. Their direct control-flow connection and concurrent ordering remain unknown. [Network cache gate](daemon_network_gate_report.md)

At `0x10057b538` the caller loads the control through S+0x570 B, immediately after acquisition returns. `0x10057b560` selects `0x1007fc14c` for signed32(control) <= 0 and `0x1007ca49c` for signed32(control) > 0. The original slots are `0x1010512f0` and `0x10109d7a0` respectively, both IA `0x12d7`. The two runs with identical cache-hit inputs and different modeled lock statuses (0 and 35) reach identical transfers.

| Control and cache at the tested phase | Second branch, if reached | Effect on control | Endpoint |
| --- | --- | --- | --- |
| Signed control <= 0, including `0x80000000` | Direct to `0x1007fc14c` | 0 B of writes | Second cleanup, then `0x10075a140` boundary. |
| Control = 1 and cache is nonnull | Index `0x6a09`, slot `0x10106ef38`, IA `0x80fa` | 0 B of writes | Cache-qualified target `0x1005c8428`. |
| Control = 1 and cache is null | Index `0x69e9`, slot `0x10106ee38`, IA `0x80fa` | 1 -> 0 | Second cleanup, then `0x10075a140` boundary. |
| Control > 1, cache nonnull control tested | Same index `0x69e9` | 2 -> 1 in the replay | Second cleanup, then `0x10075a140` boundary. |

The positive test block `0x1007ca49c` reads the cache pointer through S+0x568 B at `0x1007ca4c4`. The source check proves index `0x6a09` exactly when the input word equals 1 and the pointer is nonzero for the reaching W25. The other positive cases run `0x10057f6f0`. At `0x10057f70c` the source stores control minus one modulo 2^32 and the next branch joins `0x1007fc14c`.

The latter block builds a second cleanup record with a zero primary pointer at `0x1007fc1ac` and calls the same adapter at `0x1007fc208`. The tested records encode the same cleanup operation. The adapter requests unlock via the fallback cell when its value is nonnull. The replay then follows the zero comparison word at S+0x8be0 B through `0x1007fc23c` to the pending transfer at `0x10075a140`. This transfer reads a saved continuation from S+0x7448 B, which `0x10083c1d8` populated in the replay. Resolving the successor in the same fixture is a separate control-flow step. Both endpoint paths record zero accesses to the emitter's 16 B output interval.

## Assumptions and verification

| Assumption | Dependent evidence | Falsification probe |
| --- | --- | --- |
| A1. The pinned daemon image supplies original instructions, rebase words and authenticated slots. | Import names, branch addresses, initializer roots and reacquisition bank. | Check 22 fixup records and all 256 bank inputs against original bytes. |
| A2. The saved caller state reaches the initializer-produced addresses. | Same-cell relationship with the earlier network-record gate. | Replay the root writers, restore the original caller registers and independently vary both cell inputs. Natural reach of the producer and any intervening stores remain unknown. |
| A3. The imported once operation is already complete. Thread lock functions return the explicitly modeled value. | Continued original control and recorded lock arguments. | Use null, distinct and equal pointer inputs. Vary status 0 and 35 for the cache-qualified case. Hardware PAC, native once execution and actual lock effects remain unknown. |
| A4. The retained field/control record and S+0x8be0 B comparison word come from the declared fixture. | Exact post-cleanup continuation and both bounded endpoints. | Check the record at each call and vary the signed control and cache pointer before the branch. |

Run `python3 -B triage_evidence/audit_daemon_discovery_relock.py` in the existing Unicorn, Capstone and Z3 setup. The receipt records five bit-vector checks, seven profiles and 136 logical transfers. Time is O(n) in replay instruction visits excluding solver work, and receipt space is O(t) in recorded transfers.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Continued network context | High | Recover the two inputs at S+0x878 B and S+0x858 B on the cache-qualified arm, and the saved continuation reaching `0x10075a140` on the other arm. |
| Caller linkage and byte ownership | High | Establish which caller initialized these cells and find the first byte consumer of S+0x1ba0 B. |
| Native driver exchange | High | Correlate a daemon-side caller PC and its reaching state with an observed FairPlayIOKit request and reply. |
