# Installed selector 26 cleanup and core result

Across 32 offline cases, both outcomes of the post-helper 16 B `FPTTLV` allocation reach cleanup and restore the original kernel staging bytes. The core prepares different nonzero return values for the two outcomes. The values are present in `W0` immediately before the final floating-point register restore and authenticated return. [Preceding helper audit](live_fairplay_selector26_helper_report.md)

| Modeled allocation result at `0xfffffe000a683228` | Cases | Raw status saved at `0xfffffe000a6a6254` | Core `W0` at `0xfffffe000a6a7484` |
| --- | ---: | --- | --- |
| Null | 16 | `0xce515bb2` | `0xffff5bd4` |
| Fresh 16 B container | 16 | `0xce515bb8` | `0xffff5bde` |

## Internal parser and cleanup

The allocation site is reused from the first fallback parse. Here the input pointer in context `+0x618` names the fourth protected nested record's body, and the continuation in context `+0x5c8` names `0xfffffe000a6a6234`. The extent at workspace `+0xc8c` is encoded as the nested span length XOR `0x31ae0066`. The span is 96 B or 112 B. On a fresh allocation the store at `0xfffffe000a683290` initializes both container pointers to zero. In the inspected 288 B example, the selected parser reads the first ten protected bytes and then requests retirement of that empty container. The null allocation goes directly to the saved continuation and has no reads from those protected record bodies during the new segment. [Original fallback parser inputs](live_fairplay_selector26_fallback_report.md) [Fourth nested record](live_fairplay_selector26_nested_report.md)

Both modeled outcomes save a raw failure word at workspace `+0xd98`. They clean up the nested records, message and older fallback list. The complete 288 B example interleaves each protected-record buffer retirement with its owning node retirement, then requests container retirement. These are allocator interfaces in the model.

| Operation | Installed instruction | Observed interface |
| --- | --- | --- |
| Record buffer retirement | `0xfffffe000a6a1978` | `_IOFreeData`, record backing and stored extent |
| Node retirement | `0xfffffe000a6a1898` | `_IOFreeTypeImpl`, 32 B node descriptor and node |
| Container retirement | `0xfffffe000a6a1754` | `_IOFreeTypeImpl`, 16 B container descriptor and container |
| Restore provider staging | `0xfffffe000a6a7284` | One byte per iteration, from offset N-1 B down to 0 B |
| Release protected fallback buffer | `0xfffffe000a6a7318` | `_IOFreeData`, protected buffer and original extent N |
| Release context | `0xfffffe000a6a73f0` | `_IOFreeTypeImpl`, context descriptor and context |
| Release workspace | `0xfffffe000a6a7440` | `_IOFreeAligned`, workspace and 16,384 B |

Every case verifies all N byte stores and equality with its initial provider staging buffer, for N=272 B or N=288 B. The restoration loop takes O(N) time with constant loop state. Each returned word is the saved raw status XOR `0x31ae0066`. The null case yields the same numeric status as the four earlier provider setup failures. The word alone cannot identify the failing layer. [Earlier proof of the restoration loop](userclient_caller_return_report.md) [Adapter failure returns](userclient_transfer_boundary_report.md)

## Provider and Mach boundary

The installed provider saves the returned `X0` at `0xfffffe000a546490`, requests copy-back of N bytes at `0xfffffe000a5464d4` and restores that status at `0xfffffe000a546568`. The handler tests the low word at `0xfffffe000a545224` and writes the descriptor on zero. If either modeled value reaches the handler through a normal return, it takes the error path after copy-back has been requested. The previously audited method stub selects the short error reply for a nonzero method result. That predicts a 36 B user message, ID 2965, to the send-once right created for request 2865. The supplied trace terminates before any such request. [Provider transfer](live_kext_selector26_transfer_report.md) [Mach transport and emitters](live_iokit_mach_transport_report.md) [Supplied trace](zut_trace_report.md)

## Verification

The offline checks reused all 16 saved nested-parser checkpoints, re-executed the private helper, and continued each case twice with different allocation outcomes. The collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The predecessor helper receipt SHA-256 is `47787985d8651eff9da158e07233ade7cb2b32856b9024c27c4e0b3c3d0008ed`. The checks compared the raw error store, every restored staging byte and the exact `W0` at the last modeled instruction boundary. The post-helper probe stopped at the unsupported vector-pair restore. The final `RETAB` at `0xfffffe000a6a7488` and the provider bridge are static evidence.

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The retained frame, aggregate and workspace fixtures describe the input epoch. | Raw error and restored bytes for the 32 cases. | Compare the helper argument, nested span and staged bytes in a matched ordinary transaction. |
| Allocator outcomes and ordinary retirement returns follow the selected model. | Cleanup order and arrival at the epilogue. | Compare requested object identities and post-call state with actual allocator behavior. |
| The final authentication and provider return complete normally. | Conditional error reply and copy-back request. | Correlate the returned method status, copy count and delivered reply in one transaction. |

| Impact | Open evidence |
| --- | --- |
| High | Match a native request, descriptor copy-in, core result, copy-back count and reply. |
| High | Establish the native conditions for descriptor publication and successful method completion. |
| Medium | Recover and validate the complete fourth-body parser result selection across ordinary inputs. |

QG1-QG7 cover factual scope, the outcome matrix and assumptions, byte accounting, source identity and bounded native evidence.
