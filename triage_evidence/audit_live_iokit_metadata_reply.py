#!/usr/bin/env python3
"""Audit the ordinary inline 2865/2965 metadata path without sending IPC."""

import argparse
import json
from pathlib import Path
import struct
import subprocess

import z3

from audit_iokit_sync_error_reply import Slice
from audit_live_iokit_mach_transport import CACHE_UUID, IOKIT, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map
from bootpolicy_cache_reader import Cache, Dylib, CS
from lskd_values_symbolic import resize


H, REQ, KSP, A, EXT, USP, OUT, SIZE, SCALARS, OOL = range(0x100000, 0x240000, 0x20000)
NDR_ADDRESS = 0xfffffe000cb0a7d0
NDR = 0x0000000100000000
VALUE, NAME, BITS, SELECTOR = z3.BitVecs("provider_word32 receive_name32 converted_header_bits32 selector32", 32)
METADATA = Path(__file__).with_name("live_fairplay_metadata_audit.json.zst")


class Sources:
    def __init__(self, collection, cache):
        self.collection = collection
        self.cache = cache
        self.windows = {}

    def span(self, start, end):
        key = (start, end)
        if key not in self.windows:
            read = self.collection.read if start >= 1 << 63 else self.cache.read
            self.windows[key] = {"label": "slice", "start": hex(start), "end": hex(end),
                                 "bytes_hex": read(start, end - start).hex()}
        return self.windows[key]

    def check(self, pc, mnemonic, operands):
        word, = CS.disasm(bytes.fromhex(self.span(pc, pc + 4)["bytes_hex"]), pc)
        assert (word.mnemonic, word.op_str) == (mnemonic, operands), hex(pc)


def prove(name, conditions, *wrong):
    solver = z3.SolverFor("QF_BV")
    solver.set(timeout=30000)
    solver.add(*conditions)
    assert solver.check() == z3.sat, name
    solver.add(z3.simplify(z3.Or(*wrong)))
    query = solver.to_smt2()
    assert solver.check() == z3.unsat, (name, solver.reason_unknown())
    return {"name": name, "counterexample_query": query, "result": "unsat"}


def prepare_reply(src):
    # The expanded request has no descriptors or input scalars. Caller supplies
    # four-byte inline capacity and zero scalar capacity and OOL lengths.
    x = Slice(src, [
        ("x21", H), ("x24", H + 32), ("x25", REQ + 32), ("x22", REQ - 96),
        ("x23", REQ - 96), ("sp", KSP), ("w0", 0x2345),
    ], [
        (REQ + 40, 4, SELECTOR), (REQ + 44, 4, 0), (REQ + 48, 4, 0),
        (REQ + 52, 8, 0), (REQ + 60, 8, 0), (REQ + 68, 4, 4),
        (REQ + 72, 4, 0), (REQ + 76, 8, 0), (REQ + 84, 8, 0),
    ])
    x.run_slice(0xfffffe000be8164c, 0xfffffe000be816b4)
    report = prove("stub passes reply data and count cells directly", [z3.Or(SELECTOR == 22, SELECTOR == 23)],
                   x.read("w1") != SELECTOR, x.read("w3") != 0, x.read("w5") != 0,
                   x.get(KSP, 8) != H + 48, x.get(KSP + 8, 8) != H + 44,
                   x.get(H + 44, 4) != 4, x.get(KSP + 0x3c, 4) != 0,
                   x.read("x6") != 0, x.read("x7") != 0)
    src.check(0xfffffe000be816b4, "bl", "#0xfffffe000c5bff74")
    return x, report


def carry_count_and_value(src, reply, metadata):
    # A is the IOExternalMethodArguments record. The ordinary flags-3 path
    # receives these values from the synchronous implementation.
    x = Slice(src, [("sp", EXT), ("x2", A), ("x8", 0x2345)], [
        (A + 8, 8, 0), (A + 0x38, 4, 0), (A + 0x58, 8, H + 48), (A + 0x60, 4, 4),
    ])
    x.run_slice(0xfffffe000c5b23c0, 0xfffffe000c5b23d4)
    x.seed("x20", 0x3456)
    x.seed("x19", 0x2345)
    x.run_slice(0xfffffe000c5b2654, 0xfffffe000c5b266c)
    src.check(0xfffffe000c5b266c, "bl", "#0xfffffe000c5b47d4")
    out = [(x.read("x4") != H + 48), (x.read("x5") != EXT + 16), (x.get(EXT + 16, 8) != 4)]
    src.check(0xfffffe000c5b4820, "ldr", "x9, [x5]")
    src.check(0xfffffe000c5b4824, "cmp", "x9, x10")
    src.check(0xfffffe000c5b484c, "cbz", "x8, #0xfffffe000c5b4958")
    src.check(0xfffffe000c5b495c, "mov", "w7, #0x705d")
    src.check(0xfffffe000c5b49b8, "mov", "x1, x4")
    src.check(0xfffffe000c5b4a34, "braa", "x17, x7")
    for method in metadata["methods"].values():
        store = int(method["output_store"], 16)
        userclient = Slice(src, [("x19", H + 48), ("x0", resize(VALUE, 64))])
        userclient.run_slice(store - 8, store + 4)
        out.extend((userclient.read("w0") != 0, userclient.get(H + 48, 4) != VALUE))
    x.seed("w0", 0)
    x.seed("w21", 0xe00002c2)
    x.run_slice(0xfffffe000c5b2670, 0xfffffe000c5b2688)
    out.extend((x.read("w0") != 0, x.get(A + 0x60, 4) != 4))

    # Synchronous argument construction and count writeback. Method routing,
    # locking and provider internals enter as the independently checked ABI.
    src.check(0xfffffe000c5c0128, "str", "x8, [sp, #0x88]")
    src.check(0xfffffe000c5c0134, "str", "w24, [sp, #0x90]")
    src.check(0xfffffe000c5c0220, "bl", "#0xfffffe000c5bfe6c")
    r = Slice(src, [("sp", A - 0x30), ("x0", x.read("x0")),
                    ("x27", KSP + 0x3c), ("x28", REQ + 84)], [
        (A - 0x10, 8, H + 44), (A + 0x50, 4, 0),
        (A + 0x60, 4, x.get(A + 0x60, 4)), (A + 0x70, 4, 0),
    ])
    r.run_slice(0xfffffe000c5c0224, 0xfffffe000c5c0248)
    out.extend((r.get(H + 44, 4) != 4, r.get(KSP + 0x3c, 4) != 0,
                r.get(REQ + 84, 8) != 0, r.read("x23") != 0))
    for address, width, value in [(H + 44, 4, r.get(H + 44, 4)), (H + 48, 4, VALUE),
                                  (KSP + 0x3c, 4, r.get(KSP + 0x3c, 4)), (REQ + 84, 8, 0)]:
        reply.store(resize(address, 64), width, resize(value, width * 8), 0)
    return prove("provider word and fixed count survive the legacy adapter", [], *out)


def finish_and_pack(src, reply):
    # Retain the ordinary release's permitted X0 clobber and reload status.
    reply.seed("w0", 0)
    reply.run_slice(0xfffffe000be816b8, 0xfffffe000be816bc)
    src.check(0xfffffe000be816dc, "blraa", "x9, x16")
    reply.seed("x0", z3.BitVec("release_return_ignored", 64))
    reply.run_slice(0xfffffe000be816e0, 0xfffffe000be816e4)
    src.check(0xfffffe000be816e4, "cbz", "w0, #0xfffffe000be816fc")
    status = reply.read("w0")
    reply.seed("x16", H)
    reply.seed("x8", REQ)
    reply.seed("x23", NDR_ADDRESS - 0x7d0)
    for address, size, value in [(REQ, 4, 0x1513), (REQ + 16, 8, 0x567800),
                                  (REQ + 28, 4, 2865), (NDR_ADDRESS, 8, NDR)]:
        reply.store(resize(address, 64), size, resize(value, size * 8), 0)
    reply.run_slice(0xfffffe000bd3c45c, 0xfffffe000bd3c490)
    reply.run_slice(0xfffffe000be816fc, 0xfffffe000be81714)
    scalar_ok = reply.condition("lo")
    reply.seed("x22", REQ + 84)
    reply.run_slice(0xfffffe000be81718, 0xfffffe000be81738)
    src.check(0xfffffe000be81738, "bl", "#0xfffffe000c697810")
    scalar_copy_extent = reply.read("x2")
    reply.run_slice(0xfffffe000be8173c, 0xfffffe000be81758)
    body = [(24, 8, NDR), (32, 4, 0), (36, 4, 4), (40, 4, VALUE),
            (44, 4, 0), (48, 8, 0)]
    kernel = prove("success stub writes 64-byte expanded reply", [], status != 0,
                   z3.Not(scalar_ok), scalar_copy_extent != 0, reply.get(H + 4, 4) != 64,
                   reply.get(H + 8, 8) != 0x567800, reply.get(H + 28, 4) != 2965,
                   *(reply.get(H + 8 + offset, width) != value for offset, width, value in body))
    # The ordinary namespace conversion gives zero remote name and the
    # converted local receive name. Pack the header in the original buffer.
    for offset, value in [(8, 0), (16, NAME)]:
        reply.store(resize(H + offset, 64), 8, resize(value, 64), 0)
    for name, value in [("x8", H), ("x0", H), ("w10", reply.get(H + 4, 4)),
                        ("w13", 0), ("w9", 0), ("w12", BITS), ("x21", EXT), ("w27", 0)]:
        reply.seed(name, value)
    reply.run_slice(0xfffffe000bd0e5ec, 0xfffffe000bd0e5f8)
    src.check(0xfffffe000bd0e5f8, "xtn", "v1.2s, v1.2d")
    q = reply.read("q1")
    reply.write("q1", z3.ZeroExt(64, z3.Concat(z3.Extract(95, 64, q), z3.Extract(31, 0, q))))
    reply.run_slice(0xfffffe000bd0e5fc, 0xfffffe000bd0e614)
    fields = [(0, 4, BITS), (4, 4, 56), (8, 4, 0), (12, 4, NAME),
              (16, 4, 0), (20, 4, 2965)] + body
    packed = prove("in-place copyout contracts header by eight bytes", [], reply.read("x0") != H + 8,
                   *(reply.get(H + 8 + offset, width) != value for offset, width, value in fields))
    return fields, [kernel, packed]


def accepted_reply(src, fields):
    memory = [(USP + 16 + offset, width, value) for offset, width, value in fields]
    memory += [(SIZE, 4, 4), (SCALARS, 4, 0), (USP + 0x2010, 8, OUT), (USP + 0x2020, 8, OUT + 16)]
    x = Slice(src, [("sp", USP), ("x29", USP + 0x2000), ("x26", SIZE),
                    ("x25", SCALARS), ("x23", OOL)], memory)
    x.run_slice(0x184ebe0d0, 0x184ebe0d8)
    checks = [z3.Not(x.condition("ne"))]
    x.run_slice(0x184ebe0dc, 0x184ebe0e0)
    checks.append(z3.Not(x.condition("eq")))
    x.run_slice(0x184ebe0e4, 0x184ebe0e8)
    checks.append(z3.Extract(31, 31, x.read("w8")) != 0)
    x.run_slice(0x184ebe0ec, 0x184ebe100)
    checks.append(z3.Not(x.condition("hi")))
    x.run_slice(0x184ebe144, 0x184ebe148)
    checks.append(x.read("w9") != 0)
    x.run_slice(0x184ebe15c, 0x184ebe160)
    checks.append(x.read("w19") != 0)
    for start, end, condition in [
        (0x184ebe164, 0x184ebe16c, "ls"), (0x184ebe170, 0x184ebe17c, "hs"),
        (0x184ebe180, 0x184ebe190, "hs"), (0x184ebe194, 0x184ebe1a4, "ls"),
        (0x184ebe1a8, 0x184ebe1b4, "ls"), (0x184ebe1b8, 0x184ebe1c4, "eq"),
        (0x184ebe1c8, 0x184ebe1d4, "ls"),
    ]:
        x.run_slice(start, end)
        checks.append(z3.Not(x.condition(condition)))
    x.run_slice(0x184ebe1ec, 0x184ebe200)
    checks.extend((x.read("x0") != OUT, x.read("x1") != USP + 16 + 40, x.read("x2") != 4))
    src.check(0x184ebe200, "bl", "#0x18806c550")
    x.store(resize(OUT, 64), 4, x.get(USP + 16 + 40, 4), 0)
    x.run_slice(0x184ebe204, 0x184ebe218)
    checks.append(z3.Not(x.condition("ls")))
    x.run_slice(0x184ebe238, 0x184ebe24c)
    src.check(0x184ebe24c, "bl", "#0x18806c550")
    checks.append(x.read("x2") != 0)
    x.run_slice(0x184ebe250, 0x184ebe26c)
    x.run_slice(0x184ebdf94, 0x184ebdf98)
    checks.extend((x.get(OUT, 4) != VALUE, x.get(SIZE, 4) != 4, x.read("w0") != 0,
                   x.get(OOL, 8) != 0, x.get(SCALARS, 4) != 0))
    w = Slice(src, [("x19", SIZE), ("x29", USP), ("x0", x.read("x0"))],
              [(SIZE, 8, 4), (USP - 0x14, 4, x.get(SIZE, 4))])
    w.run_slice(0x184ebde60, 0x184ebde68)
    checks.append(z3.Not(w.condition("ls")))
    w.run_slice(0x184ebde6c, 0x184ebde70)
    w.run_slice(0x184ebde78, 0x184ebde7c)
    checks.extend((w.get(SIZE, 8) != 4, w.read("w0") != 0))
    return prove("framework accepts and returns all four provider bytes", [z3.Extract(31, 31, BITS) == 0], *checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current_collection", type=Path)
    args = parser.parse_args()
    collection = Collection(args.current_collection, IDENTITIES[1])
    cache = Cache()
    framework = Dylib(cache, IOKIT)
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    assert framework.uuid == "82be1de5-91c4-3152-b63b-81db4c5e7992"
    assert collection.read(NDR_ADDRESS, 8) == struct.pack("<Q", NDR)
    assert "_NDR_record" in collection.names(NDR_ADDRESS)
    routine = mig_map(collection)["routines"][2865]
    assert routine["stub"]["target"] == "0xfffffe000be8152c"
    src = Sources(collection, cache)
    meta = json.loads(subprocess.check_output(["zstd", "-dc", METADATA]))
    assert tuple(meta["current_identity"]) == IDENTITIES[1]
    src.check(0x184ebe090, "bl", "#0x188088af0")
    for pc, mnemonic, operands in [
        (0x18806c550, "adrp", "x17, #0x1e20f1000"),
        (0x18806c554, "add", "x17, x17, #0xfa0"),
        (0x18806c558, "ldr", "x16, [x17]"),
        (0x18806c55c, "braa", "x16, x17"),
        (0xfffffe000bd3c78c, "ldr", "w23, [x16, #0x28]"),
        (0xfffffe000bd3c794, "b.ne", "#0xfffffe000bd3c7a8"),
        (0xfffffe000bd0f208, "bl", "#0xfffffe000bd0fbf0"),
        (0x184ebe0d8, "b.eq", "#0x184ebe134"),
        (0x184ebe0e0, "b.ne", "#0x184ebe13c"),
        (0x184ebe0e8, "tbnz", "w8, #0x1f, #0x184ebe14c"),
        (0x184ebe100, "b.hi", "#0x184ebe144"),
        (0x184ebe148, "cbz", "w9, #0x184ebe15c"),
        (0x184ebe160, "cbnz", "w19, #0x184ebe150"),
        (0x184ebe16c, "b.hi", "#0x184ebe14c"),
        (0x184ebe17c, "b.lo", "#0x184ebe150"),
        (0x184ebe190, "b.lo", "#0x184ebe150"),
        (0x184ebe1a4, "b.hi", "#0x184ebe150"),
        (0x184ebe1b4, "b.hi", "#0x184ebe150"),
        (0x184ebe1c4, "b.ne", "#0x184ebe150"),
        (0x184ebe1d4, "b.ls", "#0x184ebe1ec"),
        (0x184ebe218, "b.ls", "#0x184ebe238"),
    ]:
        src.check(pc, mnemonic, operands)
    copy_veneer = {k: v for k, v in cache.pointer(0x1e20f1fa0).items() if k != "path"}
    assert copy_veneer["authenticated"] and copy_veneer["target"] == "0x1855ded60"
    memmove = Dylib(cache, "/usr/lib/system/libsystem_platform.dylib")
    assert any(s["name"] == "__platform_memmove" for s in memmove.symbols_at(0x1855ded60))
    reply, initial = prepare_reply(src)
    names = carry_count_and_value(src, reply, meta)
    fields, proofs = finish_and_pack(src, reply)
    proofs = [initial, names, *proofs, accepted_reply(src, fields)]
    values = {selector: row["output_hex"] for selector, row in meta["conditional_metadata"].items()}
    report = {
        "collection": IDENTITIES[1], "cache_uuid": cache.uuid, "iokit_uuid": framework.uuid,
        "routine": routine, "proofs": proofs,
        "selected_original_windows": list(src.windows.values()),
        "framework_copy_fixup": copy_veneer, "normal_kernel_message_bytes": 64,
        "normal_user_message_bytes": 56, "application_word_by_selector": values,
        "native_reply_observed": False,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
