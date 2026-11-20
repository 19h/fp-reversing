#!/usr/bin/env python3
"""Compare the pinned bridge's method fixups with the nominal selector 26 ABI."""

import argparse
import json
from pathlib import Path
import subprocess

from analyze_zut_trace import digest
from audit_archived_iokit_open_retirement import RAX_COMMIT, TRACE_SHA, trace_record
from audit_archived_iokit_reply_import import check_memory_routines
from audit_archived_iokit_task_translation import XNU_COMMIT, XNU_SOURCES, check_source


EVIDENCE = Path(__file__).parent
RECEIPTS = {
    "daemon_selector26_request_bytes_audit": "2e1a288a55f811522c497d0d3e27ba670779e912b5f8ca81352d12dcb67fc82f",
    "live_iokit_mach_transport_audit": "bf54c7845bc01963901dfceecfa9db120c8c96f0ca52e41299dfe83e9cc6c415",
    "live_kext_selector26_comparison": "a80f34820fd7a65d511a2c5c16da88c96ebaf649a26b4aa23e311337f827ed7d",
    "live_kext_selector26_transfer_audit": "19568bd216d51e18fc15710d6a61e1d496df9493ea99706dba8cda2398d84e79",
    "live_iokit_selector26_inline_reply_audit": "a3e1e1656ea114953efc2e0b20e8f86d43fe8becc9d978243f9f2dff7795baec",
    "live_iokit_selector26_task_audit": "e6f80b9baa4bf979bdb0319bee6d9afe96db9c01aa7f87ab77e8cbc4cede9409",
}
RAX_ANCHORS = {
    "bridge/kernel.rs": {
        21: "METHOD: i32 = 2865", 33: "MAX_BUFFER: u64 = 64 << 20",
        75: "(count as usize * size).div_ceil(4) * 4", 82: "o += 4; // selector",
        83: "let scalars = u32_at(b, o)?", 84: "past(o + 4, scalars, 8)",
        85: "let inband = u32_at(b, o)?", 86: "past(o + 4, inband, 1)",
        87: "let ool_input = o", 88: "o += 16", 89: "o += 8",
        90: "Some((ool_input, output.then_some(o)))",
        112: "method_fields(buf, ndr + 8, id == id::METHOD)", 113: "fields.push((i, false))",
        114: "fields.extend(out.map(|o| (o, true)))", 129: "addr == 0 || size == 0",
        135: "vec![0u8; size as usize]", 137: "proc.space.read_raw(addr, &mut b)",
        139: "buf[at..at + 8].copy_from_slice", 141: "fix.output = Some((addr, fix.buffers.len()))",
        151: "let Some((guest, i)) = fix.output else", 152: "return;",
        167: "u64_at(raw, o)", 173: "(n as usize).min(b.len())", 174: "proc.space.write_raw(guest",
    },
    "bridge/translate.rs": {
        120: "bridge.mirror.arm()", 121: "host::task_port()",
        252: "kernel::names_memory(m.id) && !matches!(m.reply, Some(Right::SendOnce(_)))",
        323: "buf[HEADER_SIZE..].copy_from_slice(&m.body)",
        402: "class == host::opt64::KOBJECT_CALL",
        414: "kernel::prepare(proc, m.id, &mut buf)?",
        420: "super::mirror::before_send(proc)", 424: "host::msg2(",
        434: "kernel::finish(proc, m.id, f, &buf)", 721: "raw[HEADER_SIZE..size].to_vec()",
    },
    "bridge/mirror.rs": {
        67: "reserve(proc)", 90: "r.submap", 91: "r.prot & vm::VM_PROT_READ == 0",
        103: "adopt(proc, r)", 126: "!proc.space.is_free(r.start, len)",
        138: "host::share_entry(r.start, len, prot)", 162: "proc.space.map(r.start, len, mapping)",
        185: ".vma_snapshot()", 195: "Some(r) if r.start <= at => at = r.end",
        198: "host::reserve(at, end - at, RESERVED_TAG)",
    },
    "bridge/host.rs": {
        582: "pub fn reserve", 587: "task(),", 591: "vmflags::FIXED",
        592: "NULL,", 595: "0,", 596: "0,", 597: "inherit::NONE",
    },
}
HANDLER_SITES = {
    "0xfffffe000a5451e8": "210040f9", "0xfffffe000a5451ec": "820a40b9",
    "0xfffffe000a5451f0": "040c4ea9", "0xfffffe000a54521c": "30093fd7",
    "0xfffffe000a545240": "680200f9", "0xfffffe000a545248": "680a00b9",
}
PROVIDER_SITES = {
    "0xfffffe000a546364": "04680694", "0xfffffe000a54647c": "10093fd7",
    "0xfffffe000a54648c": "c3bf0494", "0xfffffe000a5464d4": "31093fd7",
}


def load_receipts():
    loaded = {}
    for stem, expected in RECEIPTS.items():
        raw = subprocess.check_output(["zstd", "-dc", EVIDENCE / (stem + ".json.zst")])
        assert digest(raw) == expected, stem
        loaded[stem] = json.loads(raw)
    return loaded


def check_words(records, expected):
    by_pc = {record["pc"]: record for record in records}
    assert all(by_pc[pc]["word"] == word for pc, word in expected.items())
    return [by_pc[pc] for pc in expected]


def project_offsets(daemon, method_record):
    assert daemon["trace"]["sha256"] == TRACE_SHA
    assert not daemon["native_method_executed"] and not daemon["trace"]["observed_2865_or_2965"]
    assert (method_record["count_in"], method_record["count_out"]) == (16, 16)
    assert method_record["flags"] == 3
    cases = []
    for case in daemon["cases"]:
        inline = case["inline_size"]
        # NDR at 24, selector at 32, zero scalar count at 36, inline count at 40.
        ool_in = 44 + (inline + 3) // 4 * 4
        ool_out = ool_in + 16 + 8
        assert ool_out + 16 == case["predicted_request_user_bytes"]
        descriptor = case["descriptor"]
        if descriptor is not None:
            assert descriptor["pointer_matches_aggregate"]
            assert descriptor["extent"] == case["aggregate_size"]
            assert (inline, ool_in, ool_out) == (16, 60, 84)
            assert 44 + 8 + 4 <= ool_in
        else:
            assert inline == case["aggregate_size"] and inline != method_record["count_in"]
        cases.append({
            "class": case["class"], "call_pc": case["method_call_pc"],
            "aggregate_bytes": case["aggregate_size"], "inline_bytes": inline,
            "request_bytes": ool_out + 16,
            "explicit_ool_input_offset_bytes": ool_in, "explicit_ool_output_offset_bytes": ool_out,
            "nested_pointer_offset_bytes": 44 if descriptor else None,
            "nested_extent_offset_bytes": 52 if descriptor else None,
            "native_adapter_accepts_input_extent": inline == method_record["count_in"],
        })
    assert {(c["class"], c["aggregate_bytes"]) for c in cases} == {
        ("0x98", 272), ("0x98", 288), ("0x99", 272), ("0x99", 288),
    }
    return cases


def check_reference(archive, receipts):
    assert 2865 not in archive["guest_send_ids"]
    transport = receipts["live_iokit_mach_transport_audit"]
    assert (transport["method_request_id"], transport["method_reply_id"]) == (2865, 2965)
    assert transport["user"]["request_emission_sites"]["2865"] == "0x184ebe090"
    assert transport["user"]["user_request_bytes_at_16_B"] == 100
    comparison = receipts["live_kext_selector26_comparison"]
    assert not comparison["native_method_observed"]
    method = comparison["current"]["method_map"]["methods"]["26"]
    transfers = receipts["live_kext_selector26_transfer_audit"]["current"]
    task = receipts["live_iokit_selector26_task_audit"]
    reply = receipts["live_iokit_selector26_inline_reply_audit"]
    assert task["identity"]["sha256"] == transfers["identity"][0] == reply["kernel_identity"][0]
    assert task["direct_calls"]["0xfffffe000c585320"] == "0xfffffe000be4734c"
    return {
        "fixtures": project_offsets(receipts["daemon_selector26_request_bytes_audit"], method),
        "fixed_adapter_counts": [method["count_in"], method["count_out"]],
        "handler_sites": check_words(transfers["handler"], HANDLER_SITES),
        "provider_sites": check_words(transfers["provider"], PROVIDER_SITES),
        "task_map_call": {"pc": "0xfffffe000c585320", "target": "0xfffffe000be4734c"},
        "framework_reply_copy": check_words(reply["framework_reply_copy"], {
            "0x184ebe200": "d4b8c694", "0x184ebe204": "540300b9",
        }),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("rax_checkout", type=Path)
    parser.add_argument("xnu_checkout", type=Path)
    args = parser.parse_args()
    routines = check_memory_routines(args.rax_checkout)
    assert 2865 in routines["members"]["names_memory"] and 2865 not in routines["members"]["refused"]
    path = "osfmk/device/device.defs"
    sha256, _ = XNU_SOURCES[path]
    print(json.dumps({
        "trace_sha256": TRACE_SHA,
        "retained_receipt_digests": RECEIPTS,
        "reference_interface": check_reference(trace_record(args.trace), load_receipts()),
        "candidate_rax": {
            "commit": RAX_COMMIT, "routine_dispatch": routines,
            "files": [check_source(args.rax_checkout, RAX_COMMIT, "src/user/darwin/" + rel, anchors)
                      for rel, anchors in RAX_ANCHORS.items()],
        },
        "reference_mig": check_source(args.xnu_checkout, XNU_COMMIT, path, {
            614: "routine io_connect_method", 619: "inband_input", 620: "ool_input",
            621: "ool_input_size", 623: "inband_output", 625: "ool_output", 626: "ool_output_size",
        }, sha256),
        "scope": "offline byte-offset and source join; native request, page backing and copy-back unknown",
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
