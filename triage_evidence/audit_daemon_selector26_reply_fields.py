#!/usr/bin/env python3
"""Verify the pinned daemon's descriptor reply loads and immediate data use."""

import hashlib
import json

import audit_daemon_selector26_return as reply


def local_loads(frame, lower, upper):
    return [
        (pc, address - lower, width)
        for pc, address, width in frame.loads
        if address < upper and address + width > lower
    ]


def load_rows(rows):
    return [{'pc': hex(pc), 'offset_bytes': offset, 'width_bytes': width}
            for pc, offset, width in rows]


def audit():
    digest = hashlib.sha256(reply.SOURCE.read_bytes()).hexdigest()
    assert digest == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    profiles = {}
    for size, extent, fields in (
        (16, 14, [(0x100293078, 0, 8), (0x1001dc090, 16, 4), (0x1002ffc0c, 8, 8)]),
        (0x100000010, 14, [(0x100293078, 0, 8)]),
        (16, 13, [(0x100293078, 0, 8), (0x1001dc090, 16, 4)]),
    ):
        frame = reply.second_return(size, extent)
        observed = local_loads(frame, reply.SP, reply.SP + 24)
        assert observed == fields
        payload = local_loads(frame, reply.DATA, reply.DATA + 14)
        assert len(payload) == (14 if (size, extent) == (16, 14) else 0)
        profiles[f'{size}:{extent}'] = {
            'stack_loads': load_rows(observed),
            'payload_loads': load_rows(payload),
            'record_status_store_pc': hex(frame.stores[-1][0]),
            'return_pc': hex(frame.return_pc),
        }
    direct = {}
    for status in (0, 0xffff5bbc):
        frame = reply.first_return(status, 16)
        count_loads = local_loads(frame, reply.SP, reply.SP + 8)
        assert count_loads == ([(0x1002724a0, 0, 8)] if status == 0 else [])
        direct[hex(status)] = load_rows(count_loads)
    return {
        'scope': 'Original instruction replay with modeled normal API returns.',
        'daemon_sha256': digest,
        'descriptor_profiles': profiles,
        'direct_output_size_loads': direct,
        'instruction_spans': list(reply.SPANS.values()),
        'native_exchange_observed': False,
    }


if __name__ == '__main__':
    print(json.dumps(audit(), indent=2))
