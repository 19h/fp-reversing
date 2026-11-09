#!/usr/bin/env python3
"""Original CoreFP authenticated import stubs and direct B/BL encodings.

O(B+S+X+R) time and O(S+X+R) output space for text bytes, stubs,
cross-references and retained original small ranges. A direct edge is a static
candidate, not a complete reachable path. Protected indirect calls are omitted.
No native target/loader/API/IPC executes.
"""
import bisect
import json
from pathlib import Path
import struct
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from appstore_agent_reader import CS


def main():
    s=Pointers();stubs={};ranges={};edges=[]
    sec=next(x for x in s.meta['sections'] if x['section']=='__auth_stubs')
    assert sec['size']%16==0
    for at in range(sec['address'],sec['address']+sec['size'],16):
        raw=s.read(at,16);ins=list(CS.disasm(raw,at))
        assert [x.mnemonic for x in ins]==['adrp','add','ldr','braa']
        assert ins[0].op_str.startswith('x17, #') and ins[1].op_str.startswith('x17, x17, #')
        assert ins[2].op_str=='x16, [x17]' and ins[3].op_str=='x16, x17'
        cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16)
        ptr=s.decoded[cell];assert ptr['bind'] and ptr['authenticated'] and ptr['address_diversity']==1 and ptr['key']=='IA'
        stubs[at]={'address':hex(at),'bytes':raw.hex(),'sha256':sha(raw),'pointer':ptr,
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}
    for sec in s.meta['sections']:
        if sec['section']!='__text':continue
        data=s.read(sec['address'],sec['size']);assert len(data)%4==0
        for ix,(word,) in enumerate(struct.iter_unpack('<I',data)):
            if word&0x7c000000!=0x14000000:continue
            pc=sec['address']+ix*4;delta=word&0x3ffffff
            if delta&0x2000000:delta-=0x4000000
            target=pc+delta*4
            if target not in stubs:continue
            fi=bisect.bisect_right(s.starts,pc)-1;assert fi>=0
            start=s.starts[fi];end=s.starts[fi+1] if fi+1<len(s.starts) else sec['address']+sec['size']
            if start not in ranges:
                raw=s.read(start,end-start);row={'start':hex(start),'end':hex(end),'size_bytes':len(raw),'sha256':sha(raw),
                    'end_basis':'next LC_FUNCTION_STARTS entry' if fi+1<len(s.starts) else '__text section end'}
                ranges[start]=row
            # Keep every range hash and edge; retain full small bodies for
            # semantic API calls, rather than hundreds of canary-only tails.
            row=ranges[start]
            if row['size_bytes']<=0x4000 and 'original_function' not in row and stubs[target]['pointer']['import']['name']!='___stack_chk_fail':
                raw=s.read(start,end-start)
                row['original_function']={'start':hex(start),'end':hex(end),'bytes':raw.hex(),'sha256':sha(raw),
                    'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,start)]}
            a=max(start,pc-48);z=min(end,pc+20);raw=s.read(a,z-a)
            edges.append({'callsite':hex(pc),'instruction_bytes':struct.pack('<I',word).hex(),
                'branch':'bl' if word>>31 else 'b','stub':hex(target),'import':stubs[target]['pointer']['import'],
                'compiler_function_start':hex(start),'window':{'start':hex(a),'bytes':raw.hex(),
                    'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]},
                'complete_path_reachability':'unknown'})
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'stubs':list(stubs.values()),
        'direct_branch_candidates':edges,'original_ranges':list(ranges.values()),
        'fixup_inventory_sha256':sha((ROOT/'corefp_fixups_inventory.json').read_bytes()),
        'generator_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'corefp_import_calls.json').write_text(json.dumps(out,indent=2)+'\n')
    from collections import Counter
    print(json.dumps({'stubs':len(stubs),'direct_branches':len(edges),'caller_ranges':len(ranges),
        'import_counts':dict(Counter(x['import']['name'] for x in edges))}))


if __name__=='__main__':main()
