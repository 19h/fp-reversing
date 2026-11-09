#!/usr/bin/env python3
"""Original LC_FUNCTION_STARTS ownership context for parser source ranges.

These are metadata-delimited compiler ranges,not proof of complete semantic
routines,conventional calls,or reachability. O(B+F+R*log F) time/space. Read-only
original binary and retained contracts;no IDB or native target operation.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from daemon_receive_tools import IMAGE,SOURCE,ROOT
from resolve_kernel_collection_interfaces import commands
from bootpolicy_cache_reader import uleb


def sha(b):return hashlib.sha256(b).hexdigest()
def starts():
    out=[];record=None
    for at,cmd,n in commands(IMAGE.data,0):
        if cmd!=0x26:continue
        off,size=struct.unpack_from('<II',IMAGE.data,at+8);raw=IMAGE.data[off:off+size];record={'file_offset':off,'size_bytes':size,'sha256':sha(raw)};p=0;a=0x100000000
        while p<len(raw):
            delta,p=uleb(raw,p)
            if not delta:break
            a+=delta;out.append(a)
    assert record and len(out)==len(set(out));return out,record

def main():
    funcs,meta=starts();c=json.loads((ROOT/'rpc502_parser_contracts.json').read_text());owners={};segments=[]
    for row in c['original_ranges']:
        a=int(row['start'],16);z=int(row['end'],16);p=a;parts=[]
        while p<z:
            i=bisect.bisect_right(funcs,p)-1;assert 0<=i<len(funcs)-1;start,end=funcs[i:i+2];raw=IMAGE.read(start,end-start);owners[start]={'start':hex(start),'end':hex(end),'size_bytes':end-start,'sha256':sha(raw)};limit=min(z,end);parts.append({'start':hex(p),'end':hex(limit),'compiler_range_start':hex(start)});p=limit
        segments.append({'source_start':row['start'],'source_end':row['end'],'compiler_segments':parts})
    out={'scope':__doc__,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{'rpc502_parser_contracts.json':sha((ROOT/'rpc502_parser_contracts.json').read_bytes())},'source_sha256':sha(SOURCE.read_bytes()),'LC_FUNCTION_STARTS':meta,'compiler_start_count':len(funcs),'all_compiler_starts':[hex(v)for v in funcs],'selected_compiler_ranges':list(owners.values()),'source_range_ownership':segments,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_parser_compiler_ownership.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compiler_starts':len(funcs),'selected_compiler_ranges':len(owners),'source_ranges':len(segments)}),flush=True)

if __name__=='__main__':main()
