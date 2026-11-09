#!/usr/bin/env python3
"""Finite original RPC502 file/parser/cleanup and supplemental-open sequences.

Explicit sidecar bytes enter the frozen original worker environment. No parser
PC/frame/gate override. Original sources execute in a private guarded guest;
external behavior,allocation and cleanup results remain declared models.
O(C*(B+V+E+S)) bounded time/space;no native target or host-resource operation.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from probe_rpc502_parser import Parser,ROOT,SOURCE


def cases():
    out=[]
    def add(label,h=1,t=0,n=64,fixture=None,opaque=b'\0'*4,optionals=(0,0,0),pattern_offset=None):
        raw=bytearray(max(n,24));struct.pack_into('>I',raw,0,h);raw[4:8]=opaque;struct.pack_into('>4I',raw,8,t,*optionals)
        if pattern_offset is not None:
            for i in range(24,min(n,56)):raw[i]=(i-24+pattern_offset)&255
        out.append({'label':label,'file_hex':bytes(raw[:n]).hex(),'fixture':fixture or {}})
    for h in range(9):add('header_'+str(h),h=h,t=1)
    for h in [63,64,65,0x7fffffff,0x80000000,0xffffffff]:add('header_'+hex(h),h=h,t=1)
    for t in [0,1,2,3,4,5,6,7,8,0x7fffffff,0x80000000,0xffffffff]:add('selector_'+hex(t),t=t)
    for n in [1,2,3,4,5,7,8,9,11,12,16,40,55,56,57,58,63,64]:add('extent_'+str(n),t=1,n=n)
    for h in [1,3,5]:
        for t in [1,2]:add('record_'+str(h)+'_'+str(t),h=h,t=t,opaque=bytes.fromhex('12345678'),optionals=(0x11223344,0x55667788,0x99aabbcc),pattern_offset=24)
    for offset in range(0,256,32):add('span_pattern_'+str(offset),t=2,pattern_offset=offset)
    for marker in [0x55,0x75,0x54,0x76]:add('opaque_marker_'+hex(marker),t=1,opaque=bytes([marker,0x12,0x34,0x56]))
    for byte in [0,0xff]:
        add('tail_ignored_'+str(byte),t=1,n=57);raw=bytearray.fromhex(out[-1]['file_hex']);raw[-1]=byte;out[-1]['file_hex']=raw.hex()
    for label,f in [('allocation_NULL',{'extra_malloc_NULL':True}),('allocation_boundary',{'extra_malloc_stop':True}),('unmap_error',{'unmap_result':-1}),('close_error',{'close_result':-1})]:add(label,fixture=f)
    return out


def run_case(case):
    q=Parser(bytes.fromhex(case['file_hex']),case['fixture']);r=q.run();return r,q.instruction_bank


def main():
    rows=[];pool={}
    for case in cases():
        r,bank=run_case(case)
        for a,item in bank.items():old=pool.get(a);assert old is None or old==item;pool[a]=item
        raw=json.dumps(r,separators=(',',':')).encode();rows.append({'case':case,'steps':r['steps'],'stop_reason':r['stop_reason'],'original_visit_count':r['original_visit_count'],'original_ordered_bytes_sha256':r['original_ordered_bytes_sha256'],'payload_encoding':'zlib compressed UTF-8 JSON,base64','payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode()});print(json.dumps({'case':case['label'],'steps':r['steps'],'stop':r['stop_reason'],'last':r['records'][-1],'extra_malloc':r['extra_malloc_calls']}),flush=True)
    dependencies=['probe_rpc502_parser.py','probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py','daemon_rpc502_context_probe.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in dependencies},'source_sha256':sha(SOURCE),'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'target_host_operations_executed':False,'full_goal_complete':False};(ROOT/'rpc502_parser_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'instruction_records':len(pool)}),flush=True)

if __name__=='__main__':main()
