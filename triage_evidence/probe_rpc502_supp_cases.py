#!/usr/bin/env python3
"""Finite whole-worker supplemental byte classes,cursors,ABI and ownership.

All cases enter original RPC502 worker;external IO/environment/serial API
behavior is declared. O(C*(B+V+E+S)) time and retained space,with bounded
case extents and visits. No native target,host target API or IDB mutation.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from probe_rpc502_supp import Supplemental,ROOT,SOURCE


def make(v,n=256,A=0,B=0,C=0,body=None):
    raw=bytearray(max(n,64+32*A+B+C)if A<=4 and B<=128 and C<=128 else max(n,64));raw[0]=v
    if v in [1,4]:
        off=24 if v==1 else 4;struct.pack_into('>I',raw,off,A);cursor=off+4+32*A
        if cursor+4<=len(raw):struct.pack_into('>I',raw,cursor,B)
        data=cursor+4
    elif v in [2,3,5]:
        struct.pack_into('>I',raw,4,A);cursor=8+A
        if cursor+4<=len(raw):struct.pack_into('>I',raw,cursor,B)
        data=cursor+4;cursor=data+B
        if cursor+4<=len(raw):struct.pack_into('>I',raw,cursor,C)
    else:data=32
    if body is not None and data<len(raw):raw[data]=body
    return bytes(raw[:n])


def cases():
    out=[]
    def add(label,v=1,n=256,A=0,B=0,C=0,body=None,fixture=None,raw=None):out.append({'label':label,'file_hex':(make(v,n,A,B,C,body)if raw is None else raw).hex(),'fixture':fixture or {}})
    for v in range(256):add('byte_'+str(v),v=v)
    for v,ns in [(1,[0,1,2,3,4,7,8,11,12,23,24,27,28,31,32,159,160]),(4,[7,8,11,12,139,140]),(2,[7,8,11,12,15,16])]:
        for n in ns:add('extent_'+str(v)+'_'+str(n),v=v,n=n)
    for v in [1,2,3,4,5]:
        for A,B,C in [(1,2,128),(2,16,64),(0,1,1),(0,2,0),(0,16,2),(0,64,128)]:add('cursor_'+str(v)+'_'+str(A)+'_'+str(B)+'_'+str(C),v=v,n=512,A=A,B=B,C=C)
    for v,n in [(1,191),(1,192),(4,171),(4,172)]:add('skip_extent_'+str(v)+'_'+str(n),v=v,n=n,A=1)
    for v in [1,2,4]:
        for A in [0x7fffffff,0x80000000,0xffffffff]:add('huge_A_'+str(v)+'_'+hex(A),v=v,A=A,n=64)
    for v in [1,2,4]:
        for body in [1,0x80,0xff]:add('body_'+str(v)+'_'+str(body),v=v,n=512,B=16,C=128,body=body)
    for errno in [1,2,4,13]:add('open_errno_'+str(errno),n=0,fixture={'second_open_result':-1,'second_errno_u32':errno})
    for label,f in [('stat_error',{'second_fstat_result':-1}),('stat_error_seeded',{'second_fstat_result':-1,'seed_size_on_stat_error':True}),('map_failed',{'second_mmap_failed':True}),('close_failed',{'second_close_result':-1}),('first_unmap_failed',{'first_unmap_result':-1}),('first_close_failed',{'first_close_result':-1}),('unknown_tail',{'second_size_u64':256})]:add(label,n=32 if label=='unknown_tail' else 256,fixture=f)
    return out


def run_case(case):
    q=Supplemental(bytes.fromhex(case['file_hex']),case['fixture']);r=q.run();return r,q.instruction_bank


def main():
    rows=[];pool={};sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    for case in cases():
        r,bank=run_case(case)
        for a,i in bank.items():assert a not in pool or pool[a]==i;pool[a]=i
        blob=json.dumps(r,separators=(',',':')).encode();rows.append({'case':case,'steps':r['steps'],'stop_reason':r['stop_reason'],'payload_zlib_base64':base64.b64encode(zlib.compress(blob)).decode()});print(case['label'],r['steps'],r['stop_reason'],r['records'][-1],flush=True)
    deps=['probe_rpc502_supp.py','probe_rpc502_parser.py','probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py','daemon_rpc502_context_probe.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'target_host_operations_executed':False,'full_goal_complete':False};(ROOT/'rpc502_supp_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)

if __name__=='__main__':main()
