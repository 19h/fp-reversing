#!/usr/bin/env python3
"""Original-image 720-byte allocation/initializer and bounded field census.
O(text words + retained bytes) time; O(matches + retained bytes) space.
Syntactic matches are candidates, not owner equivalence or native callers.
"""
import json, struct, hashlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,selected,verify_original_fixups
from recover_daemon_iokit_census import text_section
from recover_daemon_context_lock import ida_output

def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

SPECS=[('allocate720',0x100badfc0,0x100bae090),
       ('initialize720',0x100b0b6fc,0x100b0b9a4),
       ('null_successor',0x1009687c8,0x100968828),
       ('known20_consumer',0x100be25b8,0x100be2600),
       ('other_field_consumer',0x100a5a514,0x100a5a64c)]

def capture():
    A,N=text_section();raw=IMAGE.read(A,N);matches={'ADD64_immediate_238':[], 'unsigned_memory_238_nonSP':[], 'STR64_plus8_nonSP':[],'STR64_SP_3118':[]}
    for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
        pc=A+4*j;labels=[]
        if w&0xffc00000==0x91000000 and ((w>>10)&4095)==0x238:labels.append('ADD64_immediate_238')
        if w&0x3b000000==0x39000000 and (((w>>10)&4095)<<((w>>30)&3))==0x238 and ((w>>5)&31)!=31:labels.append('unsigned_memory_238_nonSP')
        if w&0xffc00000==0xf9000000 and ((w>>10)&4095)==1 and ((w>>5)&31)!=31:labels.append('STR64_plus8_nonSP')
        if w&0xffffffe0==0xf90003e0|((0x3118//8)<<10):labels.append('STR64_SP_3118')
        for label in labels:
            b=IMAGE.read(pc-16,36);ins=list(CS.disasm(b,pc-16));assert len(ins)==9
            matches[label].append({'pc':hex(pc),'word':hex(w),'context_start':hex(pc-16),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
    spans=[]
    for name,a,z in SPECS:
        b=IMAGE.read(a,z-a);spans.append({'label':name,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest()})
    live=[];r=json.loads((ROOT/'daemon_record720_ida_bytes.json').read_text());assert not r.get('isError')
    for row in ida_output(r)['results']:
        a=int(row['address'],16);b=bytes.fromhex(row['bytes']);assert len(b)==row['size_read']==row['size_requested'] and IMAGE.read(a,len(b))==b
        live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    bank=selected(0x100fc4230,0x101031fa0,0xe4,0xcbb0);assert bank['slot']=='0x10109ff58' and bank['target']=='libSystem/_malloc'
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'text_address':hex(A),'text_size_bytes':N,'text_sha256':hashlib.sha256(raw).hexdigest(),'spans':spans,'censuses':matches,'census_limit':'Aligned literal encodings only; no alias, alternate constant construction, scaled register, pair/unscaled store or phase completeness claim. Non-SP registers can still be stack aliases.','allocator_bank':{'premise':'saved SP+2978=100FC4230 and incoming X13=101031FA0; controller words arbitrary u32',**bank},'fixups':verify_original_fixups([0x10109ff58,TABLE+0x5691*8,TABLE+0x5692*8]),'live_IDB_matches':live,'dependencies':{n:sha(ROOT/n)for n in ['daemon_receive_tools.py','recover_daemon_iokit_census.py','recover_daemon_context_lock.py','daemon_record720_ida_bytes.json']},'native_target_executed':False,'idb_mutated':False,'registry_value_identity_established':False,'full_goal_complete':False}

def main():
    out=capture();(ROOT/'daemon_record720_source.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'counts':{k:len(v)for k,v in out['censuses'].items()},'IDA_bytes':sum(r['size_bytes']for r in out['live_IDB_matches'])}),flush=True)
if __name__=='__main__':main()
