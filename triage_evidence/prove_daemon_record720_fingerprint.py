#!/usr/bin/env python3
"""Rebuild callback field/initializer/state contracts from original A64.
O(lifted instructions + solver resources) time/space; 30 s/query.
Source-local statements preserve alignment, record and phase prerequisites.
"""
import json
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from prove_daemon_registry_lookup import RegistryLift
from lskd_values_symbolic import part,mem,cell,resize

class FingerprintLift(RegistryLift):
    def run(self,label):
        original=self.c;row=next(r for r in self.c['spans']if r['label']==label)
        from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address
            if i.mnemonic=='subs':
                name=i.reg_name(i.operands[0].reg);n=self.width(name);a=self.operand(i,i.operands[1],n);b=self.operand(i,i.operands[2],n)
                self.cmp_left=a;self.cmp_right=b;self.equal=a==b;self.carry=z3.UGE(a,b);self.write(name,a-b);self.count+=1
            else:
                self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
        self.c=original;return self

def obligations(c):
    RP,IP,CP,DP,X,Y,SP=z3.BitVecs('fingerprint_record64 fingerprint_item64 fingerprint_user64 fingerprint_destination64 fingerprint_X64 fingerprint_Y64 fingerprint_SP64',64)
    N,STATE,BUF=z3.BitVecs('fingerprint_encoded_total32 fingerprint_digest_state32 fingerprint_buffer_count32',32)
    qs=[];counts={}
    def run(name,a,z,seeds=(),memory=()):
        v=FingerprintLift(part(c,name,a,z))
        for reg,value in seeds:v.seed(reg,value)
        for address,n,value in memory:mem(v,address,n,value)
        v.run(name);counts[name]=v.count;return v
    def add(name,bad,pre=z3.BoolVal(True)):qs.append((name,z3.And(pre,bad)))
    attach=run('context_attachment',0x1004ab0d8,0x1004ab0e4,[('x0',CP),('x19',DP),('sp',SP)])
    add('all_u64_context_attachment',z3.Or(cell(attach,CP+0x60,8)!=DP,cell(attach,SP+0x80,8)!=DP,attach.read('x10')!=CP+0x60))
    C=0x68000d0000;T=0x68000e0000;DEST=0x68000f0000
    copy=run('root_total_copy',0x10040f8e0,0x10040f8f0,[('x20',T),('x0',C),('sp',SP)],[(T+16,4,N),(C+0x60,8,DEST)])
    add('all_u32_root_total_copy',z3.Or(cell(copy,DEST,4)!=N,cell(copy,SP+8,8)!=C))
    key=(resize(RP,32)^0xf9d49974)*0xda51a827
    caller=run('initializer_caller',0x10040f8f0,0x10040f954,[('x29',RP+0x78),('sp',SP),('x1',X),('x2',Y)])
    add('aligned8_initializer_caller_fields',z3.Or(cell(caller,RP,4)!=(key^0xb308),cell(caller,RP+8,4)!=(key^0x7efd0a1c),cell(caller,RP+16,8)!=RP-0x64),RP&7==0)
    keydec=run('initializer_key',0x10045c53c,0x10045c570,[('x0',RP)])
    add('all_u64_initializer_key_decoder',keydec.read('w10')!=key)
    # Compose at 0x10045C570 using the independently lifted key theorem above.
    dec=run('initializer_decode',0x10045c570,0x10045c5ac,[('x0',RP),('w10',key)],[(RP,4,key^0xb308),(RP+8,4,key^0x7efd0a1c),(RP+16,8,DP)])
    add('controlB308_initializer_mask',dec.read('w10')!=0x8266)
    add('initializer_mode2_and_counter_reset',z3.Or(dec.read('w14')!=0xb308,cell(dec,DP+64,8)!=0,cell(dec,DP+92,4)!=0,cell(dec,DP+96,4)!=2))
    update=run('callback_runtime_update',0x10040f8ac,0x10040f8e0,[('x14',X),('sp',SP),('x10',0xa5cd4cf),('x2',0x1010b7e78),('x1',0x1010c4670)],[(0x1010c4670,8,Y)])
    t=(Y-X)^(SP+0x58);m=z3.BitVecVal(0xa5cd4cf,64);k=z3.BitVecVal(0x73d046208eaed1a6,64)
    add('all_u64_callback_runtime_updates',z3.Or(cell(update,0x1010b7e78,8)!=t*m+k,cell(update,0x1010c4670,8)!=(t^k)*m))
    result=run('callback_status_gate',0x100478f20,0x100478f44,[('w0',STATE),('w1',0x8b3dc651),('w26',0x8f9c)])
    # The source SUBS sets EQ from this expression, before the following ADD.
    value=STATE-((STATE<<1)&0x167b8ca2)
    add('all_u32_callback_status_dispatch',result.read('w8')!=z3.If(value==0,z3.BitVecVal(0x8f9c^0x46a5,32),z3.BitVecVal(0x8f9c,32)))
    add('all_u32_callback_status_zero_test',(value==0)!=(STATE==0))
    # Complete writer identity, including store offsets, from original words.
    E=STATE^0xf4f92df7;W=0x68000c0000;OUT=0x68000c0100
    writer=run('digest_word_writer',0x1000c6970,0x1000c6a08,[('x12',W),('x1',OUT),('w10',0x601df515),('w11',0x9fe20aeb)],[(W+72,4,E)])
    add('all_u32_digest_word_bytes',z3.Or(*[cell(writer,OUT+j,1)!=(z3.Extract(31-8*j,24-8*j,STATE)^z3.BitVecVal(0x98,8))for j in range(4)]))
    return qs,counts

if __name__=='__main__':
    c=json.loads((ROOT/'daemon_record720_fingerprint_source.json').read_text());qs,counts=obligations(c);rows=[]
    for name,expr in qs:
        a=ROOT/f'daemon_fingerprint720_{name}_original.smt2';b=ROOT/f'daemon_fingerprint720_{name}.smt2';s=z3.Solver();s.add(expr);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(expr));ans=str(s.check());print(name,ans,flush=True)
        assert ans=='unsat',(name,ans,str(s.model())if ans=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':ans})
    p={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fingerprint_source.json','prove_daemon_registry_lookup.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'daemon_record720_fingerprint_proofs.json').write_text(json.dumps(p,indent=2)+'\n')
