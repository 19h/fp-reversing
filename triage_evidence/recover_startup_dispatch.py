#!/usr/bin/env python3
"""Original startup ordering, phase names and returning-callback cursor ABI.

Read-only source/fixup recovery and scalar proofs. Native ordering, callback
success, reentrancy and publication visibility remain unobserved. O(B+I+R+P)
source time/space; pointer-chain probes and SMT cost are separate.
"""
import argparse
from collections import Counter
import json
import struct
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_cold_init import pointer
from recover_event_wait_table import StartupLift
from lskd_values_symbolic import resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

FUNCTIONS={'sort_boot':0xfffffe000c62f4e4,'sort_recursive':0xfffffe000c61b4ec,'compare':0xfffffe000c630754,
           'dispatch':0xfffffe000c6302c4,'phase_observer':0xfffffe000bd3ad04,'ipc_boot':0xfffffe000c630790}
CURSOR=0xfffffe000cbc9a48
PHASE=0xfffffe0007f8b5f0
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_event_wait_table.py',
      'lskd_values_symbolic.py','resolve_kernel_collection_interfaces.py','verify_daemon_reader_record_payloads_publication.py',
      'event_wait_table_checks.json']


class OrderLift(StartupLift):
    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address;m,o=i.mnemonic,i.operands
            if m in ['cneg','csel']:
                cond=i.op_str.rsplit(',',1)[1].strip();assert cond in ['ls','eq']
                p=z3.ULE(self.cmp_left,self.cmp_right)if cond=='ls'else self.equal
                a=self.read(i.reg_name(o[1].reg))
                b=-a if m=='cneg'else self.read(i.reg_name(o[2].reg))
                self.write(i.reg_name(o[0].reg),z3.If(p,-a,a)if m=='cneg'else z3.If(p,a,b));self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run(label)
        self.c=saved;return self


def prove(c):
    q={};pieces={};A,B=z3.BitVecs('entry_A64 entry_B64',64)
    p,r,s,t=z3.BitVecs('phase_A32 rank_A32 phase_B32 rank_B32',32)
    T=z3.BitVec('requested_phase32',32);C=z3.BitVec('cursor64',64);FN,ARG=z3.BitVecs('callback64 argument64',64)
    def run(name,a,z,seeds,cells=(),obj=None):
        if obj is None:obj=OrderLift(part(c,name,a,z))
        else:obj.c=part(c,name,a,z)
        for reg,v in seeds.items():obj.seed(reg,v)
        for at,n,v in cells:mem(obj,at,n,v)
        prior=obj.count;obj.run(name);assert obj.count-prior==(z-a)//4
        pieces[name]={'start':hex(a),'end':hex(z),'instructions':obj.count-prior};return obj
    prefix=run('compare_phase',0xfffffe000c630758,0xfffffe000c630764,{'x0':A,'x1':B},[(A,4,p),(B,4,s)])
    q['phase_compare']=prefix.equal!=(p==s)
    unequal=run('compare_unequal_phase',0xfffffe000c630784,0xfffffe000c63078c,{},obj=prefix)
    q['unequal_phase_result']=z3.And(p!=s,unequal.read('w0')!=z3.If(z3.ULT(p,s),resize(-1,32),resize(1,32)))
    equal=run('compare_rank',0xfffffe000c630768,0xfffffe000c630780,{'x0':A,'x1':B},[(A+4,4,r),(B+4,4,t)])
    expected=z3.If(r==t,resize(0,32),z3.If(z3.ULT(r,t),resize(-1,32),resize(1,32)))
    q['equal_phase_rank_result']=equal.read('w0')!=expected
    result=z3.If(p==s,equal.read('w0'),unequal.read('w0'))
    less=z3.Or(z3.ULT(p,s),z3.And(p==s,z3.ULT(r,t)))
    q['lexicographic_comparator']=result!=z3.If(z3.And(p==s,r==t),resize(0,32),z3.If(less,resize(-1,32),resize(1,32)))
    q['comparator_equality_ignores_payload']=z3.And(p==s,r==t,result!=0)
    o=run('dispatch_threshold',0xfffffe000c630318,0xfffffe000c630320,{'x24':C,'w19':T},[(C,4,p)])
    q['threshold_unsigned_admission']=z3.ULE(o.cmp_left,o.cmp_right)!=(z3.ULE(p,T))
    o=run('pre_callback_phase',0xfffffe000c630358,0xfffffe000c630360,{'w8':p,'x21':PHASE&~0xfff})
    q['pre_callback_phase']=cell(o,PHASE,4)!=p-1
    o=run('callback_arguments',0xfffffe000c630368,0xfffffe000c630370,{'x24':C},[(C+8,8,FN),(C+16,8,ARG)])
    q['callback_arguments']=z3.Or(o.read('x8')!=FN,o.read('x0')!=ARG,o.read('x17')!=0x2abe)
    o=run('post_callback_cursor',0xfffffe000c630374,0xfffffe000c63037c,{'x24':C,'x23':CURSOR&~0xfff})
    q['post_callback_cursor']=z3.Or(o.read('x24')!=C+24,cell(o,CURSOR,8)!=C+24)
    o=run('completed_phase',0xfffffe000c6303b4,0xfffffe000c6303b8,{'w19':T,'x21':PHASE&~0xfff})
    q['completed_phase']=cell(o,PHASE,4)!=T
    for name,a,value in [('initial_dispatch_argument',0xfffffe000c630240,3),
                         ('ipc_boot_phase13_argument',0xfffffe000c6308c8,13),
                         ('ipc_boot_phase14_argument',0xfffffe000c630bf8,14)]:
        o=run(name,a,a+4,{})
        q[name]=o.read('w0')!=value
    out={}
    for name,expression in q.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(expression);result=solver.check();assert result==z3.unsat,(name,str(result),solver.reason_unknown())
        out[name]={'query':solver.to_smt2(),'result':str(result)}
    return out,pieces


def build():
    k=Kernel();spans=[]
    for label,a in FUNCTIONS.items():
        f=k.function(a);f['label']=label;f['bytes_hex']=f.pop('bytes');spans.append(f)
    section=next(s for s in k.kernel['sections']if s['section']=='__init_entry_set');rows=[];logical=bytearray()
    for a in range(section['address'],section['address']+section['size'],24):
        raw=k.read(a,24);phase,rank=struct.unpack_from('<II',raw);normalized=bytearray(raw);fixups=[]
        for off in [8,16]:
            if raw[off:off+8]!=bytes(8):
                ptr=pointer(k,a+off);fixups.append(ptr);normalized[off:off+8]=int(ptr['target'],16).to_bytes(8,'little')
        rows.append({'address':hex(a),'phase32':phase,'rank32':rank,'bytes_hex':raw.hex(),'logical_bytes_hex':normalized.hex(),'fixups':fixups});logical.extend(normalized)
    names=[]
    for phase in list(range(1,17))+[19]:
        ptr=pointer(k,0xfffffe0007e64530+8*phase);a=int(ptr['target'],16);raw=k.read(a,80).split(b'\0')[0]+b'\0'
        names.append({'phase32':phase,'pointer':ptr,'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
    c={'spans':spans};proofs,pieces=prove(c)
    data={name:{'address':hex(a),'bytes_hex':k.read(a,n).hex()}for name,a,n in [
      ('diagnostic_name',0xfffffe000704fabb,31),('phase_file_word',PHASE,4),('logging_flag',0xfffffe0007e64510,4)]}
    assert bytes.fromhex(data['diagnostic_name']['bytes_hex'])==b'kernel_startup_initialize_upto\0'
    counts={'queries_unsat':len(proofs),'source_pieces':len(pieces),'source_lifted_instances':sum(r['instructions']for r in pieces.values()),
      'spans':len(spans),'instructions':sum(len(r['instructions'])for r in spans),'startup_records':len(rows),'startup_fixups':sum(len(r['fixups'])for r in rows),'phase_names':len(names)}
    counts['code_B']=counts['instructions']*4
    return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in DEPS},'kernel_collection_sha256':k.sha256,
      'spans':spans,'startup_section':section,'records':rows,'logical_table_bytes_hex':logical.hex(),'phase_names':names,
      'phase_histogram':{str(p):n for p,n in sorted(Counter(r['phase32']for r in rows).items())},
      'cursor_initial_pointer':pointer(k,CURSOR),'data':data,'proofs':proofs,'source_pieces':pieces,
      'exact_symbols':k.symbols(FUNCTIONS.values()),'verified_counts':counts,
      'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args();out=build();p=ROOT/'startup_dispatch_checks.json'
    if args.verify:assert json.loads(read(p))==out
    else:p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)
