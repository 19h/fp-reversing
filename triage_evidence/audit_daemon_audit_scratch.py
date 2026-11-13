#!/usr/bin/env python3
"""Independent byte-addressed source replay, scratch effects and BSM ABI audit.

O(receipt bytes+cases*(visits+effects)+queries) time/space; 30 s/query.
No native API, IPC, allocation/free, hardware PAC or IDB mutation executes.
"""
import json,subprocess
from collections import Counter
from pathlib import Path
import z3
from capstone.arm64_const import ARM64_OP_IMM
from daemon_receive_tools import ROOT,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from recover_daemon_return_bank_origins import Algebra
import audit_daemon_environment_outputs as Parent
import recover_daemon_audit_scratch as R

class Lift(Parent.Lift):
    def load(self,address,n):
        value=super().load(address,n)
        if self.pc==0x1006e6128:
            assert n==8 and self.integer(address)==R.TABLE+8*0x5e
            self.saved_continuation_fixup=(self.integer(address),self.integer(value))
        return value

    def one(self,i):
        if i.writeback and i.mnemonic in ['str','strb','ldrb']:
            self.pc=i.address;o=i.operands;name=i.reg_name(o[0].reg);base=i.reg_name(o[1].mem.base)
            old=self.read(base);address=self.address(i,o[1]);n=1 if i.mnemonic.endswith('b') else self.width(name)//8
            if i.mnemonic.startswith('str'):self.store(address,n,self.read(name),i.address)
            else:self.write(name,self.load(address,n))
            self.write(base,old+o[-1].imm if o[-1].type==ARM64_OP_IMM else address);return
        return super().one(i)

    def run(self):
        c=self.c;pc=int(c['entry_PC'],16);by_read={};by_write={}
        for row in c['source_reads']:by_read.setdefault(row['source_visit_index'],[]).append(row)
        for row in c['source_writes']:by_write.setdefault(row['source_visit_index'],[]).append(row)
        for ix,(visit,frame) in enumerate(zip(c['source_visits'],c['source_frames'])):
            assert visit['pc']==frame['pc']==hex(pc);self.pc=pc;self.frame(frame);self.events=[]
            raw=IMAGE.read(pc,4);assert visit['bytes_hex']==raw.hex();i=next(Parent.DEC.disasm(raw,pc));m=i.mnemonic;next_pc=pc+4
            if m in ['braa','blraa','ret']:
                target=self.integer(self.read('x30' if m=='ret' else i.reg_name(i.operands[0].reg)))
                edge={'pc':hex(pc),'target':hex(target),'kind':m,'modifier':None}
                if m!='ret':
                    origin=self.saved_continuation_fixup if pc==0x10079af60 else self.last_authenticated_load
                    assert origin and origin[1]==target,(hex(pc),origin,hex(target))
                    slot=origin[0];word=int.from_bytes(IMAGE.read(slot,8),'little')
                    assert word>>63 and not((word>>48)&7)
                    modifier=self.integer(self.read(i.reg_name(i.operands[1].reg)))
                    assert modifier==(word>>32)&65535;edge['modifier']=hex(modifier)
                    self.counts['original_authenticated_edges_checked']+=1
                self.edges.append(edge)
                if m=='blraa':self.write('x30',z3.BitVecVal(pc+4,64))
                next_pc=target
            elif m=='b':next_pc=i.operands[0].imm
            elif m.startswith('b.'):
                if self.projected(self.condition(m[2:])):next_pc=i.operands[0].imm
            elif m in ['cbz','cbnz']:
                val=self.integer(self.read(i.reg_name(i.operands[0].reg)))
                if (val==0)==(m=='cbz'):next_pc=i.operands[1].imm
            else:self.one(i)
            for kind,expected in [('read',by_read.get(ix,[])),('write',by_write.get(ix,[]))]:
                actual=[e for e in self.events if e['kind']==kind];assert len(actual)==len(expected),(hex(pc),kind)
                for a,e in zip(actual,expected):
                    assert a['address']==e['address'] and a['size_bytes']==e['size_bytes']
                    assert a['bytes_hex']==e['bytes_hex' if kind=='read' else 'after_hex'],(hex(pc),a,e)
                    if 'known_mask_hex' in e:assert a['known_mask_hex']==e['known_mask_hex']
                    self.counts[kind+'_bytes_checked']+=a['size_bytes']
            self.counts['source_visits']+=1;pc=next_pc
        assert c['boundary']['pc']==hex(pc);self.pc=pc;self.frame({**c['boundary'],'NZCV':c['boundary_NZCV']})
        assert self.edges==[{k:e[k] for k in ['pc','target','kind','modifier']} for e in c['logical_edges']]
        assert not self.symbols
        return {'boundary':hex(pc),'verified_counts':dict(self.counts),'all_checks_pass':True,'native_target_executed':False}

def interface(c):
    row=c['trace'];cfg=c['configuration'];s=int(row['caller_SP'],16);u=cfg['cursor64'];r=s+0xc070+u
    w=row['source_writes'];calls=row['source_calls'];p=int(c['pointer64'],16)
    def exact(pc,a,n,value):
        found=[x for x in w if x['pc']==hex(pc)]
        assert len(found)==1 and found[0]['address']==hex(a) and found[0]['size_bytes']==n
        assert int.from_bytes(bytes.fromhex(found[0]['after_hex']),'little')==value
    exact(0x1006e6134,s+0x4ec8,8,R.NEXT);exact(0x1006e6140,s+0xa7f8,8,s+0x7820)
    exact(0x1006e6144,s+0xa800,8,s+0xf0c);exact(0x1006e615c,s+0xa808,8,r+32)
    exact(0x1006e6164,s+0x16d0,8,u+0x420)
    if not p:
        exact(0x10079af50,s+0x16d0,8,u);assert not calls and len(w)==6
        assert row['boundary']['registers31'][28]=='0x74c29d88'
        return {'kind':'null_restore','stores':6,'cursor_restored':True,'continued_to':hex(R.NEXT)}
    exact(0x100810158,s+0x7820,8,0);exact(0x100810164,s+0xf0c,4,0x8b3dc651)
    exact(0x100810214,s,8,0)
    assert len(calls)==1 and calls[0]['pc']=='0x1008101d0' and calls[0]['target']==hex(R.COPY)
    assert calls[0]['arguments8'][:3]==[hex(p),hex(r),'0x20']
    assert row['boundary']['registers31'][:8]==[hex(r),'0x0','0x0','0x0','0x0','0x0',hex(s+0x571c),'0x0']
    assert row['boundary']['detail']['modifier']=='0xdc55'
    readbytes={};written={}
    for e in row['source_reads']:
        a=int(e['address'],16)
        if p<=a<a+e['size_bytes']<=p+32:
            for j,b in enumerate(bytes.fromhex(e['bytes_hex'])):readbytes[a+j]=b
    for e in w:
        a=int(e['address'],16)
        if r<=a<a+e['size_bytes']<=r+32:
            for j,b in enumerate(bytes.fromhex(e['after_hex'])):written[a+j]=b
    assert len(readbytes)==len(written)==32
    assert bytes(readbytes[p+j] for j in range(32))==bytes(written[r+j] for j in range(32))==bytes.fromhex(c['copied32_hex'])
    assert not any(int(e['address'],16)<s+0x5720 and s+0x571c<int(e['address'],16)+e['size_bytes'] for e in w)
    return {'kind':'pending_PID_extraction','copy_site':'0x1008101d0','source':hex(p),'destination':hex(r),
            'copied_bytes':32,'BSM_site':hex(R.BSM),'PID_output':hex(s+0x571c),'PID_initialized_in_component':False,
            'stack_argument9_null':True,'native_API_executed':False}

def sdk_checks():
    code='''#include <bsm/libbsm.h>
#include <stddef.h>
_Static_assert(sizeof(void*)==8,"pointer64");
_Static_assert(sizeof(audit_token_t)==32,"audit_token32");
_Static_assert(sizeof(((audit_token_t*)0)->val[0])==4,"token_word32");
_Static_assert(sizeof(pid_t)==4,"PID32");
_Static_assert(((pid_t)-1)<0,"signed_PID");
_Static_assert(__builtin_types_compatible_p(__typeof__(&audit_token_to_au32),
 void(*)(audit_token_t,uid_t*,uid_t*,gid_t*,uid_t*,gid_t*,pid_t*,au_asid_t*,au_tid_t*)),"BSM_prototype");
void audit_scratch_probe(const audit_token_t *token,pid_t *pid_out) {
 audit_token_to_au32(*token,0,0,0,0,0,pid_out,0,0);
}
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    asm=p.stdout;assert '_audit_token_to_au32' in asm
    assert all(line in asm for line in ['mov\tx6, x1','ldp\tq0, q1, [x0]','stp\tq0, q1, [sp, #16]',
                                       'str\txzr, [sp]','add\tx0, sp, #16'])
    assert all('mov\tx%d, #0'%j in asm for j in [1,2,3,4,5,7])
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'assembly':asm,'exit_code':0,
            'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)} for n in ['usr/include/bsm/libbsm.h','usr/include/mach/message.h']],
            'scope':'Compile-only current Darwin arm64e ABI comparison; historical build SDK and runtime libbsm identity unknown.',
            'native_API_executed':False,'emitted_object':False}

def replays(e):
    rows=[];totals=Counter()
    for kind,cases in [('component',e['cases']),('retained',e['retained_cases'])]:
        for ix,c in enumerate(cases):
            row=Lift(c['trace']).run();row.update(kind=kind,case_index=ix);rows.append(row);totals.update(row['verified_counts'])
    return rows,dict(totals)

def retained_join(e):
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));out=[]
    for c in e['retained_cases']:
        ix=c['parent_case_index'];before=parent['cases'][ix]['caller_consumer'];after=c['trace']
        assert after['entry_registers31']==before['boundary']['registers31'] and after['entry_NZCV']==before['boundary_NZCV']
        assert after['caller_SP']==before['boundary']['SP'] and after['entry_PC']==before['boundary']['pc']
        assert c['unknown_cursor_bytes']==8 and not c['native_pointer_origin_established']
        assert len(after['source_writes'])==3 and len(after['source_visits'])==26
        assert after['boundary']['pc']=='0x1006e6148'
        assert after['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
        assert [x['pc'] for x in after['source_writes']]==['0x1006e6134','0x1006e6140','0x1006e6144']
        expected={}
        for row in R.Parent.intervals(parent['cases'][ix]):
            for f in row['initial_private_fixtures']:
                expected.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
            for w in row['source_writes']:
                at=int(w['address'],16)
                if R.Parent.Parent.Base.P<=at<at+w['size_bytes']<=R.Parent.Parent.Base.P+R.Parent.Parent.Base.SIZE:
                    expected.update({at+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
        actual={}
        for f in after['initial_private_fixtures']:
            actual.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
        assert actual==expected
        s=int(after['caller_SP'],16);assert not any(s+0x9d0+j in actual for j in range(8))
        out.append({'parent_case_index':ix,'registers_flags_SP_identical':True,'all_private_defined_bytes_identical':True,
                    'unknown_cursor_bytes_preserved':8,'provider_gap_closed':False})
    return out

def copy_obligations(e):
    out=[]
    for alignment in range(8):
        c=next(c for c in e['cases'] if c['configuration']['pointer']=='alignment_'+str(alignment)
               and c['configuration']['placement']==0 and c['configuration']['controllers']==[0,0]
               and c['configuration']['cursor64']==0)
        trace=c['trace'];indices=[j for j,r in enumerate(trace['source_visits']) if R.COPY<=int(r['pc'],16)<0x10046faf8]
        assert indices==list(range(indices[0],indices[-1]+1));frame=trace['source_frames'][indices[0]]
        src=int(c['pointer64'],16);dst=int(c['scratch_base64'],16)
        token=[z3.BitVec('as_copy_%d_byte_%d'%(alignment,j),8) for j in range(32)]
        class Bytes(Algebra):
            def __init__(self):super().__init__();self.bytes={src+j:b for j,b in enumerate(token)};self.reads=[];self.writes=[]
            def load(self,address,n):
                a=z3.simplify(address).as_long();assert src<=a<a+n<=src+32
                self.reads.extend(range(a,a+n));return z3.Concat(*[self.bytes[a+j] for j in range(n-1,-1,-1)]) if n>1 else self.bytes[a]
            def store(self,address,n,value,pc):
                a=z3.simplify(address).as_long();assert dst<=a<a+n<=dst+32
                self.writes.extend(range(a,a+n))
                for j in range(n):self.bytes[a+j]=z3.Extract(8*j+7,8*j,resize(value,n*8))
        v=Bytes()
        for j,x in enumerate(frame['registers31']):v.seed('x'+str(j),int(x,16))
        v.seed('sp',int(frame['SP'],16))
        for name,bit in [('n',31),('z',30),('carry',29),('overflow',28)]:setattr(v,name,z3.BoolVal(bool(int(frame['NZCV'],16)&(1<<bit))))
        for k,ix in enumerate(indices):
            visit=trace['source_visits'][ix];pc=int(visit['pc'],16);i=next(Parent.DEC.disasm(IMAGE.read(pc,4),pc));v.pc=pc;m=i.mnemonic;nextpc=pc+4
            if m=='b':nextpc=i.operands[0].imm
            elif m.startswith('b.'):
                cond=z3.simplify(v.condition(m[2:]));assert z3.is_true(cond) or z3.is_false(cond)
                if z3.is_true(cond):nextpc=i.operands[0].imm
            elif m in ['cbz','cbnz']:
                value=z3.simplify(v.read(i.reg_name(i.operands[0].reg)));assert z3.is_bv_value(value)
                if (value.as_long()==0)==(m=='cbz'):nextpc=i.operands[1].imm
            elif m=='ret':nextpc=z3.simplify(v.read('x30')).as_long()
            elif i.writeback:
                assert m in ['ldr','str','ldrb','strb'];o=i.operands;name=i.reg_name(o[0].reg);base=i.reg_name(o[1].mem.base)
                old=v.read(base);address=v.address(i,o[1]);n=1 if m.endswith('b') else v.width(name)//8
                if m.startswith('ld'):v.write(name,v.load(address,n))
                else:v.store(address,n,v.read(name),pc)
                v.write(base,old+o[-1].imm if o[-1].type==ARM64_OP_IMM else address)
            else:v.one(i)
            assert nextpc==int(trace['source_visits'][ix+1]['pc'],16)
        assert sorted(v.reads)==list(range(src,src+32)) and sorted(v.writes)==list(range(dst,dst+32))
        q=z3.Solver();q.set(timeout=30000);assert q.check()==z3.sat
        q.add(z3.Or(*[v.bytes[dst+j]!=token[j] for j in range(32)]));assert q.check()==z3.unsat
        out.append({'source_alignment_mod8':alignment,'arbitrary_input_bits':256,'query':q.to_smt2(),
                    'source_visits':len(indices),'bytes_read_once':32,'bytes_written_once':32,'result':'unsat',
                    'payload_independent_control_verified':True,'nonoverlapping_fixture_pointers':True})
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));lifts,totals=replays(e)
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    fresh=R.obligations();assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for row in e['source_proofs']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(row['query']);assert q.check()==z3.unsat
    alternatives=[]
    for c in e['cases']:
        cfg={**c['configuration'],'pattern':c['configuration']['pattern']^255};other=R.component(cfg)
        # Token bytes change, but control, addresses, sizes and call arguments do not.
        for key in ['source_visits','logical_edges','source_calls']:
            assert other['trace'][key]==c['trace'][key]
        for key in ['source_reads','source_writes']:
            assert [(r['pc'],r['address'],r['size_bytes']) for r in other['trace'][key]]==[(r['pc'],r['address'],r['size_bytes']) for r in c['trace'][key]]
        r=Lift(other['trace']).run();r.update(kind='alternate_component',case_index=len(alternatives));lifts.append(r)
        totals_counter=Counter(totals);totals_counter.update(r['verified_counts']);totals=dict(totals_counter)
        alternatives.append({'configuration':cfg,'same_source_control_addresses_and_calls':True,'all_checks_pass':True})
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(R.SOURCE),'dependencies':e['dependencies'],'independent_lifts':lifts,'independent_totals':totals,
            'interfaces':[interface(c) for c in e['cases']],'retained_joins':retained_join(e),'alternate_controls':alternatives,
            'copy_proofs':copy_obligations(e),
            'verified_counts':e['verified_counts'],'source_queries_unsat':len(fresh),'SDK_checks':sdk_checks(),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['independent_totals']),flush=True)
