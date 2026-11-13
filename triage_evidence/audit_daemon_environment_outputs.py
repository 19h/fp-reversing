#!/usr/bin/env python3
"""Independent byte-addressed source lift for environment-output CPU journals.

Unknown copies retain symbolic origins; unknown addresses/branches fail closed.
O(visits*(state+byte effects)+queries) time/space;30 s/query.
No native API/IPC, allocation, free or hardware PAC executes.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_IMM
from daemon_receive_tools import ROOT,IMAGE,FIXUPS
from daemon_context_transfer_symbolic import loaded_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_environment_outputs as R

DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True

class Lift(Algebra):
    def __init__(self,c):
        super().__init__();self.c=c;self.bytes={};self.events=[];self.symbols={};self.counts=Counter();self.edges=[]
        self.last_authenticated_load=None
        for j,value in enumerate(c['entry_registers31']):self.seed('x'+str(j),int(value,16))
        self.seed('sp',int(c['caller_SP'],16));flags=int(c['entry_NZCV'],16)
        for name,bit in [('n',31),('z',30),('carry',29),('overflow',28)]:setattr(self,name,z3.BoolVal(bool(flags&(1<<bit))))
        for f in c['initial_private_fixtures']+c['initial_image_fixtures']:
            a=int(f['address'],16)
            for j,b in enumerate(bytes.fromhex(f['bytes_hex'])):self.bytes[a+j]=z3.BitVecVal(b,8)

    def integer(self,x):
        x=z3.simplify(resize(x,64));assert z3.is_bv_value(x),('unknown address/control',hex(self.pc),str(x));return x.as_long()

    def projected(self,x):
        x=z3.simplify(x)
        if self.symbols:x=z3.simplify(z3.substitute(x,*[(v,z3.BitVecVal(self.c['configuration']['pattern'],8)) for v in self.symbols.values()]))
        if z3.is_bool(x):assert z3.is_true(x) or z3.is_false(x);return int(z3.is_true(x))
        assert z3.is_bv_value(x),(hex(self.pc),str(x));return x.as_long()

    def load(self,address,n):
        a=self.integer(address);parts=[];unknown=[]
        if all(j not in self.bytes for j in range(a,a+n)) and a in FIXUPS and n==8:
            t=FIXUPS[a]['target'];value=(R.Base.GUARD if t=='libSystem/___stack_chk_guard' else R.Base.HELPER if t=='libSystem/___chkstk_darwin'
                 else R.Base.IMPORTS[t] if isinstance(t,str) else t)+R.Base.ADDENDS.get(a,0)
            raw=(value&((1<<64)-1)).to_bytes(8,'little')
            for j,b in enumerate(raw):self.bytes[a+j]=z3.BitVecVal(b,8)
        if n==8 and a in FIXUPS and FIXUPS[a]['kind'].startswith('auth-'):
            self.last_authenticated_load=(a,self.projected(z3.Concat(*[self.bytes[a+j] for j in range(7,-1,-1)])))
        for at in range(a,a+n):
            if at not in self.bytes:
                if R.Base.P<=at<R.Base.P+R.Base.SIZE:
                    var=z3.BitVec('deo_unknown_'+hex(at),8);self.symbols[at]=var;self.bytes[at]=var
                else:self.bytes[at]=z3.BitVecVal(loaded_bytes(at,1)[0],8)
            part=self.bytes[at];parts.append(part)
            if not z3.is_bv_value(z3.simplify(part)):unknown.append(at)
        if unknown:assert self.pc in R.COPIES,('unknown used beyond pure copy',hex(self.pc),unknown)
        x=z3.Concat(*reversed(parts)) if n>1 else parts[0]
        self.events.append({'kind':'read','address':hex(a),'size_bytes':n,'bytes_hex':self.projected(x).to_bytes(n,'little').hex(),
                            'known_mask_hex':bytes(int(j not in unknown) for j in range(a,a+n)).hex()})
        return x

    def store(self,address,n,value,pc):
        a=self.integer(address);value=resize(value,n*8);mask=[]
        for j in range(n):
            b=z3.simplify(z3.Extract(8*j+7,8*j,value));self.bytes[a+j]=b;mask.append(int(z3.is_bv_value(b)))
        self.events.append({'kind':'write','address':hex(a),'size_bytes':n,'bytes_hex':self.projected(value).to_bytes(n,'little').hex(),
                            'known_mask_hex':bytes(mask).hex()})

    def one(self,i):
        self.pc=i.address;m=i.mnemonic;o=i.operands
        if m=='sxtw':self.write(i.reg_name(o[0].reg),z3.SignExt(32,resize(self.read(i.reg_name(o[1].reg)),32)));return
        if i.writeback:
            assert m in ['stp','ldp','ldr'];op=o[2] if m in ['stp','ldp'] else o[1]
            base=i.reg_name(op.mem.base);old=self.read(base);address=self.address(i,op)
            count=2 if m in ['stp','ldp'] else 1
            for j in range(count):
                name=i.reg_name(o[j].reg);n=self.width(name)//8;at=address+j*n
                if m=='stp':self.store(at,n,self.read(name),i.address)
                else:self.write(name,self.load(at,n))
            after=old+o[-1].imm if o[-1].type==ARM64_OP_IMM else address
            self.write(base,after);return
        return super().one(i)

    def frame(self,row):
        for j,want in enumerate(row['registers31']):
            assert self.projected(self.read('x'+str(j)))==int(want,16),(row['pc'],j)
            self.counts['register_values_checked']+=1
        assert self.integer(self.read('sp'))==int(row['SP'],16)
        self.counts['register_values_checked']+=1
        if 'NZCV' in row:
            flags=sum(self.projected(getattr(self,n))<<bit for n,bit in [('n',31),('z',30),('carry',29),('overflow',28)])
            assert flags==int(row['NZCV'],16),(row['pc'],'NZCV',hex(flags),row['NZCV']);self.counts['NZCV_values_checked']+=1

    def run(self):
        c=self.c;pc=int(c['entry_PC'],16);reads=Counter();writes=Counter()
        for row in c['source_reads']:reads[row['source_visit_index']]+=1
        for row in c['source_writes']:writes[row['source_visit_index']]+=1
        by_read={j:[] for j in reads};by_write={j:[] for j in writes}
        for row in c['source_reads']:by_read[row['source_visit_index']].append(row)
        for row in c['source_writes']:by_write[row['source_visit_index']].append(row)
        for ix,(visit,frame) in enumerate(zip(c['source_visits'],c['source_frames'])):
            assert visit['pc']==frame['pc']==hex(pc);self.pc=pc;self.frame(frame);self.events=[]
            raw=IMAGE.read(pc,4);assert visit['bytes_hex']==raw.hex();i=next(DEC.disasm(raw,pc));m=i.mnemonic;next_pc=pc+4
            if m in ['pacibsp','paciasp','autibsp','autiasp']:pass
            elif m in ['braa','blraa','ret','retab']:
                name='x30' if m in ['ret','retab'] else i.reg_name(i.operands[0].reg)
                target=self.integer(self.read(name));self.edges.append({'pc':hex(pc),'target':hex(target),'kind':m})
                if m in ['braa','blraa']:
                    assert self.last_authenticated_load and self.last_authenticated_load[1]==target
                    slot=self.last_authenticated_load[0];word=int.from_bytes(IMAGE.read(slot,8),'little')
                    assert (word>>49)&3==0 and (word>>48)&1==0
                    modifier=self.integer(self.read(i.reg_name(i.operands[1].reg)))
                    assert modifier==(word>>32)&65535;self.edges[-1]['modifier']=hex(modifier)
                    self.counts['original_authenticated_edges_checked']+=1
                else:self.edges[-1]['modifier']=None
                if m=='blraa':self.write('x30',z3.BitVecVal(pc+4,64))
                next_pc=target
            elif m=='b':next_pc=i.operands[0].imm
            elif m.startswith('b.'):
                take=z3.simplify(self.condition(m[2:]));assert z3.is_true(take) or z3.is_false(take)
                if z3.is_true(take):next_pc=i.operands[0].imm
            else:self.one(i)
            for kind,expected in [('read',by_read.get(ix,[])),('write',by_write.get(ix,[]))]:
                actual=[e for e in self.events if e['kind']==kind];assert len(actual)==len(expected),(hex(pc),kind)
                for a,e in zip(actual,expected):
                    assert a['address']==e['address'] and a['size_bytes']==e['size_bytes']
                    assert a['bytes_hex']==e['bytes_hex' if kind=='read' else 'after_hex'],(hex(pc),a,e)
                    if 'known_mask_hex' in e:assert a['known_mask_hex']==e['known_mask_hex'],(hex(pc),a,e)
                    self.counts[kind+'_bytes_checked']+=a['size_bytes']
                    if '00' in a['known_mask_hex']:self.counts['unknown_copy_bytes_checked']+=a['size_bytes']
            self.counts['source_visits']+=1;pc=next_pc
        assert c['boundary']['pc']==hex(pc);self.pc=pc;self.frame({**c['boundary'],'NZCV':c['boundary_NZCV']})
        assert self.edges==[{k:e[k] for k in ['pc','target','kind','modifier']} for e in c['logical_edges']]
        return {'configuration':c['configuration'],'boundary':c['boundary']['pc'],'verified_counts':dict(self.counts),
                'unknown_origins_retained':len(self.symbols),'all_checks_pass':True,'native_target_executed':False}

def sdk_checks():
    code='''#include <notify.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
_Static_assert(sizeof(void*)==8,"pointer64");
_Static_assert(sizeof(int)==4,"int32");
_Static_assert(sizeof(uint32_t)==4,"uint32");
_Static_assert(sizeof(struct timeval)==16,"timeval16");
_Static_assert(offsetof(struct timeval,tv_sec)==0,"seconds_offset0");
_Static_assert(offsetof(struct timeval,tv_usec)==8,"microseconds_offset8");
_Static_assert(__builtin_types_compatible_p(__typeof__(&notify_check),uint32_t(*)(int,int*)),"notify_check_ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&malloc),void*(*)(size_t)),"malloc_ABI");
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-fsyntax-only','-x','c','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'exit_code':0,'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)}
            for n in ['usr/include/notify.h','usr/include/sys/time.h','usr/include/stdlib.h']],
            'scope':'Current arm64e SDK comparison only; original build SDK and native implementation pairing unknown.',
            'API_executed':False,'emitted_artifact':False}

def interface(c):
    cfg=c['configuration'];s=int(c['caller_SP'],16);f=s-0x4a0;b=c['boundary'];pc=int(b['pc'],16)
    if cfg['kind']=='caller':
        assert len(c['source_calls'])==2 and [x['target'] for x in c['source_calls']]==['0x100001e0c',hex(R.ENTRY)]
        check=c['checkpoints'][0];assert check['pc']==hex(R.ENTRY) and check['SP']==hex(s)
        assert check['registers31'][0]=='0xfffffffffffffffe'
        assert check['registers31'][1:5]==[hex(s+off) for _,off,_ in R.OUTPUTS]
    clears=[w for w in c['source_writes'] if w['pc'] in ['0x100e1e7e0','0x100e1e7e8','0x100e1e7f0','0x100e1e7f8']]
    if cfg['null_mask']:
        assert pc==R.RETURN and not clears and not c['unknown_copy_effects'] and not c['source_calls']
        assert b['registers31'][0]=='0xffff5037' and b['SP']==hex(s)
        assert b['registers31'][19:30]==c['entry_registers31'][19:30]
        return {'kind':'null_output_rejection','returned_u32':'0xffff5037','output_stores':0,'all_checks_pass':True}
    assert len(clears)==4
    for w,(_,off,n) in zip(clears,R.OUTPUTS):
        assert w['address']==hex(s+off) and w['size_bytes']==n and w['after_hex']=='00'*n
    if b['detail']['symbol']=='libSystem/_notify_check':
        arg=cfg['argument64'];signed=arg-(1<<64) if arg>>63 else arg
        offset,token,root=(0x194,0x5034,0x1010ca324) if signed in [-8,-6,-5,-4,-3,-2] else (
                           (0x158,0x5036,0x1010ca31c) if signed==-1 else (0x17c,0x5035,0x1010ca2c0))
        assert pc in [0x100e1f2d8,0x100e1f3e4,0x100e1f498]
        assert b['registers31'][:2]==[hex(token),hex(f+offset)] and b['detail']['modifier']=='0x89e0'
        return {'kind':'notify_check','token_source':hex(root),'token32':hex(token),'changed_pointer':hex(f+offset),
                'call_site':hex(pc),'native_port_or_emission_established':False,'all_checks_pass':True}
    if b['detail']['symbol']=='libSystem/_gettimeofday':
        assert pc==0x100e1ee5c and b['registers31'][:2]==[hex(f+0x390),'0x0']
        assert cfg['cache_mode'] in ['hit0','hit1'] and not cfg['flag8']&1
        return {'kind':'cache_hit_clock','cache_index':0 if cfg['cache_mode']=='hit0' else 1,'timeval':hex(f+0x390),'all_checks_pass':True}
    assert b['detail']['symbol']=='libSystem/_malloc' and pc==0x100e1ea4c and b['registers31'][0]=='0x18'
    assert len(c['unknown_copy_effects'])==(3 if cfg['kind']=='caller' else 0)
    return {'kind':'allocation24','bytes':24,'unknown_copy_pairs':len(c['unknown_copy_effects']),'all_checks_pass':True}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['bank_rules']==R.banks() and e['source_regions']==R.source()
    used={int(x['address'],16) for c in e['cases'] for x in c['source_reads'] if x['size_bytes']==8 and int(x['address'],16) in FIXUPS}
    used.update(int(x['slot'],16) for x in e['bank_rules']);assert e['source_fixups']==R.fixups(used)
    for pc,row in e['source_pool'].items():
        i=next(DEC.disasm(IMAGE.read(int(pc,16),4),int(pc,16)))
        assert row=={'pc':pc,'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==12
    for old,new in zip(e['source_proofs'],fresh):
        assert old['label']==new['label'] and old['premises_nonvacuous']
        q=z3.Solver();q.set(timeout=30000);q.from_string(old['query']);assert q.check()==z3.unsat
    replays=[];totals=Counter();interfaces=[];paired=[]
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    for c in e['cases']:
        interfaces.append(interface(c));alt=R.probe({**c['configuration'],'pattern':c['configuration']['pattern']^255})
        assert c['source_visits']==alt['source_visits'] and c['boundary']==alt['boundary'] and c['logical_edges']==alt['logical_edges']
        assert c['source_calls']==alt['source_calls']
        for x,y in zip(c['source_writes'],alt['source_writes']):
            assert {k:v for k,v in x.items() if k!='after_hex'}=={k:v for k,v in y.items() if k!='after_hex'}
            if 'unknown_origins' not in x:assert x['after_hex']==y['after_hex']
        for p in [c,alt]:
            row=Lift(p).run();replays.append(row);totals.update(row['verified_counts'])
        paired.append({'configuration':c['configuration'],'alternate_pattern':alt['configuration']['pattern'],
                       'same_source_control_and_boundary':True,'unknown_copies_remain_undefined':True})
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'dependencies':e['dependencies'],
            'verified_counts':e['verified_counts'],'source_queries_unsat':12,'interfaces':interfaces,
            'independent_lifts':replays,'independent_totals':dict(totals),'paired_backing_controls':paired,'SDK_checks':sdk_checks(),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    a=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({k:a[k] for k in ['verified_counts','independent_totals','all_checks_pass']}),flush=True)
