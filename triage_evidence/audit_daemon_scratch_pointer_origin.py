#!/usr/bin/env python3
"""Independent instruction, byte-effect, admission and scratch-lifetime audit.

O(cases*(visits+effects)+text words+queries) time and space,30 s/query.
Logical authenticated edges are checked against original words, never executed
as native PAC. No native API, allocation, free or IPC executes.
"""
import itertools,json,subprocess
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,TABLE,verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_scratch_pointer_origin as R

PRIVATE=0x6e00000000;EXTENT=0x40000

def original_target(at):
    word=int.from_bytes(IMAGE.read(at,8),'little')
    assert word>>63==1 and (word>>62)&1==0
    assert (word>>48)&1==0 and (word>>49)&3==0
    return 0x100000000+(word&0xffffffff),(word>>32)&65535

def sdk_checks():
    code='''#include <sys/time.h>
#include <stddef.h>
_Static_assert(sizeof(struct timeval)==16,"timeval_extent");
_Static_assert(_Alignof(struct timeval)==8,"timeval_alignment");
_Static_assert(offsetof(struct timeval,tv_sec)==0,"seconds_offset");
_Static_assert(offsetof(struct timeval,tv_usec)==8,"microseconds_offset");
_Static_assert(sizeof(((struct timeval*)0)->tv_sec)==8,"seconds_width");
_Static_assert(sizeof(((struct timeval*)0)->tv_usec)==4,"microseconds_width");
_Static_assert(((__typeof__(((struct timeval*)0)->tv_sec))-1)<0,"signed_seconds");
_Static_assert(((__typeof__(((struct timeval*)0)->tv_usec))-1)<0,"signed_microseconds");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gettimeofday),int(*)(struct timeval*,void*)),"clock_prototype");
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-fsyntax-only','-x','c','-']
    r=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0 and not r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'exit_code':0,'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)}
            for n in ['usr/include/sys/time.h','usr/include/sys/_types/_timeval.h']],
            'compiler':subprocess.check_output(['xcrun','clang','--version'],text=True).splitlines()[0],
            'scope':'Fresh compile-only current arm64e Darwin SDK ABI; original build SDK identity unknown.',
            'emitted_artifact':False,'API_executed':False}

def helper_controls():
    bank=R.clock_bank()['bank'];left=int(bank['left'],16);right=int(bank['right'],16);slot=int(bank['slot'],16)
    assert bank['target']=='libSystem/_gettimeofday' and bank['constant']=='0x14'
    l=IMAGE.read(left,256);r=IMAGE.read(right,256)
    assert [j^r[l[j]^0x56] for j in range(256)]==[0x14]*256
    import_token=0x7d00000200;out=[]
    for placement,(c0,c1),pattern in itertools.product([0,0x100],[(0,0),(0xffffffff,1),(0x80000000,0xffffffff),(0x13579bdf,0x2468ace0)],[0x35,0xca]):
        u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
        u.mem_map(PRIVATE,EXTENT);u.mem_write(PRIVATE,bytes([pattern])*EXTENT);s=PRIVATE+0x20000+placement
        p0=PRIVATE+0x1000;p1=PRIVATE+0x1100;data=s+0xc0a0;pages=set()
        for a in [R.SPECIAL,0x1007b3058,left,right,slot]:
            pg=a&~4095
            if pg not in pages:u.mem_map(pg,4096);u.mem_write(pg,IMAGE.read(pg,4096));pages.add(pg)
        for a,n,x in [(s+0x9c8,8,p0),(s+0x9c0,8,p1),(s+0x870,8,left),(s+0x868,8,right),(s+0x9d8,8,TABLE),
                      (p0,4,c0),(p1,4,c1),(slot,8,import_token)]:u.mem_write(a,x.to_bytes(n,'little'))
        for reg,x in [('SP',s),('X0',data),('X21',0x1f74)]:u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg),x)
        events=[]
        def hook(cpu,t,a,n,value,opaque):events.append({'address':hex(a),'size_bytes':n,'value':hex(int.from_bytes(cpu.mem_read(a,n),'little'))})
        u.hook_add(uc.UC_HOOK_MEM_READ,hook)
        u.emu_start(R.SPECIAL,0x1007b3058,count=31)
        mix=(((c0+c1)&0xffffffff)^0xa6)*0xa5cd4cf&0xffffffff;j=mix&255;k=l[j]^0x56
        assert len(events)==10 and events[5]['address']==hex(left+j) and events[7]['address']==hex(right+k)
        assert events[-1]=={'address':hex(slot),'size_bytes':8,'value':hex(import_token)}
        for reg,x in [('X0',data),('X1',0),('X8',import_token),('X17',0x9298),('X19',0x79ea),('X24',2),('X25',0x367a)]:
            assert u.reg_read(getattr(ar,'UC_ARM64_REG_'+reg))==x
        out.append({'SP':hex(s),'controller0_u32':hex(c0),'controller1_u32':hex(c1),'backing_pattern':pattern,
                    'source_visits':31,'reads':events,'arguments2':[hex(data),'0x0'],'call_site':'0x1007b3058',
                    'target':bank['target'],'call_executed':False,'all_checks_pass':True})
    return out

def return_controls():
    out=[];start=0x1007b305c;end=0x1007b307c
    for status in [0,1,0xffffffff,0x80000000,0x7fffffff,0x74c29dee]:
        u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
        u.mem_map(start&~4095,4096);u.mem_write(start,IMAGE.read(start,end-start))
        for reg,x in [('X0',status),('X19',0x79ea),('X24',2),('X25',0x367a),('X21',0x1f74)]:u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg),x)
        u.emu_start(start,end,count=8);index=0x3c16 if status==0 else 0x1f74
        assert u.reg_read(ar.UC_ARM64_REG_X8)==index
        out.append({'return32':hex(status),'index':hex(index),'source_visits':8,'all_checks_pass':True,'API_executed':False})
    return out

class Replay:
    def __init__(self,c,pattern):
        self.c=c;self.pattern=pattern;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.known=set();self.counts=Counter();self.actual=[]
        self.cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.cs.detail=True
        self.u.mem_map(PRIVATE,EXTENT);self.u.mem_write(PRIVATE,bytes([pattern])*EXTENT)
        for n,x in c['initial_registers'].items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int(x,16))
        self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(c['initial_NZCV'],16))
        for f in c['initial_private_fixtures']:
            a=int(f['address'],16);n=f['size_bytes'];self.u.mem_write(a,int(f['value'],16).to_bytes(n,'little'));self.known.update(range(a,a+n))
        for row in R.slots():
            a=int(row['slot'],16);target,_=original_target(a);self.map_image(a);self.u.mem_write(a,target.to_bytes(8,'little'))
        for row in c['steps']:self.map_image(int(row['pc'],16))
        self.u.hook_add(uc.UC_HOOK_MEM_READ,self.on_read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.on_write)

    def map_image(self,a):
        page=a&~4095
        if page not in self.pages:
            self.u.mem_map(page,4096);self.u.mem_write(page,IMAGE.read(page,4096));self.pages.add(page)

    def on_read(self,u,t,a,n,value,data):
        if PRIVATE<=a<a+n<=PRIVATE+EXTENT:assert all(j in self.known for j in range(a,a+n)),('undefined read',hex(a))
        else:assert n==8 and a in FIXUPS
        value=int.from_bytes(u.mem_read(a,n),'little')
        self.actual.append({'kind':'read','address':hex(a),'size_bytes':n,'value':hex(value)})
        self.counts['read_bytes_checked']+=n

    def on_write(self,u,t,a,n,value,data):
        assert PRIVATE<=a<a+n<=PRIVATE+EXTENT
        self.known.update(range(a,a+n));value&=(1<<(8*n))-1
        self.actual.append({'kind':'write','address':hex(a),'size_bytes':n,'value':hex(value)})
        self.counts['write_bytes_checked']+=n;self.counts['write_effects_checked']+=1

    def run(self):
        registers=dict(self.c['initial_registers']);edges={r['pc']:r for r in self.c['logical_edges']};steps=self.c['steps']
        pc=R.ENTRY
        for seq,row in enumerate(steps):
            assert row['pc']==hex(pc);raw=IMAGE.read(pc,4);assert bytes(self.u.mem_read(pc,4))==raw
            i=next(self.cs.disasm(raw,pc));self.actual=[]
            if i.mnemonic=='braa':
                edge=edges[row['pc']];names=i.op_str.split(',');target=self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+names[0].strip().upper()))
                mod=self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+names[1].strip().upper()))
                assert hex(target)==edge['target'] and hex(mod)==edge['modifier']
                matches=[at for at in [TABLE+8*j for j in R.INDICES] if original_target(at)==(target,mod)]
                assert len(matches)==1;self.counts['original_authenticated_edges_checked']+=1
                pc=target
            else:
                assert i.mnemonic not in ['bl','blraa','blr','svc','ret','retab']
                self.u.emu_start(pc,pc+4,count=1);pc+=4;self.counts['A64_instructions_executed']+=1
            assert self.actual==row['events'],(row['pc'],self.actual,row['events'])
            registers.update(row['registers_after'])
            for name,want in registers.items():
                assert self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+name.upper()))==int(want,16),(row['pc'],name)
                self.counts['register_values_checked']+=1
            assert self.u.reg_read(ar.UC_ARM64_REG_NZCV)==int(row['NZCV_after'],16),(row['pc'],'NZCV')
            self.counts['NZCV_values_checked']+=1;self.counts['source_visits']+=1
            for ev in self.actual:
                if ev['kind']=='write':assert int.from_bytes(self.u.mem_read(int(ev['address'],16),ev['size_bytes']),'little')==int(ev['value'],16)
        assert self.c['boundary']['pc']==hex(pc)
        s=int(self.c['configuration']['SP'],16);u=int(self.c['configuration']['cursor64'],16)
        pointer=(s+0xc0b0+u)&R.MASK;final=(u+0x80)&R.MASK if pc==R.SPECIAL else u
        assert int.from_bytes(self.u.mem_read(s+0x4a20,8),'little')==pointer
        assert int.from_bytes(self.u.mem_read(s+0x16d0,8),'little')==final
        return {'configuration':self.c['configuration'],'physical_backing_pattern':self.pattern,
                'boundary':self.c['boundary'],'pointer64':hex(pointer),'final_cursor64':hex(final),
                'verified_counts':dict(self.counts),'all_checks_pass':True,'native_target_executed':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_regions']==R.source() and e['original_slots']==R.slots()
    assert e['source_fixups']==verify_original_fixups({TABLE+8*j for j in R.INDICES})
    assert e['bounded_census']==R.census()
    assert e['retained_context']==R.retained_context()
    assert e['clock_helper']==R.clock_bank()
    assert original_target(TABLE+8*0x1366)==(R.RETURN,0xd08c)
    assert original_target(TABLE+8*0xebf)==(0x10084c9b8,0xe8b8)
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==9
    for old,new in zip(e['source_proofs'],fresh):
        assert old['label']==new['label'] and old['premises_nonvacuous'] and new['premises_nonvacuous']
        q=z3.Solver();q.set(timeout=30000);q.from_string(old['query']);assert q.check()==z3.unsat
    replays=[];totals=Counter();boundaries=Counter()
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    for c in e['cases']:
        for pattern in [0x35,0xca]:
            row=Replay(c,pattern).run();replays.append(row);totals.update(row['verified_counts']);boundaries.update([row['boundary']['kind']])
    assert len(e['cases'])==132 and len(replays)==264
    controls=helper_controls();returns=return_controls();sdk=sdk_checks()
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'dependencies':e['dependencies'],
            'source_queries_unsat':9,'verified_counts':e['verified_counts'],'independent_replays':replays,
            'independent_totals':dict(totals),'boundary_counts':dict(boundaries),
            'helper_controls':controls,'return_controls':returns,'SDK_checks':sdk,
            'retained_IOKit_caller_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    a=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({k:a[k] for k in ['verified_counts','independent_totals','boundary_counts','all_checks_pass']}),flush=True)
