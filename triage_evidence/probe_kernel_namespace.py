#!/usr/bin/env python3
"""Original KC namespace/reply instructions in explicit private fixtures.

PAC, object locks, allocation/initialization, guard disposition, task context,
turnstile effects and SMR environment are explicit models. Atomic counters and
selected state transitions execute original instructions. Unknown operations
stop. No native target, host IPC/lock/allocation/callback or kernel code runs.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from recover_kernel_namespace import (LOOKUP,MQUEUE,TRANSLATE,LINK,PREPARE,COMPLETE,ADJUST,
    USER_REPLY,KERNEL_REPLY,KERNEL_UNBIND,ALLOC,LOCK,UNLOCK,RELEASE_SAFE,TRYLOCK)

ROOT=Path(__file__).resolve().parent
STACK=0x6000000000;SPACE=0x6100000000;SMR=0x6200000000;THREAD=0x6300000000
OBJ=0x6400000000;OLD=OBJ+0x4000;DEST=0x6500000000;OUT=0x6600000000
RO=0x6700000000;META=0x6800000000;TASK=0x6900000000;TS=0x6a00000000
HALT=0x6b00000000;PROC=TASK+0x800
TABLE=0x400000100000;TABLE2=TABLE+0x4000
RIGHTS=0x2c020001;NAME=0x32f
RETURN_HELPER=0xfffffe000bd7e9c4


class Probe:
    def __init__(self,k,label,kind,seed):
        self.k=k;self.label=label;self.kind=kind;self.seed=seed;self.events=[];self.pac=[]
        self.steps=0;self.reason=None;self.locked=set();self.phase=0;self.snapshots=[]
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
        self.allowed=[];pages=set()
        for a in (LOOKUP,MQUEUE,TRANSLATE,LINK,PREPARE,COMPLETE,ADJUST,USER_REPLY,
                  KERNEL_REPLY,KERNEL_UNBIND,LOCK,RELEASE_SAFE,TRYLOCK,0xfffffe000bcdcc7c):
            r=k.function(a);end=int(r['end'],16);self.allowed.append((a,end))
            pages.update(range(a&~4095,(end+4095)&~4095,4096))
        h=hashlib.sha256()
        for a in sorted(pages):
            raw=k.read(a,4096);h.update(struct.pack('<Q',a));h.update(raw)
            self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);self.u.mem_write(a,raw)
        self.code_hash=h.hexdigest();self.code_pages=sorted(pages)
        stubs={TRYLOCK,UNLOCK,ALLOC,0xfffffe000bd0aecc,0xfffffe000be8663c,
            0xfffffe000c629ba0,0xfffffe000c641fd8,0xfffffe000c641fa8,
            0xfffffe000bcc922c,0xfffffe000bcc92c8,0xfffffe000bccdbb4,
            RETURN_HELPER,0xfffffe000bd7deec,0xfffffe000c2ba130,0xfffffe000be81ebc,
            0xfffffe000bd69f7c,0xfffffe000bd68a7c,0xfffffe000bd683e0,
            0xfffffe000bd75c64,0xfffffe000bccd170,0xfffffe000bd682cc,
            0xfffffe000bd68474,0xfffffe000bcce310,0xfffffe000bd69ae8,
            0xfffffe000bd68354,0xfffffe000bd6a0d8,0xfffffe000bd0b274,
            0xfffffe000c62996c,0xfffffe000c6340d8}
        self.stub_pages=sorted({a&~4095 for a in stubs}-pages)
        for a in self.stub_pages:self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
        self.local_ranges=[(STACK,0x10000),(SPACE,4096),(SMR,4096),(THREAD,4096),
            (OBJ,0x8000),(DEST,4096),(OUT,4096),(RO,4096),(TASK,4096),(TS,8192),(HALT,4096),
            (TABLE,0x8000)]
        for a,n in self.local_ranges:self.u.mem_map(a,n)
        self.global_ranges=[(0xfffffe000caac348,24),(0xfffffe0007e66e08,8),
            (0xfffffe0007e66e50,16),(0xfffffe0007e66f00,8),
            (0xfffffe0007e63348,8),(0xfffffe000caec500,16)]
        global_pages={a&~4095 for a,n in self.global_ranges}
        for a in global_pages:self.u.mem_map(a,4096)
        # Zone metadata is an explicit private model, never host zone state.
        self.metadata_pages=set()
        for a in (OBJ,OLD,DEST):
            index=(a>>10)&0xffffffff0;at=META+index;page=at&~4095
            if page not in self.metadata_pages:self.u.mem_map(page,4096);self.metadata_pages.add(page)
            self.put(at,'H',seed.get('metadata_class',0x17 if seed.get('type',11)==0 else 0x16) if a==OBJ else 0x16)
        self.put(0xfffffe0007e66e50,'Q',OBJ-4096);self.put(0xfffffe0007e66e58,'Q',DEST+4096)
        self.put(0xfffffe0007e66f00,'Q',META)
        self.put(0xfffffe000caac348,'Q',0x100);self.put(0xfffffe000caac350,'Q',SMR)
        self.put(THREAD+0x1b8,'H',seed.get('cpu',0));self.put(THREAD+0x1c0,'Q',RO)
        self.put(THREAD+0x1c8,'I',seed.get('initial_preemption_count',0));self.put(RO+0x4c,'B',4 if seed.get('ast') else 0)
        self.put(TASK+0x318,'Q',SPACE)
        self.name=seed.get('name',NAME);self.bits=seed.get('bits',RIGHTS);idx=(self.name&0xffffffff)>>8
        self.token=TABLE|5 if seed.get('array_mode','normal')=='normal' else (TABLE&~(1<<46))|1
        self.put(SPACE+0x48,'Q',0 if seed.get('null_table') else self.token)
        capacity=1024 if seed.get('array_mode','normal')=='normal' else 16384
        if (idx+1)*24<=capacity:
            for table in (TABLE,TABLE2):
                self.put(table+24*idx,'Q',0 if seed.get('null_object') else OBJ)
                self.put(table+24*idx+8,'I',self.bits)
        for a,refs in ((OBJ,seed.get('object_refs',2)),(OLD,seed.get('old_refs',3)),(DEST,seed.get('dest_refs',5))):
            self.put(a,'B',seed.get('type',11) if a==OBJ else 11)
            self.put(a+4,'I',refs);self.put(a+0x40,'Q',THREAD)
        self.put(OBJ+0x10,'I',seed.get('link_flags',seed.get('state',0)<<12))
        self.put(OBJ+0x58,'Q',seed.get('inheritor',0))
        self.put(OBJ+0x60,'I',seed.get('diagnostic_pid',0x1234))
        self.put(DEST+0x70,'Q',TS);self.put(TS+0x58,'I',seed.get('turnstile_count',1))
        self.put(DEST+0x12,'B',1 if seed.get('group_tracking') else 0)
        self.put(THREAD+0x298,'Q',RO if seed.get('group_tracking') else 0)
        self.put(OUT,'I',0xdeadbeef);self.put(OUT+8,'Q',0xbadcafe)
        self.put(0xfffffe0007e63348,'Q',SPACE+0x800)
        self.put(0xfffffe000caec500,'Q',SPACE+0x900);self.put(0xfffffe000caec508,'Q',SPACE+0xa00)
        self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0xf000);self.setreg(30,HALT)
        if kind=='lookup':self.entry=LOOKUP;args=[SPACE,self.name,OUT,OUT+8]
        elif kind in ('mqueue','mqueue_then_release'):self.entry=MQUEUE;args=[SPACE,self.name,OUT+8]
        elif kind=='translate':self.entry=TRANSLATE;args=[SPACE,self.name,seed.get('right',0),OUT+8]
        elif kind in ('link','link_then_adjust'):self.entry=LINK;args=[OBJ,DEST,seed.get('bootstrap',0)]
        elif kind=='adjust':self.entry=ADJUST;args=[OBJ,0,seed.get('adjust_flags',4),0];self.locked.add(OBJ)
        elif kind=='user_reply':
            self.entry=USER_REPLY;args=[0]
            self.put(THREAD+0x450,'Q',OLD if seed.get('old_binding') else 0)
        elif kind=='kernel_reply':self.entry=KERNEL_REPLY;args=[0]
        elif kind=='kernel_unbind':self.entry=KERNEL_UNBIND;args=[THREAD];self.put(THREAD+0x3f0,'Q',OBJ)
        elif kind=='complete':self.entry=COMPLETE;args=[DEST]
        elif kind=='trylock_guard':self.entry=TRYLOCK;args=[OBJ]
        elif kind=='receive_release':self.entry=0xfffffe000bcdcdfc;args=[0];self.setreg(25,OBJ)
        else:raise AssertionError(kind)
        for n,v in enumerate(args):self.setreg(n,v)
        self.u.hook_add(uc.UC_HOOK_CODE,self.code)
        self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)

    def put(self,a,f,v):self.u.mem_write(a,struct.pack('<'+f,v))
    def get(self,a,f):return struct.unpack('<'+f,self.u.mem_read(a,struct.calcsize('<'+f)))[0]
    def reg(self,n):return self.u.reg_read(getattr(ar,f'UC_ARM64_REG_X{n}'))
    def setreg(self,n,v):self.u.reg_write(getattr(ar,f'UC_ARM64_REG_X{n}'),v&0xffffffffffffffff)
    def args(self):return [hex(self.reg(i)) for i in range(8)]
    def stop(self,kind,**kw):self.reason=kind;self.events.append({'kind':kind,**kw});self.u.emu_stop()
    def ret(self,v=0):self.setreg(0,v);self.u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
    def local(self,a,n):return any(x<=a and a+n<=x+s for x,s in self.local_ranges)
    def read(self,u,access,a,n,value,user):
        if self.local(a,n) or any(x<=a and a+n<=x+s for x,s in self.global_ranges) or a&~4095 in self.metadata_pages:return
        self.stop('unknown_read',address=hex(a),size_bytes=n,pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)))
    def write(self,u,access,a,n,value,user):
        if not self.local(a,n):self.stop('unknown_write',address=hex(a),size_bytes=n);return
        watched={OBJ+4,OBJ+0x10,OBJ+0x40,OBJ+0x58,OBJ+0x60,DEST+4,DEST+0x70,
            OLD+4,OLD+0x40,THREAD+0x3f0,THREAD+0x450,THREAD+0x1c8,
            SMR+128*self.seed.get('cpu',0),TS+0x58}
        if a in watched:self.events.append({'kind':'native_private_write','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
            'address':hex(a),'size_bytes':n,'old_value':hex(int.from_bytes(u.mem_read(a,n),'little')),
            'value':hex(value&((1<<(n*8))-1))})
    def snapshot(self):
        return {'object_refs':self.get(OBJ+4,'I'),'old_refs':self.get(OLD+4,'I'),'dest_refs':self.get(DEST+4,'I'),
            'flags':hex(self.get(OBJ+0x10,'I')),'inheritor':hex(self.get(OBJ+0x58,'Q')),
            'diagnostic_pid':self.get(OBJ+0x60,'I'),'thread_flags':hex(self.get(THREAD+0xc8,'H')),
            'owner':hex(self.get(OBJ+0x40,'Q')),'old_owner':hex(self.get(OLD+0x40,'Q')),
            'user_reply':hex(self.get(THREAD+0x450,'Q')),'kernel_reply':hex(self.get(THREAD+0x3f0,'Q')),
            'turnstile_count':self.get(TS+0x58,'I'),'preemption_count':self.get(THREAD+0x1c8,'I'),
            'smr_slot':hex(self.get(SMR+128*self.seed.get('cpu',0),'Q')),
            'out_bits':hex(self.get(OUT,'I')),'out_object':hex(self.get(OUT+8,'Q')),
            'locked_objects':[hex(a) for a in sorted(self.locked)]}
    def code(self,u,a,n,user):
        self.steps+=1
        if a==HALT:
            if self.kind=='mqueue_then_release' and not self.phase:
                self.phase=1;self.snapshots.append(self.snapshot());self.events.append({'kind':'private_next_phase','entry':'0xfffffe000bcdcdfc'})
                self.setreg(25,OBJ);u.reg_write(ar.UC_ARM64_REG_PC,0xfffffe000bcdcdfc);return
            if self.kind=='link_then_adjust' and not self.phase:
                self.phase=1;self.snapshots.append(self.snapshot());self.events.append({'kind':'private_next_phase','entry':hex(ADJUST)})
                self.locked.add(OBJ)
                for j,v in enumerate([OBJ,0,self.seed.get('adjust_flags',4),0]):self.setreg(j,v)
                self.setreg(30,HALT);u.reg_write(ar.UC_ARM64_REG_PC,ADJUST);return
            self.stop('returned',x0=hex(self.reg(0)));return
        if a==0xfffffe000bcdce14 and self.kind in ('receive_release','mqueue_then_release'):
            self.stop('receive_reference_release_boundary',x0=hex(self.reg(0)));return
        if a==TRYLOCK and self.kind!='trylock_guard':
            ok=self.seed.get('lock_result',1);self.events.append({'kind':'private_trylock','object':hex(self.reg(0)),'result':ok})
            if ok:self.locked.add(self.reg(0))
            mutation=self.seed.get('after_lock')
            idx=(self.name&0xffffffff)>>8
            if mutation:
                self.events.append({'kind':'private_after_lock_mutation','mutation':mutation})
                if mutation=='null_table':self.put(SPACE+0x48,'Q',0)
                elif mutation in ('growth_same','growth_changed'):
                    self.put(SPACE+0x48,'Q',TABLE2|5)
                    if mutation=='growth_changed':self.put(TABLE2+24*idx,'Q',OLD)
                elif mutation=='changed_object':self.put(TABLE+24*idx,'Q',OLD)
                elif mutation=='clear_rights':self.put(TABLE+24*idx+8,'I',self.bits&~0x1f0000)
                elif mutation=='change_generation':self.put(TABLE+24*idx+8,'I',self.bits^0x04000000)
                else:raise AssertionError(mutation)
            self.ret(ok);return
        if a==0xfffffe000bd0b274:
            ok=self.seed.get('lock_result',1);self.events.append({'kind':'private_lock_allow_invalid','args':self.args(),'result':ok})
            if ok:self.locked.add(self.reg(0)-0x14)
            self.ret(ok);return
        if a==UNLOCK:
            obj=self.reg(0)-0x14;self.events.append({'kind':'private_unlock','object':hex(obj),'modeled_locked':obj in self.locked})
            self.locked.discard(obj);self.ret();return
        if a==0xfffffe000bd0aecc:
            obj=self.reg(0)-0x14;self.locked.add(obj);self.events.append({'kind':'private_lock','object':hex(obj)});self.ret();return
        if a==ALLOC:
            error=self.seed.get('allocation_error',0);self.events.append({'kind':'private_port_alloc','args':self.args(),'status':error,'initial_refs':self.seed.get('allocation_refs',1)})
            if not error:
                self.put(self.reg(4),'I',NAME);self.put(self.reg(5),'Q',OBJ);self.put(OBJ+4,'I',self.seed.get('allocation_refs',1));self.locked.add(OBJ)
                self.put(OBJ,'B',11);self.put(OBJ+0x10,'I',0);self.put(OBJ+0x40,'Q',0)
            self.ret(error);return
        if a==0xfffffe000bd75c64:
            self.events.append({'kind':'private_kernel_object_alloc','args':self.args(),'object':hex(OBJ)})
            self.put(OBJ+4,'I',self.seed.get('allocation_refs',1));self.ret(OBJ);return
        if a==0xfffffe000bccd170:
            self.events.append({'kind':'private_kernel_port_init','args':self.args()})
            self.put(OBJ,'B',11);self.put(OBJ+0x10,'I',0);self.put(OBJ+0x40,'Q',0);self.locked.add(OBJ);self.ret();return
        if a==0xfffffe000bccdbb4:self.stop('native_port_destroy_boundary',args=self.args());return
        if a in (0xfffffe000bcc922c,0xfffffe000bcc92c8):
            self.events.append({'kind':'private_zero_reference_cleanup','address':hex(a),'args':self.args()});self.ret();return
        if a in (0xfffffe000c641fa8,0xfffffe000c641fd8):self.stop('reference_failure_boundary',address=hex(a),args=self.args());return
        if a in (0xfffffe000c62996c,0xfffffe000c6340d8):self.stop('zone_failure_boundary',address=hex(a),args=self.args());return
        helpers={RETURN_HELPER:TASK,0xfffffe000bd7deec:PROC,0xfffffe000c2ba130:4242,
            0xfffffe000be8663c:0,0xfffffe000c629ba0:0,0xfffffe000be81ebc:0,
            0xfffffe000bd69f7c:0,0xfffffe000bd683e0:0,0xfffffe000bcce310:0,
            0xfffffe000bd69ae8:0,0xfffffe000bd68354:0,0xfffffe000bd6a0d8:0}
        if a==0xfffffe000bd68a7c:
            # Explicit model for the final turnstile-complete branch: detach
            # and return a private object through the optional out parameter.
            self.events.append({'kind':'private_turnstile_complete','args':self.args()})
            self.put(self.reg(0)+0x70,'Q',0)
            if self.reg(4):self.put(self.reg(4),'Q',TS)
            self.ret();return
        if a==0xfffffe000bd682cc:
            self.events.append({'kind':'private_turnstile_allocate','object':hex(TS)});self.ret(TS);return
        if a==0xfffffe000bd68474:
            self.events.append({'kind':'private_turnstile_prepare','args':self.args()})
            self.put(self.reg(0)+0x70,'Q',TS);self.ret(TS);return
        if a in helpers:
            self.events.append({'kind':'private_helper','address':hex(a),'args':self.args(),'result':helpers[a]});self.ret(helpers[a]);return
        if not any(lo<=a<hi for lo,hi in self.allowed):self.stop('unknown_code',pc=hex(a));return
        ins=next(self.k.cs.disasm(bytes(u.mem_read(a,4)),a));m=ins.mnemonic
        if m=='mrs':
            if not ins.op_str.endswith(', tpidr_el1'):self.stop('unknown_system_read',instruction=ins.op_str);return
            self.setreg(int(ins.op_str.split(',')[0][1:]),THREAD);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
        if m in ('pacibsp','autibsp','autda','pacda'):
            self.pac.append({'pc':hex(a),'instruction':m,'operands':ins.op_str});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
        elif m=='retab':self.pac.append({'pc':hex(a),'instruction':m});u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
        elif m in ('svc','smc','hvc','msr','eret','brk') or m.startswith(('pac','aut','xpac')):
            self.stop('unmodeled_instruction',pc=hex(a),instruction=m+' '+ins.op_str)
    def run(self):
        initial=self.snapshot()
        try:self.u.emu_start(self.entry,0,count=30000)
        except uc.UcError as e:self.reason='engine_error';self.events.append({'kind':'engine_error','error':str(e),'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
        if self.reason is None:self.reason='instruction_budget'
        return {'label':self.label,'kind':self.kind,'seed':self.seed,'entry':hex(self.entry),
            'stop_reason':self.reason,'steps':self.steps,'events':self.events,'pac_bypasses':self.pac,
            'source_code_pages':[hex(a) for a in self.code_pages],'source_code_pages_sha256':self.code_hash,
            'private_boundary_stub_pages':[hex(a) for a in self.stub_pages],
            'initial':initial,'final':self.snapshot(),'phase_snapshots':self.snapshots,
            'native_target_executed':False,'target_host_operations_executed':False}


def main():
    k=Kernel();rows=[]
    def case(label,kind,**seed):
        row=Probe(k,label,kind,seed).run();rows.append(row)
        assert row['stop_reason'] not in ('engine_error','unknown_read','unknown_write','unknown_code','unknown_system_read','instruction_budget','unmodeled_instruction'),row
        print(json.dumps({'label':label,'stop':row['stop_reason'],'last':row['events'][-1],'final':row['final']}),flush=True)
    case('lookup_valid','lookup')
    for name in (0,3,255,0x32c,0x32d,0x32e,0x333,0xffffffff,0x2a2f):case(f'lookup_name_{name}','lookup',name=name)
    case('lookup_compact_array','lookup',array_mode='compact',name=0x1f42f)
    for label,seed in [('inactive',{'null_table':True}),('null_object',{'null_object':True}),
        ('lock_fail',{'lock_result':0}),('no_rights',{'bits':0x2c000001}),
        ('nested_preemption',{'initial_preemption_count':2}),('ast_exit',{'ast':True}),('cpu_slot',{'cpu':1})]:case('lookup_'+label,'lookup',**seed)
    for mutation in ('null_table','growth_same','growth_changed','changed_object','clear_rights','change_generation'):
        case('lookup_after_lock_'+mutation,'lookup',after_lock=mutation)
    for rights in (0x10000,0x20000,0x30000,0x40000,0x80000,0x100000):
        for ex in (False,True):case(f'mqueue_rights_{rights}_{ex}','mqueue',type=0 if rights==0x80000 else 11,bits=0x2c000001|rights|(0x200000 if ex else 0))
    case('mqueue_lookup_failure','mqueue',null_table=True)
    case('mqueue_zero_refs','mqueue',object_refs=0)
    for right in range(6):
        case(f'translate_right_{right}_present','translate',right=right,bits=0x2c000001|(0x10000<<min(right,4)))
        case(f'translate_right_{right}_absent','translate',right=right,bits=0x2c020001 if right!=1 else 0x2c010001)
    for state in range(6):case(f'link_state_{state}','link',state=state,inheritor=0 if state==0 else OLD)
    case('link_existing_pointer','link',inheritor=OLD)
    case('link_nonspecial','link',type=1)
    case('link_bootstrap','link',bootstrap=1)
    case('link_group_tracking','link',group_tracking=True)
    case('link_reference_failure','link',dest_refs=0)
    case('link_then_unlink','link_then_adjust')
    case('link_then_allow','link_then_adjust',adjust_flags=1)
    case('link_turnstile_initial_zero','link',turnstile_count=0)
    for state in (0,1,2,3,4,5):
        case(f'adjust_unlink_state_{state}','adjust',state=state,inheritor=DEST if state==1 else 0)
    case('adjust_unlink_knote','adjust',state=2,inheritor=OLD)
    case('adjust_unlink_stash','adjust',state=3,inheritor=TS)
    for state in (0,4):case(f'adjust_allow_state_{state}','adjust',state=state,adjust_flags=1)
    case('adjust_reset_bootstrap','adjust',link_flags=0x8000,adjust_flags=0x20)
    for old in (False,True):case('user_reply_'+str(old),'user_reply',old_binding=old)
    case('user_reply_alloc_error','user_reply',old_binding=True,allocation_error=3)
    case('user_reply_old_last_reference','user_reply',old_binding=True,old_refs=1)
    case('kernel_reply_new','kernel_reply')
    case('kernel_reply_unbind','kernel_unbind')
    case('kernel_reply_unbind_linked','kernel_unbind',state=1,inheritor=DEST)
    for count in (1,2):case(f'turnstile_complete_{count}','complete',turnstile_count=count)
    case('native_lock_guard_port','trylock_guard')
    case('native_lock_guard_pset','trylock_guard',type=0)
    case('native_lock_guard_lock_failure','trylock_guard',lock_result=0)
    case('native_lock_guard_bad_zone','trylock_guard',metadata_class=0x18)
    case('native_lock_guard_pset_zone_mismatch','trylock_guard',type=0,metadata_class=0x16)
    case('receive_reference_pair','mqueue_then_release')
    for refs in (0,1,2):case(f'receive_release_{refs}','receive_release',object_refs=refs)
    out={'scope':__doc__,'source_sha256':k.sha256,'unicorn_version':uc.__version__,
        'cpu_model':'UC_CPU_ARM64_MAX; enables original LSE instructions; PAC explicitly bypassed',
        'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'reader_sha256':hashlib.sha256((ROOT/'kernel_native_reader.py').read_bytes()).hexdigest(),
        'instruction_limit_per_profile':30000,'fixture_memory':'private zero-filled mappings with explicit table, SMR, zone, lock and object models',
        'profiles':rows}
    (ROOT/'kernel_namespace_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'profiles':len(rows)}))


if __name__=='__main__':main()
