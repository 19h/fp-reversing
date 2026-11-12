#!/usr/bin/env python3
"""Independent caller-prefix replay, original slice lift and conditional banks.

No import of the new producer. Complete initial CPU/touched RAM, every retained
source/API/PAC transition and final RAM are checked. Source equations retain
alignment domains, SAT controls and composition with the frozen ingress proof.
Replay/enumeration O(C*(B+P*F+V*J+R)+T+4*256) time/space upper bound;
SMT cost is separate, capped at 30 s/query. 30000 visits/profile.
No native execution or IDB mutation occurs.
"""
import bisect,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from capstone.arm64_const import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM,ARM64_CC_EQ,ARM64_EXT_UXTB,ARM64_EXT_UXTW
from audit_corefp_lookup_release import Replay as Frozen,parent_inputs,frame,restore,ret,unpack,CS
from audit_corefp_lookup_initialization import initial_page,declared_inputs
from audit_corefp_root_ingress import source_checks as ingress_source_checks
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M32=(1<<32)-1;M64=(1<<64)-1
ENTRY=0x2e4280;J=0x63000800;DATA=0x63000900;AUX=0x63000c00;META=0x64000800;DONE=0x65000000


def caller_inputs(s,c):
    # Original XOR expressed via add-minus-twice-AND; independent of producer.
    v=J+0xc2762410-2*(J&0xc2762410);key=((v^0x084ffaea)*0x01266167)&M32
    b=bytearray(64);b[:4]=(c['entry_tag_u32']^key).to_bytes(4,'little')
    b[8:16]=c['first_pointer'].to_bytes(8,'little');b[16:24]=c['second_pointer'].to_bytes(8,'little')
    b[28:32]=(c['entry_scalar_u32']^key).to_bytes(4,'little')
    row=next(v for v in s.imports if v['name']=='_mach_task_self_')
    return [(J,bytes(b)),(META,bytes([c['metadata_fill_u8']])*32),(BIND+row['ordinal']*16,c['task_port_u32'].to_bytes(4,'little'))]


class Replay(Frozen):
    def __init__(self,p,spans,s):super().__init__(p,spans,s);self.ci=self.mai=0
    def caller_point(self,label):
        row={'label':label,'CPU':frame(self.u),'visits_so_far':self.v,'models_so_far':self.mi,
          'caller64_hex':self.ram(J,64).hex(),'metadata32_hex':self.ram(META,32).hex()}
        if label in ['before_metadata_constructor','metadata_constructor_entry','before_buffer_builder','buffer_builder_entry','buffer_helper_entry','vm_helper_entry']:
            p=self.u.reg_read(A.UC_ARM64_REG_X0);row.update({'record_address':hex(p),'record32_hex':self.ram(p,32).hex()})
        assert row==self.p['caller_points'][self.ci];self.ci+=1
    def code(self,u,pc,n,d):
        self.flush();name=self.imports.get(pc);cfg=self.p['configuration']
        points={0x2e43e4:'entry_tag_decoded',0x2e469c:'before_metadata_constructor',0x1ae0a4:'metadata_constructor_entry',
          0x1ae264:'metadata_allocator_return',0x1ae2dc:'metadata_constructor_result',0x2e47e4:'before_buffer_builder',
          0x43c4d8:'buffer_builder_entry',0x47e434:'buffer_helper_entry',0x1c9fac:'vm_helper_entry',0x1ca424:'vm_route_entry',0x1ca598:'before_vm_allocate_call'}
        if pc-BASE in points:self.caller_point(points[pc-BASE])
        if name=='_vm_allocate':
            self.caller_point('vm_import_frontier');args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)]
            assert self.p['frontier']=={'reason':'before_vm_allocate','CPU':frame(u),'args_x0_x7':list(map(hex,args)),
              'callsite':hex(u.reg_read(A.UC_ARM64_REG_LR)-4-BASE),'output_word_before_hex':self.ram(args[1],8).hex()}
            self.done=True;u.emu_stop();return
        if name=='_malloc'and u.reg_read(A.UC_ARM64_REG_LR)-4-BASE==0x1ae260:
            args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)];assert self.mai==0 and args[0]==32;self.mai+=1;e=self.event()
            assert e['kind']=='declared_API'and e['name']==name and e['callsite']=='0x1ae260'and e['args_x0_x7']==list(map(hex,args))
            self.effects(e,[]);value=META if cfg['metadata_success']else 0;assert e['return_u64']==hex(value)
            f=ret(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        if pc==DONE:self.caller_point('outer_return')
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=30001);self.flush();assert self.done and not self.once
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.hi,self.li,self.mri,self.di,self.ci,self.mai]==[
          len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','handoffs','lock_events','metadata_returns','daemon_children','caller_points']]+[self.p['metadata_allocation_attempts']]
        assert self.allocs==self.p['allocations_attempted']==self.p['bootstrap_calls']==self.bi==self.cert==self.p['certificate_allocation_attempts']==0
        assert self.snapshot('frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'caller_points_checked':self.ci,'metadata_allocation_attempts_checked':self.mai,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,r,s):
    c=p['configuration'];null=not c['first_pointer']or not c['second_pointer'];early=null or not c['metadata_success']
    assert c['entry_tag_u32']==0x9744 and c['entry_scalar_u32']in [0,4096]and c['task_port_u32']in [0,0x4201]
    assert c['first_pointer']in [0,DATA]and c['second_pointer']in [0,AUX]and c['metadata_fill_u8']in [0,0xa5]
    assert p['metadata_allocation_attempts']==int(not null)and len(p['models'])==int(not null)
    assert not any(p[k]for k in ['points','handoffs','lock_events','metadata_returns','daemon_children'])
    assert not any(0x5f4584<=int(v['pc'],16)<0x5f4908 for v in p['visits'])
    before=caller_inputs(s,c)[0][1];expected=bytearray(before)
    if early:
        status=0x45e2a202 if null else 0x45e2a20f;expected[24:28]=status.to_bytes(4,'little')
        assert p['frontier']['reason']=='parent_return'and p['parent_return']is not None
        final=p['frontier']['CPU'];assert final['SP']==p['initial_CPU']['SP']and final['X31'][19:31]==p['initial_CPU']['X31'][19:31]
    else:
        status=None;f=p['frontier'];assert f['reason']=='before_vm_allocate'and p['parent_return']is None
        assert f['callsite']=='0x1ca598'and f['args_x0_x7'][:4]==[hex(c['task_port_u32']),'0x62017d70','0x1000','0x1']
        assert f['output_word_before_hex']=='a5'*8 and p['visits'][-1]['pc']=='0x1ca598'
        # The final two source loads establish task global -> W0 and function
        # fixup -> authenticated edge, without treating the name as a right.
        taskreads=[v for v in p['reads']if p['visits'][v['visit']]['pc']=='0x1ca548'];assert len(taskreads)==1
        assert taskreads[0]['address']==hex(BIND+82*16)and taskreads[0]['size_B']==4 and taskreads[0]['bytes_hex']==c['task_port_u32'].to_bytes(4,'little').hex()
        rootreads=[v for v in p['reads']if p['visits'][v['visit']]['pc']=='0x1ca540'];assert len(rootreads)==1
        slot=int(rootreads[0]['address'],16)-BASE;assert slot in [0x1d14310,0x1d1bf58]and s.decoded[slot]['import']['name']=='_mach_task_self_'
        pac=p['PAC_models'][-1];assert pac['pc']=='0x1ca598'and pac['modifier']=='0x6764'and pac['pointer_row']==s.decoded[0x1d04758]
        assert pac['pointer_row']['import']['name']=='_vm_allocate'
    assert r.ram(J,64)==bytes(expected)
    meta=bytearray(bytes([c['metadata_fill_u8']])*32)
    if not early:
        meta[:28]=struct.pack('<QIIIII',0,0x49741372,0x49741372,0x574de777,0x71349589,0xba1df9db)
        writes=[v for v in p['writes']if META<=int(v['address'],16)<META+32]
        assert sum(v['size_B']for v in writes)==28 and {int(v['address'],16)+j for v in writes for j in range(v['size_B'])}==set(range(META,META+28))
        assert [(p['visits'][v['visit']]['pc'],int(v['address'],16)-META,v['size_B'])for v in writes]==[
          ('0x1ae29c',0,8),('0x1ae2a8',8,4),('0x1ae2a8',12,4),('0x1ae2bc',16,4),('0x1ae2bc',20,4),('0x1ae2c8',24,4)]
    produced=[v for v in p['writes']if p['visits'][v['visit']]['pc']=='0x1ae2cc']
    assert len(produced)==int(not early)
    if produced:assert produced[0]['address']=='0x62017f40'and produced[0]['size_B']==8 and produced[0]['after_hex']==META.to_bytes(8,'little').hex()
    result_writes=[v for v in p['writes']if p['visits'][v['visit']]['pc']=='0x1ae2dc']
    assert len(result_writes)==int(not null)
    if result_writes:assert result_writes[0]['address']=='0x62017f68'and result_writes[0]['size_B']==4 and result_writes[0]['after_hex']==(0xba1df9db if c['metadata_success']else 0x45e2a20f).to_bytes(4,'little').hex()
    assert r.ram(META,32)==bytes(meta)
    result={'label':c['label'],'entry_tag_u32':'0x9744','entry_scalar_u32':hex(c['entry_scalar_u32']),
      'metadata_allocation_attempts':int(not null),'metadata_requested_B':None if null else 32,'early_return':early,
      'raw_caller_result_at_0x18':None if status is None else hex(status),'residual_X0_is_status':False,
      'metadata_bytes_defined':0 if early else 28,'metadata_padding_retains_fill':True,'ingress_reached':False,'native_target_executed':False}
    if not early:result.update({'task_port_input_u32':hex(c['task_port_u32']),'task_global_pointer_slot':hex(slot),
      'VM_API':'_vm_allocate','VM_callsite':'0x1ca598','VM_function_pointer_slot':'0x1d04758','VM_requested_B':4096,
      'VM_flags_u32':1,'VM_output_pointer':'0x62017d70','VM_API_executed':False,'native_right_identity':'unknown'})
    return result


def lift_caller(s,name,lo,hi,off,tagname,key_site):
    """Fail-closed lift: explicit entry bindings, loads, cmp/csel and stores."""
    CS.detail=True;p,j,cache,ptr=z3.BitVecs(name+'_I '+name+'_J '+name+'_cache '+name+'_ptr',64)
    tag=z3.BitVec(name+'_tag',32);byte=z3.BitVec(name+'_byte',8);ki=z3.BitVec(name+'_verified_Ki',32)
    sp=p-off;rf={'sp':sp,'x29':sp+0x120,'x24':j,'x'+tagname[1:]:z3.ZeroExt(32,tag)};sites=[];loads=[];stores={};equal=None;premix=key=None
    if name=='caller_22438c':bindings=[(sp+0x60,j),(j+0x34,z3.ZeroExt(24,byte)),(sp+0x30,cache),(sp+0x80,ptr)]
    elif name=='caller_4bae24':bindings=[(j+0x10,z3.ZeroExt(24,byte)),(sp+0x10,cache),(sp+0x40,ptr)]
    else:bindings=[(sp+0x50,ptr)]
    def reg(n):
        n={'fp':'x29','lr':'x30'}.get(n,n)
        if n in ['xzr','wzr']:return z3.BitVecVal(0,32 if n[0]=='w'else 64)
        x='x'+n[1:]if n.startswith('w')else n;assert x in rf,(name,n,'undefined');v=rf[x]
        return z3.Extract(31,0,v)if n.startswith('w')else v
    def put(n,v):
        n={'fp':'x29','lr':'x30'}.get(n,n)
        w=32 if n.startswith('w')else 64;assert v.size()==w;rf['x'+n[1:]if n.startswith('w')else n]=z3.ZeroExt(32,v)if w==32 else v
    def val(op,w):
        if op.type==ARM64_OP_REG:v=reg(CS.reg_name(op.reg))
        else:assert op.type==ARM64_OP_IMM;v=z3.BitVecVal(op.imm,w)
        assert v.size()==w;return v<<op.shift.value if op.shift.value else v
    def addr(op):assert op.type==ARM64_OP_MEM and not op.mem.index;return reg(CS.reg_name(op.mem.base))+op.mem.disp
    def load(a,w):
        for address,v in bindings:
            if z3.is_true(z3.simplify(a==address)):
                assert v.size()==w,(name,w,v.size());loads.append({'address_expression':str(z3.simplify(a)),'width_bits':w});return v
        raise AssertionError((name,'unbound load',a,w))
    def store(a,v):
        delta=z3.simplify(a-p);assert z3.is_bv_value(delta);n=delta.as_long();assert n not in stores;stores[n]=v
    for i in CS.disasm(s.read(lo,hi-lo),lo):
        sites.append({'address':hex(i.address),'bytes_hex':s.read(i.address,4).hex(),'instruction':i.mnemonic+' '+i.op_str})
        ops=i.operands;m=i.mnemonic;dst=CS.reg_name(ops[0].reg);w=32 if dst.startswith('w')else 64
        if m=='mov':put(dst,val(ops[1],w))
        elif m=='movk':
            shift=ops[1].shift.value;put(dst,(reg(dst)&z3.BitVecVal(~(0xffff<<shift),w))|z3.BitVecVal(ops[1].imm<<shift,w))
        elif m in ['add','sub','eor','orr','and','orn','mul']:
            a,b=val(ops[1],w),val(ops[2],w);put(dst,{'add':lambda:a+b,'sub':lambda:a-b,'eor':lambda:a^b,
              'orr':lambda:a|b,'and':lambda:a&b,'orn':lambda:a|~b,'mul':lambda:a*b}[m]())
        elif m=='cmp':equal=val(ops[0],w)==val(ops[1],w)
        elif m=='csel':assert i.cc==ARM64_CC_EQ and equal is not None;put(dst,z3.If(equal,val(ops[1],w),val(ops[2],w)))
        elif m in ['ldr','ldrb']:put(dst,load(addr(ops[1]),w))
        elif m in ['str','stur']:store(addr(ops[1]),reg(dst))
        elif m=='stp':a=addr(ops[2]);store(a,reg(dst));store(a+w//8,reg(CS.reg_name(ops[1].reg)))
        else:raise AssertionError((name,hex(i.address),m))
        if i.address==key_site-12:premix=reg('w11'if name=='caller_22438c'else 'w10'if name=='caller_4bae24'else 'w9')
        if i.address==key_site:
            keyreg='w11'if name=='caller_22438c'else 'w10'if name=='caller_4bae24'else 'w9';key=reg(keyreg);put(keyreg,ki)
    assert len(sites)*4==hi-lo and set(stores)=={0,8,16,20,24}
    return {'p':p,'j':j,'cache':cache,'ptr':ptr,'tag':tag,'byte':byte,'Ki':ki,'premix':premix,'key':key,
      'stores':stores,'sites':sites,'loads':loads,'SP':sp,'comparison':equal}


def lift_bank(s,c,prove):
    """Prove original load indices and dispatch with exhaustive bank lemma.

    The B-byte cut is justified by all 256 original A/B cases in source_checks.
    Its source address is proved first. Top 24 seed bits remain symbolic.
    """
    call=int(c['callsite'],16);name=c['label'];seed=z3.BitVec(name+'_bank_seed32',32)
    av,bv=z3.BitVecs(name+'_A_byte8 '+name+'_B_byte8',8);u64=lambda n:z3.BitVecVal(n,64)
    d=0x1c81940;sp=0x62010000;a=int(c['A_address'],16);b=int(c['B_address'],16);xor=int(c['xor_u8'],16)
    specs={0x22438c:(0x224334,0x224384,0x224344,0x224360,0x224380,'x23'),
      0x2e490c:(0x2e48bc,0x2e4904,0x2e48d4,0x2e48e8,0x2e4900,'x27'),
      0x4bae24:(0x4badd4,0x4bae1c,0x4badec,0x4bae00,0x4bae18,'x25'),
      0x14f2720:(0x14f26dc,0x14f2718,0x14f26ec,0x14f26fc,0x14f2714,'x24')}
    lo,hi,aload,bload,dispatch,dr=specs[call];rf={'x8':z3.ZeroExt(32,seed),'x9':z3.BitVec(name+'_unused_entry_X9',64),'sp':u64(sp),dr:u64(d)}
    sites=[];pointer_loads=[];saw=[]
    def reg(n):
        n={'fp':'x29','lr':'x30'}.get(n,n);x='x'+n[1:]if n.startswith('w')else n;assert x in rf,(name,n)
        return z3.Extract(31,0,rf[x])if n.startswith('w')else rf[x]
    def put(n,v):
        w=32 if n.startswith('w')else 64;assert v.size()==w;rf['x'+n[1:]if w==32 else n]=z3.ZeroExt(32,v)if w==32 else v
    def extend(v,ext,w):
        if ext==ARM64_EXT_UXTB:v=z3.Extract(7,0,v)
        elif ext==ARM64_EXT_UXTW:v=z3.Extract(31,0,v)
        else:assert not ext
        if v.size()<w:v=z3.ZeroExt(w-v.size(),v)
        assert v.size()==w;return v
    def val(op,w):
        if op.type==ARM64_OP_IMM:v=z3.BitVecVal(op.imm,w)
        else:assert op.type==ARM64_OP_REG;v=extend(reg(CS.reg_name(op.reg)),op.ext,w)
        return v<<op.shift.value if op.shift.value else v
    def addr(op):
        assert op.type==ARM64_OP_MEM;v=reg(CS.reg_name(op.mem.base))+op.mem.disp
        if op.mem.index:
            ix=extend(reg(CS.reg_name(op.mem.index)),op.ext,64);v+=ix<<op.shift.value
        return v
    for i in CS.disasm(s.read(lo,hi-lo),lo):
        sites.append({'address':hex(i.address),'bytes_hex':s.read(i.address,4).hex(),'instruction':i.mnemonic+' '+i.op_str})
        ops=i.operands;m=i.mnemonic;dst=CS.reg_name(ops[0].reg);w=32 if dst.startswith('w')else 64
        if m in ['mov','adrp']:put(dst,val(ops[1],w))
        elif m=='movk':
            shift=ops[1].shift.value;put(dst,(reg(dst)&z3.BitVecVal(~(0xffff<<shift),w))|z3.BitVecVal(ops[1].imm<<shift,w))
        elif m in ['add','sub','eor','mul']:
            v,t=val(ops[1],w),val(ops[2],w);put(dst,{'add':lambda:v+t,'sub':lambda:v-t,'eor':lambda:v^t,'mul':lambda:v*t}[m]())
        elif m in ['ldr','ldrb','ldurb']:
            at=addr(ops[1])
            if i.address==aload:
                prove(name+'_original_A_load_index',at,u64(a)+z3.ZeroExt(56,z3.Extract(7,0,seed)));value=z3.ZeroExt(24,av);saw.append('A')
            elif i.address==bload:
                prove(name+'_original_B_load_index',at,u64(b)+z3.ZeroExt(56,av^xor));value=z3.ZeroExt(24,bv);saw.append('B')
            elif i.address==dispatch:
                wanted=int(c['target_row']['address'],16);constant=c['selected_low8'][0]
                prove(name+'_original_dispatch_slot',at,u64(wanted),(bv==(z3.Extract(7,0,seed)^constant),))
                value=u64(int(c['target_row']['target'],16));saw.append('dispatch')
            else:
                at=z3.simplify(at);assert z3.is_bv_value(at),(name,hex(i.address),'unexpected symbolic pointer load');address=at.as_long()
                if address==sp+0x68 and call==0x22438c:value=u64(d)
                else:
                    rows=[c['A_pointer_row'],c['B_pointer_row']];row=next(v for v in rows if int(v['address'],16)==address)
                    assert not row['bind'];value=u64(s.qword(address));pointer_loads.append(row['address'])
            put(dst,value)
        elif m=='str':assert z3.is_true(z3.simplify(addr(ops[1])==u64(sp+8)))and call==0x22438c
        else:raise AssertionError((name,hex(i.address),m))
    assert saw==['A','B','dispatch']and len(sites)*4==hi-lo and len(pointer_loads)==2
    return {'callsite':c['callsite'],'original_sites':sites,'pointer_load_slots':pointer_loads,
      'table_pair_lemma_checked_inputs':256,'seed_domain_bits':32,'dispatch_base_assumption':hex(d),
      'target_slot':c['target_row']['address'],'target':c['target_row']['target'],'runtime_PC_gap':False}


def source_checks(s,e):
    proofs=[];counterexamples=[];callers=[];total_sites=0
    def prove(name,a,b,domain=()):
        sol=z3.Solver();sol.set(timeout=30000);sol.add(*domain,a!=b);res=sol.check();assert res==z3.unsat,(name,res)
        proofs.append({'label':name,'query':sol.to_smt2(),'result':'unsat'})
    address=z3.BitVec('outer_entry_address_low32',32)
    premix=(address+0xc2762410-2*(address&0xc2762410))^0x084ffaea
    prove('outer_entry_key_premix_all32',premix,address^0xca39defa)
    prove('outer_entry_key_composed_all32',premix*0x01266167,(address^0xca39defa)*0x01266167,(premix==(address^0xca39defa),))
    for name,lo,hi,off,tagname,ks,opadd,vals,cmpvalue in [
      ('caller_22438c',0x224250,0x224310,0x98,'w20',0x2242d8,0xaec41bfa,(0x72ceb203,0x2a3b089e),11),
      ('caller_2e490c',0x2e4844,0x2e48a0,0x78,'w21',0x2e4860,0xaec43b6b,(0x1f03fdec,),None),
      ('caller_4bae24',0x4bad18,0x4badc0,0x50,'w27',0x4bad88,0xaec40ec5,(0xbfb18293,0xf2c062ba),0x47)]:
        l=lift_caller(s,name,lo,hi,off,tagname,ks);p=l['p'];low=z3.Extract(31,0,p);k=l['Ki'];st=l['stores'];canon=(low^0xd914ae5d)*0x08c5d407
        premix_domain=(p&1==0,)if name=='caller_4bae24'else ()
        prove(name+'_key_premix',l['premix'],low^0xd914ae5d,premix_domain)
        prove(name+'_key_composed',l['key'],canon,(l['premix']==(low^0xd914ae5d),))
        if name=='caller_4bae24':
            sol=z3.Solver();sol.set(timeout=30000);sol.add(l['premix']!=(low^0xd914ae5d));assert sol.check()==z3.sat
            pv=sol.model().eval(p,model_completion=True);actual=z3.simplify(z3.substitute(l['key'],(p,pv))).as_long();wanted=z3.simplify(z3.substitute(canon,(p,pv))).as_long()
            assert pv.as_long()%8!=0 and actual!=wanted
            counterexamples.append({'label':name+'_unrestricted_key','query':sol.to_smt2(),'result':'sat','record_address':hex(pv.as_long()),
              'original_key_u32':hex(actual),'canonical_key_u32':hex(wanted)})
        if cmpvalue is None:chosen=z3.BitVecVal(vals[0],32);predicate=None
        else:
            b32=z3.ZeroExt(24,l['byte']);c32=z3.Extract(31,0,l['cache'])
            predicate=((b32+c32)&255)==cmpvalue if name=='caller_22438c'else (b32^(c32&255))==cmpvalue
            chosen=z3.If(predicate,z3.BitVecVal(vals[0],32),z3.BitVecVal(vals[1],32));prove(name+'_selector_predicate',l['comparison'],predicate)
        prove(name+'_raw_operation',st[0],l['tag']-k+opadd)
        prove(name+'_mode_preimage',st[16]-k,z3.BitVecVal(0x2d2a8321,32))
        prove(name+'_scalar_preimage',st[20]+k,chosen)
        prove(name+'_pointer8',st[8],l['ptr'])
        out=l['SP']+(0x78 if name=='caller_22438c'else 0x68 if name=='caller_2e490c'else 0x30)
        prove(name+'_pointer24',st[24],out)
        opdelta=(opadd+0x513c5990)&M32;prove(name+'_decoded_root_operation',st[0]+k+0x513c5990,l['tag']+opdelta)
        prove(name+'_decoded_root_mode',(st[16]-k)*0x59529999+0x30f52b5f,z3.BitVecVal(0x114e4318,32))
        callers.append({'label':name,'original_lifted_sites':l['sites'],'load_bindings':l['loads'],'record_SP_offset_B':off,
          'key_domain':'record_address & 1 == 0'if premix_domain else 'all u64 record addresses',
          'key_cutpoint':{'after_address':hex(ks),'symbol':str(k),'validated_by':name+'_key_composed'},
          'decoded_root_operation_addend_u32':hex(opdelta),'current_tag_for_operation_c1f7':hex((0xc1f7-opdelta)&M32),
          'decoded_root_mode_u32':'0x114e4318','scalar_preimages_u32':list(map(hex,vals)),
          'whole_function_executed_to_call':False,'runtime_state_restored_for_symbolic_cut':False})
        total_sites+=len(l['sites'])
    prove('shared_mode_preimage',z3.BitVecVal(0x2d2a8321,32)*0x59529999+0x30f52b5f,z3.BitVecVal(0x114e4318,32))
    old=json.loads(read(ROOT/'corefp_root_ingress_checks.json'));prior=ingress_source_checks(s,old)
    # Independent numeric mixer, using 64-bit-free Python u32 operations.
    scalars=[]
    for v,want in [(0x72ceb203,0x7c9bb44b),(0x2a3b089e,0xe0dd53c8),(0x1f03fdec,0x0484c46a),(0xbfb18293,0x5994b43b),(0xf2c062ba,0x290d078c)]:
        t=(v*0x2dd4c139+0x31f01626)&M32;f=t^0x1b8e4fe2
        for a,b in [(0x49b63a0a,0xc1154c69),(0xa377af8e,0x2bd4d9ed),(0xa26243c6,0x2ac135a5),(0x3fff5fdf,0xb75c29be)]:f^=((t^a)+b)&M32
        assert f==want;scalars.append({'scalar_preimage_u32':hex(v),'decoded_root_field16_u32':hex(f),'semantic_name':'unknown'})
    bankchecks=[]
    specs=[(0x1d08e18,0,0x1d077d0,-8,0xe4,0x10378,0xec,0x5f4584),(0x1d146f0,0,0x1d09f68,-8,0xc8,0x103a4,0xc0,0x5f4584),
      (0x1d146f0,0,0x1d09f68,-8,0xc8,0x103a4,0xc0,0x5f4584),(0x1d09500,0,0x1d0b590,-12,0x20,0x10410,0x94,0x2233c8)]
    assert len(e['conditional_bank_contracts'])==4
    for c,(ap,ad,bp,bd,xor,bias,want,target)in zip(e['conditional_bank_contracts'],specs):
        a=s.qword(ap)+ad;b=s.qword(bp)+bd;av=s.read(a,256);bv=s.read(b,256)
        assert c['A_pointer_row']==s.decoded[ap]and c['B_pointer_row']==s.decoded[bp]
        assert [c['A_adjust_B'],c['B_adjust_B']]==[ad,bd]and [c['A_address'],c['B_address']]==[hex(a),hex(b)]
        assert c['A_bytes_hex']==av.hex()and c['B_bytes_hex']==bv.hex()and c['selected_low8']==[x^bv[av[x]^xor]for x in range(256)]==[want]*256
        slot=0x1c81940+8*(bias+want);assert c['target_row']==s.decoded[slot]and c['target_row']['target']==hex(target)
        assert [c['xor_u8'],c['index_bias'],c['index_u32'],c['dispatch_base']]==list(map(hex,[xor,bias,bias+want,0x1c81940]))
        assert c['conditional_on_original_cached_roots_and_dispatch_base']and not c['whole_function_executed_to_call']
        bankchecks.append({'callsite':c['callsite'],'inputs_checked':256,'selected_low8':hex(want),'slot':hex(slot),'target':hex(target)})
    bank_lifts=[lift_bank(s,c,prove)for c in e['conditional_bank_contracts']]
    exact={0x224334:('adrp','x10, #0x1d07000'),0x224338:('add','x10, x10, #0x7d0'),0x22433c:('ldr','x22, [x10, #0x1648]'),
      0x224354:('ldr','x10, [x10]'),0x224358:('sub','x10, x10, #8'),0x224374:('add','w8, w9, w8, uxtb'),0x224378:('add','w8, w8, #0x17'),
      0x224380:('ldr','x8, [x23, w8, uxtw #3]'),0x224384:('sub','x0, x29, #0x88'),0x22438c:('blraa','x8, x17'),0x224390:('ldur','w26, [x29, #-0x68]'),
      0x2e48bc:('adrp','x9, #0x1d09000'),0x2e48c0:('add','x9, x9, #0xf68'),0x2e48c4:('mov','w10, #0xa788'),0x2e48cc:('ldr','x10, [x10]'),
      0x2e48d8:('mov','w11, #0xc8'),0x2e48e0:('ldr','x9, [x9]'),0x2e48e8:('ldurb','w9, [x9, #-8]'),
      0x2e48f8:('add','w8, w9, w8, uxtb'),0x2e48fc:('add','w8, w8, #0xb8'),0x2e4900:('ldr','x8, [x27, w8, uxtw #3]'),
      0x2e4904:('add','x0, sp, #0x78'),0x2e490c:('blraa','x8, x17'),
      0x4badd4:('adrp','x9, #0x1d09000'),0x4badd8:('add','x9, x9, #0xf68'),0x4bade0:('add','x10, x9, x10'),
      0x4bae10:('add','w8, w9, w8, uxtb'),0x4bae14:('add','w8, w8, #0x43'),0x4bae18:('ldr','x8, [x25, w8, uxtw #3]'),
      0x4bae1c:('add','x0, sp, #0x50'),0x4bae24:('blraa','x8, x17'),0x4bae28:('ldr','w21, [sp, #0x70]'),
      0x1ca540:('ldr','x8, [x8, w9, uxtw #3]'),0x1ca548:('ldr','w0, [x8]'),0x1ca578:('add','w2, w27, w8'),
      0x1ca58c:('add','x1, sp, #0x10'),0x1ca590:('mov','w3, #1'),0x1ca594:('mov','x17, #0x6764'),0x1ca598:('blraa','x8, x17'),
      0x2e4ed0:('str','w28, [x8, #0x18]'),0x2e42cc:('mov','w16, #0x6167'),0x2e42d0:('movk','w16, #0x126, lsl #16'),
      0x2e43b0:('mov','x10, #0x2410'),0x2e43b4:('movk','x10, #0xc276, lsl #16'),0x2e43c0:('and','w11, w0, w10'),
      0x2e43c4:('add','w10, w0, w10'),0x2e43c8:('sub','w10, w10, w11, lsl #1'),0x2e43cc:('mov','w11, #0xfaea'),
      0x2e43d0:('movk','w11, #0x84f, lsl #16'),0x2e43d4:('eor','w10, w10, w11'),0x2e43d8:('mul','w10, w10, w16'),
      0x2e43dc:('ldr','w11, [x0]'),0x2e43e0:('eor','w21, w11, w10'),0x2e43e4:('ldp','x25, x26, [x0, #8]'),
      0x2e43ec:('ldr','w11, [x0, #0x1c]'),0x2e43f0:('eor','w10, w11, w10')}
    for at,want in exact.items():i=next(CS.disasm(s.read(at,4),at));assert (i.mnemonic,i.op_str)==want,(hex(at),i.mnemonic,i.op_str,want)
    census=e['ingress_literal_census'];text=next(v for v in s.meta['sections']if v['section']=='__text');lo=text['address'];raw=s.read(lo,text['size']);hits=[]
    for at in range(0,len(raw)-4,4):
        if struct.unpack_from('<I',raw,at)[0]!=(0xd2800000|(0x6073<<5)|17):continue
        ins=next(CS.disasm(raw[at+4:at+8],lo+at+4))
        if ins.mnemonic not in ['braa','blraa']:continue
        ix=bisect.bisect_right(s.starts,lo+at)-1
        hits.append({'modifier_site':hex(lo+at),'callsite':hex(lo+at+4),'bytes_hex':raw[at:at+8].hex(),
          'function_start':hex(s.starts[ix]),'function_end':hex(s.starts[ix+1])})
    assert census['candidates']==hits and len(hits)==20 and census['text_sha256']==SHA(raw)and census['text_size_B']==len(raw)and census['text_address']==hex(lo)
    assert e['same_diversity_rebase_rows']==[s.decoded[x]for x in [0x1d03a98,0x1d03c60,0x1d03e60,0x1d03f20]]
    return {'proofs':proofs,'alignment_counterexamples':counterexamples,'callers':callers,'lifted_sites_checked':total_sites,
      'prior_ingress_source_contracts_rechecked':prior,'numeric_scalar_oracles':scalars,'conditional_bank_checks':bankchecks,
      'original_bank_lifts':bank_lifts,'bank_lifted_sites_checked':sum(len(v['original_sites'])for v in bank_lifts),
      'exact_instructions_checked':len(exact),'literal_candidates_checked':20,'literal_candidates_not_locally_classified':16,
      'local_ingress_targets':3,'distinct_same_diversity_targets':4,'native_target_executed':False}


def main():
    e=json.loads(read(ROOT/'corefp_ingress_callers_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_ingress_callers.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_base_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()]
    auth=next(v for v in s.meta['sections']if v['section']=='__auth_stubs')
    for f in e['source_spans']:
        a,b=int(f['start'],16),int(f['end'],16)
        if 'kind'in f:assert f['kind']=='complete_import_stub_16B'and b-a==16 and (a-auth['address'])%16==0 and f['bytes']==s.read(a,16).hex()and f['sha256']==SHA(s.read(a,16))
        else:assert f==s.function(a)
    totals=Counter();oracles=[]
    for index,p in enumerate(e['profiles']):
        c=p['configuration'];cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(J);cpu['X31'][1]='0x63000e00';cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        assert e['profile_caller_inputs'][index]==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in caller_inputs(s,c)]
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            for address,raw in parent_inputs()+caller_inputs(s,c):
                if a<=address<address+len(raw)<=a+4096:b[address-a:address-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b),(c['label'],hex(a));totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p,replay,s))
    assert [p['configuration']['label']for p in e['profiles']]==['metadata_null','first_pointer_null','second_pointer_null','both_pointers_null',
      'vm_frontier','scalar_4096','task_zero','caller_clobber','metadata_fill_a5']
    counts={'profiles':len(e['profiles']),'complete_early_returns':sum(p['frontier']['reason']=='parent_return'for p in e['profiles']),
      'vm_frontiers':sum(p['frontier']['reason']=='before_vm_allocate'for p in e['profiles']),
      **{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','caller_points']},
      'metadata_allocation_attempts':sum(p['metadata_allocation_attempts']for p in e['profiles'])};assert counts==e['verified_counts']
    source=source_checks(s,e)
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),
      'client_source_spans':len(e['source_spans']),'client_source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),
      'source_queries_unsat':len(source['proofs']),'alignment_controls_sat':len(source['alignment_counterexamples']),
      'lifted_original_sites_checked':source['lifted_sites_checked'],'prior_ingress_queries_rechecked':len(source['prior_ingress_source_contracts_rechecked']['proofs']),
      'bank_lifted_original_sites_checked':source['bank_lifted_sites_checked'],
      'conditional_banks_exhaustive_inputs_checked':1024,'numeric_scalar_oracles_checked':5,'literal_candidates_checked':20,
      'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_ingress_callers_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_contract_modules':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_root_ingress.py','corefp_root_ingress_checks.json',
        'audit_corefp_lookup_release.py','audit_corefp_cold_metadata.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_contracts':source,'semantic_annotations_used_as_proof':False,'full_daemon_CPU_RAM_replayed':False,
      'fresh_replay_completed':True,'process_exit_code':0,'full_goal_complete':False}
    (ROOT/'corefp_ingress_callers_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
