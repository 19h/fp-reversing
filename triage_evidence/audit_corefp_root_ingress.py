#!/usr/bin/env python3
"""Independent coherent ingress replay, original-instruction lift and ABI oracle.

No import of this increment's producer. Initial CPU/RAM, all retained client
transitions/accesses/models and final RAM are independently checked. Conditional
bank results are separate from complete caller executions and native evidence.
O(C*(B+P*F+V*J+R)) time/space upper bound; 30000 visits, 30 s/query.
"""
import bisect,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from capstone.arm64_const import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM
from audit_corefp_lookup_release import Replay as Frozen,parent_inputs,frame,unpack,CS
from audit_corefp_lookup_initialization import initial_page,declared_inputs
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M32=(1<<32)-1;M64=(1<<64)-1
ENTRY=0x5f4584;INGRESS=0x63000800;DATA=0x63000900;AUX=0x63000c00;DONE=0x65000000;HEAP=0x64000000


def ingress_inputs(c):
    p=INGRESS;mix=(((p|0xfd215347)+0x02deacb8-(p|0x02deacb8))&M32)^0x2435fd1a;k=mix*0x08c5d407&M32
    u=((1<<32)-0x30f52b5f)*pow(0x59529999,-1,1<<32)&M32
    b=bytearray(b'\xa5'*48);b[:4]=((0xc1f7-k-0x513c5990)&M32).to_bytes(4,'little');b[8:16]=AUX.to_bytes(8,'little')
    b[16:20]=((u+k)&M32).to_bytes(4,'little');b[20:24]=((int(c['scalar_u32'],16)-k)&M32).to_bytes(4,'little');b[24:32]=DATA.to_bytes(8,'little')
    return [(INGRESS,bytes(b))]


def field_transform(v):
    t=(v*0x2dd4c139+0x31f01626)&M32;out=t^0x1b8e4fe2
    for xor,add in [(0x49b63a0a,0xc1154c69),(0xa377af8e,0x2bd4d9ed),(0xa26243c6,0x2ac135a5),(0x3fff5fdf,0xb75c29be)]:out^=((t^xor)+add)&M32
    return out&M32


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans,s);self.gi=0;self.root_record=self.outer_word=self.inner_word=None
        if p['configuration']['kind']=='other_adapter_prefix':
            # Fetch backing permits the code hook to stop before this callee's
            # first instruction. Its body is not added to the executed spans.
            at=BASE+0x779ff0;page=at&~4095
            if not any(lo<=page<=hi for lo,hi,_ in self.u.mem_regions()):self.u.mem_map(page,4096)
            self.u.mem_write(at,s.read(0x779ff0,4))
    def ingress_point(self,label):
        want={'label':label,'CPU':frame(self.u),'ingress_record48_hex':self.ram(INGRESS,48).hex(),
          'root_record_address':None if self.root_record is None else hex(self.root_record),
          'root_record40_hex':None if self.root_record is None else self.ram(self.root_record,40).hex(),
          'adapter_word_address':None if self.outer_word is None else hex(self.outer_word),
          'adapter_word_u64':None if self.outer_word is None else hex(int.from_bytes(self.ram(self.outer_word,8),'little')),
          'internal_word_address':None if self.inner_word is None else hex(self.inner_word),
          'internal_word_u64':None if self.inner_word is None else hex(int.from_bytes(self.ram(self.inner_word,8),'little')),'visits_so_far':self.v}
        assert want==self.p['ingress_points'][self.gi];self.gi+=1
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE
        if at==0x5f48c0:self.root_record=u.reg_read(A.UC_ARM64_REG_X0);self.outer_word=u.reg_read(A.UC_ARM64_REG_X1);self.ingress_point('before_adapter_call')
        if at==0x8fd1b8:self.inner_word=u.reg_read(A.UC_ARM64_REG_X1);self.ingress_point('before_root_call')
        if at in [0x8e81c8,0x8fd1bc,0x5f48c4,0x5f48d8]:self.ingress_point({0x8e81c8:'root_entry',0x8fd1bc:'root_return',0x5f48c4:'adapter_return',0x5f48d8:'before_ingress_result_store'}[at])
        if self.p['configuration']['kind']=='other_adapter_prefix'and at==0x77d398:self.ingress_point('before_other_callee_call')
        if self.p['configuration']['kind']=='other_adapter_prefix'and at==0x779ff0:
            self.ingress_point('before_other_callee_body');assert self.p['frontier']=={'reason':'before_other_callee_body','CPU':frame(u)}
            self.done=True;u.emu_stop();return
        if pc==DONE:self.ingress_point('outer_return')
        return super().code(u,pc,n,d)
    def run(self):
        complete=self.p['configuration']['kind']=='complete_ingress';entry=ENTRY if complete else 0x77d190
        self.u.emu_start(BASE+entry,0,count=30001);self.flush();assert self.done and not self.once
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.hi,self.li,self.mri,self.di,self.gi,self.bi,self.cert]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','handoffs','lock_events','metadata_returns','daemon_children','ingress_points']]+[self.p['bootstrap_calls'],self.p['certificate_allocation_attempts']]
        assert self.allocs==self.p['allocations_attempted']==(2 if complete else 0)and self.snapshot('frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,'points_checked':self.pi,
          'handoffs_checked':self.hi,'lock_events_checked':self.li,'metadata_returns_checked':self.mri,'daemon_children_fresh_checked':self.di,
          'ingress_points_checked':self.gi,'bootstrap_calls_checked':self.bi,'certificate_allocation_attempts_checked':self.cert,
          'outer_returns_checked':int(complete),'other_callee_frontiers_checked':int(not complete),'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,s):
    c=p['configuration'];label=c['label'];v=int(c['scalar_u32'],16);before=ingress_inputs(c)[0][1];pts=p['ingress_points']
    if c['kind']=='other_adapter_prefix':
        assert label=='other_adapter_prefix'and len(pts)==2 and [x['label']for x in pts]==['before_other_callee_call','before_other_callee_body']
        assert pts[0]['CPU']['X31'][8]==hex(BASE+0x779ff0)and pts[1]['CPU']['PC']==hex(BASE+0x779ff0)
        assert p['parent_return']is None and not p['models']and not p['handoffs']and not p['lock_events']and not p['daemon_children']
        assert len(p['PAC_models'])==1 and p['PAC_models'][0]['pc']=='0x77d398'and p['PAC_models'][0]['pointer_row']['address']=='0x1d05158'
        assert all(x['ingress_record48_hex']==before.hex()for x in pts)and p['visits'][-1]['pc']=='0x77d398'
        return {'label':label,'kind':c['kind'],'target':'0x779ff0','pointer_slot':'0x1d05158','callee_body_executed':False,'native_target_executed':False}
    assert c['kind']=='complete_ingress'and [x['label']for x in pts]==['before_adapter_call','before_root_call','root_entry','root_return','adapter_return','before_ingress_result_store','outer_return']
    failed=label in ['lookup_error','fallback_error'];status=0x45e2a2e3 if failed else 0x45e2a20f
    assert c['allocation_success']==[label!='static_null',True]and c['lock_init_status_u32']==[0,0]
    assert c['unlock_status_u32']==(5 if label=='unlock_error'else 0)and bool(c.get('clobber_callers'))==(label=='clobber_null')
    seq=[(5,None)]if label=='lookup_error'else [(1102,None),(5,None)]if label=='fallback_error'else [(1102,None),(0,0x5034)]if label=='fallback_null'else [(0,0x5017)]
    assert c['bootstrap_results']==[{'status_u32':a,**({'write_port_u32':b}if b is not None else {})}for a,b in seq]
    sp=int(p['initial_CPU']['SP'],16);r=sp-0x50;outer=sp-0x60;k=((r^0x84b771aed97ffe38)*0xfcf33521)&M32
    record=bytearray(b'\xa5'*40);record[8:16]=DATA.to_bytes(8,'little');record[16:20]=((field_transform(v)-k)&M32).to_bytes(4,'little')
    record[20:24]=((k+0xc1f7)&M32).to_bytes(4,'little');record[24:28]=k.to_bytes(4,'little');record[32:40]=AUX.to_bytes(8,'little')
    assert all(x['root_record_address']==hex(r)and x['adapter_word_address']==hex(outer)for x in pts)
    assert all(x['root_record40_hex']==bytes(record).hex()for x in pts[:3]);record[:4]=status.to_bytes(4,'little')
    assert all(x['root_record40_hex']==bytes(record).hex()for x in pts[3:])
    seed=int.from_bytes(s.read(0x1d435b0,8),'little');assert seed==0x94a2bbf66116513d
    assert [x['adapter_word_u64']for x in pts]==[hex(seed)]*4+['0x0']*3
    inner=outer-64-16*(1+(((seed*0x2edd+1)&M64)>>60))
    assert pts[0]['internal_word_address']is None and all(x['internal_word_address']==hex(inner)for x in pts[1:])
    assert [x['internal_word_u64']for x in pts[1:]]==[hex((seed-256)&M64)]*2+[hex(seed)]*4
    expected=bytearray(before);expected[32:36]=status.to_bytes(4,'little')
    assert [x['ingress_record48_hex']for x in pts]==[before.hex()]*6+[bytes(expected).hex()]
    assert pts[0]['CPU']['X31'][:2]==[hex(r),hex(outer)]and pts[2]['CPU']['X31'][:2]==[hex(r),hex(inner)]
    assert pts[5]['CPU']['SP']==hex(outer)and pts[5]['CPU']['X31'][8]==hex(status)
    assert pts[-1]['CPU']['SP']==p['initial_CPU']['SP']and pts[-1]['CPU']['X31'][19:31]==p['initial_CPU']['X31'][19:31]
    assert all(x['CPU']['X31'][0]==hex(c['unlock_status_u32'])for x in pts[3:])
    assert p['parent_return']['parent_record48_hex']==bytes(expected).hex()
    for pac,pc,slot,target,mod in [(p['PAC_models'][0],'0x5f48c0','0x1d04e20',0x8fcfa0,'0x281b'),(p['PAC_models'][1],'0x8fd1b8','0x1d05150',0x8e81c8,'0x41d4')]:
        assert pac['pc']==pc and pac['pointer_row']['address']==slot and pac['target']==hex(BASE+target)and pac['modifier']==mod
    origin=[x for x in p['reads']if p['visits'][x['visit']]['pc']=='0x5f4830'];assert len(origin)==1 and origin[0]['address']==hex(BASE+0x1d435b0)and origin[0]['bytes_hex']==seed.to_bytes(8,'little').hex()
    assert not any(w['visit']<origin[0]['visit']and int(w['address'],16)<BASE+0x1d435b8 and BASE+0x1d435b0<int(w['address'],16)+w['size_B']for w in p['writes'])
    writes=[w for w in p['writes']if int(w['address'],16)<INGRESS+48 and INGRESS<int(w['address'],16)+w['size_B']]
    assert len(writes)==1 and writes[0]['address']==hex(INGRESS+32)and writes[0]['size_B']==4 and p['visits'][writes[0]['visit']]['pc']=='0x5f48d8'
    lock=BASE+0x1d27bf0 if label=='static_null'else HEAP
    assert [x['pointer']for x in p['lock_events']]==[hex(lock)]*2 and p['parent_return']['held_lock_model']==(hex(lock)if c['unlock_status_u32']else None)
    assert p['certificate_allocation_attempts']==int(not failed)and len(p['daemon_children'])==int(label not in ['fallback_null','lookup_error','fallback_error'])
    return {'label':label,'kind':c['kind'],'root_record':hex(r),'input_scalar_u32':hex(v),'decoded_root_field16_u32':hex(field_transform(v)),
      'decoded_root_operation_u32':'0xc1f7','decoded_root_mode_u32':'0x0','source_seed_cell':'0x1d435b0','source_seed_u64':hex(seed),
      'adapter_output_u64':'0x0','SP_after_dynamic_adjustment':hex(outer),'ingress_output_offset_B':32,'ingress_output_u32':hex(status),
      'residual_X0_u64':hex(c['unlock_status_u32']),'root_record_patched':False,'native_target_executed':False}


def lifted_fields(s):
    """Strict lift of both arithmetic slices and their four ingress loads.

    Memory bindings are declared symbolic ingress fields. Every lifted site
    is original; unrecognized instructions or memory accesses fail closed.
    """
    CS.detail=True;p,r=z3.BitVecs('ingress_address64 root_address64',64)
    q0,q16,q20=z3.BitVecs('raw0_u32 raw16_u32 raw20_u32',32);ptr8,ptr24=z3.BitVecs('pointer8_u64 pointer24_u64',64)
    ki,kr=z3.BitVecs('verified_ingress_key32 verified_root_key32',32)
    rf={'x19':p,'x0':p,'sp':r-16};stores={};sites=[];checkpoints={};loads=[]
    def reg(name):
        if name in ['xzr','wzr']:return z3.BitVecVal(0,32 if name[0]=='w'else 64)
        key='x'+name[1:]if name.startswith('w')else name;assert key in rf,(name,'undefined register')
        return z3.Extract(31,0,rf[key])if name.startswith('w')else rf[key]
    def put(name,value):
        width=32 if name.startswith('w')else 64;assert value.size()==width,(name,value.size())
        rf['x'+name[1:]if name.startswith('w')else name]=z3.ZeroExt(32,value)if width==32 else value
    def val(op,width):
        if op.type==ARM64_OP_REG:out=reg(CS.reg_name(op.reg))
        else:assert op.type==ARM64_OP_IMM;out=z3.BitVecVal(op.imm,width)
        assert out.size()==width
        if op.shift.value:out=out<<op.shift.value
        return out
    def address(op):
        assert op.type==ARM64_OP_MEM and not op.mem.index
        return reg(CS.reg_name(op.mem.base))+op.mem.disp
    def read_at(a,width):
        off=z3.simplify(a-p);assert z3.is_bv_value(off);off=off.as_long();key=(off,width)
        bindings={(0,32):q0,(16,32):q16,(20,32):q20,(8,64):ptr8,(24,64):ptr24};assert key in bindings,key
        loads.append({'ingress_offset_B':off,'width_bits':width});return bindings[key]
    def write_at(a,value):
        off=z3.simplify(a-r);assert z3.is_bv_value(off);off=off.as_long();assert off not in stores;stores[off]=value
    for lo,hi in [(0x5f4688,0x5f46c8),(0x5f46c8,0x5f47e8)]:
        for i in CS.disasm(s.read(lo,hi-lo),lo):
            sites.append({'address':hex(i.address),'bytes_hex':s.read(i.address,4).hex(),'instruction':i.mnemonic+' '+i.op_str})
            ops=i.operands;m=i.mnemonic;dst=CS.reg_name(ops[0].reg);w=32 if dst.startswith('w')else 64
            if m=='mov':put(dst,val(ops[1],w))
            elif m=='movk':
                shift=ops[1].shift.value;put(dst,(reg(dst)&z3.BitVecVal(~(0xffff<<shift),w))|z3.BitVecVal(ops[1].imm<<shift,w))
            elif m in ['add','sub','eor','orr','and','orn','mul','madd']:
                a,b=val(ops[1],w),val(ops[2],w)
                v={'add':lambda:a+b,'sub':lambda:a-b,'eor':lambda:a^b,'orr':lambda:a|b,'and':lambda:a&b,
                  'orn':lambda:a|~b,'mul':lambda:a*b,'madd':lambda:a*b+val(ops[3],w)}[m]();put(dst,v)
            elif m=='ldr':put(dst,read_at(address(ops[1]),w))
            elif m=='ldp':
                a=address(ops[2]);put(dst,read_at(a,w));put(CS.reg_name(ops[1].reg),read_at(a+w//8,w))
            elif m=='str':write_at(address(ops[1]),reg(dst))
            elif m=='stp':
                a=address(ops[2]);write_at(a,reg(dst));write_at(a+w//8,reg(CS.reg_name(ops[1].reg)))
            else:raise AssertionError((hex(i.address),m))
            if i.address in [0x5f46b8,0x5f46c4,0x5f47ac,0x5f47b8]:checkpoints[i.address]=reg('w15'if i.address<0x5f4700 else 'w3')
            # Proof cutpoints only: the two original computations are retained
            # above and proved independently before field theorems use them.
            if i.address==0x5f46c4:put('w15',ki)
            if i.address==0x5f47b8:put('w3',kr)
    return {'p':p,'r':r,'q0':q0,'q16':q16,'q20':q20,'ptr8':ptr8,'ptr24':ptr24,'stores':stores,'sites':sites,'loads':loads,'checkpoints':checkpoints,'Ki':ki,'Kr':kr}


def source_checks(s,e):
    lift=lifted_fields(s);p,r=lift['p'],lift['r'];q0,q16,q20=lift['q0'],lift['q16'],lift['q20'];low=lambda x:z3.Extract(31,0,x)
    ki=(low(p)^0xd914ae5d)*0x08c5d407;kr=(low(r)^0xd97ffe38)*0xfcf33521;kif,krf=lift['Ki'],lift['Kr'];v=q20+kif;t=v*0x2dd4c139+0x31f01626
    f=t^0x1b8e4fe2
    for x,a in [(0x49b63a0a,0xc1154c69),(0xa377af8e,0x2bd4d9ed),(0xa26243c6,0x2ac135a5),(0x3fff5fdf,0xb75c29be)]:f=f^((t^x)+a)
    cp=lift['checkpoints'];st=lift['stores'];proofs=[]
    def prove(label,left,right,assumptions=()):
        sol=z3.Solver();sol.set(timeout=30000);sol.add(*assumptions,left!=right);res=sol.check();assert res==z3.unsat,(label,res)
        proofs.append({'label':label,'query':sol.to_smt2(),'result':'unsat','uses_previously_proved_premixes':bool(assumptions)})
    premix_i=cp[0x5f46b8]==(low(p)^0xd914ae5d);premix_r=cp[0x5f47ac]==(low(r)^0xd97ffe38)
    prove('ingress_key_premix_all64',cp[0x5f46b8],low(p)^0xd914ae5d)
    prove('ingress_key_all64',cp[0x5f46c4],ki,(premix_i,))
    prove('root_key_premix_all64',cp[0x5f47ac],low(r)^0xd97ffe38)
    prove('root_key_all64',cp[0x5f47b8],kr,(premix_r,))
    prove('decoded_operation_all_fields',st[20]-krf,q0+kif+0x513c5990)
    prove('decoded_mode_all_fields',st[24]^krf,(q16-kif)*0x59529999+0x30f52b5f)
    prove('decoded_field16_exact_mixer_all_fields',st[16]+krf,f)
    prove('source_pointer24_to_root8',st[8],lift['ptr24'])
    prove('source_pointer8_to_root32',st[32],lift['ptr8'])
    mode=z3.BitVec('requested_root_mode32',32);inv=pow(0x59529999,-1,1<<32)
    prove('mode_preimage_all32',((mode-0x30f52b5f)*inv)*0x59529999+0x30f52b5f,mode)
    sp,delta=z3.BitVecs('caller_SP64 adapter_delta64',64)
    prove('postcall_result_read_address_all64',(sp+delta)+16,(sp+16)+delta)
    assert set(st)=={8,16,20,24,32}and lift['loads']==[{'ingress_offset_B':0,'width_bits':32},{'ingress_offset_B':16,'width_bits':32},
      {'ingress_offset_B':20,'width_bits':32},{'ingress_offset_B':8,'width_bits':64},{'ingress_offset_B':24,'width_bits':64}]
    bank_checks=[]
    for c,ap,ad,bp,bd,xor,bias,expected,target in zip(e['conditional_bank_contracts'],[0x1d10b08,0x1d09500],[-8,0],
      [0x1d09870,0x1d0b590],[0,-12],[0xa5,0x27],[0x1061e,0x1069b],[0xd6,0x18],[0x656b80,0x59fb30]):
        a=s.qword(ap)+ad;b=s.qword(bp)+bd;av=s.read(a,256);bv=s.read(b,256)
        assert c['A_pointer_row']==s.decoded[ap]and c['B_pointer_row']==s.decoded[bp]and c['A_adjust_B']==ad and c['B_adjust_B']==bd
        assert c['A_address']==hex(a)and c['B_address']==hex(b)and c['A_bytes_hex']==av.hex()and c['B_bytes_hex']==bv.hex()
        selected=[(j^bv[av[j]^xor])&255 for j in range(256)];assert selected==c['selected_low8']==[expected]*256
        slot=0x1c81940+8*(bias+expected);assert c['dispatch_base']=='0x1c81940'and c['index_bias']==hex(bias)and c['index_u32']==hex(bias+expected)
        assert c['xor_u8']==hex(xor)and c['target_row']==s.decoded[slot]and c['target_row']['target']==hex(target)
        bank_checks.append({'label':c['label'],'all_low8_inputs_checked':256,'constant_low8':hex(expected),'pointer_slot':hex(slot),'target':hex(target),
          'conditional_on_original_cached_roots_and_dispatch_base':True,'whole_function_executed':False})
    exact={0x5f47c0:('str','x2, [sp, #0x18]'),0x5f47dc:('str','w17, [sp, #0x20]'),0x5f47e0:('stp','w15, w0, [sp, #0x24]'),0x5f47e4:('str','x1, [sp, #0x30]'),
      0x5f4830:('ldr','x15, [x15]'),0x5f4834:('str','x15, [sp]'),0x5f48b0:('ldur','x8, [x8, #-4]'),0x5f48b4:('add','x0, sp, #0x10'),
      0x5f48b8:('mov','x1, sp'),0x5f48c0:('blraa','x8, x17'),0x5f48c8:('ldr','x9, [sp]'),0x5f48cc:('add','x8, x8, x9'),0x5f48d0:('mov','sp, x8'),
      0x5f48d4:('ldr','w8, [sp, #0x10]'),0x5f48d8:('str','w8, [x19, #0x20]'),0x9d374c:('str','x12, [sp, #0xf8]'),
      0x9d3750:('ldr','x30, [x10]'),0x9d3938:('str','x30, [sp, #0xb8]'),0x9d3f5c:('ldr','x2, [sp, #0xb8]'),
      0x9d4030:('ldr','x10, [sp, #0xf8]'),0x9d4044:('ldrb','w10, [x2, w10, uxtw]'),0x9d4058:('ldr','x8, [x26, w8, uxtw #3]'),
      0x1173d90:('ldr','x26, [x21, #0x3560]'),0x1173da4:('ldr','x11, [x21, #0x55f0]'),0x1173da8:('sub','x24, x11, #0xc'),
      0x1173ebc:('str','x24, [sp, #8]'),0x11741e4:('add','x11, x26, w10, uxtb'),0x11741f4:('ldr','x12, [sp, #8]'),
      0x11741f8:('ldrb','w11, [x12, w11, uxtw]'),0x1174218:('ldr','x8, [x27, w8, uxtw #3]')}
    exact.update({0x9d373c:('adrp','x10, #0x1d09000'),0x9d3740:('add','x10, x10, #0x870'),
      0x9d3744:('ldr','x12, [x10, #0x7298]'),0x9d3748:('sub','x12, x12, #8'),0x9d3f50:('mov','w0, #0x30b'),
      0x9d3f54:('movk','w0, #1, lsl #16'),0x9d4038:('ldrb','w10, [x10]'),0x9d403c:('mov','w11, #0xa5'),
      0x9d4040:('eor','w10, w10, w11'),0x9d404c:('eor','w8, w9, w10'),0x9d4050:('add','w8, w0, w8, uxtb'),
      0x9d4054:('add','w8, w8, #0x313'),0x11741e8:('ldrb','w11, [x11]'),0x11741ec:('mov','w25, #0x27'),
      0x11741f0:('eor','w11, w11, w25'),0x1174204:('eor','w8, w10, w11'),0x1174208:('mov','w9, #0x325'),
      0x117420c:('movk','w9, #1, lsl #16'),0x1174210:('add','w8, w9, w8, uxtb'),0x1174214:('add','w8, w8, #0x376')})
    for a,want in exact.items():i=next(CS.disasm(s.read(a,4),a));assert (i.mnemonic,i.op_str)==want
    census=e['adapter_literal_census'];text=next(v for v in s.meta['sections']if v['section']=='__text');raw=s.read(text['address'],text['size']);sites=[]
    for off in range(0,len(raw)-4,4):
        word=int.from_bytes(raw[off:off+4],'little')
        if word&0xffe0001f!=0xd2800011 or (word>>5)&65535!=0x281b:continue
        at=text['address']+off;i=next(CS.disasm(raw[off+4:off+8],at+4))
        if i.mnemonic not in ['braa','blraa']:continue
        j=bisect.bisect_right(s.starts,at)-1;sites.append({'modifier_site':hex(at),'callsite':hex(at+4),'bytes_hex':raw[off:off+8].hex(),'function_start':hex(s.starts[j]),'function_end':hex(s.starts[j+1])})
    assert census['candidates']==sites and len(sites)==12 and census['text_sha256']==SHA(raw)and census['text_size_B']==len(raw)
    return {'proofs':proofs,'lifted_original_sites':lift['sites'],'lifted_sites_checked':len(lift['sites']),'ingress_load_bindings':lift['loads'],
      'symbolic_key_cutpoints':[{'after_address':'0x5f46c4','symbol':'verified_ingress_key32','validated_by':'ingress_key_all64'},
        {'after_address':'0x5f47b8','symbol':'verified_root_key32','validated_by':'root_key_all64'}],
      'field_theorems_quantify_independent_u32_keys':True,'runtime_frames_restored_for_symbolic_cuts':False,
      'monolithic_trial_not_a_certificate':{'query_label':'decoded_operation_all_fields','timeout_ms':30000,'result':'unknown'},
      'exact_instructions_checked':len(exact),'conditional_bank_checks':bank_checks,'adapter_literal_candidates_checked':len(sites),
      'remaining_adapter_call_candidates_unresolved':11,'field16_mixer_semantic_name':'unknown'}


def main():
    e=json.loads(read(ROOT/'corefp_root_ingress_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_root_ingress.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_base_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()]
    auth=next(r for r in s.meta['sections']if r['section']=='__auth_stubs')
    for f in e['source_spans']:
        a,b=int(f['start'],16),int(f['end'],16)
        if 'kind'in f:assert f['kind']=='complete_import_stub_16B'and b-a==16 and (a-auth['address'])%16==0 and f['bytes']==s.read(a,16).hex()and f['sha256']==SHA(s.read(a,16))
        else:assert f==s.function(a)
    totals=Counter();oracles=[]
    for index,p in enumerate(e['profiles']):
        c=p['configuration'];entry=ENTRY if c['kind']=='complete_ingress'else 0x77d190
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(0x62018000+c['stack_delta_B']),'PC':hex(BASE+entry),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(INGRESS);cpu['X31'][1]='0x63000e00';cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        assert e['profile_ingress_inputs'][index]==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ingress_inputs(c)]
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            for addr,raw in parent_inputs()+ingress_inputs(c):
                if a<=addr<addr+len(raw)<=a+4096:b[addr-a:addr-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b);totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p,s))
    labels=[p['configuration']['label']for p in e['profiles']]
    assert labels==['primary_null','fallback_null','static_null','clobber_null','unlock_error','lookup_error','fallback_error',
      'scalar_one','scalar_max','scalar_a5','stack_plus16','stack_minus16','other_adapter_prefix']
    assert [int(p['configuration']['scalar_u32'],16)for p in e['profiles']]==[0]*7+[1,M32,0xa5a5a5a5,0,0,0]
    assert [p['configuration']['stack_delta_B']for p in e['profiles']]==[0]*10+[16,-16,0]
    counts={'profiles':len(e['profiles']),'complete_ingress_returns':12,'other_adapter_prefixes':1,
      **{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','ingress_points']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in e['profiles']),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in e['profiles'])};assert counts==e['verified_counts']
    assert e['adapter_reference_rows']==[s.decoded[0x1d04e20]]and e['ingress_reference_rows']==[s.decoded[0x1d03c60]]
    source=source_checks(s,e)
    d=json.loads(read(ROOT/'corefp_root_ingress_ida.json'));assert d['target']=='c3d025e56a86'and not d['IDB_mutated']and not d['native_target_executed']
    attempt=d['bytes_attempt'];assert attempt['isError']and attempt['tool_may_have_run']and not attempt['response_bytes_available']and not attempt['repeated']
    assert 'connection closed'in attempt['error']and len(d['recalls'])==2 and all(v['count']==0 and not v['truncated']for v in d['recalls'])
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),
      'client_source_spans':len(e['source_spans']),'client_source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),
      'lifted_original_sites_checked':source['lifted_sites_checked'],'source_queries_unsat':len(source['proofs']),'exact_instructions_checked':source['exact_instructions_checked'],
      'conditional_banks_exhaustive_inputs_checked':sum(v['all_low8_inputs_checked']for v in source['conditional_bank_checks']),
      'adapter_literal_candidates':12,'adapter_literal_candidates_unresolved':11,'live_source_B_checked':0,'IDA_byte_read_connection_closed':True,
      'daemon_source_visits_fresh_checked':sum(len(c['visited_original_instructions'])for p in e['profiles']for c in p['daemon_children']),
      'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_root_ingress_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_attempt_sha256':SHA(read(ROOT/'corefp_root_ingress_ida.json').encode()),'dependencies':e['dependencies'],
      'frozen_contract_modules':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_lookup_release.py','audit_corefp_cold_metadata.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_contracts':source,'semantic_annotations_used_as_proof':False,'full_daemon_CPU_RAM_replayed':False,
      'nonexecuted_frontier_fetch_backing':{'address':'0x779ff0','size_B':4,'bytes_hex':s.read(0x779ff0,4).hex(),'instruction_executed':False},
      'fresh_replay_completed':True,'process_exit_code':0,'full_goal_complete':False}
    (ROOT/'corefp_root_ingress_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
