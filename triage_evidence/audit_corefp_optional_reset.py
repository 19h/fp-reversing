#!/usr/bin/env python3
"""Independent reset replay, initial-state reconstruction and slot byte oracle.

Does not import this increment's producer. O(C*(B+P*F+V*J+R)+256*K)
conservative time/space with 4000 visits/profile, K=8 banks; SMT separate,
30 s/query. No native target/API/IPC or IDB operation.
"""
import copy,json,struct,subprocess
from collections import Counter
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from audit_corefp_lookup_initialization import Replay as Frozen,initial_page,declared_inputs,frame,restore,unpack,ret,CS
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
ENTRY=0x1f530c;REC=0x63000100;HEAP=0x64000000;DONE=0x65000000;SP=0x62018000
TOKEN=0x1d33108;SELECTOR=0x1d44409;COUNT=0x1d36090;SLOTS=0x1d32dd0
POINTS={0x1f5594:'selector_read',0x1f55a4:'selector_compare',0x1f57c4:'slot_pointer_read',0x1f5688:'common_reset',0x1f5650:'selector_clear',0x1f5664:'token_restore'}


def config(label):
    rows={'original_selector_zero':{},'selector_two':{'selector_u8':2},'selector_255':{'selector_u8':255},
      'empty':{'selector_u8':1,'count_u32':0,'slot_kinds':[]},'one_null':{'selector_u8':1,'count_u32':1,'slot_kinds':['null']},
      'three_null':{'selector_u8':1,'count_u32':3,'slot_kinds':['null']*3},
      'one_backed':{'selector_u8':1,'count_u32':1,'slot_kinds':['backed']},
      'backed_clobber':{'selector_u8':1,'count_u32':1,'slot_kinds':['backed'],'clobber_callers':True,'void_free_x0':0xfeedfacecafebeef},
      'mixed_three':{'selector_u8':1,'count_u32':3,'slot_kinds':['null','backed','backed']},
      'original_slot_free_frontier':{'selector_u8':1},'busy_token':{'token_u32':0xa94ef}}
    return {'label':label,**rows[label]}


def overlay(c):
    low=REC&0xffffffff;key=((((low|0x89102e99)-(low&0x89102e99))^0xbd0dee28)*0xdb676c6f)&0xffffffff
    out=[(REC,struct.pack('<I',key^0xf7a5))]
    for k,a,n in [('selector_u8',SELECTOR,1),('count_u32',COUNT,4),('token_u32',TOKEN,4)]:
        if k in c:out.append((BASE+a,c[k].to_bytes(n,'little')))
    for j,kind in enumerate(c.get('slot_kinds',[])):
        ptr=HEAP+256+128*j if kind=='backed'else 0;b=bytearray([49+j]*88);struct.pack_into('<Q',b,8,ptr);out.append((BASE+SLOTS+88*j,bytes(b)))
        if ptr:out.append((ptr,bytes([83+j])*64))
    return out


def snapshot(r,label):
    return {'label':label,'CPU':frame(r.u),'record32_hex':r.ram(REC,32).hex(),'selector_u8':r.ram(BASE+SELECTOR,1)[0],
      'token_u32':int.from_bytes(r.ram(BASE+TOKEN,4),'little'),'count_u32':int.from_bytes(r.ram(BASE+COUNT,4),'little'),'slots264_hex':r.ram(BASE+SLOTS,264).hex()}


class Replay(Frozen):
    def __init__(self,*args):
        super().__init__(*args);self.attempts=0;self.frees=[]
        self.active={HEAP+256+128*j for j,k in enumerate(self.p['configuration'].get('slot_kinds',[]))if k=='backed'}
    def stop(self,reason,**extra):
        assert self.p['frontier']=={'reason':reason,'CPU':frame(self.u),**extra};self.done=True;self.u.emu_stop()
    def code(self,u,pc,n,d):
        self.flush();c=self.p['configuration']
        if pc==DONE:return self.stop('ordinary_return')
        if pc==BASE+0x1f54fc:
            if self.attempts:return self.stop('before_second_CASAL',concurrent_ordering_validated=False)
            b=self.ram(pc,4);ins=next(CS.disasm(b,0x1f54fc));assert (ins.mnemonic,ins.op_str)==('casal','w17, w14, [x26]')
            assert self.p['visits'][self.v]=={'pc':'0x1f54fc','bytes_hex':b.hex(),'instruction':'casal w17, w14, [x26]'};self.v+=1
            a=u.reg_read(A.UC_ARM64_REG_X26);old=int.from_bytes(self.ram(a,4),'little');cmp=u.reg_read(A.UC_ARM64_REG_W17);new=u.reg_read(A.UC_ARM64_REG_W14)
            assert a==BASE+TOKEN and cmp==0x5d96 and new==0xa94ef;self.attempts+=1;e=self.event()
            assert {k:e[k]for k in ['kind','visit','pointer','old_u32','compare_u32','replacement_u32','concurrent_ordering_validated']}=={
              'kind':'declared_sequential_CASAL','visit':self.v-1,'pointer':hex(a),'old_u32':old,'compare_u32':cmp,'replacement_u32':new,'concurrent_ordering_validated':False}
            self.effects(e,[(a,new.to_bytes(4,'little'))]if old==cmp else [])
            f=copy.deepcopy(e['before']);f['X31'][17]=hex(old);f['PC']=hex(pc+4);assert e['after']==f;restore(u,f);return
        if pc in self.imports:
            name=self.imports[pc];args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)]
            assert name=='_free'and u.reg_read(A.UC_ARM64_REG_LR)-4-BASE==0x1f5854
            if args[0]not in self.active:return self.stop('before_unbacked_free',name=name,callsite='0x1f5854',pointer=hex(args[0]),native_free_executed=False)
            e=self.event();assert e['kind']=='declared_API'and e['name']==name and e['callsite']=='0x1f5854'and e['args_x0_x7']==list(map(hex,args))
            assert e['private_backing64_hex']==self.ram(args[0],64).hex()and e['model']=='mark private allocation inactive; retain mapped bytes; no native free'
            value=c.get('void_free_x0',0);assert e['void_result_fixture']==hex(value);self.effects(e,[])
            self.active.remove(args[0]);self.frees.append(hex(args[0]));f=ret(e['before'],value,c.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        if pc-BASE in POINTS:self.point(snapshot(self,POINTS[pc-BASE]))
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=4001);self.flush();assert self.done and self.attempts==1
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points']]
        assert self.frees==self.p['private_free_pointers']and list(map(hex,sorted(self.active)))==self.p['private_active_pointers']
        assert snapshot(self,'frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'points_checked':self.pi,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,r,s):
    c=p['configuration'];label=c['label'];cleanup='slot_kinds'in c;front=p['frontier']['reason'];busy=label=='busy_token';raw=label=='original_slot_free_frontier'
    assert front==('before_second_CASAL'if busy else 'before_unbacked_free'if raw else 'ordinary_return')
    assert r.ram(BASE+SELECTOR,1)==bytes([0 if cleanup else c.get('selector_u8',0)])
    assert int.from_bytes(r.ram(BASE+TOKEN,4),'little')==(0xa94ef if busy or raw else 0x5d96)
    assert int.from_bytes(r.ram(BASE+COUNT,4),'little')==c.get('count_u32',1)
    before={int(v['address'],16):unpack(v['payload'])for v in p['initial_RAM']}
    initial=lambda a,n:before[a&~4095][a%4096:a%4096+n]
    assert r.ram(REC,32)==initial(REC,32)
    expected=bytearray(initial(BASE+SLOTS,264));slot_writes=[];freed=[]
    # Independent fixed byte layout: native semantic types remain unknown.
    fields=[(0,8,0x29acdb77),(0x10,4,0xfb394ce9),(0x14,4,0x3f74e630),(0x18,8,0x99960b5a),
      (0x20,4,0xeb152103),(0x24,4,0xcbc97b7d),(0x28,8,0x20a6b15dcc57f527),(0x30,8,0xeb20c546),
      (0x38,8,0x44710b16),(0x40,8,0x058aaa16),(0x48,8,0x0176cb4e),(0x50,8,0x6c426f1a)]
    for j,kind in enumerate(c.get('slot_kinds',[])):
        if kind=='backed':
            ptr=HEAP+256+128*j;freed.append(hex(ptr));assert r.ram(ptr,64)==bytes([83+j])*64
            expected[88*j+8:88*j+16]=(0x614a2fa7).to_bytes(8,'little')
        for off,n,v in fields:expected[88*j+off:88*j+off+n]=v.to_bytes(n,'little')
    assert r.ram(BASE+SLOTS,264)==expected and freed==p['private_free_pointers']
    slot_writes=[w for w in p['writes']if BASE+SLOTS<=int(w['address'],16)<BASE+SLOTS+264]
    assert sum(w['size_B']for w in slot_writes)==80*len(c.get('slot_kinds',[]))+8*len(freed)
    clears=[w for w in p['writes']if int(w['address'],16)==BASE+SELECTOR];assert len(clears)==int(cleanup)
    if clears:assert clears[0]['size_B']==1 and clears[0]['after_hex']=='00'and p['visits'][clears[0]['visit']]['pc']=='0x1f5650'
    restores=[w for w in p['writes']if int(w['address'],16)==BASE+TOKEN];assert len(restores)==int(not busy and not raw)
    if restores:assert restores[0]['size_B']==4 and restores[0]['after_hex']=='965d0000'and p['visits'][restores[0]['visit']]['pc']=='0x1f5664'
    reads=[x for x in p['reads']if p['visits'][x['visit']]['pc']=='0x1f57c4'];assert len(reads)==(1 if raw else len(c.get('slot_kinds',[])))
    for j,x in enumerate(reads):assert x['address']==hex(BASE+SLOTS+88*j+8)and x['size_B']==8
    if raw:assert p['frontier']['pointer']=='0x614a2fa7'and not p['private_free_pointers']
    compare=[v for v in p['points']if v['label']=='selector_compare']
    assert len(compare)==int(not busy)
    for v in compare:assert int(v['CPU']['X31'][14],16)==1 and int(v['CPU']['X31'][13],16)==c.get('selector_u8',0)
    for j,v in enumerate(x for x in p['points']if x['label']=='common_reset'):
        assert int(v['CPU']['X31'][28],16)==j and int(v['CPU']['X31'][24],16)==0x79b8
    if front=='ordinary_return':
        f=p['frontier']['CPU'];assert f['SP']==hex(SP)and f['X31'][19:]==p['initial_CPU']['X31'][19:]
    return {'label':label,'decoded_operation_u32':'0xf7a5','frontier':front,'slot_iterations':len(reads),'reset_slots':len(c.get('slot_kinds',[])),
      'common_reset_written_B':80*len(c.get('slot_kinds',[])),'post_free_written_B':8*len(freed),'free_pointers':freed,
      'selector_final_u8':r.ram(BASE+SELECTOR,1)[0],'token_final_u32':hex(int.from_bytes(r.ram(BASE+TOKEN,4),'little')),
      'record_unchanged':True,'native_ownership_established':False,'residual_X0_semantics':'unknown'}


def source_checks(s):
    pool=0x1d05fa0;a=0x18ac070;b=0x1ac18c0
    specs=[('state_first',a,b,0x58,0xbae,pool,0x1d353b8),('state_second',a,b,0x89,0x17aa,pool,0x1d37f68),
      ('dispatch_base',a,b,0x8c,0x1486,pool,0x1c81944),
      ('token',s.qword(pool+0xab68)-8,s.qword(pool+0x38d0),11,0xbd,pool,TOKEN),
      ('selector',s.qword(pool+0xe750),s.qword(pool+0x3fc8)-8,0xc8,0x131b,pool,SELECTOR),
      ('count',a,b,0x89,0xb38,pool,COUNT),
      ('slot',s.qword(pool+0x3560),s.qword(pool+0x55f0)-12,0x27,0x1a70,pool,SLOTS+8),
      ('free',s.qword(pool+0x3560),s.qword(pool+0x55f0)-12,0x27,0x1036e,0x1c81940,None)]
    banks=[]
    for label,aa,bb,c,bias,base,target in specs:
        t=s.read(aa,256);u=s.read(bb,256);out=[x^u[t[x]^c]for x in range(256)];assert len(set(out))==1
        row=base+8*(bias+out[0]);fix=s.decoded[row]
        if target is None:assert fix['bind']and fix['import']['name']=='_free'and fix['authenticated']and fix['key']=='IA'and fix['diversity']=='0x7c9f'
        else:assert not fix['bind']and int(fix['target'],16)==target
        banks.append({'label':label,'A':hex(aa),'B':hex(bb),'A256_hex':t.hex(),'B256_hex':u.hex(),'xor_u8':hex(c),
          'bias':hex(bias),'base':hex(base),'constant_u8':hex(out[0]),'enumerated_inputs':256,'pointer_row':fix})
    exact={0x1f5420:('orr','w14, w13, w0'),0x1f5424:('and','w13, w0, w13'),0x1f5430:('sub','w13, w14, w13'),
      0x1f5434:('eor','w13, w13, w15'),0x1f5440:('mul','w13, w13, w14'),0x1f5444:('ldr','w14, [x0]'),0x1f5448:('eor','w13, w14, w13'),
      0x1f54fc:('casal','w17, w14, [x26]'),0x1f5594:('ldrb','w13, [x16]'),0x1f55a4:('cmp','w13, w14'),
      0x1f5624:('ldr','w8, [x8]'),0x1f5630:('cmp','w8, w9'),0x1f5650:('strb','wzr, [x8]'),0x1f5664:('str','w8, [x26]'),
      0x1f5694:('mov','w12, #0x58'),0x1f5698:('mul','x12, x28, x12'),0x1f569c:('add','x13, x27, x12'),
      0x1f5744:('cmp','x28, w8, uxtw'),0x1f5748:('cset','w9, lo'),0x1f57b4:('sub','x27, x15, #8'),
      0x1f57c4:('ldr','x0, [x13, #8]!'),0x1f57c8:('cmp','x0, #0'),0x1f5854:('blraa','x8, x17'),0x1f586c:('str','x8, [x9]'),
      0x1f56a0:('add','w10, w24, w10'),0x1f56a4:('orr','w11, w10, w11'),0x1f572c:('add','w10, w24, w9'),
      0x1f5730:('add','x9, x28, x10'),0x1f5734:('mov','x12, #-0x2c89'),0x1f5738:('movk','x12, #0xfffe, lsl #16'),
      0x1f573c:('add','x9, x9, x11'),0x1f5740:('add','x28, x9, x12')}
    rows=[]
    for pc,pair in exact.items():
        raw=s.read(pc,4);i=next(CS.disasm(raw,pc));assert (i.mnemonic,i.op_str)==pair;rows.append({'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
    # Lift the complete literal common-reset block, respecting W-register zero
    # extension and STP element widths; compare independently specified fields.
    regs={};stores=[];instructions=list(CS.disasm(s.read(0x1f56a8,0x1f572c-0x1f56a8),0x1f56a8));assert len(instructions)==33
    for i in instructions:
        ops=i.operands
        if i.mnemonic in ['mov','movk']:
            rn=CS.reg_name(ops[0].reg);j=int(rn[1:]);bits=32 if rn[0]=='w'else 64;val=ops[1].imm&((1<<bits)-1);shift=ops[1].shift.value
            regs[j]=val if i.mnemonic=='mov'else((regs[j]&~(65535<<shift))|(val<<shift))&((1<<bits)-1)
        else:
            assert i.mnemonic in ['str','stp'];mem=ops[-1].mem;assert CS.reg_name(mem.base)=='x13';off=mem.disp
            for op in ops[:-1]:
                rn=CS.reg_name(op.reg);n=4 if rn[0]=='w'else 8;stores.append((off,n,regs[int(rn[1:])]));off+=n
    want=[(0,8,0x29acdb77),(16,4,0xfb394ce9),(20,4,0x3f74e630),(24,8,0x99960b5a),(32,4,0xeb152103),(36,4,0xcbc97b7d),
      (40,8,0x20a6b15dcc57f527),(48,8,0xeb20c546),(56,8,0x44710b16),(64,8,0x058aaa16),(72,8,0x0176cb4e),(80,8,0x6c426f1a)]
    assert stores==want and sum(n for _,n,_ in stores)==80
    x=z3.BitVec('record_low32',32);tag=z3.BitVec('raw_tag32',32)
    reduced=(x^0x341dc0b1)*0xdb676c6f
    proofs=[]
    # Prove before multiplication to avoid a nonlinear bit-blast timeout.
    # Equality of the 32-bit operands is preserved by the same u32 multiplier.
    index=z3.BitVec('slot_index64',64)
    increment=((0x79b8+0x6728)&0xffffffff)+(((0x79b8-0x6f10)&0xffffffff)|0x4102)+0xfffffffffffed377
    for label,left,right in [('OR_minus_AND',(x|0x89102e99)-(x&0x89102e99),x^0x89102e99),
      ('key_XOR_constant',(x^0x89102e99)^0xbd0dee28,x^0x341dc0b1),('tag_round_trip',(tag^reduced)^reduced,tag)]:
        q=z3.Solver();q.set(timeout=30000);q.add(left!=right);assert q.check()==z3.unsat;proofs.append({'label':label,'query':q.to_smt2(),'result':'unsat'})
    q=z3.Solver();q.set(timeout=30000);q.add(index+increment!=index+1);assert q.check()==z3.unsat
    proofs.append({'label':'loop_increment_at_observed_W24_79b8','query':q.to_smt2(),'result':'unsat','phase_W24':'0x79b8'})
    entry=s.decoded[0x1d04f48];assert entry['target']==hex(ENTRY)and entry['diversity']=='0x30ae'and entry['key']=='IA'
    operation=s.decoded[0x1c81940+8*0xf7a5];assert operation['target']=='0x1f54c0'and operation['diversity']=='0xeadc'
    # Section type, rather than segment file padding, defines selector startup.
    from resolve_kernel_collection_interfaces import commands
    sections=[]
    for at,cmd,n in commands(s.data,0):
        if cmd!=0x19:continue
        for j in range(struct.unpack_from('<I',s.data,at+64)[0]):
            off=at+72+80*j;name,seg,addr,size,fo,al,rel,nrel,flags,r1,r2,r3=struct.unpack_from('<16s16sQQ8I',s.data,off)
            if addr<=SELECTOR<addr+size:
                sections.append({'segment':seg.rstrip(b'\0').decode(),'section':name.rstrip(b'\0').decode(),'address':hex(addr),'size_B':size,'file_offset':fo,'flags':hex(flags)})
    assert len(sections)==1 and sections[0]['section']=='__common'and int(sections[0]['flags'],16)&255==1
    assert s.read(SLOTS+8,8)==(0x614a2fa7).to_bytes(8,'little')and s.read(SLOTS+72,8)==(0x176cb4e3).to_bytes(8,'little')
    refs=[]
    for pc in [0x8eadf8,0x8eadfc]:
        raw=s.read(pc,4);i=next(CS.disasm(raw,pc));refs.append({'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
    assert [v['instruction']for v in refs]==['ldr x15, [sp, #0x450]','ldr x15, [x15, #0x48]']
    return {'banks':banks,'bank_inputs_checked':2048,'exact_instructions':rows,'common_reset_stores':[
      {'offset_B':off,'size_B':n,'value':hex(v)}for off,n,v in stores],'common_reset_lifted_instructions':33,
      'proofs':proofs,'entry_row':entry,'operation_row':operation,'selector_sections':sections,
      'root_preparation_field':hex(SLOTS+72),'root_read_instructions':refs,'free_field':hex(SLOTS+8),'common_reset_field_total_B':80}


def sdk_checks():
    code='#include <stdlib.h>\n#include <stdint.h>\n_Static_assert(sizeof(void*)==8,"pointer64");\n_Static_assert(sizeof(uint32_t)==4,"word32");\n_Static_assert(__builtin_types_compatible_p(__typeof__(&free),void(*)(void*)),"free_void");\n'
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0,r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    headers=[{'SDK_relative_header':n,'size_B':len((sdk/n).read_bytes()),'sha256':SHA((sdk/n).read_bytes())}for n in ['usr/include/stdlib.h','usr/include/stdint.h']]
    return {'command':cmd,'source':code,'exit_code':0,'stderr':r.stderr,'emitted_artifact':False,'headers':headers}


def main():
    e=json.loads(read(ROOT/'corefp_optional_reset_checks.json'));s=Pointers()
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_optional_reset.py').read_bytes())and e['thin_sha256']==THIN_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['base_declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    totals=Counter();oracles=[]
    for p in e['profiles']:
        c=p['configuration'];assert c==config(c['label']);ov=overlay(c);assert p['declared_overlay']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ov]
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(SP),'PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(REC);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            for addr,raw in ov:
                lo=max(a,addr);hi=min(a+4096,addr+len(raw))
                if lo<hi:b[lo-a:hi-a]=raw[lo-addr:hi-addr]
            assert unpack(row['payload'])==b;totals['initial_RAM_B_checked']+=4096
        r=Replay(p,e['source_spans'],s);totals.update(r.run());oracles.append(oracle(p,r,s))
    checks=source_checks(s);sdk=sdk_checks();counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','private_free_pointers']}}
    assert counts==e['verified_counts']and len(e['source_spans'])==1 and len(bytes.fromhex(e['source_spans'][0]['bytes']))==1400
    result={'verified_counts':counts,'independent_replay':dict(totals),'compact_oracle_profiles':len(oracles),'bank_inputs_checked':2048,
      'source_queries_unsat':len(checks['proofs']),'exact_instructions_checked':len(checks['exact_instructions']),'common_reset_lifted_instructions':33,
      'source_B_checked':1400,'additional_root_reference_B_checked':8,'SDK_compile_exit':0,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_optional_reset_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_auditor_dependencies':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_checks':checks,'SDK_assertions':sdk,'fresh_replay_completed':True,'process_exit_code':0,'full_goal_complete':False,
      'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False}
    (ROOT/'corefp_optional_reset_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
