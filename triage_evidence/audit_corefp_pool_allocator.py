#!/usr/bin/env python3
"""Independent original-byte pool replay, state reconstruction and layout oracle.

Does not import the new producer. No native target/API/IPC or IDB operation.
O(C*(B+P*F+V*J+R)+256*K) conservative time/space; 12000 visits/profile,
K=8 banks; SMT separately bounded to 30 s/query; compiler emits no artifact.
"""
import bisect,copy,json,struct,subprocess
from collections import Counter
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from capstone.arm64_const import ARM64_OP_REG,ARM64_OP_IMM
from audit_corefp_lookup_initialization import Replay as Frozen,initial_page,declared_inputs,frame,restore,unpack,ret,CS
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();M=(1<<64)-1
ENTRY=0x1bc12c;REC=0x63000100;HEAP=0x64000000;DONE=0x65000000;SP=0x62018000
TOKEN=0x1d33108;SELECTOR=0x1d44409;HOLDER=0x1d32dd0
POINTS={0x1bc2d4:'operation_dispatch',0x1bc3d4:'selector_read',0x1bc450:'decoded_request',0x1bc5d0:'allocation_extent',
 0x1bc9fc:'holder_head_read',0x1bca38:'node_extent_read',0x1bcf5c:'malloc_call',0x1bd058:'insert_node',
 0x1bcc30:'unlink_node',0x1bce50:'split_node',0x1bd188:'token_restore',0x1bd194:'result_store'}


def expected_config(label):
    rows={'selector_zero':{},'selector_two':{'selector_u8':2},'selector_255':{'selector_u8':255},
      'busy_token':{'selector_u8':1,'token_u32':0xa94ef},'raw_holder_frontier':{'selector_u8':1},
      'malloc_null_32':{'empty_holder':True},'malloc_null_0':{'empty_holder':True,'request_u64':0},
      'malloc_null_4799':{'empty_holder':True,'request_u64':4799},'malloc_null_4800':{'empty_holder':True,'request_u64':4800},
      'malloc_null_5000':{'empty_holder':True,'request_u64':5000},
      'arena_0':{'empty_holder':True,'malloc_success':True,'request_u64':0},
      'arena_1':{'empty_holder':True,'malloc_success':True,'request_u64':1},
      'arena_32':{'empty_holder':True,'malloc_success':True},
      'arena_128':{'empty_holder':True,'malloc_success':True,'request_u64':128},
      'arena_32_clobber':{'empty_holder':True,'malloc_success':True,'clobber_callers':True}}
    v=rows[label];return {'label':label,'request_u64':32,'selector_u8':1 if v.get('empty_holder')else 0,'malloc_success':False,**v}


def overlay(c):
    k=((REC^0xcf834db9ae8c9498)*0x9e8a2055)&M
    b=bytearray([165]*32);struct.pack_into('<QQI',b,0,0,(c['request_u64']+0x4faa3f5db623fbb0-k)&M,(0x2b9b-k)&0xffffffff)
    rows=[(REC,bytes(b)),(BASE+SELECTOR,bytes([c['selector_u8']]))]
    if 'token_u32'in c:rows.append((BASE+TOKEN,struct.pack('<I',c['token_u32'])))
    if c.get('empty_holder'):
        rows.extend((BASE+HOLDER+j,struct.pack('<Q',BASE+HOLDER+48))for j in [72,80])
    return rows


def snapshot(r,label):
    return {'label':label,'CPU':frame(r.u),'record32_hex':r.ram(REC,32).hex(),'holder88_hex':r.ram(BASE+HOLDER,88).hex(),
      'selector_u8':r.ram(BASE+SELECTOR,1)[0],'token_u32':int.from_bytes(r.ram(BASE+TOKEN,4),'little')}


class Replay(Frozen):
    def __init__(self,*args):super().__init__(*args);self.attempts=0;self.allocations=[]
    def stop(self,reason,**extra):
        assert self.p['frontier']=={'reason':reason,'CPU':frame(self.u),**extra};self.done=True;self.u.emu_stop()
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE;c=self.p['configuration']
        if pc==DONE:return self.stop('ordinary_return')
        if at==0x1bc344:
            if self.attempts:return self.stop('before_second_CASAL',concurrent_ordering_validated=False)
            raw=self.ram(pc,4);ins=next(CS.disasm(raw,at));assert ins.mnemonic+' '+ins.op_str=='casal w15, w12, [x27]'
            assert self.p['visits'][self.v]=={'pc':hex(at),'bytes_hex':raw.hex(),'instruction':ins.mnemonic+' '+ins.op_str};self.v+=1
            a=u.reg_read(A.UC_ARM64_REG_X27);old=int.from_bytes(self.ram(a,4),'little');cmp=u.reg_read(A.UC_ARM64_REG_W15);new=u.reg_read(A.UC_ARM64_REG_W12)
            assert (a,cmp,new)==(BASE+TOKEN,0x5d96,0xa94ef);self.attempts+=1;e=self.event()
            assert {k:e[k]for k in ['kind','visit','pointer','old_u32','compare_u32','replacement_u32','concurrent_ordering_validated']}=={
              'kind':'declared_sequential_CASAL','visit':self.v-1,'pointer':hex(a),'old_u32':old,'compare_u32':cmp,'replacement_u32':new,'concurrent_ordering_validated':False}
            self.effects(e,[(a,struct.pack('<I',new))]if old==cmp else [])
            f=copy.deepcopy(e['before']);f['X31'][15]=hex(old);f['PC']=hex(pc+4);assert e['after']==f;restore(u,f);return
        pointer=u.reg_read(A.UC_ARM64_REG_X9)
        if at==0x1bca38 and not(self.allocations and HEAP<=pointer<HEAP+self.allocations[0]['size_B']):
            return self.stop('before_unbacked_node_read',source_pc=hex(at),pointer=hex(pointer),access_offset_B=8,access_size_B=8,native_read_executed=False)
        if at in POINTS:self.point(snapshot(self,POINTS[at]))
        if pc in self.imports:
            name=self.imports[pc];call=u.reg_read(A.UC_ARM64_REG_LR)-4-BASE;args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)]
            assert name=='_malloc'and call==0x1bcf5c and not self.allocations
            size=args[0];assert size==max(5000,c['request_u64']+201)and size<=8192
            value=HEAP if c['malloc_success']else 0;e=self.event()
            assert e['kind']=='declared_API'and e['name']==name and e['callsite']==hex(call)and e['args_x0_x7']==list(map(hex,args))and e['return_u64']==hex(value)
            self.effects(e,[(HEAP,bytes([165])*size)]if value else []);self.allocations.append({'pointer':hex(value),'size_B':size})
            f=ret(e['before'],value,c.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=12001);self.flush();assert self.done and self.attempts==1
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points']]
        assert self.allocations==self.p['allocations']and snapshot(self,'frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,
          'models_checked':self.mi,'points_checked':self.pi,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,r,s):
    c=p['configuration'];busy=c['label']=='busy_token';raw=c['label']=='raw_holder_frontier';success=c['malloc_success'];empty=c.get('empty_holder',False)
    assert p['frontier']['reason']==('before_second_CASAL'if busy else 'before_unbacked_node_read'if raw else 'ordinary_return')
    assert r.ram(BASE+SELECTOR,1)==bytes([c['selector_u8']])
    assert int.from_bytes(r.ram(BASE+TOKEN,4),'little')==(0xa94ef if busy or raw else 0x5d96)
    pages={int(v['address'],16):unpack(v['payload'])for v in p['initial_RAM']}
    initial=lambda a,n:pages[a&~4095][a%4096:a%4096+n]
    old=initial(REC,32);expected=bytearray(old);root=bytearray(initial(BASE+HOLDER,88));result=0;payload=0;fill_count=0;arena_writes=[]
    if success:
        # Literal layout oracle, independent of trace values and producer formula.
        size=5000;packet=(max(c['request_u64'],15)+28)&~3;fill_count=packet+60;node=HEAP+size-packet-36
        result=node+24;payload=c['request_u64'];assert HEAP<=result<=result+payload<=HEAP+size
        C=0x2fecaf1f3ee407fa;remaining=size-packet-36
        struct.pack_into('<Q',root,40,(int.from_bytes(root[40:48],'little')+packet+12)&M)
        struct.pack_into('<QQ',root,72,HEAP,HEAP)
        assert r.ram(HEAP,8)==struct.pack('<Q',C)
        assert r.ram(HEAP+8,8)==struct.pack('<Q',C+remaining)
        assert r.ram(HEAP+24,16)==struct.pack('<QQ',BASE+HOLDER+48,BASE+HOLDER+48)
        assert r.ram(node,24)==struct.pack('<QQQ',C+remaining,C-packet-12,0x0fd0175a324022ad)
        assert r.ram(HEAP+4976,16)==struct.pack('<QQ',C,0xafecaf1f3ee407fa)
        # Original reverse fill is derived from the source stack address, then
        # overlaid by the metadata stores above. Verify all retained fill bytes.
        start=HEAP+4976-fill_count;buf=bytearray(((0x62017f78+j)^0xba)*((0x62017f78+j)+17)&255 for j in range(fill_count))
        buf.reverse();metadata=struct.pack('<QQQ',C+remaining,C-packet-12,0x0fd0175a324022ad)
        off=node-start;buf[off:off+24]=metadata
        assert r.ram(start,fill_count)==buf
        arena_writes=[w for w in p['writes']if HEAP<=int(w['address'],16)<HEAP+8192]
        fill=[w for w in arena_writes if p['visits'][w['visit']]['pc']=='0x1bcd74']
        assert len(fill)==fill_count and all(w['size_B']==1 for w in fill)
        assert [int(w['address'],16)for w in fill]==list(range(HEAP+4975,start-1,-1))
        assert sum(w['size_B']for w in arena_writes)==88+fill_count
        assert all(HEAP<=int(w['address'],16)<int(w['address'],16)+w['size_B']<=HEAP+size for w in arena_writes)
    if not busy and not raw:struct.pack_into('<Q',expected,0,result)
    assert r.ram(REC,32)==expected and r.ram(BASE+HOLDER,88)==root
    assert len(p['allocations'])==int(empty)
    result_stores=[w for w in p['writes']if w['address']==hex(REC)]
    assert len(result_stores)==int(not busy and not raw)
    if result_stores:assert result_stores[0]['size_B']==8 and p['visits'][result_stores[0]['visit']]['pc']=='0x1bd194'
    if raw:assert p['frontier']['pointer']=='0x176cb4e3'and not any(v['pc']=='0x1bca38'for v in p['visits'])
    for v in p['points']:
        if v['label']=='operation_dispatch':assert int(v['CPU']['X31'][20],16)==0x2b9b
        if v['label']=='decoded_request':assert int(v['CPU']['X31'][6],16)==c['request_u64']
        if v['label']=='allocation_extent':assert int(v['CPU']['X31'][10],16)==max(5000,c['request_u64']+201)
    if not busy and not raw:assert p['frontier']['CPU']['SP']==hex(SP)and p['frontier']['CPU']['X31'][19:]==p['initial_CPU']['X31'][19:]
    assert not any(w['address']==hex(BASE+SELECTOR)for w in p['writes'])
    return {'label':c['label'],'operation_u32':'0x2b9b','request_u64':c['request_u64'],'frontier':p['frontier']['reason'],
      'malloc_requests_B':[v['size_B']for v in p['allocations']],'result_pointer':hex(result)if not busy and not raw else None,
      'private_payload_extent_B':payload,'reverse_fill_stores_B':fill_count,'arena_source_write_total_B':88+fill_count if success else 0,
      'holder_list_node':hex(HEAP)if success else None,'selector_changed':False,'native_ownership_established':False,'external_reachability':'unknown'}


def source_checks(s):
    pool=0x1d05fa0;a=0x1ac19c0;b=0x1c78040
    specs=[('state_first',a,b,0x20,0xd59,pool,0x1d3377c),
      ('state_second',s.qword(pool+0xab68)-8,s.qword(pool+0x38d0),0x37,0x1794,pool,0x1d37f68),
      ('dispatch_base',a,b,0x78,0x14fb,pool,0x1c81944),('token',a,b,0x27,0xae,pool,TOKEN),
      ('selector',s.qword(pool+0x4588)-4,s.qword(pool+0x8030)-8,0xc5,0x13d9,pool,SELECTOR),
      ('holder',0x18ac070,0x1ac18c0,0xc5,0x1a86,pool,HOLDER+8),
      ('malloc',s.qword(0x1d077d0+0x1648),s.qword(0x1d077d0)-8,0xe4,0x102b0+0x38,0x1c81940,None),
      ('cleanup_free',s.qword(pool+0xab68)-8,s.qword(pool+0x38d0),0xa5,0x102b0,0x1c81940,None)]
    banks=[]
    for label,aa,bb,x,bias,base,target in specs:
        t=s.read(aa,256);u=s.read(bb,256);out=[i^u[t[i]^x]for i in range(256)];assert len(set(out))==1
        row=base+8*(bias+out[0]);fix=s.decoded[row]
        if target is None:assert fix['bind']and fix['import']['name']==('_free'if label=='cleanup_free'else '_malloc')and fix['key']=='IA'
        else:assert not fix['bind']and int(fix['target'],16)==target
        banks.append({'label':label,'A':hex(aa),'B':hex(bb),'A256_hex':t.hex(),'B256_hex':u.hex(),'xor_u8':hex(x),
          'bias':hex(bias),'base':hex(base),'constant_u8':hex(out[0]),'enumerated_inputs':256,'pointer_row':fix})
    x=z3.BitVec('record_address64',64);proofs=[]
    pre=(((x&0x569daa3f03dab736)<<1)-x+0x296255c0fc2548c9)^0xe6e1187952a9dc51
    q=z3.Solver();q.set(timeout=30000);q.add(pre!=(x^0xcf834db9ae8c9498));assert q.check()==z3.unsat
    proofs.append({'label':'address_key_pre_multiply','query':q.to_smt2(),'result':'unsat'})
    tag=0x2b9b;phase=((tag^0x2ba6)*0x79)&0xffffffff;assert phase==0x1cd5
    edges=[]
    for label,index,target,div in [('acquire',tag,0x1bc304,0xf6a9),('acquired',tag^(phase^0x1cfb),0x1bc364,0xf6a9),
      ('selector_other',phase,0x1bd188,0x2dc7),('selector_one',phase^((((phase-0xccd)&0xffffffff)|0xce1)+((phase+0xec6)^0xb6be)),0x1bc400,0x2dc7)]:
        row=0x1c81940+8*index;fix=s.decoded[row];assert fix['target']==hex(target)and int(fix['diversity'],16)==div
        edges.append({'label':label,'index':hex(index),'pointer_row':fix})
    exact={0x1bc28c:'ldr w12, [x0, #0x10]',0x1bc2cc:'add w20, w12, w11',0x1bc344:'casal w15, w12, [x27]',
      0x1bc3d4:'ldrb w12, [x12]',0x1bc3d8:'cmp w12, #1',0x1bc424:'ldr x10, [x9, #8]',0x1bc448:'add x10, x10, x11',
      0x1bc44c:'add x6, x10, x12',0x1bc5c0:'add x10, x6, #0xc9',0x1bc5c4:'mov w11, #0x1388',0x1bc5c8:'cmp x10, x11',0x1bc5cc:'csel x10, x10, x11, gt',
      0x1bc940:'stur x12, [x29, #-0x90]',0x1bc944:'add x12, x12, #0x30',0x1bc9fc:'ldr x9, [x9, #0x48]',
      0x1bca38:'ldr x12, [x9, #8]',0x1bcb50:'ldr x15, [x15]',0x1bcba4:'ldr x13, [x15, #0x18]',0x1bcbec:'ldr x14, [x0, #0x20]',
      0x1bcc30:'str x0, [x15, #0x18]',0x1bcc38:'str x15, [x17, #0x20]',0x1bce50:'str x10, [x9, #8]',0x1bce68:'stp x10, x9, [x14]',
      0x1bce70:'str x9, [x14, #0x10]',0x1bce98:'add x10, x14, #0x18',0x1bcf5c:'blraa x8, x17',
      0x1bd058:'str x13, [x0, #0x18]',0x1bd060:'str x11, [x0, #0x20]',0x1bd064:'str x0, [x12, #0x50]',0x1bd06c:'str x0, [x11, #0x18]',
      0x1bd174:'blraa x8, x17',0x1bd18c:'str w8, [x27]',0x1bd194:'str x10, [x8]'}
    sites=[]
    for pc,want in exact.items():
        raw=s.read(pc,4);i=next(CS.disasm(raw,pc));assert i.mnemonic+' '+i.op_str==want;sites.append({'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':want})
    entry=s.decoded[0x1d037d0];assert entry['target']==hex(ENTRY)and entry['diversity']=='0x478b'and entry['key']=='IA'
    peers=[r for r in s.decoded.values()if r.get('authenticated')and r.get('key')=='IA'and r.get('diversity')=='0x478b']
    # Literal modifier adjacency is an inventory, not a reaching-target proof.
    text=next(r for r in s.meta['sections']if r['section']=='__text');lo=text['address'];data=s.read(lo,text['size'])
    needle=(0xd2800000|(0x478b<<5)|17).to_bytes(4,'little');candidates=[];at=0
    while True:
        off=data.find(needle,at)
        if off<0:break
        at=off+1;pc=lo+off
        if pc%4:continue
        ins=list(CS.disasm(s.read(pc,8),pc))
        if len(ins)!=2 or ins[1].mnemonic!='blraa' or ins[1].op_str!='x8, x17':continue
        start=s.starts[bisect.bisect_right(s.starts,pc)-1]
        candidates.append({'modifier_pc':hex(pc),'callsite':hex(pc+4),'function':hex(start),'bytes8_hex':s.read(pc,8).hex(),'target_established':False})
    return {'entry_row':entry,'same_diversity_rows':peers,'literal_call_candidates':candidates,'literal_candidates_count':len(candidates),
      'literal_candidate_functions':len({r['function']for r in candidates}),'literal_scan_section':text,
      'banks':banks,'bank_inputs_checked':len(banks)*256,'proofs':proofs,'exact_instructions':sites,'dispatch_edges':edges,
      'key_constant64':'0xcf834db9ae8c9498','operation_u32':hex(tag),'phase_W9':hex(phase),'packet_formula_scope':'retained successful requests 0,1,32,128 only; not a full-domain proof'}


def sdk_checks():
    code='#include <stdlib.h>\n#include <stdint.h>\n_Static_assert(sizeof(void*)==8 && sizeof(size_t)==8 && sizeof(uint32_t)==4,"widths");\n_Static_assert(__builtin_types_compatible_p(__typeof__(&malloc),void*(*)(size_t)),"malloc_signature");\n'
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0 and not r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());names=['usr/include/stdlib.h','usr/include/stdint.h']
    return {'command':cmd,'source':code,'exit_code':0,'stderr':'','emitted_artifact':False,
      'headers':[{'SDK_relative_header':n,'size_B':len((sdk/n).read_bytes()),'sha256':SHA((sdk/n).read_bytes())}for n in names]}


def main():
    e=json.loads(read(ROOT/'corefp_pool_allocator_checks.json'));s=Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_pool_allocator.py').read_bytes())and e['thin_sha256']==THIN_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['base_declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    totals=Counter();oracles=[]
    for p in e['profiles']:
        c=p['configuration'];assert c==expected_config(c['label']);ov=overlay(c);assert p['declared_overlay']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ov]
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(SP),'PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(REC);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(4096)if a==HEAP+4096 else bytearray(initial_page(s,a))
            for addr,raw in ov:
                lo=max(a,addr);hi=min(a+4096,addr+len(raw))
                if lo<hi:b[lo-a:hi-a]=raw[lo-addr:hi-addr]
            assert unpack(row['payload'])==b;totals['initial_RAM_B_checked']+=4096
        r=Replay(p,e['source_spans'],s);totals.update(r.run());oracles.append(oracle(p,r,s))
    checks=source_checks(s);sdk=sdk_checks();counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','allocations']}}
    assert counts==e['verified_counts']and len(e['source_spans'])==1 and len(bytes.fromhex(e['source_spans'][0]['bytes']))==4236
    result={'verified_counts':counts,'independent_replay':dict(totals),'compact_oracle_profiles':len(oracles),'bank_inputs_checked':checks['bank_inputs_checked'],
      'source_queries_unsat':len(checks['proofs']),'exact_instructions_checked':len(checks['exact_instructions']),'source_B_checked':4236,
      'SDK_compile_exit':0,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_pool_allocator_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_auditor_dependencies':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_checks':checks,'SDK_assertions':sdk,'fresh_replay_completed':True,'process_exit_code':0,'full_goal_complete':False,
      'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False}
    (ROOT/'corefp_pool_allocator_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
