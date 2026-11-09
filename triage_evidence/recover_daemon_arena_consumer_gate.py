#!/usr/bin/env python3
"""Original readiness/flag contract, scalar pointer decode, branch entries,
source proofs and independent component CPU checks. O(source + 1024*instructions
+ solver resources) time, O(source + map + DAGs) space. No runtime flag value
is installed in a daemon continuation. All cases are component inputs.
"""
import json,sys,hashlib
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from capture_daemon_record720 import sha
from daemon_arena_consumer_symbolic import ConsumerFlags,CS
from lskd_values_symbolic import mem,cell
from validate_daemon_record720_spill import parse_value
S=0x680001f250;GATE=0x1010b5de0;MARKER=0x1010c5798
SPECS=[('marker',0x10062b2ac,0x10062b2d0),('flag_decode',0x10062b320,0x10062b32c),('flag_dispatch',0x10062b330,0x10062b360),('restore_arm',0x10047be18,0x10047be38),('boundary_arm',0x10061b524,0x10061b56c),('signed_compare',0x100607330,0x100607398),('gate_reacquire',0x1005f4378,0x1005f439c),('literal_copy',0x100406a48,0x100406a7c)]

def obligations():
    qs=[];counts={}
    def run(name,a,z,seeds=(),memory=()):
        v=ConsumerFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
        for r,x in seeds:v.seed(r,x)
        for at,n,x in memory:mem(v,at,n,x)
        v.run(name);counts[name]=v.count;return v
    ready=z3.BitVec('gate_readiness_byte8',8);flag=z3.BitVec('gate_runtime_flag32',32)
    v=run('marker',0x10062b2ac,0x10062b2d0,[('w9',0xa220),('x25',MARKER)],[(MARKER,1,ready)])
    # Interleaved pointer decoding has no flag-setting instructions.
    mid=list(CS.disasm(IMAGE.read(0x10062b2d0,0x60),0x10062b2d0));assert all(i.mnemonic not in ['cmp','cmn','ccmp','tst','subs','adds','ands']for i in mid)
    v.c={'spans':[{'label':'dispatch','start':'0x10062b330','bytes_hex':IMAGE.read(0x10062b330,0x24).hex()}]};v.seed('w11',flag);old=v.count;v.run('dispatch');counts['dispatch']=v.count-old
    qs.append(('all_u8_u32_readiness_flag_dispatch',v.read('w9')!=z3.If(z3.And(ready==1,flag!=0),z3.BitVecVal(0xa232,32),z3.BitVecVal(0xa220,32))))
    E=z3.BitVec('gate_encoded_pointer64',64);v=run('decode',0x10062b320,0x10062b32c,[('x11',E)])
    qs.append(('all_u64_scalar_pointer_bias',v.read('x11')!=E-0x7829387))
    P,Q=z3.BitVecs('gate_saved_continuation64 gate_phase64',64)
    v=run('restore',0x10047be18,0x10047be34,[('sp',S),('x21',GATE),('x24',Q)],[(S+0x200,8,P)])
    qs.append(('all_u64_restore_arm_contract',z3.Or(cell(v,GATE,4)!=0x5d96,v.read('w9')!=0x74c29d85,v.read('x8')!=P,v.read('x19')!=Q,v.read('x17')!=0x50cc)))
    v=run('boundary',0x10061b524,0x10061b548,[('sp',S),('x8',P),('w10',0x5a2d)])
    qs.append(('all_u64_payload_boundary_and_nonnull',z3.Or(cell(v,S+0x240,8)!=P-24,v.read('w13')!=z3.If(P==0,z3.BitVecVal(0,32),z3.BitVecVal(1,32)))))
    a,b=z3.BitVecs('issuer_input_byte8 issuer_encoded_byte8',8);phase=z3.BitVec('issuer_compare_phase32',32);src=0x6600000000
    v=run('issuer_compare',0x100607330,0x10060738c,[('sp',S),('x8',0),('x0',src),('w10',phase)],[(S+0x3b0,1,a),(src,1,b)])
    mask=(((phase+0x7fef6f30)&0xdffdfedf)+0xa012c0bd)^0x1b;equal=(a^b)==z3.Extract(7,0,mask)
    qs.append(('all_u8_u32_issuer_compare_dispatch',v.read('w10')!=(phase^z3.If(equal,z3.BitVecVal(0x22,32),z3.BitVecVal(0,32)))))
    src,dst,index=z3.BitVecs('literal_source64 literal_destination64 literal_index64',64);byte=z3.BitVec('literal_byte8',8)
    v=run('literal_copy',0x100406a48,0x100406a5c,[('x11',src),('x14',dst),('x8',index)],[(src+index,1,byte)])
    qs.append(('all_u64_u8_literal_copy_iteration',z3.Or(cell(v,dst+index,1)!=byte,v.read('x8')!=index+1)))
    return qs,counts

def cpu_components():
    u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set()
    def ensure(a,n):
        for p in range(a&~4095,(a+n+4095)&~4095,4096):
            if p not in pages:u.mem_map(p,4096);pages.add(p)
    for a,z in [(0x10062b2ac,0x10062b2d0),(0x10062b330,0x10062b354)]:ensure(a,z-a);u.mem_write(a,IMAGE.read(a,z-a))
    ensure(MARKER,1);count=0
    for marker in range(256):
        for flag in [0,1,2,0xffffffff]:
            u.mem_write(MARKER,bytes([marker]));u.reg_write(ar.UC_ARM64_REG_X25,MARKER);u.reg_write(ar.UC_ARM64_REG_W9,0xa220);u.reg_write(ar.UC_ARM64_REG_NZCV,(count&15)<<28);u.emu_start(0x10062b2ac,0,count=9);u.reg_write(ar.UC_ARM64_REG_W11,flag);u.emu_start(0x10062b330,0,count=9);expected=0xa232 if marker==1 and flag!=0 else 0xa220;assert u.reg_read(ar.UC_ARM64_REG_W9)==expected;count+=1
    return {'component_cases':count,'A64_instructions_checked':count*18,'readiness_values_exhausted':256,'flag_values_sampled':[0,1,2,0xffffffff],'native_flag_installed':False}

def original_IDB():
    rows=[]
    for name in ['daemon_arena_consumer_ida.json','daemon_arena_consumer_gate_ida.json']:
        obj=json.loads((ROOT/name).read_text())
        for c in obj['captures']:
            assert not c.get('isError');t=c['content'][0]['text'].split('[assist:tool-output]',1)[1].split('[/assist:tool-output]',1)[0].strip();results=json.loads(t)['results']
            for r in results:
                a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert IMAGE.read(a,len(b))==b;rows.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    assert len(rows)==11 and sum(r['size_bytes']for r in rows)==2624
    return rows

def issuer_snapshot():
    symbolic=json.loads((ROOT/'daemon_arena_consumer_symbolic.json').read_text());out=[]
    def value(e):
        x=z3.simplify(parse_value(e['expression'],8*e['size_bytes'],{}));assert z3.is_bv_value(x);return x.as_long()
    for row in symbolic['cases']:
        q=row['result'];es=q['effects'];sp=int(q['context']['SP'],16);writes=[(j,e)for j,e in enumerate(es)if e['kind']=='write'and e['pc']=='0x100406a54'];reads=[(j,e)for j,e in enumerate(es)if e['kind']=='read'and e['pc']=='0x100406a50'];assert len(writes)==len(reads)==98
        data=bytes(value(e)for j,e in writes);assert [int(e['address'],16)for j,e in writes]==list(range(sp+0x9fe,sp+0xa60));assert [int(e['address'],16)for j,e in reads]==list(range(0x100f266a4,0x100f26706));assert data==IMAGE.read(0x100f266a4,98)==bytes(value(e)for j,e in reads)
        left=[(j,e)for j,e in enumerate(es)if e['kind']=='read'and e['pc']=='0x100607350'];right=[(j,e)for j,e in enumerate(es)if e['kind']=='read'and e['pc']=='0x100607358'];assert len(left)==len(right)==3 and max(j for j,e in writes)<min(j for j,e in left)
        assert [int(e['address'],16)for j,e in left]==list(range(sp+0x3b0,sp+0x3b3));assert [int(e['address'],16)for j,e in right]==list(range(sp+0x9fe,sp+0xa01))
        pairs=[{'index':i,'input':value(a),'encoded_literal':value(b),'decoded_XOR81':value(b)^0x81,'matches_XOR81':value(a)==(value(b)^0x81)}for i,((j,a),(k,b))in enumerate(zip(left,right,strict=True))];assert [p['matches_XOR81']for p in pairs]==[True,True,False]
        plain=bytes(b^0x81 for b in data);assert plain.endswith(bytes([0]));out.append({'case':row['label'],'rodata_start':'0x100f266a4','size_bytes':98,'copier_load':'0x100406a50','copier_store':'0x100406a54','stack_offset':'0x9fe','raw_bytes_hex':data.hex(),'decoded_XOR81_ASCII':plain[:-1].decode('ascii'),'terminator_included':True,'input_issuer_stack_offset':'0x3b0','observed_byte_pairs':pairs,'last_literal_store_effect_index':max(j for j,e in writes),'first_compare_read_effect_index':min(j for j,e in left),'complete_issuer_policy_established':False})
    return out

def recover(check=False):
    qs,counts=obligations();proofs=[]
    for name,query in qs:
        a=ROOT/f'daemon_consumer_gate_{name}_original.smt2';b=ROOT/f'daemon_consumer_gate_{name}.smt2'
        for p,expr in [(a,query),(b,z3.simplify(query))]:
            if not check:s=z3.Solver();s.add(expr);p.write_text(s.to_smt2())
            items=z3.parse_smt2_file(str(p));s=z3.Solver();s.set(timeout=30000);s.add(*items);assert s.check()==z3.unsat;s=z3.Solver();s.set(timeout=30000);s.add(z3.Xor(z3.And(*items),expr));assert s.check()==z3.unsat
        proofs.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':'unsat'})
    assert {r[k]for r in proofs for k in ['file','original_file']}=={p.name for p in ROOT.glob('daemon_consumer_gate_*.smt2')}
    targets=[]
    for index in [0xa220,0xa232]:
        slot=TABLE+index*8;word=int.from_bytes(IMAGE.read(slot,8),'little');f=FIXUPS[slot];assert word>>63==1 and(word>>32)&0xffff==0x26a0 and(word>>48)&7==0
        targets.append({'index':hex(index),'slot':hex(slot),'word':hex(word),'target':hex(f['target']),'modifier':'0x26a0','key':'IA','address_diversity':0})
    assert [r['target']for r in targets]==['0x10047be18','0x10061b524']
    encoded=FIXUPS[0x1010a4528]['target'];assert encoded==0x1088e003f and(encoded-0x7829387)&((1<<64)-1)==0x1010b6cb8
    r={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_consumer_source.json','daemon_arena_consumer_symbolic.json','daemon_arena_consumer_symbolic.py','daemon_arena_consumer_ida.json','daemon_arena_consumer_gate_ida.json','daemon_frame_entry_contracts.json','daemon_arena_storage_contracts.json']},'spans':[{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex()}for n,a,z in SPECS],'proofs':proofs,'source_lift_counts':counts,'dispatch_targets':targets,'global_pointer':{'original_slot':'0x1010a4528','raw_word_hex':IMAGE.read(0x1010a4528,8).hex(),'decoded_rebase':hex(encoded),'bias':'-0x7829387','global':'0x1010b6cb8','current_runtime_value':'unknown'},'issuer_literal':issuer_snapshot(),'current_readiness':{'address':hex(MARKER),'source_retained_value':1,'native_current_value':'unknown'},'indexed_global_references':{'count':7,'scope':'current IDB indexed pointer-pool references; not an exhaustive writer census','writer_established':False},'live_IDB_matches':original_IDB(),'independent_component_CPU_checks':cpu_components(),'native_target_executed':False,'new_port_emission_established':False,'all_checks_pass':True,'full_goal_complete':False}
    p=ROOT/'daemon_arena_consumer_gate_contracts.json'
    if check:assert json.loads(p.read_text())==r
    else:p.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'proofs':len(proofs),'IDB_bytes':2624,'CPU':r['independent_component_CPU_checks'],'check_mode':check}),flush=True)
if __name__=='__main__':recover('--check'in sys.argv)
