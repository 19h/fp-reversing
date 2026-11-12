#!/usr/bin/env python3
"""Independent checkpoint restoration, consumer replay and record/source audit.

Never imports the new producer. Prior execution is receipt-pinned rather than
rerun. Fresh private CPU checks all new visits, journals, PAC models and RAM.
O(I+C*(B+F+V+P*J+R)) time, O(I+B+F+C*(V+J+P+R)) space; SMT separate.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as A
import z3
from audit_fpsd1201_record import Replay as Core,unpack,ROOT,RAM,CS,RECORD,OUT,OWNER,CONTEXT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();MASK=(1<<32)-1;MASK64=(1<<64)-1
PRIOR_AUDIT_SHA='40264eef84f86e6fdf9de0a480b6e46b88ffcc3f9168db976600e6bc818ca2e0'
POINTS=[0x9819c4,0x1142c08,0x1142e08,0x1142154,0x114228c,0x114245c]


class Replay(Core):
    def __init__(self,p,prior,code,banks,D):
        self.p=p;self.c=p['configuration'];self.D=D;self.phase='consumer_checkpoint';self.v=self.r=self.w=self.pi=self.ci=0
        self.pending=[];self.stats=Counter();self.used=set();self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.point_index=0
        assert p['configuration']==prior['configuration']and p['initial']==prior['terminal']and p['initial_RAM']==prior['final_RAM']
        assert prior['frontier']['pc']=='0x9819c4'and prior['frontier']['target']=='0x1142c08'and not prior['frontier']['instruction_executed']
        self.ranges=[(int(r['start'],16),int(r['start'],16)+len(bytes.fromhex(r['bytes_hex'])))for r in code]
        pages=set()
        for a,b in self.ranges+[(a,a+len(b))for a,b in banks.items()]+[(a,a+n)for a,n in RAM]+[(0x1c80000,0x1d20000)]:
            pages.update(range(a&~4095,(b+4095)&~4095,4096))
        for page in sorted(pages):self.u.mem_map(page,4096)
        for r in code:self.u.mem_write(int(r['start'],16),bytes.fromhex(r['bytes_hex']))
        for a,b in banks.items():self.u.mem_write(a,b)
        for a,row in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not row['bind']:self.u.mem_write(a,int(row['target'],16).to_bytes(8,'little'))
        self.u.mem_write(0x1d1c578,(0x1d43300).to_bytes(8,'little'))
        assert len(p['initial_RAM'])==3
        for row,(a,n)in zip(p['initial_RAM'],RAM):
            b=unpack(row['payload']);assert row['address']==hex(a)and len(b)==n;self.u.mem_write(a,b);self.stats['checkpoint_RAM_bytes_checked']+=n
        f=p['initial']
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        self.frame(f);self.record=self.reg(0);self.cursor=self.reg(1)
        j=p['checkpoint_pointer_load']['prior_read_index'];r=prior['source_reads'][j]
        assert p['checkpoint_pointer_load']=={'prior_read_index':j,'read':r,'source_visit':prior['source_visits'][r['visit']]}
        assert(r['address'],r['size_B'],r['bytes_hex'])==('0x1d056a0',8,(0x1142c08).to_bytes(8,'little').hex())
        visit=p['checkpoint_pointer_load']['source_visit'];pc=int(visit['pc'],16);b=bytes.fromhex(visit['bytes_hex'])
        assert self.ram(pc,4)==b and next(CS.disasm(b,pc)).mnemonic in ['ldr','ldur']
        self.stats['checkpoint_reaching_pointer_loads_checked']+=1
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def point(self,pc):
        e=self.p['consumer_points'][self.point_index];self.point_index+=1;self.frame(e['CPU'])
        raw=self.ram(self.record,48);ptr=lambda j:int.from_bytes(raw[j:j+8],'little');q=ptr(0);pair=self.ram(q,24);views={}
        for name,a in [('pair_first',int.from_bytes(pair[:8],'little')),('pair_second',int.from_bytes(pair[8:16],'little')),('output',ptr(8)),('auxiliary',ptr(24)),('input',ptr(32)),('modulus',ptr(40))]:
            d=self.ram(a,16);payload=int.from_bytes(d[8:],'little');valid=any(lo<=payload<payload+512<=lo+n for lo,n in RAM)
            views[name]={'address':hex(a),'descriptor16_hex':d.hex(),'payload512_hex':self.ram(payload,512).hex()if valid else None}
        actual={'pc':hex(pc),'record_pointer':hex(self.record),'record48_hex':raw.hex(),'pair_pointer':hex(q),'pair24_hex':pair.hex(),'descriptors':views,
          'caller_cursor_pointer':hex(self.cursor),'caller_cursor_u64':hex(int.from_bytes(self.ram(self.cursor,8),'little'))}
        if pc in [0x1142154,0x114228c]:actual.update({'child_cursor_pointer':hex(self.reg(1)),'child_cursor_u64':hex(int.from_bytes(self.ram(self.reg(1),8),'little'))})
        if pc==0x114245c:actual.update({'outgoing_record_pointer':hex(self.reg(0)),'outgoing_record48_hex':self.ram(self.reg(0),48).hex(),'outgoing_cursor_pointer':hex(self.reg(1)),'outgoing_cursor_u64':hex(int.from_bytes(self.ram(self.reg(1),8),'little'))})
        assert actual=={k:v for k,v in e.items()if k!='CPU'}
        state=int.from_bytes(raw[16:20],'little')^((((self.record&MASK)^0x1766cddd)*0xb7a7bfff)&MASK);assert state==0x8a6e
        assert ptr(40)==CONTEXT+0x290
        if self.c['control']=='null_auxiliary':
            d=bytes.fromhex(views['auxiliary']['descriptor16_hex']);n=(int.from_bytes(d[4:8],'little')-0x4b0cf050)&MASK
            b=bytes.fromhex(views['auxiliary']['payload512_hex']);assert n==1 and int.from_bytes(b[:4],'little')^0x1ac70ef2==65537
        else:assert self.c['control']=='as_staged'and ptr(24)==CONTEXT+0x3a0 and views['auxiliary']['descriptor16_hex']=='a5'*16 and views['auxiliary']['payload512_hex']is None
        if pc==0x1142154:
            w=self.p['consumer_points'][1];seed=int(w['caller_cursor_u64'],16);pad=16*((((seed*11973+1)&MASK64)>>60)+1)
            assert int(e['CPU']['sp'],16)==int(w['CPU']['sp'],16)-64-pad
            assert int(e['child_cursor_u64'],16)==(seed-240)&MASK64;self.stats['consumer_wrapper_frame_geometries_checked']+=1
        if pc==0x114228c:
            child=self.p['consumer_points'][3];assert int(e['child_cursor_u64'],16)==(int(child['child_cursor_u64'],16)+240)&MASK64
            self.stats['consumer_child_cursor_restores_checked']+=1
        if pc==0x114245c:
            out=bytes.fromhex(e['outgoing_record48_hex']);p=lambda j:int.from_bytes(out[j:j+8],'little');r=self.reg(0)
            assert p(0)==int.from_bytes(pair[8:16],'little')and p(16)==ptr(40)and p(24)==q and p(40)==ptr(32)
            assert int.from_bytes(out[8:12],'little')^((((r&MASK)^0x7043a3fa)*0x4ecee2ad)&MASK)==0xd7f4
            local=self.ram(p(32),16);assert int.from_bytes(local[:8],'little')==0x4b0cf05000000082
            assert int.from_bytes(local[8:],'little')==int(e['CPU']['sp'],16)+0x2b8
            assert r==int(e['CPU']['registers31'][29],16)-0x90
            self.stats['outgoing_record_contracts_checked']+=1
        self.stats['consumer_record_checkpoints_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in POINTS:self.point(pc)
        if pc==0x114245c:
            self.frame(self.p['terminal']);target=0x74fd0c;slot=0x1d03d18;row=self.D[slot]
            assert(self.reg(8),self.reg(17))==(target,0xca9b)
            assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==(hex(target),'0xca9b','IA',0)
            assert any(r['address']==hex(slot)and r['size_B']==8 and r['bytes_hex']==target.to_bytes(8,'little').hex()for r in self.p['source_reads'][:self.r])
            assert self.p['frontier']=={'pc':hex(pc),'target':hex(target),'modifier':'0xca9b','original_slot':hex(slot),'instruction':'blraa x8, x17','instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()}
            self.used.add(slot);self.stop='unretained_callee';u.emu_stop();return
        if pc==0x9819c4:
            assert self.p['source_visits'][self.v]=={'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'};self.v+=1
            e=self.p['PAC_models'][self.pi];self.pi+=1;self.frame(e['before'])
            assert e=={'pc':hex(pc),'kind':'blraa','before':self.p['initial'],'target':'0x1142c08','modifier':'0x4032','original_slot':'0x1d056a0'}
            assert(self.reg(8),self.reg(17))==(0x1142c08,0x4032)
            row=self.D[0x1d056a0];assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==('0x1142c08','0x4032','IA',0)
            self.used.add(0x1d056a0);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,0x1142c08);return
        Core.hook(self,u,pc,n,data)
    def run(self):
        self.u.emu_start(0x9819c4,0,count=10000);self.flush();assert self.stop==self.p['stop_reason']=='unretained_callee'
        assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])
        assert self.point_index==len(self.p['consumer_points'])==6 and [p['pc']for p in self.p['consumer_points']]==[hex(pc)for pc in POINTS]
        assert self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
        for row in self.p['used_original_pointer_rows']:
            if row['bind']:assert row['import']['name']=='___stack_chk_guard';continue
            word=int(row['word'],16);decoded=word&MASK if word>>63 else(word&((1<<43)-1))|(((word>>43)&255)<<56)
            assert decoded==int(row['target'],16)
            if word>>63:assert word>>49&3==0 and word>>32&65535==int(row['diversity'],16)and word>>48&1==row['address_diversity']
            self.stats['original_pointer_profile_associations_checked']+=1
        for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['final_RAM_bytes_checked']+=n
        assert len(self.p['final_RAM'])==3 and not self.p['native_effects']
        assert self.p['final_status_u32']==hex(int.from_bytes(self.ram(RECORD+0x30,4),'little'))=='0xa5a5a5a5'
        assert self.p['final_delta_cell_u64']==hex(int.from_bytes(self.ram(OUT,8),'little'))==hex(self.c['seed_u64'])
        for name in ['source_reads','source_writes']:
            for r in self.p[name]:
                a=int(r['address'],16);n=r['size_B'];assert not(a<OWNER+0x900 and OWNER+0x880<a+n)
                for key in ['auxiliary','input']:
                    d=self.p['consumer_points'][0]['descriptors'][key];b=bytes.fromhex(d['descriptor16_hex']);ptr=int.from_bytes(b[8:],'little')
                    count=(int.from_bytes(b[4:8],'little')-0x4b0cf050)&MASK;count=count-(1<<32)if count>>31 else count
                    if abs(count)<=128:assert not(a<ptr+4*abs(count)and ptr<a+n)
                    else:assert key=='auxiliary'and b==b'\xa5'*16
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128
        self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi})
        return self.stats


def sources(e,old):
    assert e['code_spans'][:19]==old['code_spans']
    a=json.loads(read(ROOT/'fpsd1201_consumer_ida_readback.json'));assert not a['IDB_mutated']and not a['native_target_executed']
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==a['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    slices=[struct.unpack_from('>5I',raw,8+20*j)for j in range(struct.unpack_from('>I',raw,4)[0])]
    _,_,offset,length,_=next(s for s in slices if s[:2]==(0x100000c,0x80000002));thin=raw[offset:offset+length]
    assert SHA(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    at=32;segments=[]
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,at)
        if cmd==0x19:
            _,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append((vm,fo,fs))
        if cmd==0x26:fo,fs=struct.unpack_from('<II',thin,at+8);blob=thin[fo:fo+fs]
        at+=n
    def get(a,n):
        vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2]);return thin[fo+a-vm:fo+a-vm+n]
    starts=[];v=shift=pc=0
    for byte in blob:
        v|=(byte&127)<<shift
        if byte&128:shift+=7;continue
        if not v:break
        pc+=v;starts.append(hex(pc));v=shift=0
    assert starts==json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']
    for r in e['code_spans']:assert get(int(r['start'],16),len(bytes.fromhex(r['bytes_hex'])))==bytes.fromhex(r['bytes_hex'])
    for j,r in enumerate(a['spans']):
        b=bytes.fromhex(r['bytes_hex']);assert SHA(b)==r['sha256']==r['original_sha256']and r['current_equals_IDA_original_bytes']and len(b)==r['size_B']
        assert starts[starts.index(r['start'])+1]==r['end_exclusive']and e['code_spans'][19+j]=={**r,'role':['consumer_cursor_wrapper','consumer_implementation'][j]}
    assert len(a['spans'])==2 and sum(r['size_B']for r in a['spans'])==3292
    lookup=json.loads(read(ROOT/'corefp_lookup_contracts.json'));banks={}
    for row in lookup['banks']:
        for ak,bk in [('first_address','first_bytes'),('second_address','second_bytes')]:
            address=int(row[ak],16);b=bytes.fromhex(row[bk]);assert address not in banks or banks[address]==b;banks[address]=b
    for address,b in banks.items():assert get(address,len(b))==b
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    for address,r in D.items():assert int.from_bytes(get(address,8),'little')==int(r['word'],16)
    parent=next(r for r in json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))['spans']if r['role']=='parent');b=bytes.fromhex(parent['bytes_hex']);assert get(int(parent['start'],16),len(b))==b
    assert e['reference_file_check']=={**old['reference_file_check'],'code_bytes_checked':34332}
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    exact={0x1142d00:('ldr','x21, [x19]'),0x1142d04:('mov','w1, #0x2ec5'),0x1142d64:('sub','x15, x21, #0xf0'),
      0x1142e08:('blraa','x8, x17'),0x1142e18:('str','x8, [x19]'),0x1142280:('ldr','x9, [x1]'),0x1142284:('add','x9, x9, #0xf0'),
      0x1142288:('str','x9, [x1]'),0x11422cc:('ldr','w10, [x0, #0x10]'),0x11422d4:('ldr','x26, [x0]'),0x11422d8:('ldp','x10, x9, [x0, #0x18]'),
      0x11422e4:('ldr','x16, [x0, #0x28]'),0x1142304:('ldr','x10, [x26, #8]'),0x1142350:('stp','x16, x26, [x29, #-0x80]'),
      0x1142354:('stp','x13, x9, [x29, #-0x70]'),0x1142358:('stur','x10, [x29, #-0x90]'),0x114245c:('blraa','x8, x17')}
    for pc,want in exact.items():assert(ins[pc].mnemonic,ins[pc].op_str)==want,(hex(pc),ins[pc].mnemonic,ins[pc].op_str)
    for p in e['proofs']:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.parse_smt2_string(p['query']));assert q.check()==z3.unsat and p['result']=='unsat'
    p=z3.BitVec('independent_consumer_pointer',32);s=z3.BitVec('independent_consumer_cursor',64);r=p^0x562bc3c0
    top=z3.LShR(s*z3.BitVecVal(11973,64)+1,60);pad=((top<<4)+31)&0x1f0
    claims=[(((r|0xf4a6b85c)-(r&0xf4a6b85c))^0xb5ebb641)*0xb7a7bfff==(p^0x1766cddd)*0xb7a7bfff,
      s-0xf0+0xf0==s,pad==16*(top+1),z3.And(z3.UGE(pad,16),z3.ULE(pad,256)),z3.Extract(15,0,s-0xf0+0xf0-s)==0]
    for claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));assert q.check()==z3.unsat
    return banks,D,{'fresh_IDA_spans':2,'fresh_IDA_bytes':3292,'compiler_bounded_bodies':2,'total_selected_code_bytes':34332,
      'original_fixup_words_checked':len(D),'compiler_starts_checked':len(starts),'retained_queries_unsat':len(e['proofs']),
      'independent_queries_unsat':len(claims),'exact_source_instructions_checked':len(exact),'complete_algorithm_universally_proved':False}


def main():
    e=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'));old=json.loads(read(ROOT/'fpsd1201_reduction_checks.json'))
    prior=json.loads(read(ROOT/'fpsd1201_reduction_audit.json'));assert SHA(read(ROOT/'fpsd1201_reduction_audit.json').encode())==PRIOR_AUDIT_SHA
    assert prior['fresh_replay_completed']and prior['result']['all_checks_pass']and prior['checks_sha256']==SHA(read(ROOT/'fpsd1201_reduction_checks.json').encode())
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_consumer.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_consumer_ida_readback.json').encode())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    banks,D,source=sources(e,old);total=Counter();indices=[j for j,p in enumerate(old['profiles'])if p['configuration']['operand_u32']]
    assert len(e['profiles'])==len(indices)==12
    for p,j in zip(e['profiles'],indices):assert p['prior_profile_index']==j;total.update(Replay(p,old['profiles'][j],e['code_spans'],banks,D).run())
    assert not any(e[k]for k in ['new_operand_controls_supplied','whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'fresh_replay':dict(total),'profiles':12,'prefix_instructions_rerun':0,'prior_full_replay_receipt_sha256':PRIOR_AUDIT_SHA,
      'next_callee_targets':['0x74fd0c'],'candidate_inline128_reads_or_writes':0,'auxiliary_or_input_limb_reads_or_writes':0,
      'complete_consumer_return_established':False,'whole_parent_replayed':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_consumer_checks.json').encode()),'IDA_readback_sha256':e['IDA_readback_sha256'],
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_consumer_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
