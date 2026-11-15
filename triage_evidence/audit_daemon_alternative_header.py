#!/usr/bin/env python3
"""Universal alternative word writer and composed header-to-parent publication.
O(parent bytes + replay*32 + source DAG) time/space, excluding solver search
(30 s/query). Fifteen universal normalizer lemmas justify checked proof cuts.
Source-only composition adds no target interval or concrete allocator return.
"""
import json
import z3
from daemon_receive_tools import ROOT,SOURCE,TABLE,FIXUPS,IMAGE
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift,number
from audit_daemon_alternate_word import LemmaLift
from audit_daemon_alternative_fill import Source as Supplied
from audit_daemon_record_storage import word,index
from recover_daemon_record_storage import KEYS
from audit_daemon_storage_flag import replay
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
import recover_daemon_alternative_header as R

DEPS=['audit_daemon_append_fields.py','audit_daemon_alternate_word.py','audit_daemon_alternative_fill.py',
      'audit_daemon_record_storage.py','recover_daemon_record_storage.py','audit_daemon_storage_flag.py',
      'audit_daemon_state_table_mixing.py','audit_daemon_environment_outputs.py','lskd_values_symbolic.py',
      'recover_daemon_return_bank_origins.py']
WHITEN=0x36cad8b3
MASK_PCS=[0x10047c6c4,0x10047c8d0,0x10047ca7c,0x10047cc5c]
TABLE_PCS=[0x10047c6d4,0x10047c8e0,0x10047ca8c,0x10047cc68]
CACHE_PCS=[0x10047c6e4,0x10047c8ec,0x10047ca98,0x10047cc74]
FRAME_LOADS={0x1007d39f4:(0x9d0,8),0x1007d3a00:(0x2338,8),0x1007d3a04:(0x3608,4),
    0x1007d3a24:(0x9d8,8),0x1005c5b70:(0x9d8,8),0x10047c6a4:(0x9d8,8),
    0x10047c6c0:(0x878,8),0x10047c6d0:(0x858,8),0x1005189bc:(0x2338,8),
    0x1005189c0:(0x3608,4),0x1005189c4:(0xb24,4),0x1005189f4:(0x9d0,8),
    0x100518b38:(0x9d8,8),0x10057c168:(0x9d8,8),0x10050a818:(0x9d0,8),
    0x10050a828:(0x2338,8),0x10050a82c:(0x3608,4),0x10050a84c:(0x9d8,8),
    0x100817c94:(0x9d0,8),0x100817ca4:(0x76e0,8),0x100817cac:(0x9d8,8),
    0x100825884:(0x2338,8),0x100825888:(0x76e0,8),0x10082588c:(0x3e00,8),
    0x100825894:(0x3608,4),0x1008258b4:(0x662f,1),0x1008258d4:(0x36e8,8),
    0x1008258dc:(0x9d8,8),0x10068ae70:(0x16d0,8),0x10068ae7c:(0x8ca8,8)}
DISPATCH_PCS={0x1007d3a28,0x1005c5b74,0x10047c6a8,0x100518b3c,
              0x10057c16c,0x10050a850,0x100817cb0,0x1008258e0}


class Reduced(Supplied):
    def __init__(self,values,contexts):
        super().__init__(values)
        self.contexts,self.inputs,self.cuts=contexts,{},[]

    def one(self,ins):
        for j,(a,b,reg,k) in enumerate(R.NORMALIZERS):
            if ins.address==a:
                self.inputs[j]=self.read(reg)
                for n,value in self.contexts[j].items():
                    assert z3.is_true(z3.simplify(self.read(n)==value)),(hex(a),n)
        super().one(ins)
        for j,(a,b,reg,k) in enumerate(R.NORMALIZERS):
            if ins.address+4==b:
                self.write(reg,self.inputs[j]^KEYS[k])
                self.cuts.append({'start':hex(a),'end_exclusive':hex(b),'register':reg,'round':k,
                                  'context':{n:hex(v) for n,v in self.contexts[j].items()}})


class Composition(Reduced):
    def __init__(self,frame,cells,mask,table,contexts):
        super().__init__({},contexts)
        self.frame,self.cells,self.mask,self.table=frame,cells,mask,table
        self.address_checks,self.dispatches,self.caches,self.edges=[],[],[],[]
        self.batch=-1
        self.seed('sp',frame)

    def load(self,address,n):
        self.loads.append((self.pc,address,n))
        if self.pc in FRAME_LOADS:
            off,size=FRAME_LOADS[self.pc];assert size==n
            self.address_checks.append(address!=self.frame+off)
            return resize(self.cells[off],8*n)
        if self.pc in DISPATCH_PCS:
            slot=number(address);assert n==8 and slot in FIXUPS and isinstance(FIXUPS[slot]['target'],int)
            self.dispatches.append({'pc':hex(self.pc),'slot':hex(slot),'target':hex(FIXUPS[slot]['target'])})
            return z3.BitVecVal(FIXUPS[slot]['target'],64)
        if self.pc in MASK_PCS:
            assert n==4;self.address_checks.append(address!=0x1010c67d4);return self.mask
        if self.pc in TABLE_PCS:
            assert n==8;self.address_checks.append(address!=0x1010c8268);return self.table
        assert self.pc in CACHE_PCS and n==8,hex(self.pc)
        j=CACHE_PCS.index(self.pc)
        value=z3.BitVec('header_compose_cache_'+str(self.batch)+'_'+str(j)+'64',64)
        self.caches.append((self.batch,j,address,value))
        return value

    def compose(self):
        for j,name in enumerate(R.PROGRAM):
            a,b=R.SPANS[name]
            if name=='word_writer':self.batch+=1
            self.run_block(a,b-4)
            ins=next(DEC.disasm(IMAGE.read(b-4,4),b-4));assert ins.mnemonic=='braa'
            target=self.read(ins.reg_name(ins.operands[0].reg));modifier=self.read(ins.reg_name(ins.operands[1].reg))
            expected=R.SPANS[R.PROGRAM[j+1]][0] if j+1<len(R.PROGRAM) else self.cells[0x8ca8]
            self.edges.append((b-4,target,modifier,expected))
            if j+1<len(R.PROGRAM):
                d=self.dispatches[-1];slot=int(d['slot'],16);raw=int.from_bytes(IMAGE.read(slot,8),'little')
                assert number(target)==int(d['target'],16) and number(modifier)==(raw>>32)&65535
        return self


def obligations():
    out,contexts=[],[]
    def prove(label,bad,premises=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat,label
        s.add(z3.simplify(bad));result=s.check()
        assert result==z3.unsat,(label,str(result),s.reason_unknown())
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
        print(json.dumps({'source_proof':label,'result':'unsat'}),flush=True)
    def seed(v,values):
        for n,x in values.items():v.seed(n,x)
        return v
    frame,base,u,parent,cursor,continuation,table=z3.BitVecs(
        'header_frame64 header_base64 header_U64 header_parent64 header_cursor64 header_continuation64 header_table64',64)
    coord,payload,mask,phase=z3.BitVecs('header_coordinate32 header_payload32 header_mask32 header_phase32',32)
    v=seed(Supplied(),{'sp':frame,'w22':coord});v.run_block(*R.SPANS['coordinate_copy'])
    prove('W22_copy_to_saved_coordinate',z3.Or(v.stores[0]['address']!=frame+0x3608,v.stores[0]['value']!=coord))
    v=seed(Supplied(),{'sp':frame,'x15':frame+0x8000,'x12':continuation,'x9':parent})
    v.run_block(*R.SPANS['type_literal']);v.run_block(*R.SPANS['entry_saves'])
    prove('literal_type_and_entry_saved_continuation_parent',z3.Or(v.read('w11')!=0x867a282a,*[
        z3.Or(w['address']!=a,w['value']!=resize(value,n*8),w['size_bytes']!=n)
        for w,(a,n,value) in zip(v.stores,[(frame+0x8ca8,8,continuation),(frame+0xb24,4,0x867a282a),(frame+0x36e8,8,parent)])]))
    x=z3.BitVec('header_normalizer_input64',64)
    for a,b,reg,k in R.NORMALIZERS:
        v=LemmaLift(reg);seed(v,R.CONTEXT);v.seed(reg,x);v.run_block(a,b)
        prove('normalizer_'+hex(a),v.read(reg)!=x^KEYS[k]);contexts.append(v.context)
    v=seed(Supplied({0x1005c5b70:(8,TABLE),0x1005c5b74:(8,0x10047c6a4)}),{'sp':frame,'w19':0x5054})
    v.run_block(0x1005c5b70,0x1005c5c60)
    prove('all_word_writer_context_constants_from_original_setup',z3.Or(*[v.read(n)!=a for n,a in R.CONTEXT.items()],
        v.read('x28')!=0x10047c6a4,v.read('x17')!=0x8241,
        *[a!=(frame+0x9d8 if pc==0x1005c5b70 else TABLE+8*0x5054) for pc,a,n in v.loads]))
    # Generic four-byte writer: arbitrary coordinates, payload and cached words.
    target=z3.BitVec('header_writer_continuation64',64)
    cache=[z3.BitVec('header_writer_cache'+str(j)+'64',64) for j in range(4)]
    values={0x10047c6a4:(8,TABLE),0x10047c6a8:(8,target),0x10047c6c0:(8,0x1010c67d4),
            0x10047c6d0:(8,0x1010c8268),**{pc:(4,mask) for pc in MASK_PCS},
            **{pc:(8,table) for pc in TABLE_PCS},**{pc:(8,cache[j]) for j,pc in enumerate(CACHE_PCS)}}
    v=seed(Reduced(values,contexts),{**R.CONTEXT,'sp':frame,'x22':base,'w9':coord-0xf741235c,'w10':payload,'w21':phase})
    v.run_block(0x10047c6a4,0x10047cd34)
    assert len(v.cuts)==15 and len(v.loads)==16 and len(v.stores)==4
    generic_cuts=v.cuts
    addresses=[base+z3.ZeroExt(32,coord+j) for j in range(4)]
    expected={0x10047c6a4:frame+0x9d8,0x10047c6a8:TABLE+8*z3.SignExt(32,phase),
              0x10047c6c0:frame+0x878,0x10047c6d0:frame+0x858,
              **{pc:z3.BitVecVal(0x1010c67d4,64) for pc in MASK_PCS},
              **{pc:z3.BitVecVal(0x1010c8268,64) for pc in TABLE_PCS},
              **{pc:table+index(addresses[j],mask) for j,pc in enumerate(CACHE_PCS)}}
    prove('all_writer_load_addresses_match_reader_cache_index',z3.Or(*[a!=expected[pc] for pc,a,n in v.loads]))
    def maskbyte(address,k):return z3.Extract(7,0,z3.LShR(word(address,k),(address&7)*8))
    for j,w in enumerate(v.stores):
        expected_byte=z3.Extract(31-8*j,24-8*j,payload^WHITEN)^maskbyte(addresses[j],cache[j])
        prove('word_writer_byte_'+str(j),z3.Or(w['address']!=addresses[j],w['size_bytes']!=1,w['value']!=expected_byte))
    stable={n:a for n,a in R.CONTEXT.items() if n!='x16'}
    prove('word_writer_return_and_repeated_call_context',z3.Or(v.read('x21')!=target,v.read('x17')!=0x1ac9,
        v.read('x22')!=base,v.read('x25')!=KEYS[6],v.read('x16')!=KEYS[4],v.read('x28')!=KEYS[5],
        v.read('x30')!=KEYS[3],v.read('sp')!=frame,*[v.read(n)!=a for n,a in stable.items()]))
    # The second-word carry circuit is an affine u32 transform followed by XOR.
    raw=z3.BitVec('header_saved_second_word32',32)
    v=seed(Supplied({0x1005189f4:(8,0x6cf4)}),{'sp':frame,'w8':0xffffe360,'w9':coord,'w10':raw})
    v.run_block(0x1005189c8,0x100518b2c)
    prove('second_word_arithmetic_all_u32',z3.Or(v.read('w10')!=((raw+0xeceb3944)^WHITEN),
        v.loads[0][1]!=frame+0x9d0))
    cells={0x9d0:0x6cf4,0x2338:base,0x3608:coord,0xb24:raw,0x9d8:TABLE,
           0x878:0x1010c67d4,0x858:0x1010c8268,0x76e0:u,0x3e00:0,0x662f:0,
           0x36e8:parent,0x16d0:cursor,0x8ca8:continuation}
    v=Composition(frame,cells,mask,table,contexts).compose()
    assert len(v.cuts)==45 and len(v.stores)==21 and len(v.caches)==12 and len(v.edges)==12
    count=coord+0x89271580
    prove('composed_all_private_global_and_cache_load_addresses',z3.Or(*v.address_checks,*[
        a!=table+index(base+z3.ZeroExt(32,count+4*batch+j),mask) for batch,j,a,k in v.caches]))
    logical=[z3.BitVecVal(20,32),raw+0xeceb3944,z3.BitVecVal(1,32)]
    for batch in range(3):
        bad=[]
        for j in range(4):
            w=v.stores[4*batch+j];a=base+z3.ZeroExt(32,count+4*batch+j);k=v.caches[4*batch+j][3]
            bad.extend([w['address']!=a,w['size_bytes']!=1,w['value']!=(
                z3.Extract(31-8*j,24-8*j,logical[batch])^maskbyte(a,k))])
        prove('composed_header_word_'+str(batch),z3.Or(*bad))
    field=coord+(0x6cf4^0x9a13b551)
    expected_stores=[(u+0x20,8,0),(u,8,base),(u+8,8,0),(u+0x14,4,field),
                     (u+0x18,4,coord),(u+0x10,4,field),(u+0x28,4,0xd299e646),
                     (parent,8,u),(frame+0x16d0,8,cursor-32)]
    prove('composed_U_fields_parent_publication_and_cursor_rewind',z3.Or(*[
        z3.Or(w['address']!=a,w['size_bytes']!=n,w['value']!=resize(value,n*8))
        for w,(a,n,value) in zip(v.stores[12:],expected_stores)]))
    prove('published_default_and_capacity_match_header_and_allocation',z3.Or(
        v.stores[15]['value']+0xef133bef!=coord+0x89271594,
        v.stores[16]['value']+0x89271580!=count))
    prove('composed_all_branch_targets_and_final_saved_return',z3.Or(*[target!=expected for pc,target,modifier,expected in v.edges],
        v.edges[-1][2]!=0x5ae9,v.read('sp')!=frame,v.read('w8')!=1))
    prove('header_extent_nonwrapping_and_all_20_record_bytes_inside_request',z3.Or(
        z3.ZeroExt(32,coord+0x89271594)!=z3.ZeroExt(32,count)+20,
        z3.UGE(count+19,coord+0x89271594),z3.ULT(count+19,count)),[z3.ULE(count,0xffffffeb)])
    composed_cuts,composed_loads=v.cuts,len(v.loads)
    # Separate source contracts at the retained saved continuation. No new
    # alternative interval is joined to that earlier clear-route snapshot.
    returned=z3.BitVec('header_caller_result32',32)
    v=seed(Supplied({0x1007812f4:(8,0x6cf4),0x100781320:(8,TABLE)}),{'sp':frame,'w8':returned})
    v.run_block(0x1007812e8,0x100781324)
    prove('caller_gate_uses_result_low_bit',z3.Or(v.read('w8')!=z3.If(returned&1!=0,
        z3.BitVecVal(0x64d7,32),z3.BitVecVal(0x6504,32)),v.read('w9')!=0x1a3,v.read('w19')!=0x8c1deaf7))
    v=seed(Supplied({0x1006b2204:(8,parent+0x4aba552460e435c6),0x1006b222c:(8,TABLE),
                    0x1006b2230:(8,0x1006bdb90)}),{'sp':frame,'w9':0x1a3})
    v.run_block(0x1006b2200,0x1006b223c)
    prove('caller_parent_bias_cancels_and_builds_result_pointer',z3.Or(v.read('x10')!=parent,
        v.read('x11')!=frame+0xd98,v.read('x12')!=0x1006bdb90,v.read('w8')!=0x6cf4,v.read('x17')!=0x5c3f,
        *[a!=expected for (pc,a,n),expected in zip(v.loads,[frame+0x26e0,frame+0x9d8,TABLE+8*0x602e])]))
    destination=z3.BitVec('header_caller_destination64',64)
    v=seed(Supplied({0x1006bdb98:(8,u),0x1006bdb9c:(8,TABLE),0x1006bdba0:(8,0x10072c448),
                    0x1006bdbd4:(8,destination)}),{'sp':frame,'x10':parent,'x11':frame+0xd98,'w9':0x1a3,'w8':0x6cf4})
    v.run_block(0x1006bdb90,0x1006bdbe4)
    route=z3.If(u!=0,z3.BitVecVal(0x9344,64),z3.BitVecVal(0x92f1,64))
    prove('caller_reloads_published_U_and_saves_child_result_pair',z3.Or(
        *[a!=expected for (pc,a,n),expected in zip(v.loads,[parent,frame+0x9d8,TABLE+8*0x1a3,TABLE+8*route])],
        *[z3.Or(w['address']!=a,w['value']!=value,w['size_bytes']!=8) for w,(a,value) in zip(v.stores,
             [(frame+0x3980,0x10072c448),(frame+0xaf18,u),(frame+0xaf20,frame+0xd98)])],v.read('x17')!=0xe3b))
    return out,{'generic':generic_cuts,'composition':composed_cuts},composed_loads


def controls():
    c=z3.BitVec('header_control_coordinate32',32);raw=z3.BitVec('header_control_raw32',32)
    specs=[('wrapping_extent_cannot_establish_record_room',z3.And(c==0xfffffff0,z3.ULT(c+20,c)),'sat'),
           ('arbitrary_input_does_not_force_sean',raw+0xeceb3944!=0x7365616e,'sat'),
           ('retained_input_maps_to_sean',z3.BitVecVal(0x867a282a,32)+0xeceb3944!=0x7365616e,'unsat'),
           ('span_word_payload_and_writer_whitening_cancel',z3.BitVecVal(0x36cad8a7,32)^WHITEN!=20,'unsat'),
           ('third_word_payload_and_writer_whitening_cancel',z3.BitVecVal(0x36cad8b2,32)^WHITEN!=1,'unsat')]
    out=[]
    for label,condition,expected in specs:
        s=z3.Solver();s.set(timeout=30000);s.add(condition);assert str(s.check())==expected,label
        out.append({'label':label,'query':s.to_smt2(),'result':expected,'source_scalar_model_only':True,'native_admission_established':False})
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.extract()
    proofs,cuts,loads=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'source_sha256':sha(SOURCE),
        'dependencies':{p:sha(ROOT/p) for p in DEPS},'independent_totals':replay(e),'source_proofs':proofs,
        'scalar_controls':controls(),'proof_cut_lemmas':15,'proof_cut_applications':60,'proof_cut_contexts_verified':cuts,
        'composition':{'source_visits':e['verified_counts']['composed_source_visits'],'loads':loads,'stores':21,
            'buffer_byte_stores':12,'U_field_stores':7,'U_bytes_written':40,'U_bytes_not_written':8,
            'parent_pointer_stores':1,'cursor_stores':1,'branches':12,'word_writer_invocations':3},
        'source_alternative_header_publication_contract_established':True,'alternative_constructor_observed':False,
        'native_cache_epoch_established':False,'native_parent_epoch_established':False,'new_port_emission_established':False,
        'target_instruction_rewrites':0,'prior_admissions_rerun':False,'new_target_intervals':0,
        'new_guest_input_bytes':0,'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({'source_proofs':len(a['source_proofs']),**a['independent_totals'],'composition':a['composition']}),flush=True)
