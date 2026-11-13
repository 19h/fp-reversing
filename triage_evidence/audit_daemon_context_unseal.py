#!/usr/bin/env python3
"""Independent scalar/AdvSIMD replay and constructor/reader representation joins.

O(receipts+visits*(register state+byte effects)+query DAG) time/space;
solver work separate, 30 s/query. No native operations or hardware PAC.
"""
import json,struct,itertools,zlib,base64
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import Lift as ParentLift,fixture_bytes,state_bytes,join
from daemon_callback_simd import apply,lanes,packed,qname
from lskd_values_symbolic import resize
from lskd_values_symbolic import mem,cell
from recover_daemon_return_bank_origins import Algebra
from audit_daemon_environment_outputs import DEC
from validate_daemon_context_seal import encode,decode,pick,mask
import recover_daemon_context_unseal as R

class Lift(ParentLift):
    def __init__(self,c):
        super().__init__(c)
        for j,x in enumerate(c['entry_Q_registers32']):self.seed('q'+str(j),int(x,16))

    def key(self,n):return 'q'+n[1:] if n[:1] in 'qvsdhb' and n[1:].isdigit() else super().key(n)
    def width(self,n):return {'q':128,'v':128,'d':64,'s':32,'h':16,'b':8}[n[0]] if n[:1] in 'qvsdhb' and n[1:].isdigit() else super().width(n)
    def seed(self,n,v):self.regs[self.key(n)]=resize(v,128 if self.key(n).startswith('q') else 64)
    def write(self,n,v):
        if n in ['xzr','wzr']:return
        self.regs[self.key(n)]=z3.simplify(resize(resize(v,self.width(n)),128 if self.key(n).startswith('q') else 64))

    def frame(self,row):
        super().frame(row)
        for j,x in enumerate(row['Q_registers32']):
            assert self.projected(self.read('q'+str(j)))==int(x,16),(row['pc'],'Q'+str(j))
            self.counts['vector_register_values_checked']+=1

    def load(self,a,n):
        if n==16:
            lo=super().load(a,8);hi=super().load(a+8,8);return z3.Concat(hi,lo)
        return super().load(a,n)

    def store(self,a,n,value,pc):
        if n==16:
            super().store(a,8,resize(value,64),pc);super().store(a+8,8,z3.Extract(127,64,resize(value,128)),pc);return
        return super().store(a,n,value,pc)

    def one(self,i):
        self.pc=i.address;m=i.mnemonic;o=i.operands
        if m=='fneg':
            assert i.op_str=='d6, d6';self.write('d6',self.read('d6')^(1<<63));return
        if m in ['umull2','ushll2']:
            count,width=__import__('daemon_callback_simd').arrangement(i.op_str.split(',')[0]);source_width=width//2
            a=lanes(self.read(qname(i.reg_name(o[1].reg))),source_width,2*count)[count:]
            if m=='umull2':
                b=lanes(self.read(qname(i.reg_name(o[2].reg))),source_width,2*count)[count:]
                value=packed([z3.ZeroExt(source_width,x)*z3.ZeroExt(source_width,y) for x,y in zip(a,b)])
            else:value=packed([z3.ZeroExt(source_width,x)<<o[2].imm for x in a])
            self.write(qname(i.reg_name(o[0].reg)),value);return
        if apply(self,i):return
        if m=='ldurh':self.write(i.reg_name(o[0].reg),self.load(self.address(i,o[1]),2));return
        if m=='udiv':
            n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);b=self.operand(i,o[2],n)
            self.write(i.reg_name(o[0].reg),z3.If(b==0,z3.BitVecVal(0,n),z3.UDiv(a,b)));return
        return super().one(i)

def interfaces(e):
    parent=json.loads(read(ROOT/'daemon_network_gate_checks.json'));prod,images,table=R.producer();counts=Counter()
    for c in e['cases']:
        before=parent['consumer_cases'][c['parent_consumer_index']]['intervals'][-1];rows=c['intervals'];p=prod[c['producer_case_index']]
        expected=state_bytes(before);effects=c['image_premises']+[c['root_premise'],*c['foreign_owner_premises'],
            {'address':hex(R.CELL),'bytes_hex':c['encoded_reference_premise_hex']}]
        for f in effects:expected.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
        assert fixture_bytes(rows[0],'private')|fixture_bytes(rows[0],'image')==expected
        gp=before['boundary']['registers31'].copy();gp[9]=c['entry_X9_premise'];assert rows[0]['entry_registers31']==gp
        assert rows[0]['entry_PC']==hex(R.ENTRY) and rows[0]['caller_SP']==before['boundary']['SP'] and rows[0]['entry_NZCV']==before['boundary_NZCV']
        assert c['image_premises']==images and c['foreign_owner_premises']==[
            {'address':hex(R.D),'bytes_hex':p['sealed_context_hex']},{'address':hex(R.TABLE_DATA),'bytes_hex':table.hex()}]
        assert c['encoded_reference_premise_hex']==p['publication']['events'][0]['value']['hex']
        for a,b in zip(rows,rows[1:]):
            join(a,b);assert a['boundary']['Q_registers32']==b['entry_Q_registers32'];counts['complete_intermediate_joins']+=1
        assert int.from_bytes(bytes(state_bytes(rows[0])[int(rows[0]['caller_SP'],16)+0xb6b0+j] for j in range(8)),'little')==R.D
        assert rows[1]['boundary']['registers31'][11]==hex(R.D) and rows[1]['boundary']['registers31'][8]==p['context_seed32']
        current=state_bytes(rows[-1]);raw=bytes(current[R.D+j] for j in range(552))
        assert raw.hex()==p['raw_context_hex']==c['final_context_hex']
        assert raw==decode(bytes.fromhex(p['sealed_context_hex']),int(p['context_seed32'],16))
        assert encode(raw,int(p['context_seed32'],16)).hex()==p['sealed_context_hex']
        assert int.from_bytes(raw[8:16],'little')==int(c['final_raw_lock64'],16)==int(p['raw_lock_value64'],16)
        writes=[w for r in rows for w in r['source_writes'] if w['address']==hex(R.CELL)]
        assert len(writes)==1 and writes[0]['pc']=='0x100481d98' and writes[0]['after_hex']==struct.pack('<Q',R.D).hex()
        assert all(not r['source_calls'] for r in rows)
        for r in rows:
            for w in r['source_writes']:
                a=int(w['address'],16);n=w['size_bytes']
                assert R.D<=a<a+n<=R.D+552 or 0x6800000000<=a<a+n<=0x6800100000 or a==R.CELL
                if R.D<=a<R.D+552:counts['bounded_context_write_bytes']+=n
        counts.update(caller_to_constructor_state_joins=1,reference_decode_checks=1,complete_context_inverse_checks=1,raw_lock_field_checks=1,raw_reference_publications=1)
    for c in e['reference_cases']:
        pre,post,dec=c['intervals'];pointer=int(c['pointer_word64'],16);fold=int(c['fold32'],16);k=fold*0xeb36c1ca&0xffffffff
        join(pre,post);assert pre['boundary']['Q_registers32']==post['entry_Q_registers32']
        assert pre['boundary']['pc']=='0x1003c41d0' and post['entry_PC']=='0x1003c4324' and c['context_body_not_executed_in_this_component_control']
        for reg,i in [(15,7),(14,6),(13,5),(11,3)]:
            assert int(pre['boundary']['registers31'][reg],16)==((((k+i)&0xffffffff)^k)*0x01000193&0xffffffff)%i
        join(post,dec,same_registers=False);expected=post['boundary']['registers31'].copy()
        for reg,value in [(9,int(c['encoded_reference64'],16)),(10,fold),(8,0xeb36c1ca)]:expected[reg]=hex(value)
        assert expected==dec['entry_registers31'] and post['boundary']['Q_registers32']==dec['entry_Q_registers32']
        current=state_bytes(dec);s=int(dec['caller_SP'],16)
        assert int.from_bytes(bytes(current[s+0xb6b0+j] for j in range(8)),'little')==pointer
        packed_word=int(c['encoded_reference64'],16);a=[(k*k^k)&0xffffffff,((k|1)*k^k)&0xffffffff]
        words=struct.unpack('<2I',struct.pack('<Q',packed_word));raw=bytearray(struct.pack('<2I',*[
            ((((words[j]^a[j])-a[j])*0x359c449b)&0xffffffff) for j in range(2)]))
        for i in range(1,8):j=((((k+i)&0xffffffff)^k)*0x01000193&0xffffffff)%i;raw[i],raw[j]=raw[j],raw[i]
        assert int.from_bytes(raw,'little')==pointer and not c['native_pointer_validity_claimed']
        assert all(not r['source_calls'] and not r['foreign_owners'] for r in c['intervals'])
        counts.update(isolated_reference_inverse_controls=1,encoder_decoder_state_joins=2,source_reference_index_checks=4)
    return {'verified_counts':dict(counts),'scope':'Separate producer-compatible state transfer; native epoch, ownership, synchronization and daemon-kext pairing remain unknown.'}

class Equation(Lift):
    def __init__(self):Algebra.__init__(self)
    load=Algebra.load;store=Algebra.store
    def block(self,a,b):
        for ins in DEC.disasm(IMAGE.read(a,b-a),a):self.one(ins)

def obligations():
    qs=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    byte,k,i=z3.BitVecs('cu_byte8 cu_key8 cu_index8',8)
    prove('all_byte_multiply_and_xor_inverse',((((byte^k)*0x93)*0x9b)^k)!=byte)
    word,add=z3.BitVecs('cu_word32 cu_add32',32)
    prove('all_u32_reference_lane_affine_inverse',(((add+word*0x01000193)^add)^add)-add!=word*0x01000193)
    prove('all_u32_reference_lane_odd_multiplier_inverse',(word*0x01000193)*0x359c449b!=word)
    a,b=z3.BitVecs('cu_swap_A64 cu_swap_B64',64);x=a^b;y=x^b;z=y^x
    prove('all_u64_distinct_address_XOR_swap',z3.Or(y!=a,z!=b))
    for d,m,sh,adjust in [(7,0x24924925,2,True),(6,0xaaaaaaab,2,False),(5,0xcccccccd,2,False),(3,0xaaaaaaab,1,False)]:
        n=z3.Int('cu_div_n_'+str(d));hi=(n*m)/(1<<32)
        quotient=(hi+(n-hi)/2)/(1<<sh) if adjust else hi/(1<<sh)
        prove('all_u32_magic_quotient_divisor_'+str(d),quotient!=n/d,z3.And(n>=0,n<(1<<32)))
    seed,index=z3.BitVecs('cu_seed32 cu_index32',32);data=z3.BitVec('cu_data128',128);base=0x70000000
    v=Equation();v.seed('x11',base);v.seed('x9',0);v.seed('q16',z3.Concat(seed,seed,seed,seed))
    v.seed('q5',0x009b009b009b009b);v.seed('q6',int.from_bytes(bytes.fromhex('9b00'*8),'little'))
    v.seed('q4',int.from_bytes(IMAGE.read(0x100e2c6c0,16),'little'))
    for q,off in [(0,12),(1,8),(2,4),(3,0)]:v.seed('q'+str(q),z3.Concat(*[index+off+j for j in range(3,-1,-1)]))
    mem(v,base,16,data);v.block(0x100481cb4,0x100481d1c)
    expected=z3.Concat(*reversed([(z3.Extract(j*8+7,j*8,data)*0x9b)^z3.Extract(7,0,seed^((index+j+seed)*(index+j-seed))) for j in range(16)]))
    prove('all_u32_seed_index_and_128_input_bits_original_vector_inverse',cell(v,base,16)!=expected)
    data4=z3.BitVec('cu_tail_data32',32);v=Equation();v.seed('x8',base);v.seed('x9',0);v.seed('q0',z3.Concat(seed,seed,seed,seed))
    v.seed('q1',z3.Concat(*[index+j for j in range(3,-1,-1)]));v.seed('q2',0x009b009b009b009b);mem(v,base,4,data4)
    v.block(0x100481d54,0x100481d80)
    expected=z3.Concat(*reversed([(z3.Extract(j*8+7,j*8,data4)*0x9b)^z3.Extract(7,0,seed^((index+j+seed)*(index+j-seed))) for j in range(4)]))
    prove('all_u32_seed_index_and_32_input_bits_original_tail_inverse',cell(v,base,4)!=expected)
    for d in [1,2,4]:
        prove('reference_shuffle_index_is_zero_for_divisor_'+str(d),z3.URem(((seed+d)^seed)*0x01000193,z3.BitVecVal(d,32))!=0)
    n=z3.BitVec('cu_word_index32',32);v=Equation();v.seed('w8',seed);v.seed('w10',n);v.seed('w9',0x01000193)
    v.block(0x100481c2c,0x100481c38);numerator=((seed+n)^seed)*0x01000193
    prove('original_inverse_word_numerator',v.read('w12')!=numerator)
    u32,q32=z3.BitVecs('cu_machine_numerator32 cu_machine_quotient32',32);v=Equation()
    v.seed('w12',u32);v.seed('w13',q32);v.seed('w10',n);v.block(0x100481c3c,0x100481c40)
    prove('original_inverse_word_remainder_subtraction',v.read('w12')!=u32-q32*n)
    for d in range(1,69):
        u=z3.Int('cu_numerator_for_divisor_'+str(d));q=u/d;rem=u-q*d
        prove('inverse_word_remainder_range_and_nonoverflow_divisor_'+str(d),
              z3.Or(rem<0,rem>=d,q*d>u,q*d>=(1<<32)),z3.And(u>=0,u<(1<<32)))
    return qs

def producer_audit(e):
    original=json.loads(read(ROOT/'daemon_context_lock_profiles.json'))['cases']+[json.loads(read(ROOT/'daemon_context_lock_success.json'))['case']]
    count=0
    for c,p in zip(original,e['producer_evidence']):
        trace=json.loads(zlib.decompress(base64.b64decode(c['payload_zlib_base64'])))
        for step in trace['steps']:
            assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex'];count+=1
            for ev in step['events']:
                if ev['kind']=='write':assert not(int(ev['address'],16)<R.TABLE_DATA+512 and R.TABLE_DATA<int(ev['address'],16)+ev['size_bytes'])
        fold=int(p['context_seed32'],16)^((R.D*0xeb36c1ca)&0xffffffff)
        assert fold==0xc41c69cd and R.reference_encode(R.D,fold)==int.from_bytes(bytes.fromhex(p['publication']['events'][0]['value']['hex']),'little')
        assert decode(bytes.fromhex(p['sealed_context_hex']),int(p['context_seed32'],16)).hex()==p['raw_context_hex']
    assert count==43843
    return {'producer_profiles_checked':13,'original_source_visits_checked':count,'table_extent_bytes':512,'later_table_overlapping_writes':0}

def permutation_certificate():
    # The descending eight-byte shuffle has four variable indices; the
    # modulo-4/2/1 indices are zero. Enumerate every bounded combination.
    rows=[]
    for j7,j6,j5,j3 in itertools.product(range(7),range(6),range(5),range(3)):
        choices={7:j7,6:j6,5:j5,4:0,3:j3,2:0,1:0};p=list(range(8))
        for i in range(7,0,-1):j=choices[i];p[i],p[j]=p[j],p[i]
        q=p.copy()
        for i in range(1,8):j=choices[i];q[i],q[j]=q[j],q[i]
        assert q==list(range(8));rows.append({'indices':[j7,j6,j5,j3],'encoded_source_byte_indices':p})
    assert len(rows)==630;return rows

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    counts=Counter();lifts=[]
    for j,row in enumerate(R.intervals(e)):
        result=Lift(row).run();result['interval_index']=j;lifts.append(result);counts.update(result['verified_counts'])
        if j%8==0:print(json.dumps({'interval':j,'source_visits':counts['source_visits']}),flush=True)
    qs=obligations();cert=permutation_certificate()
    return {'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'independent_lifts':lifts,'independent_totals':dict(counts),'interfaces':interfaces(e),'source_proofs':qs,
            'source_queries_unsat':len(qs),'permutation_certificate':cert,'producer_audit':producer_audit(e),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'interfaces':e['interfaces']}),flush=True)
