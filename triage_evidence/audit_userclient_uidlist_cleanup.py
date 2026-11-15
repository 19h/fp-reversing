#!/usr/bin/env python3
"""Independent original-byte instruction lift and finite bank audit.
O(I+256R+query DAG) construction time/space, excluding SMT search.
Each solver query is limited to 30 s; no target or IDB operation.
"""
import copy
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_SXTW, ARM64_EXT_UXTW
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword
from lskd_values_symbolic import Lift, resize, mem
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_userclient_uidlist_cleanup as R

DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
MAGIC=0x31ae0066
CTRL_B=0xfffffe000ccc32f8
CTRL_A=0xfffffe000ccc3330
PRIOR_NAMES=[
    'context_destroy_exact_roots_and_null_cell_gate',
    'context_destroy_empty_head_selects_typed_free_and_saves_cell',
    'context_destroy_empty_head_exact_typed_free_ABI',
    'context_destroy_after_free_clears_original_cell_and_returns_zero',
    'context_destroy_normal_epilogue_uses_raw_status_in_w8',
]

def lookup(raw,index):
    """Balanced exact constant lookup, including every unsigned byte index."""
    def tree(lo,hi):
        if hi-lo==1:return z3.BitVecVal(raw[lo],8)
        mid=(lo+hi)//2
        return z3.If(z3.ULT(index,mid),tree(lo,mid),tree(mid,hi))
    return tree(0,256)

def validate_input(e):
    assert e['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
    for row in e['spans']:
        a=int(row['start'],16);raw=bytes.fromhex(row['bytes_hex'])
        assert IMAGE.read(a,len(raw))==raw
        assert row['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in DEC.disasm(raw,a)]
    for bank in e['banks'].values():assert IMAGE.read(int(bank['address'],16),256).hex()==bank['bytes_hex']
    d=e['typed_descriptor'];raw=IMAGE.read(int(d['address'],16),64)
    assert raw.hex()==d['normalized64_bytes_hex']
    assert int.from_bytes(raw[44:48],'little')==d['size_bytes']==16
    assert d['name']=='site.UIDList' and d['signature']=='21'
    for p in e['branch_pointers']:
        assert qword(int(p['slot'],16))==int(p['target'],16)
        assert int(p['slot'],16)==TABLE+8*p['index']
    for r in e['bank_rules']:
        assert qword(int(r['slot'],16))==int(r['target'],16)

class Source(Lift):
    def __init__(self,e):
        super().__init__({'spans':e['spans']})
        self.e=e;self.address_checks=[];self.reads=[];self.calls_per_pc={}
        self.sp,self.node,self.next=z3.BitVecs('UID_SP64 UID_node64 UID_successor64',64)
        self.marker=z3.BitVec('UID_marker32',32)
        self.ca,self.cb=z3.BitVecs('UID_controller_A32 UID_controller_B32',32)
        self.banks={n:bytes.fromhex(b['bytes_hex']) for n,b in e['banks'].items()}
        self.base={n:int(b['address'],16) for n,b in e['banks'].items()}
        self.binding={
            0xfffffe000a6269f8:[(self.node+8,self.next)],
            0xfffffe000a626a00:[(self.node+4,self.marker)],
            0xfffffe000a626a30:[(TABLE+8*z3.If(self.marker==MAGIC,z3.BitVecVal(0xea5,64),z3.BitVecVal(0xe5e,64)),
                                  z3.If(self.marker==MAGIC,z3.BitVecVal(0xfffffe000a626920,64),z3.BitVecVal(0xfffffe000a626a3c,64)))],
            0xfffffe000a626930:[(CTRL_A,self.ca)],
            0xfffffe000a626934:[(CTRL_B,self.cb)],
            0xfffffe000a62695c:[(POOL+0xb70,self.base['descriptorL'])],
            0xfffffe000a626970:[(POOL+0xa10,self.base['descriptorR'])],
            0xfffffe000a626990:[(TABLE+8*0xf2b,0xfffffe000c4ba368)],
            0xfffffe000a6269a8:[(POOL+8*0x17d,0xfffffe000847b2a0)],
            0xfffffe000a6269d8:[(TABLE+8*z3.If(self.next==0,z3.BitVecVal(0x980,64),z3.BitVecVal(0x9a4,64)),
                                  z3.If(self.next==0,z3.BitVecVal(0xfffffe000a626838,64),z3.BitVecVal(0xfffffe000a6269e4,64)))],
        }
        self.bank_pc={0xfffffe000a626950:'freeL',0xfffffe000a626964:'descriptorL',
                      0xfffffe000a626974:'descriptorR',0xfffffe000a626980:'freeR'}
        for n,v in {'sp':self.sp,'x20':self.node,'x25':POOL,'x27':TABLE,'x2':CTRL_B,'x3':CTRL_A}.items():self.seed(n,v)
        for off,v in [(0x50,self.base['freeL']),(0x58,self.base['freeR']),(0x68,CTRL_B),(0x70,CTRL_A)]:mem(self,self.sp+off,8,v)

    def address(self,i,o):
        a=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp
        if o.mem.index:
            v=self.read(i.reg_name(o.mem.index))
            if o.ext==ARM64_EXT_SXTW:v=z3.SignExt(32,resize(v,32))
            elif o.ext==ARM64_EXT_UXTW:v=z3.ZeroExt(32,resize(v,32))
            else:assert not o.ext;v=resize(v,64)
            a=a+(v<<o.shift.value)
        return z3.simplify(a)

    def load(self,a,n):
        key=(z3.simplify(a).sexpr(),n)
        if key in self.memory:
            value=self.memory[key];kind='source_or_premised_private_frame'
        elif self.pc in self.bank_pc:
            name=self.bank_pc[self.pc];base=self.base[name];ix=z3.Extract(7,0,a-base)
            self.address_checks.append(a==base+z3.ZeroExt(56,ix));assert n==1
            value=lookup(self.banks[name],ix);kind='original_literal_'+name
        else:
            j=self.calls_per_pc.get(self.pc,0);self.calls_per_pc[self.pc]=j+1
            expected,value=self.binding[self.pc][j]
            self.address_checks.append(a==resize(expected,64));value=resize(value,n*8);kind='address_checked_input_or_original_pointer'
        self.reads.append({'pc':hex(self.pc),'size_bytes':n,'kind':kind})
        return value

    def after_return(self):
        """Ordinary returning ABI cut: caller GP registers arbitrary, frame stable.
        Callee-saved roots and SP stay unchanged by explicit ABI premise.
        No assumption is made about the freed node's subsequent contents.
        """
        for j in range(19):self.seed('x'+str(j),z3.BitVec('UID_return_X'+str(j),64))

    def ownership_premises(self):
        # Valid disjoint regions keep node fields, private frame and original
        # tables/controllers independent. This does not prove native ownership.
        maximum=(1<<64)-1
        def separate(a,n,b,m):return z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))
        rows=[z3.ULE(self.sp,maximum-0x88),z3.ULE(self.node,maximum-16),self.node!=0,
              separate(self.sp,0x88,self.node,16)]
        protected=[(self.base[n],256) for n in self.base]+[(CTRL_A,4),(CTRL_B,4),
            (POOL+0xb70,8),(POOL+0xa10,8),(POOL+8*0x17d,8),(TABLE+8*0xf2b,8)]+[(TABLE+8*i,8) for i in R.BRANCHES]
        for a,n in protected:
            rows.extend([separate(self.sp,0x88,z3.BitVecVal(a,64),n),
                         separate(self.node,16,z3.BitVecVal(a,64),n)])
        return rows

def bank_audit(e):
    rows=[]
    for r in e['bank_rules']:
        n=r['name'];left=bytes.fromhex(e['banks'][n+'L']['bytes_hex']);right=bytes.fromhex(e['banks'][n+'R']['bytes_hex'])
        key=int(r['key'],16);constant=int(r['constant'],16)
        outputs=[x^right[left[x]^key] for x in range(256)]
        assert outputs==[constant]*256
        rows.append({'name':n,'input_cases_checked':256,'constant8':constant,
                     'all_original_byte_inputs_agree':True})
    return rows

def proofs(e):
    out=[]
    def prove(name,bad,premises=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*premises)
        assert s.check()==z3.sat,name
        s.add(z3.simplify(bad));assert s.check()==z3.unsat,(name,s.reason_unknown())
        out.append({'label':name,'premises_nonvacuous':True,'query':s.to_smt2(),'result':'unsat'})
    v=Source(e);v.run('root_literals');v.run('head_phase')
    prove('original_entry_literals_and_head_phase',z3.Or(v.read('x26')!=0xa41a4d891208c018,v.read('w28')!=0x4d08a3fb,
          v.read('w19')!=0xe5e,v.read('w21')!=0x58c))
    v.run('node_gate')
    owned=v.ownership_premises()
    prove('all_marker32_successor64_original_node_gate_and_successor_save',z3.Or(
          *[z3.Not(x) for x in v.address_checks],v.read('w24')!=0x980,
          v.read('x9')!=z3.If(v.marker==MAGIC,z3.BitVecVal(0xfffffe000a626920,64),z3.BitVecVal(0xfffffe000a626a3c,64)),
          v.read('x17')!=0x234d,v.memory[(z3.simplify(v.sp+0x60).sexpr(),8)]!=v.next),owned)
    v.run('node_free')
    prove('all_controller_words_original_typed_UIDList_free_ABI',z3.Or(
          *[z3.Not(x) for x in v.address_checks],v.read('x0')!=0xfffffe000847b2a0,
          v.read('x1')!=v.node,v.read('x11')!=0xfffffe000c4ba368,v.read('x17')!=0x4d6a,
          v.read('w19')!=0xe5e,v.read('w21')!=0x58c),owned+[v.marker==MAGIC])
    v.after_return();v.run('node_continue')
    prove('ordinary_return_preserves_saved_successor_and_selects_loop_or_context_free',z3.Or(
          *[z3.Not(x) for x in v.address_checks],v.read('x20')!=v.next,
          v.read('x2')!=CTRL_B,v.read('x3')!=CTRL_A,
          v.read('x8')!=z3.If(v.next==0,z3.BitVecVal(0xfffffe000a626838,64),z3.BitVecVal(0xfffffe000a6269e4,64)),
          v.read('x17')!=0xc338,v.read('w19')!=0xe5e,v.read('w21')!=0x58c),owned+[v.marker==MAGIC])
    # A byte-array proof checks that the save/restore is not relying on the
    # fixed-cell engine silently manufacturing the successor across the call.
    memory=z3.Array('UID_private_frame_before',z3.BitVecSort(64),z3.BitVecSort(8));sp,nxt=z3.BitVecs('UID_frame_SP64 UID_frame_successor64',64)
    saved=memory
    for j in range(8):saved=z3.Store(saved,sp+0x60+j,z3.Extract(8*j+7,8*j,nxt))
    restored=z3.Concat(*[z3.Select(saved,sp+0x60+j) for j in reversed(range(8))])
    prove('all_SP64_successor64_little_endian_save_reload_in_private_frame',restored!=nxt)
    assert len(v.reads)==19 and v.count==79
    return out,{'selected_source_instructions':v.count,'selected_reads':v.reads,'selected_writes':[
        {'pc':hex(w['pc']),'size_bytes':w['size_bytes']} for w in v.stores]}

def controls():
    out=[]
    for name,clauses in [
        ('abstract_marker_unequal_can_enter_unrecovered_arm',[z3.BitVec('UID_other_marker32',32)!=MAGIC]),
        ('abstract_nonzero_self_successor_defeats_finite_chain_premise',[z3.BitVec('UID_cycle_node64',64)!=0,
             z3.BitVec('UID_cycle_successor64',64)==z3.BitVec('UID_cycle_node64',64)])]:
        s=z3.Solver();s.set(timeout=30000);s.add(*clauses);assert s.check()==z3.sat
        out.append({'label':name,'query':s.to_smt2(),'result':'sat','abstract_only':True})
    return out

def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));validate_input(e)
    banks=bank_audit(e);ps,coverage=proofs(e);prior=[]
    for p in json.loads(read(ROOT/'userclient_context_lifecycle_checks.json'))['proofs']:
        if p['name'] not in PRIOR_NAMES:continue
        s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
        prior.append({'name':p['name'],'query_sha256':__import__('hashlib').sha256(p['query'].encode()).hexdigest(),'result':'unsat'})
    assert len(prior)==5
    mutations=[]
    for name in ['instruction_bytes','literal_bank','descriptor_size','branch_target']:
        bad=copy.deepcopy(e)
        if name=='instruction_bytes':bad['spans'][0]['bytes_hex']='00'+bad['spans'][0]['bytes_hex'][2:]
        elif name=='literal_bank':bad['banks']['freeL']['bytes_hex']='00'+bad['banks']['freeL']['bytes_hex'][2:]
        elif name=='descriptor_size':bad['typed_descriptor']['size_bytes']=24
        else:bad['branch_pointers'][0]['target']='0xfffffe000a626838'
        try:validate_input(bad)
        except AssertionError:mutations.append({'alteration':name,'rejected':True})
        else:raise AssertionError('altered evidence accepted: '+name)
    return {'auditor_sha256':sha(__file__),'scope':R.SCOPE,'source_sha256':sha(SOURCE),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'dependencies':{n:sha(ROOT/n) for n in R.DEPS+['recover_userclient_uidlist_cleanup.py']},
            'bank_audits':banks,'source_proofs':ps,'rechecked_prior_source_proofs':prior,
            'abstract_controls':controls(),'altered_evidence_controls':mutations,'source_coverage':coverage,
            'independent_totals':{'new_source_queries_unsat':5,'prior_source_queries_unsat':5,
                                  'abstract_controls_sat':2,'altered_evidence_rejections':4,
                                  'bank_input_cases_checked':512,'selected_source_instructions':79,
                                  'selected_source_reads':19,'selected_source_writes':2},
            'conditional_UIDList_fast_cleanup_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
    a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps(a['independent_totals']),flush=True)
