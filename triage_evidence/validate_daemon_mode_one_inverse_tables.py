#!/usr/bin/env python3
"""Source SSA and finite algebra certificates;no CPU/target/API execution."""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_inverse_tables import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_scatter import Engine as Parent,ADDR,lookup,DIVS,SELECTORS,ADDRESS_GROUPS,SWAPS
from validate_daemon_list_output import bv,split
from validate_daemon_existing_scalar_reader import DECL,z,neq,prefix
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['IDX','JDX','ARG','CWORD0','CWORD1']+['A'+str(j)for j in range(4)]+['SEL'+str(j)for j in range(14)])+'(declare-fun CELL0 () (_ BitVec 64))\n(declare-fun CELL1 () (_ BitVec 64))\n'
EXTRA+=''.join(f'(declare-fun {n}_S{j} () (_ BitVec 32))\n'for n in['first','second']for j in range(15))
A=[(84784+757*j)%963 for j in range(16)];B=[(12869+757*j)%963 for j in range(16)];C=[(534442+757*j)%963 for j in range(256)]
def frame(o):return f'(bvadd K {bv(o)})'
def at(i):return f'(bvadd TABLE {bv(i*8)})'
def lut(values,arg,width=32):
 e=bv(values[-1],width)
 for j in range(len(values)-2,-1,-1):e=f'(ite (= {arg} {bv(j,width)}) {bv(values[j],width)} {e})'
 return e
def xor(*values):
 e=values[0]
 for v in values[1:]:e=f'(bvxor {e} {v})'
 return e
class Engine(Parent):
 def operand(self,t,w,shift=None):
  if shift and shift.split()[0]in('uxtb','uxth'):
   p=shift.split();n=8 if p[0]=='uxtb'else 16;e=f'((_ zero_extend {w-n}) {self.get(t,n)})'
   return f'(bvshl {e} {bv(int(p[1][1:],0),w)})'if len(p)>1 else e
  return super().operand(t,w,shift)
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   ps=split(i['operands']);m=i['mnemonic'];w=32 if ps[0].startswith('w')else 64
   if m=='adrp':self.put(ps[0],self.get(ps[1],w))
   elif m=='ubfiz':
    l,n=int(ps[2][1:],0),int(ps[3][1:],0);self.put(ps[0],f'(bvshl (bvand {self.get(ps[1],w)} {bv((1<<n)-1,w)}) {bv(l,w)})')
   elif m=='bfxil':
    l,n=int(ps[2][1:],0),int(ps[3][1:],0);mask=(1<<n)-1;self.put(ps[0],f'(bvor (bvand {self.get(ps[0],w)} {bv(~mask,w)}) (bvand (bvlshr {self.get(ps[1],w)} {bv(l,w)}) {bv(mask,w)}))')
   elif m=='mvn':self.put(ps[0],f'(bvnot {self.get(ps[1],w)})')
   else:super().run({'instructions':[i]},pc+4);continue
   self.sites.append(i['ea'])
  return self
def fresh(label,r=None,loads=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=label+'_');g.declarations='';return g
SECOND_DIVS={
 1:(0x100dbfc94,0x100dbfc9c,'w8',15,0,0,'w17',{17:15}),
 2:(0x100dbfcd4,0x100dbfcf0,'w13',14,0x92492493,34,'w17',{}),
 3:(0x100dbfcf8,0x100dbfd14,'w9',13,0x4ec4ec4f,34,'w1',{}),
 4:(0x100dbfda0,0x100dbfdb8,'w0',12,0xaaaaaaab,35,'w0',{}),
 5:(0x100dbfe14,0x100dbfe24,'w2',11,0xba2e8ba3,35,'w0',{0:0xba2e8ba3}),
 6:(0x100dbfde4,0x100dbfdfc,'w13',10,0xcccccccd,35,'w1',{}),
 7:(0x100dbfe6c,0x100dbfe84,'w5',9,0x38e38e39,33,'w0',{}),
 9:(0x100dbff2c,0x100dbff50,'w1',7,0x24924925,32,'w5',{}),
 10:(0x100dbfee0,0x100dbfef0,'w6',6,0xaaaaaaab,34,'w2',{10:0xaaaaaaab}),
 11:(0x100dbffe0,0x100dbfff0,'w20',5,0xcccccccd,34,'w8',{8:0xcccccccd}),
 13:(0x100dc00b8,0x100dc014c,'w11',3,0xaaaaaaab,33,'w10',{10:0xaaaaaaab}),
}
SECOND_SELECTORS={e-4:(j,out)for j,(_,e,_,_,_,_,out,_)in SECOND_DIVS.items()}
SECOND_SELECTORS.update({0x100dbfc58:(0,'w10'),0x100dbff64:(8,'w0'),0x100dc00dc:(12,'w1'),0x100dc01ec:(14,'w8')})
SECOND_ADDRESSES=[
 (0x100dbfc70,0x100dbfc78,'w10','w16',0,'w10'),
 (0x100dbfcbc,0x100dbfcc4,'w10','w16',1,'w10'),
 (0x100dbfd30,0x100dbfd38,'w12','w16',2,'w12'),
 (0x100dbfd54,0x100dbfd5c,'w17','w16',3,'w0'),
 (0x100dbfdd0,0x100dbfdd8,'w0','w16',4,'w8'),
 (0x100dbfe38,0x100dbfe40,'w12','w16',5,'w12'),
 (0x100dbfe84,0x100dbfe8c,'w12','w16',6,'w12'),
 (0x100dbfef0,0x100dbfef8,'w9','w16',7,'w0'),
 (0x100dbff6c,0x100dbff74,'w7','w16',8,'w7'),
 (0x100dbffa0,0x100dbffa8,'w17','w16',8,'w17'),
 (0x100dbffc4,0x100dbffcc,'w17','w16',9,'w17'),
 (0x100dc0018,0x100dc0020,'w17','w16',10,'w17'),
 (0x100dc0074,0x100dc007c,'w8','w16',11,'w17'),
 (0x100dc0160,0x100dc0168,'w13','w16',12,'w13'),
 (0x100dc0180,0x100dc0188,'w0','w16',12,'w13'),
 (0x100dc01b0,0x100dc01b8,'w11','w16',13,'w11'),
 (0x100dc01cc,0x100dc01d4,'w10','w16',13,'w10'),
 (0x100dc01fc,0x100dc0204,'w8','w16',14,'w8'),
]
SECOND_SWAPS=[
 (0x100dbfc9c,0x100dbfc80,0x100dbfca0,0x100dbfca4),
 (0x100dbfcf4,0x100dbfccc,0x100dbfd18,0x100dbfd1c),
 (0x100dbfd20,0x100dbfd4c,0x100dbfd50,0x100dbfd6c),
 (0x100dbfd78,0x100dbfd74,0x100dbfd7c,0x100dbfd90),
 (0x100dbfd94,0x100dbfde0,0x100dbfe24,0x100dbfe28),
 (0x100dbfe50,0x100dbfe48,0x100dbfe58,0x100dbfe5c),
 (0x100dbfe90,0x100dbfe98,0x100dbfea4,0x100dbfea8),
 (0x100dbfecc,0x100dbff54,0x100dbff58,0x100dbff5c),
 (0x100dbff78,0x100dbff7c,0x100dbff80,0x100dbffac),
 (0x100dbffd0,0x100dbfff8,0x100dbfffc,0x100dc0000),
 (0x100dc0028,0x100dc0044,0x100dc0060,0x100dc0064),
 (0x100dc0080,0x100dc0088,0x100dc008c,0x100dc0094),
 (0x100dc0154,0x100dc016c,0x100dc017c,0x100dc01a4),
 (0x100dc01c0,0x100dc01bc,0x100dc01c4,0x100dc01d8),
 (0x100dc01e4,0x100dc020c,0x100dc0210,0x100dc0214),
]
def algebra(s):
 raw=bytes.fromhex(s['data_roots'][2]['bytes']);operation=[];rows=[]
 for x in range(256):
  arg=x^0x34;n=0x53807+527*arg;r=n%944;y=raw[r];v=y^(y>>1)^(0xe8|(y>>5))^0xac;assert 0<=v<16
  operation.append(v);rows.append({'input_byte':x,'source_argument':arg,'numerator':n,'table_offset':r,'encoded_byte':y,'decoded_nibble':v})
 op=lambda a,b:operation[a+16*b];identities=[e for e in range(16)if all(op(e,a)==a and op(a,e)==a for a in range(16))];assert identities==[9]
 cycle=[9]
 for j in range(15):cycle.append(op(cycle[-1],3))
 assert len(set(cycle))==16 and op(cycle[-1],3)==9
 assert all(op(cycle[a],cycle[b])==cycle[(a+b)%16]for a in range(16)for b in range(16))
 assert all(op(op(a,b),c)==op(a,op(b,c))for a in range(16)for b in range(16)for c in range(16))
 assert all(op(a,b)==op(b,a)for a in range(16)for b in range(16))
 assert all(len({op(a,b)for a in range(16)})==16 for b in range(16))
 return {'source_lookup_cases':rows,'operation256':operation,'identity':9,'generator':3,'cyclic_labels':cycle,'isomorphism_pairs':256,'associativity_triples':4096,'commutativity_pairs':256,'Latin_rows':16,'isomorphic_to_addition_mod16':True,'A_offsets':A,'B_offsets':B,'C_offsets':C}
def certificates(s):
 proofs=[];tr={};extra_sem={};fs=s['fragments'];math=algebra(s)
 def solve(n,body,cc=(),result='unsat',integer=False,extra='',note=''):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+extra+''.join('(assert '+c+')\n'for c in cc)+body+'\n(check-sat)\n';p=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert p.returncode==0 and not p.stderr and p.stdout.strip()==result,(n,p.stdout,p.stderr);proofs.append({'name':n,'query':q,'result':result,'scope':note or SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',cc)
 def part(n,label=None,r=None,loads=None,a=None,end=None):
  label=label or n;f=fs[n];a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll=dict(loads or{});dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb')and i['ea']not in ll:
    w=8 if i['mnemonic']=='ldrb'else 32 if i['operands'].startswith('w')else 64;v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))');ll[i['ea']]=(v,w)
  g=fresh(label,r,ll);g.declarations='\n'.join(dd)+'\n';g.run({'instructions':ii},end);tr[label]=g.record();return g
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def st(g,pc):return next(q for q in g.stores if q['site']==hex(pc))
 seed=part('seed',r={13:bv(0x8a66),11:frame(0xd00)},loads={'0x100ca09c4':('TABLE',64)})
 constants={0:0x1a,3:963,4:0x20d201,5:0x8f5b2627,6:0x70a4d9d9,7:0xdde36fa6,12:0x6d9c,13:0x8a66,14:0x97,15:0x4509954f,16:0x2aa59c9a,19:0x221c905a,20:0x52b84955,21:0xad47b6ab,22:0x2a529,23:0x41,24:0x4428d341,25:0x08512482,26:0x08717682,27:0x44080140,28:0x3a85999e,30:0x2a06049a,1:0x4509953f,10:0xb9577d9c}
 cert('first_shuffle_exit_initializes_inverse_constants',seed,[neq(seed.get('w'+str(j)),bv(v,32))for j,v in constants.items()if j!=10]+[neq(rd(seed,0x100ca09c8)['address'],at(0x8a66)),neq(seed.get('x11'),frame(0xd00))])
 rr={k:bv(v)for k,v in constants.items()};rr.update({1:z('(bvadd #x4509953f IDX)'),11:frame(0xd00)})
 inv=part('inverse',r=rr,loads={'0x100dd1674':('B0',8),'0x100dd1724':(frame(0xd00),64),'0x100dd174c':('TABLE',64)})
 byte_index='((_ zero_extend 24) (bvxor B0 #xd4))';out=st(inv,0x100dd1730)
 cert('inverse_reads_A_and_writes_B_with_original_index',inv,[neq(rd(inv,0x100dd1674)['address'],f'(bvadd {frame(0xd00)} {z(lut(A,"IDX"))})'),neq(out['address'],f'(bvadd {frame(0xd00)} {z(lut(B,byte_index))})'),neq(out['value'],'((_ extract 7 0) (bvxor IDX #x000000d4))'),neq(inv.get('w1'),'(bvadd #x45099540 IDX)'),neq(inv.get('w10'),'#x0f8b967c'),neq(inv.get('w12'),'#x00006d9c'),neq(inv.get('w3'),'#x000003c3'),neq(inv.get('x11'),frame(0xd00)),neq(rd(inv,0x100dd1750)['address'],f'(ite (= IDX #x0000000f) {at(0x8a68)} {at(0x8a66)})')],['(bvult IDX #x00000010)','(bvuge B0 #xd0)','(bvult B0 #xe0)'])
 reset=part('reset',r={10:z('(bvadd #x0f8b967c IDX)'),12:bv(0x6d9c),11:frame(0xd00)},loads={'0x100c97418':('TABLE',64)})
 out=st(reset,0x100c973f4)
 cert('reset_restores_identity_A_without_touching_B',reset,[neq(out['address'],f'(bvadd {frame(0xd00)} {z(lut(A,"IDX"))})'),neq(out['value'],'((_ extract 7 0) (bvxor IDX #x000000d4))'),neq(reset.get('w14'),'#x000002f5'),neq(reset.get('w16'),'#x000003c3'),neq(reset.get('w4'),'#x00008d87'),neq(reset.get('w12'),'#x00006d9c'),neq(reset.get('x11'),frame(0xd00)),neq(rd(reset,0x100c9741c)['address'],f'(ite (= IDX #x0000000f) {at(0x6dcb)} {at(0x6d9c)})')],['(bvult IDX #x00000010)'])
 # Table-family roots are original unauthenticated rebases plus source bias.
 for n,slot,reg,which in [('left_root',0x1010a2fb8,'x22',0),('right_root',0x1010a4000,'x23',1)]:
  f=fs[n];pc=f['instructions'][0]['ea'];d=s['data_roots'][which];g=part(n,r={17:bv(0x1010a1960)},loads={pc:(bv(d['fixup']['target']),64)});cert(n+'_rebased_pointer_and_bias',g,[neq(rd(g,int(pc,16))['address'],bv(slot)),neq(g.get(reg),bv(int(d['target'],16)))])
 fr=part('frame_roots',r={24:'CELL1',23:bv(0x100f4e390),22:bv(0x100e99a00)});fc=part('frame_counter',r={2:'CELL0'})
 cert('frame_bank_and_counter_root_publication',fr,[neq(q['address'],frame(off))for q,off in zip(fr.stores,[0x438,0x570,0x578])]+[neq(fr.stores[0]['value'],'CELL1'),neq(fr.stores[1]['value'],bv(0x100f4e390)),neq(fr.stores[2]['value'],bv(0x100e99a00))]);cert('frame_counter_pointer_publication',fc,[neq(fc.stores[0]['address'],frame(0x580)),neq(fc.stores[0]['value'],'CELL0')])
 for d,m,shift,limit in[(963,0x440dd2cf,40,4294967295),(963,0x2207,23,65535),(963,0x440dd3,32,100000),(944,0x456c7a,32,500000)]:
  solve(f'exact_reciprocal_{d}_{shift}_{limit}',f'(assert (distinct (div (* XI {m}) {1<<shift}) (div XI {d})))',['(<= 0 XI)',f'(<= XI {limit})'],integer=True)
 extra_sem['basic_control']={'inverse_rounds':16,'reset_rounds':16,'generation_rounds':256,'first_table_encoding':'E(j)=d4 XOR j','inverse_relation':'B[pi(j)]=E(j),where A[j]=E(pi(j))','reset_relation':'A[j]=E(j)','native_claim':False}
 return proofs,tr,{**math,**extra_sem}
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_inverse_divisor',lambda t:t['fragments']['inverse']['instructions'][4].__setitem__('operands','w9, w10, w4, w9')),('wrong_bank_key',lambda t:t['operation_bank_results256'].__setitem__(0,0)),('wrong_fixed_data',lambda t:t['data_roots'][2].__setitem__('bytes','00'*944)),('missing_second_shuffle',lambda t:t['fragments'].pop('second_shuffle')),('invent_native',lambda t:t.__setitem__('target_executed',True)),('invent_full_goal',lambda t:t.__setitem__('full_goal_complete',True))];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']}
 expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'}
 counts={**s['verified_source_counts'],'untranslated_instruction_sites':len(expected-sites),'queries_unsat':sum(q['result']=='unsat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa),'group_isomorphism_pairs':sem['isomorphism_pairs'],'group_associativity_triples':sem['associativity_triples']}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_mode_one_scatter.py':sha(ROOT/'validate_daemon_mode_one_scatter.py'),'validate_daemon_list_output.py':sha(ROOT/'validate_daemon_list_output.py')},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_implemented_checks_pass':True,'all_checks_pass':False,'validation_stage':'checkpoint_partial','complete_semantic_chain_proved':False,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
