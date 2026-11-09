#!/usr/bin/env python3
"""Source-linked fixed-width interface certificates; no target execution."""
import copy,json,re,subprocess
from recover_daemon_reader_outer_lifecycle import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_reader_container_origins import SSA as ParentSSA,lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,split
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)'
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('OBJ',64),('CTX',64),('INPUT',64),('POS',64),('BASE',64),('SAVED',64),('REST',64),('ENCLEN',32),('F',32),('RESULT',32),('DISCR',32),('RFLAG',8)]+[('FIELD'+str(j),w)for j,w in enumerate([32,32,32,8,8,32,32,8])])
EXTRA+=''.join(f'(declare-fun HAVOC_{n}_{j} () (_ BitVec 64))\n'for n in ['FILL','ALLOC']for j in list(range(1,19))+[30])
class Engine(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in getattr(self,'bank_sites',{}):
    name,base=self.bank_sites[pc];a=self.address(split(i['operands'])[1]);self.loads[i['ea']]=(f'(LUT_{name} ((_ extract 7 0) (bvsub {a} {bv(base)})))',8)
   if pc==0x1006c8a20:
    # LDR W11,[X13],#0x27: load from old base, then update X13.
    a=self.get('x13');v,w=self.loads[i['ea']];assert w==32;self.reads.append({'site':i['ea'],'address':a,'width_bits':32,'input':v});self.put('w11',v);self.put('x13',f'(bvadd {a} {bv(0x27)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def certificates(s):
 pp=[];tr={};fs=s['fragments'];ld=''.join(lut(str(j)+side,bytes.fromhex(b[key]))for j,b in enumerate(s['banks'])for side,key in [('L','left_bytes'),('R','right_bytes')])
 bank_sites={0x100963940:('0L',0x100fc4230),0x100963964:('0R',0x101031fa0),0x1008c3fdc:('1L',0x100e99a00),0x1008c3fec:('1R',0x100f4e390)}
 def solve(n,body,result='unsat',note=''):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+ld+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE+' '+note});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None,a=None,end=None):
  label=label or n;f=fs[n];a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll={};dd=[]
  roots={0x9b0:0x100fc4230,0x9a8:0x101031fa0,0x600:0x100e99a00,0x5f8:0x100f4e390}
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']=='ldrh'else 32 if i['operands'].startswith('w')else 64;v=None
    for off in [0x9d8,0x9d0,*roots]:
     if i['operands'].endswith(f'[sp, #{hex(off)}]'):v='TABLE'if off==0x9d8 else PH if off==0x9d0 else bv(roots[off])
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.bank_sites=bank_sites;g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 frame=lambda o:f'(bvadd K {bv(o)})';at=lambda ix:f'(bvadd TABLE {bv(ix*8)})'
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def st(g,pc):return next(q for q in g.stores if q['site']==hex(pc))
 def store(g,pc,addr,val):q=st(g,pc);return[neq(q['address'],addr),neq(q['value'],val)]
 def after(gs,n,result=None):return {0:result or'HAVOC_'+n+'_1',**{j:'HAVOC_'+n+'_'+str(j)for j in list(range(1,19))+[30]},**{j:gs[-1].get('x'+str(j))for j in range(19,30)}}
 for j,b in enumerate(s['banks']):solve(b['role']+'_all_byte_inputs',f'(assert (distinct (bvxor B0 (LUT_{j}R (bvxor (LUT_{j}L B0) {bv(b["key_u8"],8)}))) {bv(b["results_256"][0],8)}))',note='Exact original-file bank contents; native bank-root values and stability remain premises.')
 setup=part('setup','setup_pre',r={20:bv(0x3977),24:'OUT',23:'INPUT',22:'(concat ((_ extract 63 32) Z22) ENCLEN)'},loads={'0x1009638dc':('POS',64)},end=0x10096398c);g=setup[-1]
 tt=[neq(g.get('x0'),f'(bvadd K {bv(0xc070)} POS)'),neq(g.get('x1'),bv(0)),neq(g.get('x2'),bv(32)),neq(rd(g,0x10096397c)['address'],at(0xcc9b))]
 for pc,off,v in[(0x1009638d0,0x1d60,'OUT'),(0x1009638d8,0x5d4c,'ENCLEN'),(0x1009638f4,0x16d0,f'(bvadd POS {bv(32)})'),(0x1009638f8,0x56f8,'INPUT'),(0x100963954,0x285c,'#x8b3dc651')]:tt+=store(g,pc,frame(off),v)
 add('outer_arguments_and_local32_reservation',setup,tt,note='Incoming W20=3977; low32 W22 is encoded extent, not an operation-status assumption. Internal fill is opaque with its prior source-certified role.')
 setupret=part('setup','setup_post',r=after(setup,'FILL'),a=0x100963990);g=setupret[-1];good=f'(and (distinct OUT {bv(0)}) (distinct INPUT {bv(0)}) (distinct ENCLEN #x8b3dc651))'
 add('outer_null_and_encoded_zero_gate',setup+setupret,[neq(rd(g,0x1009639bc)['address'],f'(ite {good} {at(0x3977)} {at(0x3986)})'),neq(g.get('w25'),'#x0000539e'),neq(g.get('w21'),'#x00004f91')],note='Normal callee preserves X19-X29/SP; all other GPRs are fresh. Both CCMP NZCV=4 fallbacks are translated.')
 ap=part('allocate','alloc_pre',chain=setupret,end=0x1008c4010);g=ap[-1];add('outer_malloc128_request',setup+ap,[neq(g.get('x0'),bv(128)),neq(rd(g,0x1008c4004)['address'],at(0xcc0d)),neq(g.get('x17'),bv(0x6aa4)),neq(g.get('w20'),'#x0000a3b3'),neq(g.get('w21'),'#x00004f91')],[good])
 ar=part('allocate','alloc_post',r=after(ap,'ALLOC','OBJ'),a=0x1008c4014);g=ar[-1];add('outer_allocation_result_pointer_and_gate',setup+ap+ar,store(g,0x1008c4014,frame(0x1ae8),'OBJ')+[neq(rd(g,0x1008c4034)['address'],f'(ite (= OBJ {bv(0)}) {at(0x539e)} {at(0x53a5)})')],[good])
 zero=part('zero',chain=ar);g=zero[-1];add('outer_first_two_pointer_cells_zero',setup+ap+zero,[neq(g.stores[j]['address'],'OBJ'if j==0 else f'(bvadd OBJ {bv(8)})')for j in range(2)]+[neq(q['value'],bv(0))for q in g.stores]+[neq(g.get('w22'),'#x00006cf4')],[good,f'(distinct OBJ {bv(0)})'],note='Only first16 B are initialized here; full128 B initialization and final object type are not inferred.')
 pcs=[0x1006c8a20,0x1006c8a28,0x1006c8a30,0x1006c8a38,0x1006c8a40,0x1006c8a48,0x1006c8a50,0x1006c8a5c];src=[0,0x48,0x4c,0x50,0x51,0x68,0x54,0x6c];dst=[0x10,0x58,0x5c,0x60,0x61,0x78,0x64,0x7c];writes=[0x1006c8a24,0x1006c8a2c,0x1006c8a34,0x1006c8a3c,0x1006c8a44,0x1006c8a4c,0x1006c8a54,0x1006c8a68];widths=[32,32,32,8,8,32,32,8]
 cp=part('copy_fields',r={0:'OBJ',19:'CTX'},loads={hex(pc):('FIELD'+str(j),widths[j])for j,pc in enumerate(pcs)});g=cp[-1];tt=[]
 for j in range(8):tt.append(neq(rd(g,pcs[j])['address'],f'(bvadd CTX {bv(src[j])})'));tt+=store(g,writes[j],f'(bvadd OBJ {bv(dst[j])})','FIELD'+str(j)if j<7 else'(bvxor (bvand FIELD7 #x01) #x7f)')
 tt+=store(g,0x1006c8a58,frame(0x9b8),'CTX');add('context_to_outer_selected_field_map',cp,tt,note='Independent transfer prefix with CTX/OBJ live/disjoint and fresh allocation-result provenance as compositional premises; no unobserved path join or equality with the separately allocated112 B object is asserted.')
 staged=part('stage',r={12:bv(0x4b1d),9:'O',4:z('ENCLEN'),8:'SAVED'},loads={'0x100609e4c':('BASE',64),'0x100609e64':('OBJ',64),'0x100609e6c':('F',32),'0x100609e78':('RFLAG',8)});g=staged[-1];pred='(and (distinct F #x00000000) (= (bvand RFLAG #x01) #x01))'
 add('N19_payload_cursor_object_and_flag_stage',staged,store(g,0x100609e54,frame(0x4890),'SAVED')+store(g,0x100609e58,frame(0x285c),'ENCLEN')+store(g,0x100609e60,frame(0x82e8),f'(bvadd BASE O)')+[neq(rd(g,0x100609e64)['address'],frame(0x1ae8)),neq(rd(g,0x100609e78)['address'],f'(bvadd OBJ {bv(0x7c)})'),neq(g.get('x19'),'OBJ'),neq(rd(g,0x100609e94)['address'],f'(ite {pred} {at(0x4b59)} {at(0x4b1d)})')],note='Entry W12=4b1d is an upstream phase premise; source of BASE/O/ENCLEN/F remains open.')
 sel=part('select',chain=staged);g=sel[-1];add('N19_exact_reader_or_alternate_gate',sel,[neq(g.get('w21'),'#x00000b9a'),neq(rd(g,0x1008017ac)['address'],f'(ite (= F #x00000000) {at(0x344e)} (ite (= (bvand RFLAG #x01) #x01) {at(0x344e)} {at(0x342d)}))')],['(not '+pred+')'])
 add('composed_stage_and_selector_reach_N19_exactly_when_F_zero',[],[neq('(and (not '+pred+') (or (= F #x00000000) (= (bvand RFLAG #x01) #x01)))','(= F #x00000000)')],note='Both source gates are required. The isolated second gate also accepts flag lowbit1, but that case is diverted by the preceding gate when F is nonzero.')
 call=part('caller',chain=sel);g=call[-1];add('N19_parent_is_saved_outer_object',call,[neq(g.get('x8'),f'(bvadd OBJ {bv(8)})'),neq(g.get('x9'),frame(0x82e8)),neq(g.get('x10'),frame(0x285c)),neq(rd(g,0x1004e1fc0)['address'],at(0x3884))],['(not '+pred+')','(or (= F #x00000000) (= (bvand RFLAG #x01) #x01))'],note='Established N19 output contract writes its16 B list-container pointer through OBJ+8. Continuity of frame/OBJ across the parser is a premise, not a native owner observation.')
 ret=part('returned',r={22:PH,6:z('RESULT')});g=ret[-1];add('raw_result_saved_before_success_cleanup_split',ret,store(g,0x100975d5c,frame(0x5f60),'RESULT')+[neq(g.get('w8'),'#x0000539e'),neq(g.get('w9'),'#x00001fbb'),neq(g.get('w6'),'#x8b3dc651'),neq(rd(g,0x100975d8c)['address'],f'(ite (= RESULT #x8b3dc651) {at(0xc022)} {at(0xc04f)})')],note='W6 reset occurs on both branches, after RESULT was saved. It is not a proof all paths return success.')
 pub=part('publish',chain=ret,loads={'0x100918d8c':('OBJ',64),'0x100918d90':('OUT',64)});g=pub[-1];add('success_publishes_outer_object_through_borrowed_cell',pub,store(g,0x100918d94,'OUT','OBJ')+[neq(g.get('w21'),'#x00004f91'),neq(rd(g,0x100918d9c)['address'],at(0x539e))],['(= RESULT #x8b3dc651)'],note='Borrowed OUT comes from K1d60 and object from K1ae8; pointer publication is local and does not emit IPC.')
 dis=part('dispose',chain=ret,loads={'0x100a0bf78':('OBJ',64)});g=dis[-1];add('failed_result_changes_heap_value_to_local_pointer_cell',dis,store(g,0x100a0bf7c,frame(0x4230),'OBJ')+store(g,0x100a0bf88,frame(0x4a68),frame(0x4230))+[neq(g.get('x8'),frame(0x4230)),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x100a0bf9c)['address'],at(0x1fbb))],['(distinct RESULT #x8b3dc651)'])
 cl=part('cleanup',chain=dis);g=cl[-1];add('cleanup_receives_pointer_cell_address',cl,store(g,0x1007322e0,frame(0x5120),frame(0x4230))+[neq(rd(g,0x100732304)['address'],f'(ite (= {frame(0x4230)} {bv(0)}) {at(0x5086)} {at(0x5096)})')],['(distinct RESULT #x8b3dc651)'],note='K4230 is the forwarded nonnull cell address; its heap pointee OBJ is a separate value. Existing drain/free contracts remain conditional; complete failure cleanup is outside scope.')
 restore=part('restore',chain=pub,loads={'0x100927584':('REST',64),'0x100927598':('DISCR',32)});g=restore[-1];add('common_exit_restores_local_cursor_by32',restore,store(g,0x100927594,frame(0x16d0),f'(bvsub REST {bv(32)})')+[neq(g.get('w8'),'#x0000b2cf'),neq(rd(g,0x1009275a0)['address'],at(0x4f91))],['(= RESULT #x8b3dc651)'])
 add('reserve_restore_algebra',[],[neq(f'(bvsub (bvadd POS {bv(32)}) {bv(32)})','POS')],note='K16d0 is a modular local cursor, not architectural SP or a Mach port.')
 aft=part('after',chain=restore);g=aft[-1];ix=0xb2cf^(((0xb2cf^0xa9a3)+11)^0x1b5e);add('next_continuation_uses_signed_discriminator',aft,[neq(rd(g,0x100908b80)['address'],f'(ite (bvslt DISCR #x650271e4) {at(ix)} {at(0xb2cf)})')],['(= RESULT #x8b3dc651)'],note='DISCR is loaded from Kd5c. No public operation or endpoint meaning is assigned.')
 solve('reject_heap_pointer_as_cleanup_cell',prefix(*dis)+'(assert (distinct OBJ '+frame(0x4230)+'))\n(assert '+neq(dis[-1].get('x8'),'OBJ')+')','sat',note='Abstract source interpretation counterexample only; no target input, memory fault or request is constructed.')
 return pp,tr,[]
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_allocation_width',lambda t:t['fragments']['allocate']['instructions'][23].__setitem__('operands','w0, #0x70')),('wrong_parent_cell',lambda t:t['fragments']['caller']['instructions'][6].__setitem__('operands','x8, x19, #0')),('missing_context_transfer',lambda t:t['fragments'].pop('copy_fields')),('wrong_flag_bank',lambda t:t['banks'][0].__setitem__('key_u8',0)),('invent_transport',lambda t:t.__setitem__('native_target_executed',True)),('omit_writer_candidate',lambda t:t['writer_candidates']['candidates'].pop())];out=[]
 for n,op in ops:t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,_=certificates(s);sites={p for q in tr.values()for p in q['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')};assert sites==expected,(expected-sites,sites-expected)
 aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'counterexamples_sat':sum(p['result']=='sat'for p in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_container_origins.py':sha(ROOT/'validate_daemon_reader_container_origins.py')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'source_recapture_match':True,'all_checks_pass':True,'complete_outer_parser_proved':False,'complete_cleanup_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
