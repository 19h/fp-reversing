#!/usr/bin/env python3
"""Static allocation-call boundaries and conditional frame/heap contracts."""
import copy,json,re,subprocess
from recover_daemon_reader_container_origins import ROOT,P,SCOPE,FLAGS,sha,build,LEFT,RIGHT
from validate_daemon_reader_value_consumers import SSA as ParentSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,split
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)'
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('HOST',64),('CONT16',64),('CONT112',64),('ALLOC',64),('OBJ',64),('CTX',64),('PARENT',64),('CP0',64),('CP1',64),('RAWLEN',32),('STATUS',32),('CTRL0',32),('CTRL1',32)])
EXTRA+=''.join(f'(declare-fun HAVOC_{tag}_{j} () (_ BitVec 64))\n'for tag in['ALLOC','OBJ']for j in list(range(1,19))+[30])
class SSA(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   m=i['mnemonic'];ps=split(i['operands'])
   if m=='stp':
    assert len(ps)==3 and'!'not in ps[2];w=32 if ps[0].startswith('w')else 64;a=self.address(ps[2])
    for j in range(2):self.stores.append({'site':i['ea'],'address':a if j==0 else f'(bvadd {a} {bv(w//8)})','value':self.get(ps[j],w),'width_bits':w})
    self.sites.append(i['ea'])
   elif m=='subs':
    w=32 if ps[0].startswith('w')else 64;a=self.get(ps[1],w);b=self.operand(ps[2],w,ps[3]if len(ps)>3 else None);self.compare(a,b,w);self.put(ps[0],f'(bvsub {a} {b})');self.sites.append(i['ea'])
   else:
    if pc in(0x1004958a0,0x1004958b0,0x1006d67d4,0x1006d67e4):
     left=pc in(0x1004958a0,0x1006d67d4);a=self.address(ps[1]);self.loads[i['ea']]=(f'(LUT_{"L"if left else"R"} ((_ extract 7 0) (bvsub {a} {bv(LEFT if left else RIGHT)})))',8)
    super().run({'instructions':[i]},pc+4)
  return self
def lut(name,raw):
 e=bv(raw[-1],8)
 for j in range(254,-1,-1):e=f'(ite (= x {bv(j,8)}) {bv(raw[j],8)} {e})'
 return f'(define-fun LUT_{name} ((x (_ BitVec 8))) (_ BitVec 8) {e})\n'
def certificates(s):
 pp=[];tr={};summ=[];fs=s['fragments'];bank=s['allocation_bank'];ld=lut('L',bytes.fromhex(bank['left_bytes']))+lut('R',bytes.fromhex(bank['right_bytes']))
 def solve(n,body,scope,result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+ld+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':scope})
 def frame(o):return f'(bvadd K {bv(o)})'
 def at(ix):return f'(bvadd TABLE {bv(ix*8)})'
 def part(n,label,r=None,loads=None,chain=None,start=None,end=None):
  f=fs[n];start=start or int(f['start'],16);end=end or(int(f['end'],16)if n=='init112'else int(f['instructions'][-1]['ea'],16));ii=[i for i in f['instructions']if start<=int(i['ea'],16)<end];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']=='ldrh'else 32 if i['operands'].startswith('w')else 64;v=None
    for off,value in[(0x9d8,'TABLE'),(0x9d0,PH),(0x968,bv(LEFT)),(0x960,bv(RIGHT))]:
     if i['operands'].endswith(f'[sp, #{hex(off)}]'):v=value
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update({j:chain[-1].get('x'+str(j))for j in range(31)}if chain else r or{});g=SSA(rr,ll,namespace=label+'_');g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def add(n,gs,tt,scope,cc=()):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',scope)
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def after_call(pre,result):return {0:result,**{j:f'HAVOC_{result}_{j}'for j in list(range(1,19))+[30]},**{j:pre[-1].get('x'+str(j))for j in range(19,30)}}
 scope='Static source contract;file-backed banks/cache values,valid owners and successful PAC/normal callee return are premises. Call models preserve SP and X19-X29;other caller-saved inputs are fresh. No target call is executed.'
 solve('bank_all_byte_inputs','(assert (distinct (bvxor B0 (LUT_R (bvxor (LUT_L B0) #x4e))) #xff))','All256 abstract byte inputs under the two exact original-file banks. This is not proof that native mutable bank cells match the file.')
 caller=part('caller16','caller16',r={19:'HOST',21:bv(0xb9a)});g=caller[-1];add('caller16_private_interface',caller,[neq(g.get('w20'),'#x0000c4dd'),neq(g.get('x8'),f'(bvadd HOST {bv(8)})'),neq(g.get('x9'),frame(0x82e8)),neq(g.get('x10'),frame(0x285c)),neq(rd(g,0x1004e1fc0)['address'],at(0x3884))],scope+' Entry W21=b9a is an explicit upstream premise;it derives allocator modec4dd and output parent+8.')
 ll={'0x100495820':('RAWLEN',32),'0x100495824':('BUF',64),'0x10049582c':('CONT16',64),'0x100495870':('CP0',64),'0x100495874':('CTRL0',32),'0x100495878':('CP1',64),'0x10049587c':('CTRL1',32),'0x1004958c4':('FN',64)}
 pre=part('alloc16','pre16',loads=ll,chain=caller,end=0x1004958d0);g=pre[-1];want=[(0x7910,'CONT16'),(0x8398,f'(bvadd HOST {bv(8)})'),(0x631c,'RAWLEN'),(0x5cf8,'BUF'),(0xdb8,bv(0)),(0x7df0,'#x8b3dc651'),(0x12c8,bv(0xfa039b7ca50c772e)),(0x63a0,bv(0))];assert len(g.stores)==len(want);tt=[]
 for q,(off,value)in zip(g.stores,want):tt.extend([neq(q['address'],frame(off)),neq(q['value'],value)])
 tt.extend([neq(g.get('x0'),bv(16)),neq(g.get('x8'),'FN'),neq(g.get('x17'),bv(0x6aa4)),neq(rd(g,0x1004958c4)['address'],at(0xcc0d)),neq(rd(g,0x10049582c)['address'],at(0xb9a)),neq(rd(g,0x100495820)['address'],frame(0x285c)),neq(rd(g,0x100495824)['address'],frame(0x82e8))]);add('pair16_allocation_and_default_cells',pre,tt,scope+' Exact original malloc binding receives size16 B. Default raw64 constant is not assigned decoded numeric meaning.')
 post=part('alloc16','post16',r=after_call(pre,'ALLOC'),start=0x1004958d4);g=post[-1];add('pair16_normal_allocation_result_gate',[*pre,g],[neq(g.stores[0]['address'],frame(0x6368)),neq(g.stores[0]['value'],'ALLOC'),neq(rd(g,0x1004958f8)['address'],f'(ite (= ALLOC {bv(0)}) {at(0xc4dd)} {at(0xc4e0)})'),neq(g.get('w6'),'#x74c29d85')],scope+' Allocation-result gate uses inherited modec4dd,not frame phase6cf4.')
 failure=part('return16','pair16_failure',chain=post);add('pair16_failed_allocation_continuation',[*pre,*failure],[neq(failure[-1].get('x21'),'CONT16'),neq(failure[-1].get('w6'),'#x74c29d85'),neq(failure[-1].get('x17'),bv(0xbcd2))],scope+' No direct borrowed-output store occurs in this checked failure continuation;aliased frame writes and final external return are separate.',['(= ALLOC '+bv(0)+')']);assert not failure[-1].stores
 zero=part('zero16','pair16_zero',chain=post);g=zero[-1];add('pair16_zero_pair',[*pre,*zero],[neq(g.stores[0]['address'],'ALLOC'),neq(g.stores[0]['value'],bv(0)),neq(g.stores[1]['address'],f'(bvadd ALLOC {bv(8)})'),neq(g.stores[1]['value'],bv(0)),neq(rd(g,0x1005b07b4)['address'],at(0x3599)),neq(g.get('x8'),bv(0)),neq(g.get('w12'),'#x0000b350')],scope+' Nonnull allocation is assumed valid for16 B and separate from the frame. Two u64 cells are zeroed.',['(distinct ALLOC '+bv(0)+')'])
 loop=part('loop16','pair16_loop',chain=zero);g=loop[-1];size='((_ zero_extend 32) (bvxor RAWLEN #x8b3dc651))';add('pair16_initial_remaining_input_gate',[*pre,*loop],[neq(g.get('x11'),size),neq(g.get('w9'),'#x00006cf4'),neq(rd(g,0x1004ddb1c)['address'],f'(ite (= {size} {bv(0)}) {at(0xb350)} {at(0xb358)})')],scope+' At initial cursor zero,this checks nonempty decoded extent,not a minimum record header size.')
 empty=part('empty16','pair16_empty',loads={'0x1005588bc':('ALLOC',64)},chain=loop);ok=part('success16','pair16_success',chain=empty);pub=part('publish16','pair16_publish',loads={'0x100588170':(f'(bvadd HOST {bv(8)})',64),'0x100588178':('CONT16',64)},chain=ok);g=pub[-1];add('pair16_empty_input_pointer_publication',[*pre,*pub],[neq(g.stores[0]['address'],f'(bvadd HOST {bv(8)})'),neq(g.stores[0]['value'],'ALLOC'),neq(g.get('x6'),bv(0x8b3dc651)),neq(g.get('x21'),'CONT16')],scope+' Empty decoded input publishes the initialized pair through parent+8. Parent/heap/frame owners must be valid and separate;no complete container type or final external return is proved.',['(= RAWLEN #x8b3dc651)','(distinct ALLOC '+bv(0)+')'])
 clear=part('clear16','pair16_clear',loads={'0x1007976a0':('STATUS',32)});cp=part('publish16','pair16_clear_publish',loads={'0x100588170':('OUT',64),'0x100588178':('CONT16',64)},chain=clear);g=cp[-1];add('separate_pair_pointer_clear_path',cp,[neq(clear[-1].stores[0]['address'],frame(0x6368)),neq(clear[-1].stores[0]['value'],bv(0)),neq(g.stores[0]['address'],'OUT'),neq(g.stores[0]['value'],bv(0)),neq(g.get('x6'),z('STATUS'))],scope+' Separate entry79768c clears and publishes NULL while preserving the named status. No allocation-failure-to-this-entry join or free is inferred.')
 ad=part('admission','context_admission',r={11:bv(0x50e4),10:'CTX'},loads={'0x100549890':('PARENT',64)});g=ad[-1];want=[(0x78f0,'#x8b3dc651'),(0x7390,'#x8b3dc651'),(0x7d98,bv(0)),(0x8608,bv(0))];tt=[]
 for q,(o,v)in zip(g.stores,want):tt.extend([neq(q['address'],frame(o)),neq(q['value'],v)])
 tt.extend([neq(rd(g,0x100549890)['address'],frame(0x82d8)),neq(rd(g,0x1005498ac)['address'],f'(ite (= PARENT {bv(0)}) {at(0x50e6)} {at(0x50e4)})'),neq(g.get('x10'),'CTX'),neq(g.get('w9'),'#x00000fd4')]);add('context_gate_and_shared_value_defaults',ad,tt,scope+' Admission entry modeW11=50e4 is a premise;its upstream caller remains unjoined.')
 ctx=part('context','context_saved',chain=ad);g=ctx[-1];add('incoming_context_saved_before_allocation',ctx,[neq(g.stores[0]['address'],frame(0x5e50)),neq(g.stores[0]['value'],'CTX'),neq(g.get('w22'),'#x00006cf4'),neq(g.get('x19'),frame(0x8608)),neq(g.get('x11'),bv(LEFT)),neq(rd(g,0x1004d3e30)['address'],at(0x4a8d))],scope+' Comparison context is incoming X10. This establishes a saved-register source,not request/process/environment attribution.',['(distinct PARENT '+bv(0)+')'])
 ll={'0x1006d67a4':('CONT112',64),'0x1006d67a8':('CP0',64),'0x1006d67ac':('CTRL0',32),'0x1006d67b0':('CP1',64),'0x1006d67b4':('CTRL1',32),'0x1006d67f8':('FN',64)};p112=part('alloc112','pre112',chain=ctx,loads=ll,end=0x1006d6804);g=p112[-1];add('separate112_allocation_argument_and_bank',p112,[neq(g.get('x0'),bv(112)),neq(rd(g,0x1006d67a4)['address'],at(0xfd4)),neq(rd(g,0x1006d67f8)['address'],at(0xcc0d)),neq(g.get('x17'),bv(0x6aa4))],scope+' The separately requested112 B allocation does not define the already saved comparison-context pointer.')
 q112=part('alloc112','post112',r=after_call(p112,'OBJ'),start=0x1006d6808);g=q112[-1];add('separate112_allocation_result_gate',[*p112,g],[neq(g.get('x20'),'OBJ'),neq(rd(g,0x1006d6824)['address'],f'(ite (= OBJ {bv(0)}) {at(0x1e17)} {at(0x1e10)})'),neq(g.get('w6'),'#x74c29d85')],scope)
 fail=part('fail112','failure112',chain=q112);add('separate112_failure_continuation',[*p112,*fail],[neq(fail[-1].get('x21'),'CONT112'),neq(fail[-1].get('x17'),bv(0xecaa))],scope+' Indirect return through the preserved continuation;no final native return proof.',['(= OBJ '+bv(0)+')'])
 init=part('init112','initial112_prefix',chain=q112);g=init[-1];want=[(0,'#x1d45dafb'),(4,'#x00000000'),(0x48,bv(0)),(0x50,'#x00'),(0x51,'#x25')];tt=[]
 for q,(o,v)in zip(g.stores,want):tt.extend([neq(q['address'],f'(bvadd OBJ {bv(o)})'),neq(q['value'],v)])
 add('separate112_initial_field_prefix',[*p112,*init],tt,scope+' Only the first12 instructions are captured here;the largest accessed byte offset51 gives82 B envelope within112 B request. Remaining initialization/helper behavior and full type are unproved.',['(distinct OBJ '+bv(0)+')'])
 solve('reject_conflating_context_and_new112_object',prefix(*p112,*q112)+'(assert (distinct CTX OBJ))\n(assert '+neq(ctx[-1].stores[0]['value'],q112[-1].get('x20'))+')','Abstract source counterexample: context saved before allocation and returned object have different source origins and may differ numerically. This is not proof of native pointer inequality or an out-of-bounds access.','sat')
 return pp,tr,summ
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_bank_byte',lambda t:t['allocation_bank'].__setitem__('key_u8',0)),('wrong_object_width',lambda t:t['fragments']['init112']['instructions'][7].__setitem__('operands','wzr, [x20, #0x48]')),('missing_caller',lambda t:t['fragments'].pop('caller16')),('invent_heap_type',lambda t:t.__setitem__('complete_container_type_proved',True)),('wrong_null_branch',lambda t:t['branch_edges'][1].__setitem__('index','0x6cf4')),('omit_context_candidate',lambda t:t['writer_census']['candidates'].pop())];aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;aa.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return aa
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr,summ=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for n,f in s['fragments'].items()for i in f['instructions']if i['mnemonic']not in('braa','blraa')};assert sites==expected,(len(sites),len(expected),expected-sites)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'counterexamples_sat':sum(p['result']=='sat'for p in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)};c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_value_consumers.py':sha(ROOT/'validate_daemon_reader_value_consumers.py')},'proofs':pp,'translations':tr,'family_summaries':summ,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'source_recapture_match':True,'normal_allocation_return_is_premise':True,'native_object_types_proved':False,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
