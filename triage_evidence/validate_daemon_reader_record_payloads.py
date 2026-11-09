#!/usr/bin/env python3
"""Source/SMT typed payload and recoding certificate; no target execution."""
import copy,json,re,subprocess
from recover_daemon_reader_record_payloads import ROOT,P,SCOPE,FLAGS,sha,build
from validate_daemon_reader_record_headers import SSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,split
from validate_daemon_typed_scalar import WordCuts,parts,initial,KEYS
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)';QBASE=0x1376253dadee7b93;PRE64=0x80915f9a168f26e3;WIRE64=0xfa039b7ca50c772e
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('T',16),('NODE',64),('REC',64),('SPAN',64),('RAW64',64),('VAL32',32),('CTX',64),('HRAW',32),('STATUS',32),('COUNT',64),('B',64),('U4',64),('U5',64),('U6',64),('U7',64),('SBYTE',8)])
class Engine(SSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in getattr(self,'cuts',{}):self.put(split(i['operands'])[0],self.cuts[pc]);self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self

def certificates(s):
 pp=[];tr={};cache={};fs=s['fragments'];enc='(bvxor PL #x8b3dc651)';tag='((_ sign_extend 16) T)';at=lambda ix:f'(bvadd TABLE {bv(ix*8)})';frame=lambda off:f'(bvadd K {bv(off)})'
 scope='Source component with valid stable/disjoint frame, node, record and source owners, pinned constants/cache epoch and successful PAC as premises. No target execution, native delivery, ownership or daemon-kext pairing is proved.'
 def solve(n,body,result='unsat',extra_scope=''):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':scope+' '+extra_scope,'reused_codec_lemma':False});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None,a=None,end=None,cuts=None):
  label=label or n;f=fs[n];a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v=None
    m=re.fullmatch(r'[xw][0-9]+, \[sp, #(0x[0-9a-f]+)\]',i['operands'])
    if m:
     off=int(m[1],16);v='TABLE'if off==0x9d8 else PH if off==0x9d0 else cache.get(off)
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.cuts=cuts or{};g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',extra_scope=note)
 setup=part('setup',r={21:bv(0x6cf4),24:bv(0x27b),22:z('HRAW')},loads={'0x1008ecba4':('NODE',64),'0x1008ecbb4':('T',16),'0x1008ecc34':(enc,32),'0x1008ecc4c':('VAL32',32)})
 for q in setup[-1].stores:
  m=re.fullmatch(r'\(bvadd K #x([0-9a-f]+)\)',q['address'])
  if m:cache[int(m[1],16)]=q['value']
 tt=[]
 for off,want in[(0x970,tag),(0x930,'#x0000a630'),(0x928,'#xffffd0ee'),(0x8e8,'#x00001c16'),(0x908,'#x0000aeb8'),(0x900,'#x00001c10'),(0x980,enc),(0x8f0,'VAL32')]:tt.append(neq(cache[off],want))
 add('N19_typed_payload_cache_producers',setup,tt)
 router=part('router',chain=setup);g=router[-1];low='(bvslt T #xd0ee)';add('signed_lower_partition',router,[neq(g.get('w3'),tag),neq(rd(g,0x1004a0f80)['address'],f'(ite {low} {at(0xa631)} {at(0xa630)})')])
 upper=part('upper',chain=router);g=upper[-1];add('signed_upper_partition',upper,[neq(g.get('w16'),'#x00001c16'),neq(rd(g,0x10079971c)['address'],f'(ite (bvslt T #x1742) {at(0xaeb8)} {at(0xaec5)})')],['(not '+low+')'])
 c64=part('check64',chain=router);g=c64[-1];add('exact_u64_tag',c64,[neq(g.get('w14'),'#x000027fc'),neq(rd(g,0x1004f83e8)['address'],f'(ite (= T #xc31c) {at(0xa8bf)} {at(0x1c16)})'),neq(g.get('w6'),'#x74c29d88')],[low])
 c32=part('check32',chain=upper);g=c32[-1];add('exact_u32_tag',c32,[neq(rd(g,0x1004cd7b8)['address'],f'(ite (= T #xd0ee) {at(0x77a2)} {at(0x1c16)})'),neq(g.get('w6'),'#x74c29d88')],['(not '+low+')','(bvslt T #x1742)'])
 csp=part('checkspan',chain=upper);g=csp[-1];add('exact_span_tag',csp,[neq(g.get('w14'),'#x0000cadc'),neq(rd(g,0x1005549b8)['address'],f'(ite (= T #x1742) {at(0xc9b8)} {at(0x1c16)})'),neq(g.get('w6'),'#x74c29d88')],['(not (bvslt T #x1742))'])
 l64=part('length64',chain=c64,loads={'0x1006072f0':(enc,32)});g=l64[-1];add('u64_exact_eight_byte_extent',l64,[neq(rd(g,0x10060731c)['address'],f'(ite (= PL #x00000008) {at(0x9641)} {at(0x27fc)})'),neq(g.get('w16'),'#x00006cf4'),neq(g.get('w6'),'#x74c29d8f')],['(= T #xc31c)'])
 l32=part('length32',chain=c32);g=l32[-1];add('u32_exact_four_byte_extent',l32,[neq(rd(g,0x1005c35bc)['address'],f'(ite (= PL #x00000004) {at(0x7fdb)} {at(0x1c16)})'),neq(g.get('w22'),'#x00006cf4'),neq(g.get('w6'),'#x74c29d8f')],['(= T #xd0ee)'])
 cp=part('count_prefix',r={0:'NODE',21:z(enc),23:bv(0x27f2)});cs=part('count_save',chain=cp);g=cs[-1];q=f'(bvadd {z("PL")} {bv(QBASE)})';add('N19_saved_additive_payload_count',cs,[neq(g.stores[0]['address'],frame(0xa630)),neq(g.stores[0]['value'],q)],note='Explicit disjoint prefix/save recapture;intervening original instructions are checked not to write X8. This count is not an XOR encoding.')
 sp=part('span_gate',chain=csp,loads={'0x1004b9cec':(f'((_ extract 31 0) {q})',32)});g=sp[-1];decoded=g.get('x16');add('span_count_decode_and_zero_partition',sp,[neq(g.get('w22'),'#x00006cf4'),neq(g.get('w16'),'(bvxor PL #xadee7b93)'),neq(rd(g,0x1004b9d80)['address'],f'(ite (= PL #x00000000) {at(0xcafd)} {at(0xcadc)})')],['(= T #x1742)'])
 p64=part('call64',chain=l64);g=p64[-1];add('N19_u64_writer_call',p64,[neq(g.get('w0'),'#x00001351'),neq(g.get('x1'),frame(0xa628)),neq(g.get('x14'),frame(0x5440)),neq(g.get('x16'),bv(PRE64)),neq(rd(g,0x10053f034)['address'],at(0x7d2d))],['(= T #xc31c)','(= PL #x00000008)'])
 e64=part('writer64_entry',chain=p64,loads={'0x1005a2c2c':('NODE',64),'0x1005a2c30':('REC',64),'0x1005a2c54':('RAW64',64),'0x1005a2c60':('FN',64)});g=e64[-1];add('N19_u64_writer_input_and_return_selector',e64,[neq(rd(g,0x1005a2c2c)['address'],frame(0x5440)),neq(rd(g,0x1005a2c30)['address'],f'(bvadd NODE {bv(24)})'),neq(rd(g,0x1005a2c54)['address'],frame(0xa628)),neq(g.get('x16'),f'(bvxor RAW64 {bv(PRE64)})'),neq(rd(g,0x1005a2c60)['address'],at(0x1351)),neq(g.get('x0'),'FN')],['(= T #xc31c)','(= PL #x00000008)'])
 p32=part('call32',chain=l32);w32=part('word_call',chain=p32);g=w32[-1];add('N19_u32_payload_writer_call',w32,[neq(g.get('w24'),'#x000002a5'),neq(g.get('x16'),f'(bvadd NODE {bv(24)})'),neq(g.get('x19'),bv(0x71134a47fbd9f0b7+10)),neq(g.get('w22'),'(bvxor VAL32 #x01263f51)'),neq(rd(g,0x100615010)['address'],at(0x9da7))],['(= T #xd0ee)','(= PL #x00000004)'])
 add('N19_scalar_pre_mask_value_composition',[],[neq('(bvxor VAL32 #x01263f51 #x8a1bf900)','(bvxor VAL32 #x8b3dc651)'),neq(f'(bvxor RAW64 {bv(PRE64)} #x7a92c4e6b38351cd)',f'(bvxor RAW64 {bv(WIRE64)})')],note='Generic writer lemmas are source-recaptured dependencies. The N19 raw64 reader transform itself remains unproved;wire64 is expressed in terms of the staged raw64 operand.')
 ss=part('span_setup',chain=sp,loads={'0x1007fd5fc':('NODE',64),'0x1007fd608':('REC',64),'0x1007fd610':('SPAN',64)});g=ss[-1];add('span_copy_entry_count_and_owners',ss,[neq(g.get('x16'),z('PL')),neq(g.get('x14'),'REC'),neq(g.get('x2'),'SPAN'),neq(g.get('w0'),'#x000037fd'),neq(rd(g,0x1007fd5f8)['address'],at(0x3802)),neq(rd(g,0x1007fd5fc)['address'],frame(0x5440)),neq(rd(g,0x1007fd608)['address'],f'(bvadd NODE {bv(24)})'),neq(rd(g,0x1007fd610)['address'],frame(0x57a0))],['(= T #x1742)','(distinct PL #x00000000)'])
 # Generic scalar-mask cuts below are justified by separate span seed/round proofs.
 lc=part('span_loop','span_loop_cut',r={**{j:ss[-1].get('x'+str(j))for j in range(31)},16:'COUNT'},loads={'0x100791d08':('SBYTE',8)},cuts={0x100791ebc:'U',0x100791f04:'V'});g=lc[-1];src=f'(bvadd SPAN (bvsub COUNT {bv(1)}))';dst=f'(bvadd REC COUNT {bv(9)})';mask=lambda word,a:f'((_ extract 7 0) (bvlshr {word} (bvshl (bvand {a} {bv(7)}) {bv(3)})))';add('span_loop_read_write_countdown_and_partition',[*ss,*lc],[neq(rd(g,0x100791d08)['address'],src),neq(g.stores[0]['address'],dst),neq(g.stores[0]['value'],f'(bvxor SBYTE {mask("U",src)} {mask("V",dst)} #x78)'),neq(g.get('x16'),f'(bvsub COUNT {bv(1)})'),neq(rd(g,0x100791f38)['address'],f'(ite (= COUNT {bv(1)}) {at(0x37fd)} {at(0x3802)})')],['(= T #x1742)','(distinct PL #x00000000)',f'(bvuge COUNT {bv(1)})'])
 ex=part('writer64_exit',r={0:'FN'});add('N19_u64_writer_exit_phase',ex,[neq(ex[-1].get('x22'),PH),neq(ex[-1].get('x0'),'FN')],note='Low32 phase6cf4;upper phase bits remain arbitrary.')
 # Common post-payload handoff under the phase supplied by each successful route.
 post=part('post_payload',r={22:bv(0x6cf4)},loads={'0x1005c6368':('CTX',64),'0x1005c6370':('HRAW',32)});le=part('lookup_entry',chain=post,loads={'0x1006fd1c0':('CONT',64)});g=le[-1];want=[(0x7060,'CONT'),(0xaa5c,'HRAW'),(0xaa60,frame(0xde8))];tt=[]
 for st,(off,v)in zip(g.stores,want):tt.extend([neq(st['address'],frame(off)),neq(st['value'],v)])
 tt.extend([neq(post[-1].stores[0]['address'],frame(0xde8)),neq(post[-1].stores[0]['value'],bv(0)),neq(rd(g,0x1006fd1c0)['address'],at(0x1308)),neq(g.get('x8'),'CTX'),neq(rd(g,0x1006fd1ec)['address'],f'(ite (= CTX {bv(0)}) {at(0xc157)} {at(0xc1ca)})')]);add('post_payload_lookup_context_key_output_and_saved_return',le,tt,note='This is a context lookup handoff,not an established list append. Key is the saved encoded preceding word;output is a zeroed borrowed pointer cell.')
 ln=part('lookup_null',chain=le);add('null_lookup_context_early_return',ln,[neq(ln[-1].get('x10'),'CONT'),neq(ln[-1].get('w6'),'#x74c29d88')],['(= CTX '+bv(0)+')'])
 lp=part('lookup_nonnull',chain=le);add('nonnull_lookup_context_dispatch',lp,[neq(rd(lp[-1],0x10070d1f8)['address'],at(0x5e28))],['(distinct CTX '+bv(0)+')'])
 lr=part('lookup_return',r={6:z('STATUS')});ls=part('lookup_status',chain=lr);g=ls[-1];add('lookup_return_signed_status_partition',ls,[neq(rd(lr[-1],0x1007c4d5c)['address'],at(0x416a)),neq(rd(g,0x1006b9768)['address'],f'(ite (bvslt STATUS #x74c29ded) {at(0x4124)} {at(0x411a)})')],note='Signed comparison on raw status,not a decoded public error classification. Further insertion/back-edge work remains open.')
 # Exact selected type tree, independent of pointer/native validity.
 accepted='(ite (bvslt T #xd0ee) (and (= T #xc31c) (= PL #x00000008)) (ite (bvslt T #x1742) (and (= T #xd0ee) (= PL #x00000004)) (= T #x1742)))';expect='(or (and (= T #xc31c) (= PL #x00000008)) (and (= T #xd0ee) (= PL #x00000004)) (= T #x1742))';add('complete_selected_payload_type_extent_partition',[],[neq(accepted,expect)])
 return pp,tr,{'span_setup_chain':ss,'span_cut':lc,'cache':cache,'part':part,'add':add,'solve':solve,'scope':scope}

def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_tag_target',lambda t:t['branch_edges'][0].__setitem__('index','0x0')),('omit_count_save',lambda t:t['fragments'].pop('count_save')),('wrong_scalar_source_width',lambda t:t['fragments']['writer64_entry']['instructions'][10].__setitem__('operands','w1, [x1]')),('wrong_span_store',lambda t:t['fragments']['span_loop']['instructions'][-11].__setitem__('operands','w16, [x14]')),('invent_full_insert',lambda t:t.__setitem__('complete_insertion_proved',True)),('omit_prior_writer',lambda t:t['prior_source_recaptures'].pop())];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr,ctx=certificates(s);aa=alterations(s)
 expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};sites={pc for g in tr.values()for pc in g['source_sites']};assert expected<=sites,(len(expected),len(sites),expected-sites)
 counts={**s['verified_source_counts'],'new_queries_unsat':len(pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(g['source_sites'])for g in tr.values()),'SSA_definitions':sum(g['SSA_definitions']for g in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_record_headers.py':sha(ROOT/'validate_daemon_reader_record_headers.py')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'complete_insertion_proved':False,'complete_parser_proved':False,'source_recapture_match':True,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
