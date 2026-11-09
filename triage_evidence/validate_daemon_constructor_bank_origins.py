#!/usr/bin/env python3
"""Static initializer origin and consumer compatibility certificate; no target execution."""
import copy,json,subprocess
from recover_daemon_constructor_bank_origins import ROOT,P,SCOPE,FLAGS,IMAGE,CS,FIXUPS,EXPECTED,DC,sha,h,build,project,structure
from validate_daemon_constructor_inputs import SSA as ParentSSA,make,prefix,bv,split
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in['K','P','WORD','DELTA','FIELD','C2']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in['TAG','C0','C1','C3','C4'])+''.join('(declare-fun '+n+' () (_ BitVec 8))\n'for n in['LB0','RB0','LB1','RB1','LB2','RB2'])
class ProjectionSSA(ParentSSA):
 def run(self,f,end=None):
  # The retained source path crosses code-layout order. Translate the explicit
  # source projection order, one instruction at a time, without executing it.
  for i in f['instructions']:
   if i['ea']in getattr(self,'cuts',{}):
    self.put(split(i['operands'])[0],self.cuts[i['ea']]);self.sites.append(i['ea'])
   elif i['mnemonic']=='adrp':
    a=split(i['operands']);self.put(a[0],bv(int(a[1][1:],0)));self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},int(i['ea'],16)+4)
  return self

def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(tt):return'(assert (or '+' '.join(tt)+'))'
def solve(n,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(n,r.stdout,r.stderr)
 return{'name':n,'query':q,'result':'unsat','scope':scope}
RUNTIME={'0x10061a32c':('C0',32),'0x10061a334':('C1',32),'0x10061a3ac':('C2',64),'0x10061a824':('C3',32),'0x10061a828':('C4',32)}
BYTELOADS={'0x10061a36c':('LB0',8),'0x10061a38c':('RB0',8),'0x10061a3d4':('LB1',8),'0x10061a3f0':('RB1',8),'0x10061a844':('LB2',8),'0x10061a858':('RB2',8)}
PAIRS=[('0x10061a36c','0x10061a38c',0x100fc4230,0x101031fa0,0xf3,0x43,'LB0','RB0'),('0x10061a3d4','0x10061a3f0',0x100e99700,0x100f4e190,0x56,0x14,'LB1','RB1'),('0x10061a844','0x10061a858',0x100fc4230,0x101031fa0,0x6c,0x87,'LB2','RB2')]

def lift(p,word=None,ns='v_',phase_cut=True):
 ll={};key='(bvmul (bvxor ((_ extract 31 0) P) #xeaae0ac9) #x7398180b)'
 for r in p['loads']:
  if r['kind']=='pool_fixup':ll[r['site']]=(word or bv(r['fixup']['target']),64)
  elif r['kind']=='runtime_controller':ll[r['site']]=RUNTIME[r['site']]
  elif r['kind']=='bank_byte':ll[r['site']]=BYTELOADS[r['site']]
  elif r['kind']=='protected_tag':ll[r['site']]=('(bvxor TAG '+key+')',32)
  else:raise AssertionError(r)
 rr={j:'Z'+str(j)for j in range(31)};rr.update({'sp':'K',0:'P'});g=ProjectionSSA(rr,ll,namespace=ns);g.cuts=({'0x10061a5b4':'(bvxor P '+bv(0x39048b9ddf8693f2^0x839101713528993b)+')'}if phase_cut and p['field_offset']=='0x9d0'else{});g.run(p);g.declarations='';return g

def verify(s):
 assert s['static_scope']==SCOPE and s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in s['fragments'].values():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);assert IMAGE.read(a,len(bb))==bb and h(bb)==f['sha256'];assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 q=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text())['cases'][0]
 assert set(s['field_projections'])=={hex(o)for o in EXPECTED}
 for off,p in s['field_projections'].items():assert p==project(q,int(off,16))
 for r in s['pointer_records']:assert FIXUPS[int(r['slot'],16)]==r['fixup']and IMAGE.read(int(r['slot'],16),8).hex()==r['raw_bytes']
 assert len(s['frozen_field_ledgers'])==8
 for row in s['frozen_field_ledgers']:
  assert not row['native_evidence']and row['boundary']=='before_shared_setup_branch'and len(row['fields'])==14
  for f in row['fields']:assert f['overlapping_writes_total']==1 and int.from_bytes(bytes.fromhex(f['writer']['after_hex']),'little')==EXPECTED[int(f['offset'],16)]
 for r in s['constructor_consumers']:assert r['same_frame_reaching_definition_proved']is False and IMAGE.read(int(r['site'],16),4).hex()==r['bytes']
 for b in s['bank_lemmas']:
  l,r=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);vv=[i^r[l[i]^b['key_u8']]for i in range(256)];assert vv==b['results_256']and len(set(vv))==1 and vv[0]==int(b['collapsed_byte'],16)
 assert not s['setup_store_footprint']['SP_write_sites']and not s['setup_store_footprint']['call_sites']and s['setup_store_footprint']['branch_sites']==['0x1004c3634']and len(s['setup_store_footprint']['stores'])==129
 for r in s['literal_store_census']['fields']:assert s['field_projections'][r['offset']]['writer']in r['candidate_PCs']
 return True

def proofs(s):
 pp=[];tr={}
 p=s['field_projections']['0x9d0'];cut={'instructions':[i for i in p['instructions']if int(i['ea'],16)<=0x10061a5b4]};g=ProjectionSSA({0:'P'},namespace='k_').run(cut);g.declarations='';n='all_u64_phase_key_prefix_normalization';pp.append(solve(n,g.prefix()+mismatch([neq(g.get('x10'),'(bvxor P '+bv(0x39048b9ddf8693f2^0x839101713528993b)+')')]),'Exact source prefix through EOR at61a5b4, before multiplication; proves the full-u64 normal form used by the separate phase cut.'));tr[n]=[g.record()]
 for off,p in s['field_projections'].items():
  g=lift(p);assert len(g.stores)==1 and g.stores[0]['width_bits']==64;st=g.stores[0];expected='((_ zero_extend 32) TAG)'if int(off,16)==0x9d0 else p['expected_value'];expected=bv(int(expected,16))if expected.startswith('0x')else expected;tt=[neq(st['address'],'(bvadd K '+bv(int(off,16))+')'),neq(st['value'],expected)];extra='';by={r['site']:r for r in g.reads}
  for a,z,L,R,key,delta,lb,rb in PAIRS:
   if a not in by:continue
   index='(bvsub '+by[a]['address']+' '+bv(L)+')';tt.append('(bvugt '+index+' #x00000000000000ff)');tt.append(neq(by[z]['address'],'(bvadd '+bv(R)+' ((_ zero_extend 56) (bvxor '+lb+' '+bv(key,8)+')))'));extra+='(assert (= '+rb+' (bvxor ((_ extract 7 0) '+index+') '+bv(delta,8)+')))\n'
  for r in p['loads']:
   if r['kind']in('pool_fixup','runtime_controller'):tt.append(neq(by[r['site']]['address'],bv(int(r['nominal_address'],16))))
   elif r['kind']=='protected_tag':tt.append(neq(by[r['site']]['address'],'(bvadd P #x0000000000000008)'))
  n='field_'+off[2:]+'_origin';pp.append(solve(n,g.prefix()+extra+mismatch(tt),'Exact retained-path register projection and store, arbitrary unrelated registers/runtime controller reads and full-u32 tag. Phase projection uses the61a5b4 normalization cut justified by all_u64_phase_key_prefix_normalization; other projections have no cut. Original nominal decoded pool words are premises; byte-collapse relations are justified by768 concrete cases and the proved source byte addresses. No later reaching-definition/native claim.'));tr[n]=[g.record()]
  if int(off,16)in[0x9b0,0x9a8,0x968,0x960,0x5f0,0x5e0,0x870,0x868,0x5d0,0x5d8]:
   loads=[r for r in p['loads']if r['kind']=='pool_fixup'];assert len(loads)==1 and len(p['loads'])==1;v=loads[0]['fixup']['target'];bias=(int(p['expected_value'],16)-v)&((1<<64)-1);g=lift(p,'WORD');st=g.stores[0]
   tt=[neq(st['value'],'(bvadd WORD '+bv(bias)+')'),'(and (= WORD (bvadd '+bv(v)+' DELTA)) '+neq(st['value'],'(bvadd '+bv(int(p['expected_value'],16))+' DELTA)')+')',neq(st['address'],'(bvadd K '+bv(int(off,16))+')')]
   n='field_'+off[2:]+'_all_u64_loaded_word_affine';pp.append(solve(n,g.prefix()+mismatch(tt),'All-u64 loaded pool word and arbitrary additive delta; source bias/copies preserve that delta. This is a local loaded-word identity, not a native ASLR/loader/authentication theorem.'));tr[n]=[g.record()]
 gs=[];tt=[]
 for j,r in enumerate(s['constructor_consumers']):
  g=ParentSSA({'sp':'K'},{r['site']:('FIELD',64)},namespace='c'+str(j)+'_').run({'instructions':[r['instruction']]},int(r['site'],16)+4);g.declarations='';gs.append(g);assert len(g.reads)==1 and g.reads[0]['width_bits']==64;tt.extend([neq(g.reads[0]['address'],'(bvadd K '+bv(int(r['field_offset'],16))+')'),neq(g.get(split(r['instruction']['operands'])[0]),'FIELD')])
 pp.append(solve('twenty_six_exact_constructor_field_loads',prefix(*gs)+mismatch(tt),'All-u64 K and supplied FIELD; source address/width/register load compatibility only. Initializer frame equality and preservation to these later consumers remain unproved.'));tr['twenty_six_exact_constructor_field_loads']=[g.record()for g in gs]
 gs=[];tt=[]
 for j,r in enumerate(s['setup_store_footprint']['stores']):
  rr={n:'Z'+str(n)for n in range(31)};rr['sp']='K';g=ParentSSA(rr,namespace='st'+str(j)+'_').run({'instructions':[r['instruction']]},int(r['site'],16)+4);g.declarations='';assert len(g.stores)==1;gs.append(g);st=g.stores[0];tt.append(neq(st['address'],'(bvadd K '+bv(r['offset_bytes'])+')'));assert st['width_bits']==r['width_bytes']*8
  for off,p in s['field_projections'].items():
   if p['writer']==r['site']:continue
   a='(bvadd K '+bv(int(off,16))+')';ae='(bvadd K '+bv(int(off,16)+8)+')';end='(bvadd '+st['address']+' '+bv(r['width_bytes'])+')';tt.append('(and (bvult '+st['address']+' '+ae+') (bvult '+a+' '+end+'))')
 extra='(assert (bvule K #xfffffffffffef22f))\n'
 global EXCLUDED_FOOTPRINT
 EXCLUDED_FOOTPRINT='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+prefix(*gs)+extra+mismatch(tt)+'\n(check-sat)\n'
 address_terms=[t for t in tt if t.startswith('(distinct ')];assert len(address_terms)==129
 pp.append(solve('setup_exact_fixed_store_addresses',prefix(*gs)+mismatch(address_terms),'All129 source store addresses with unchanged SP, independently of stored values. Full setup has no calls or SP writes and only its final branch.'));tr['setup_exact_fixed_store_addresses']=[g.record()for g in gs]
 pairs=0
 for r in s['setup_store_footprint']['stores']:
  written={(r['offset_bytes']+b)&((1<<64)-1)for b in range(r['width_bytes'])}
  for off,p in s['field_projections'].items():
   if p['writer']==r['site']:continue
   tracked={(int(off,16)+b)&((1<<64)-1)for b in range(8)};assert written.isdisjoint(tracked);pairs+=1
 assert pairs==1796
 pp.append(solve('all_u64_common_frame_byte_address_injectivity','(assert (distinct (= (bvadd K WORD) (bvadd K DELTA)) (= WORD DELTA)))','Any common base and u64 relative byte offsets: modular addition is bijective. Together with1796 finite nonoverlap store/field pairs and exact source addresses, proves local setup byte-footprint separation; does not prove physical owners or later paths.'))

 return pp,tr

def alterations(s):
 ops=[('SP_invariance_relabel',lambda t:t['setup_store_footprint']['SP_write_sites'].append('0x1004c24a4')),('source_byte',lambda t:t['fragments']['setup'].__setitem__('bytes','00'+t['fragments']['setup']['bytes'][2:])),('projection_drop',lambda t:t['field_projections']['0x9b0']['instructions'].pop(0)),('origin_value',lambda t:t['field_projections']['0x9a8'].__setitem__('expected_value','0x0')),('profile_value',lambda t:t['frozen_field_ledgers'][0]['fields'][0]['writer'].__setitem__('after_hex','00'*8)),('bank_result',lambda t:t['bank_lemmas'][0]['results_256'].__setitem__(0,0)),('reaching_definition_relabel',lambda t:t['constructor_consumers'][0].__setitem__('same_frame_reaching_definition_proved',True)),('census_writer_removed',lambda t:next(r for r in t['literal_store_census']['fields']if r['offset']=='0x9b0')['candidate_PCs'].remove(t['field_projections']['0x9b0']['writer'])),('native_relabel',lambda t:t['frozen_field_ledgers'][0].__setitem__('native_evidence',True)),('pointer_target',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0))]
 aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:aa.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return aa

def uncut_phase_query(s):
 # Reconstruct the initially timed-out query for reproducibility; this query is
 # retained as excluded evidence and is not replayed/accepted as a certificate.
 g=lift(s['field_projections']['0x9d0'],phase_cut=False);tt=[neq(g.stores[0]['address'],'(bvadd K #x00000000000009d0)'),neq(g.stores[0]['value'],'((_ zero_extend 32) TAG)'),neq(g.reads[0]['address'],'(bvadd P #x0000000000000008)')]
 return'(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+g.prefix()+mismatch(tt)+'\n(check-sat)\n'

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s);counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'translated_instruction_instances':sum(len(g['source_sites'])for gs in tr.values()for g in gs),'SSA_definitions':sum(g['SSA_definitions']for gs in tr.values()for g in gs),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_constructor_inputs.py':sha(ROOT/'validate_daemon_constructor_inputs.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'excluded_approach':{'name':'uncut_phase_key_and_store','observed_initial_result':'unknown','query':uncut_phase_query(s),'timeout_ms':15000,'accepted_as_proof':False,'scope':'Initial uncut phase origin solver attempt reached timeout; final certificate uses a separate exact source-prefix normalization and justified phase cut.'},'excluded_store_approach':{'name':'combined_ordered_intervals','observed_initial_result':'unknown','query':EXCLUDED_FOOTPRINT,'timeout_ms':15000,'accepted_as_proof':False,'scope':'Initial ordered-interval footprint query reached timeout; final certificate uses source address equations,1796 finite byte-footprint pairs and all-u64 common-base injectivity.'},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
