#!/usr/bin/env python3
"""Independent bank/ABI/status checks and full-width scalar proofs.
O(B+F+I+256K) plus bounded SMT; no target execution or emulation.
"""
import copy,json,subprocess
from pathlib import Path
from recover_managed_adapter_dispatch import ROOT,P,FLAGS,build,sha,h,instructions,auth
def check(s):
 count=0
 def at(r,offset,mn,op):
  nonlocal count
  a=int(r['start'],16)+offset;x=next(i for i in r['instructions']if int(i['ea'],16)==a);assert(x['mnemonic'],x['operands'])==(mn,op),(hex(a),x,mn,op);count+=1
 assert len(s['images'])==2
 for im in s['images']:
  ranges={r['start']:r for r in im['ranges']};adapter=im['ranges'][0];base=int(adapter['start'],16);B=int(im['dispatch_base'],16);ptr={r['address']:r for r in im['original_pointer_records']};banks={r['label']:r for r in im['banks']};calls=im['calls']
  assert len(ranges)==7 and len(calls)==10 and len({r['target']for r in calls})==6
  assert len(im['banks'])==17 and im['reference']['fixups_compared']==18811 and im['reference']['all_chain_memberships_and_targets_match']
  assert len({(b['first_address'],b['second_address'],b['key_u8'])for b in im['banks']})==13
  assert all(c['target']==calls[2]['target']for c in calls[2:7])
  for b in im['banks']:
   a=bytes.fromhex(b['first_bytes']);z=bytes.fromhex(b['second_bytes']);assert len(a)==len(z)==256 and len(set(a))==len(set(z))==256
   v=[i^z[a[i]^b['key_u8']]for i in range(256)];assert v==b['results_256']and set(v)=={b['constant_u8']}
  for i,c in enumerate(calls):
   p=ptr[c['pointer_slot']];assert int(c['pointer_slot'],16)==B+8*(banks[c['bank']]['constant_u8']+c['add_index_u32'])and p['target']==c['target']and p['authenticated']and not p['bind']
   assert c['pointer_auth_metadata']==auth(p)=={'diversity_u16':c['call_modifier_u16'],'address_diversity':False,'key_index':0}
   off=int(c['site'],16)-base;at(adapter,off,'blraa','x8, x17');at(adapter,off-4,'mov','x17, #'+hex(c['call_modifier_u16']))
   if i:
    at(adapter,off-20,'and','w8, w8, #0xff');at(adapter,off-16,'add','w8, w8, #'+hex(c['add_index_u32']));at(adapter,off-12,'ldr','x8, [x22, w8, uxtw #3]');at(adapter,off-8,'sub','x0, x29, #0x80')
   else:
    at(adapter,off-8,'mov','w2, #0x80');at(adapter,off-12,'mov','w1, #0');at(adapter,off-16,'add','x0, sp, #0x40')
  for j,g in enumerate(im['gates']):
   assert g['encoded_zero_u32']==0x0ef7dc36 and g['record_status_offset_bytes']==(24 if j<5 else 12)
   off=int(g['branch_site'],16)-base;at(adapter,off,'braa','x9, x17');at(adapter,off-4,'mov','x17, #0xe7ef')
   window=[r for r in adapter['instructions']if int(g['branch_site'],16)-80<=int(r['ea'],16)<int(g['branch_site'],16)]
   assert any(r['mnemonic']=='ldur'and r['operands']==('w8, [x29, #-0x68]'if j<5 else'w8, [x29, #-0x74]')for r in window)
   assert any(r['mnemonic']=='cset'and r['operands']=='w9, eq'for r in window)
   no,yes=g['outcomes'];assert no['record_status_equals_encoded_zero']is False and yes['record_status_equals_encoded_zero']is True and no['index_u32']==0x3a0
   assert no['target']==hex(base+0x1314)and yes['target']==hex(base+[0x344,0x468,0x57c,0x690,0x7bc,0x8b0][j])
   for o in g['outcomes']:
    p=ptr[o['pointer_slot']];assert int(o['pointer_slot'],16)==B+o['index_u32']*8 and p['target']==o['target']and auth(p)==o['pointer_auth_metadata']
  marker=ranges[calls[8]['target']]
  for off,mn,op in[(0,'mov','w8, #0x284b'),(4,'movk','w8, #0x723c, lsl #16'),(8,'str','w8, [x0, #4]'),(12,'ret','')]:at(marker,off,mn,op)
  filler=ranges[calls[0]['target']]
  for off,mn,op in[(0,'neg','w8, w0'),(4,'and','x8, x8, #7'),(8,'cmp','x2, x8'),(12,'csel','x8, x2, x8, lo'),(0x6c,'sub','x8, x2, x8'),(0x84,'lsr','x10, x8, #3'),(0x88,'add','x10, x10, #7'),(0x8c,'lsr','x10, x10, #3'),(0x90,'ubfx','x11, x8, #3, #3'),(0xf8,'subs','x10, x10, #1'),(0x100,'and','x8, x8, #7')]:at(filler,off,mn,op)
  status=ranges[calls[9]['target']]
  for off,mn,op in[(0xc8,'ldr','w15, [x0, #4]'),(0x10c,'ldr','w8, [x8, #0x4c]'),(0x128,'str','w8, [x0, #8]')]:at(status,off,mn,op)
  assert len(im['direct_external_calls'])==4 and all(e['stub']['binding']['symbol']=='___stack_chk_fail'and e['stub']['binding']['library']=='/usr/lib/libSystem.B.dylib'for e in im['direct_external_calls'])
  assert len(im['nested_selected_edges'])==6
  for e in im['nested_selected_edges']:
   source=ranges[e['source_function']];off=int(e['site'],16)-int(source['start'],16);at(source,off,'blraa','x8, x17');at(source,off-4,'mov','x17, #'+hex(e['pointer_auth_metadata']['diversity_u16']));assert ptr[e['pointer_slot']]['target']==e['target']and auth(ptr[e['pointer_slot']])==e['pointer_auth_metadata']
  assert im['status_source']['field_address']=='0x10055a488'and im['status_source']['original_u32']==0x15014d6d and im['status_source']['runtime_value']=='unknown'
  for off,mn,op in[(0x1300,'ldr','x8, [sp, #0x28]'),(0x1304,'ldr','x9, [sp, #8]'),(0x1308,'str','x8, [x9]'),(0x1334,'eor','w0, w8, w9'),(0x1354,'retab','')]:at(adapter,off,mn,op)
  for r in im['ranges']:assert h(bytes.fromhex(r['bytes']))==r['sha256']and instructions(bytes.fromhex(r['bytes']),int(r['start'],16))==r['instructions']
 assert all(s[k]is False for k in FLAGS)
 return count
def proofs():
 queries={'encoded_zero':'''(declare-fun v () (_ BitVec 32))
(assert (distinct (= (bvxor v #x0ef7dc36) #x00000000) (= v #x0ef7dc36)))''','bulk_word_count':'''(declare-fun q () (_ BitVec 64))
(assert (and (bvuge q #x0000000000000001) (bvule q #x1fffffffffffffff)))
(define-fun groups () (_ BitVec 64) (bvlshr (bvadd q #x0000000000000007) #x0000000000000003))
(define-fun first () (_ BitVec 64) (ite (= (bvand q #x0000000000000007) #x0000000000000000) #x0000000000000008 (bvand q #x0000000000000007)))
(assert (distinct (bvadd first (bvmul (bvsub groups #x0000000000000001) #x0000000000000008)) q))'''};out=[]
 for name,body in queries.items():
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr
  out.append({'name':name,'query':q,'result':'unsat','exit_code':r.returncode,'scope':'Manual scalar translation matched to selected original instructions; not native reachability or whole-function proof.'})
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=check(s);bad=[]
 for name in ['bank','target','diversity','gate','marker','output_width','fill_length','execution']:
  a=copy.deepcopy(s);im=a['images'][0];adapter=im['ranges'][0]
  if name=='bank':im['banks'][0]['key_u8']^=1
  elif name=='target':im['calls'][0]['target']=im['calls'][1]['target']
  elif name=='diversity':im['calls'][0]['call_modifier_u16']^=1
  elif name=='gate':im['gates'][0]['record_status_offset_bytes']=12
  elif name=='marker':next(r for r in im['ranges']if r['start']==im['calls'][8]['target'])['instructions'][0]['operands']='w8, #0'
  elif name=='output_width':next(r for r in adapter['instructions']if r['operands']=='x8, [x9]')['operands']='w8, [x9]'
  elif name=='fill_length':next(r for r in adapter['instructions']if r['operands']=='w2, #0x80')['operands']='w2, #0x40'
  else:a['target_executed']=True
  try:check(a)
  except AssertionError:bad.append(name)
  else:raise AssertionError('Alteration accepted: '+name)
 proof=proofs();counts={**s['verified_source_counts'],'exact_instruction_assertions':n,'scalar_queries_unsat':len(proof),'rejected_alterations':len(bad)}
 scope={'original_executable_slices':2,'target_instruction_execution':False,'target_emulation':False,'PAC_execution':False,'all_adapter_authenticated_calls_locally_resolved':True,'transitive_external_interfaces_unknown':True,'native_status_and_output_unknown':True}
 out={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'verified_counts':counts,'static_scope':scope,'proofs':proof,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_controls':bad,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts))
if __name__=='__main__':main()
