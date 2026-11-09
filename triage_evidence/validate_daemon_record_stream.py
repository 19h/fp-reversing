#!/usr/bin/env python3
"""Static bit-vector and frozen-byte checks; no guest or target operations."""
import copy,json,subprocess
from recover_daemon_record_stream import ROOT,P,SCOPE,FLAGS,IMAGE,CS,sha,h,build,OCCURRENCE
from validate_daemon_list_output import StaticSSA,bv
def packet(records):
 return b''.join(int(r['H'],16).to_bytes(4,'big')+int(r['T'],16).to_bytes(2,'big')+r['P_bytes'].to_bytes(4,'big')+bytes.fromhex(r['payload_hex'])for r in records)
def verify(s):
 assertions=0
 for f in s['fragments'].values():
  raw=bytes.fromhex(f['bytes']);a=int(f['start'],16);assert h(raw)==f['sha256'] and IMAGE.read(a,len(raw))==raw
  ii=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)];assert ii==f['instructions'];assertions+=1
 for e in s['branches']:
  row=next(r for r in s['pointer_records']if r['slot']==e['slot']);assert row['fixup']['target']==int(e['target'],16);assertions+=1
 for p in s['retained_model_evidence']['profiles']:
  outer=p['outer_records'];inner=p['inner_records'];raw=packet(outer);n=p['path_size_including_NUL_bytes'];Li=64+16*(n//16);Lo=112+16*(n//16)
  assert 1<=n<=1024 and len(raw)==Lo==p['packet_size_bytes']==p['setter_extent_bytes'] and h(raw)==p['packet_sha256']
  assert packet(inner)==bytes.fromhex(outer[1]['payload_hex']) and len(packet(inner))==Li
  assert outer[-1]['H']==inner[-1]['H']=='0x0' and outer[-1]['T']==inner[-1]['T']=='0x50db'
  assert outer[-1]['P_bytes']==14 and inner[-1]['P_bytes']==16-(n&15)
  assert outer[-1]['payload_hex']=='00'*14 and inner[-1]['payload_hex']=='00'*inner[-1]['P_bytes']
  assert [r['size_bytes']for r in p['allocations']]==[16,Li,Lo]
  assert p['allocations'][-1]['pointer']==p['setter_buffer'] and p['dictionary']==p['send_dictionary']
  assert p['source_PC_memberships']==OCCURRENCE and not p['native_evidence']
  event=p['selected_auth_events'][0];assert event['target']=='0x1006bc13c' and event['modifier']=='0x6e32'
  assert all(e['authentication']=='bypassed in private synthetic model'for e in p['selected_auth_events']);assertions+=10
 assert len(s['retained_model_evidence']['profiles'])==12 and not s['retained_model_evidence']['legacy_generators_rerun'];return assertions
def graphs(s):
 f=s['fragments']
 v=StaticSSA({'sp':'SP',8:bv(0x3b5c),9:'M',12:'PAYLOAD_OFFSET',11:'END',14:'((_ zero_extend 32) (bvxor H #xabffbeef))'},namespace='stop_').run(f['variable'],0x100a85db4)
 r=StaticSSA({'sp':'SP',12:v.get('x12')},{'0x100c8f234':('Q',64)},namespace='result_').run(f['result'],0x100c8f238)
 u=StaticSSA({'sp':'SP',9:r.get('x9'),8:r.get('x8')},{'0x100c044e0':('OUT',64),'0x100c044e8':(r.stores[0]['value'],32)},namespace='publish_').run(f['publish_result'],0x100c044ec)
 return v,r,u
def solve(name,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(name,r.stdout,r.stderr)
 return {'name':name,'query':q,'result':'unsat','scope':scope}
def proofs(s):
 v,r,u=graphs(s);out=[]
 declarations='(declare-fun H () (_ BitVec 32))\n'+''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in ['SP','M','PAYLOAD_OFFSET','END','Q','OUT'])
 actual=[f'(distinct {v.get("w8")} (ite (= H #x00000000) #x00003b5c #x00003b60))',f'(distinct {v.get("w12")} #x00005f5a)',f'(distinct {r.get("w9")} #x0000893a)',f'(distinct {r.stores[0]["value"]} #x8b3dc651)',f'(distinct {u.stores[0]["value"]} Q)',f'(distinct {u.stores[0]["address"]} OUT)',f'(distinct {u.get("w23")} #x8b3dc651)']
 out.append(solve('source_stop_dispatch_and_Q_publication',declarations+v.prefix()+r.prefix()+u.prefix()+'(assert (or '+' '.join(actual)+'))','Exact translated prefix, inherited phase3b5c and H encoding; branch selection for arbitrary H. Publication edge is selected only for H=0; no reachability or whole-message acceptance claim.'))
 out.append(solve('writer_trailer_fits_reader_and_u32_copy_extent','''
(declare-fun t () (_ BitVec 32))
(define-fun T () (_ BitVec 64) ((_ zero_extend 32) t))
(define-fun P () (_ BitVec 64) (bvsub #x0000000000000010 (bvand (bvadd T #x000000000000000a) #x000000000000000f)))
(define-fun L () (_ BitVec 64) (bvadd T #x000000000000000a P))
(assert (bvule t #xffffffe5))
(assert (or (bvult P #x0000000000000001) (bvugt P #x0000000000000010)
 (bvule L T) (bvult (bvsub L T) #x000000000000000a)
 (bvugt L #x00000000fffffff0) (distinct (bvand L #x000000000000000f) #x0000000000000000)
 (distinct L ((_ zero_extend 32) ((_ extract 31 0) L)))))
''','Conditional writer size contract, c=T,N=L. Does not prove the preceding body parses or that output reaches this reader.'))
 out.append(solve('nested_arcade_grammar_sizes','''
(declare-fun n () (_ BitVec 64))
(assert (and (bvuge n #x0000000000000001) (bvule n #x0000000000000400)))
(define-fun Ti () (_ BitVec 64) (bvadd n #x0000000000000026))
(define-fun Pi () (_ BitVec 64) (bvsub #x0000000000000010 (bvand (bvadd Ti #x000000000000000a) #x000000000000000f)))
(define-fun Li () (_ BitVec 64) (bvadd Ti #x000000000000000a Pi))
(define-fun To () (_ BitVec 64) (bvadd Li #x0000000000000018))
(define-fun Po () (_ BitVec 64) (bvsub #x0000000000000010 (bvand (bvadd To #x000000000000000a) #x000000000000000f)))
(define-fun Lo () (_ BitVec 64) (bvadd To #x000000000000000a Po))
(define-fun rounds () (_ BitVec 64) (bvand n #xfffffffffffffff0))
(assert (or (distinct Pi (bvsub #x0000000000000010 (bvand n #x000000000000000f)))
 (distinct Li (bvadd #x0000000000000040 rounds)) (distinct Po #x000000000000000e)
 (distinct Lo (bvadd #x0000000000000070 rounds))))
''','All n=1..1024 B under the specified nested record grammar and conditional writer formula; not universal native path behavior.'))
 out.append(solve('wire50db_signed_tag','''
(define-fun stored () (_ BitVec 16) (bvxor #x50db #x11c3))
(define-fun decision () (_ BitVec 16) (bvadd stored #x0003))
(assert (or (distinct stored #x4118) (distinct decision #x411b) (bvslt decision #x0000)))
''','16-bit stored discriminator and signed test; earlier all-discriminator proof connects the upper leaf.'))
 selected={'daemon_xpc_records_checks.json':['header_and_u32_value_encoding','all_discriminator_membership','buffer_size_p_plus10','initial_fit_implies_constructor_extent_bound'],
           'daemon_xpc_iteration_checks.json':['loop_fit_progress_and_header_range']}
 for file,names in selected.items():
  old=json.loads((ROOT/file).read_text())
  for p in old['proofs']:
   if p['name']in names:
    q=p['query'];rr=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
    assert rr.returncode==0 and not rr.stderr and rr.stdout.strip()=='unsat'
    out.append({'name':'rechecked_'+p['name'],'prior_file':file,'prior_sha256':sha(ROOT/file),'query':q,'result':'unsat','scope':p['scope']})
 return out
def alterations(s):
 changes=[('source_byte',lambda t:t['fragments']['variable'].__setitem__('bytes','00'+t['fragments']['variable']['bytes'][2:])),
  ('branch_target',lambda t:t['branches'][0].__setitem__('target','0x100000000')),
  ('allocation_extent',lambda t:t['retained_model_evidence']['profiles'][0]['allocations'][-1].__setitem__('size_bytes',1)),
  ('setter_pointer',lambda t:t['retained_model_evidence']['profiles'][0].__setitem__('setter_buffer','0x1')),
  ('dictionary',lambda t:t['retained_model_evidence']['profiles'][0].__setitem__('send_dictionary','0x1')),
  ('packet_digest',lambda t:t['retained_model_evidence']['profiles'][0].__setitem__('packet_sha256','0'*64)),
  ('inner_stop_tag',lambda t:t['retained_model_evidence']['profiles'][0]['inner_records'][-1].__setitem__('T','0x9777')),
  ('auth_event',lambda t:t['retained_model_evidence']['profiles'][0]['selected_auth_events'][0].__setitem__('target','0x100000000'))]
 out=[]
 for name,alter in changes:
  t=copy.deepcopy(s);alter(t)
  try:verify(t)
  except AssertionError:out.append({'name':name,'rejected':True})
  else:raise AssertionError('accepted alteration '+name)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();assertions=verify(s);pp=proofs(s);aa=alterations(s);gg=graphs(s)
 assert not gg[0].reads and len(gg[1].reads)==1 and len(gg[2].reads)==2
 counts={**s['verified_source_counts'],'instruction_and_profile_assertions':assertions,'component_queries_unsat':len(pp),'translated_source_sites':sum(len(g.sites)for g in gg),'SSA_definitions':sum(len(g.defs)for g in gg),'rejected_alterations':len(aa),'grammar_length_domain_cases':1024}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_list_output.py':sha(ROOT/'validate_daemon_list_output.py')},'source_recapture_match':True,'instruction_and_profile_assertions':assertions,'proofs':pp,'prefix_translation':[g.record()for g in gg],'alterations':aa,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'verified_counts':counts,'static_scope':SCOPE,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
