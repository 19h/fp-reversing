#!/usr/bin/env python3
"""Static source-to-SMT constructor rejection and candidate retirement certificate."""
import copy,json,subprocess
from recover_daemon_constructor_failure import ROOT,P,SCOPE,FLAGS,IMAGE,CS,FIXUPS,TABLE,sha,h,build
from validate_daemon_constructor_inputs import SSA,make,prefix,bv,split
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in['K','C','N','B','CONT','TABLE','FN','STATUS','L','R','P0','P1']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in['E','C0','C1'])+'(declare-fun LB () (_ BitVec 8))\n(declare-fun RB () (_ BitVec 8))\n'
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(tt):return'(assert (or '+' '.join(tt)+'))'
def solve(n,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(n,r.stdout,r.stderr)
 return{'name':n,'query':q,'result':'unsat','scope':scope}
def verify(s):
 assert s['static_scope']==SCOPE and s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in s['fragments'].values():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);assert IMAGE.read(a,len(bb))==bb and h(bb)==f['sha256'];assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 for row in s['pointer_records']:assert FIXUPS[int(row['slot'],16)]==row['fixup']and IMAGE.read(int(row['slot'],16),8).hex()==row['raw_bytes']
 for b in s['retirement_banks']:
  l,r=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);vv=[i^r[l[i]^b['key_u8']]for i in range(256)];assert vv==b['results_256']and len(set(vv))==1 and b['target']=='libSystem/_free'and b['slot']=='0x10109ff30'and b['left_frame_slot']=='0x5f0'and b['right_frame_slot']=='0x5e0'
 assert s['free_binding']['symbol']=='_free'and s['free_binding']['total_addend']==0
 for n in ['failure','free_buffer','free_node','early_return']:
  stores=[i for i in s['fragments'][n]['instructions']if i['mnemonic'].startswith(('str','stp'))]
  assert stores==([{'ea':'0x10078c3f4','mnemonic':'str','operands':'xzr, [x20, #0x18]'}]if n=='free_buffer'else[])
 for row in s['liveness_intervals']:assert not{p+str(r)for r in row['preserved_registers']for p in('x','w')}&set(row['written_registers'])
 e=s['metadata_erratum'];assert e['historical_value']=='0x5f0'and e['correct_value']=='0x968'and e['source_instruction']=={'ea':'0x100948bbc','mnemonic':'ldr','operands':'x10, [sp, #0x968]'}
 assert len(s['retained_profiles'])==12
 for p in s['retained_profiles']:
  assert not p['native_evidence']and set(p['cleanup_target_occurrences'].values())=={0}and set(p['cleanup_call_occurrences'].values())=={0}
  assert len(p['node_result_pointers'])==len(p['buffer_result_pointers'])==5 and all(int(v,16)!=0 for v in p['node_result_pointers']+p['buffer_result_pointers'])
 return True

def proofs(s):
 pp=[];tr={}
 def add(n,gs,tt,scope,extra=''):
  gs=gs if isinstance(gs,list)else[gs];pp.append(solve(n,prefix(*gs)+extra+mismatch(tt),scope));tr[n]=[g.record()for g in gs]
 def read(g,pc):return next(v for v in g.reads if v['site']==pc)
 def at(ix):return f'(bvadd TABLE {bv(ix*8)})'
 def target(g,pc,condition,a,b):return neq(read(g,pc)['address'],f'(ite {condition} {at(a)} {at(b)})')
 ent=make(s,'entry',0x100700d80,0x100700de8,{0:'C',8:bv(0x6cf4),'sp':'K'},{'0x100700d8c':('TABLE',64),'0x100700d90':('CONT',64)},'e_')
 add('null_container_selected_early_return',ent,[target(ent,'0x100700ddc','(= C #x0000000000000000)',0xab69,0xabaa),neq(ent.get('w6'),'#x74c29d88'),neq(ent.stores[0]['address'],'(bvadd K #x0000000000006ed0)'),neq(ent.stores[0]['value'],'CONT')],'Selected phase6cf4; null C selects saved-continuation return before allocation. Shared-frame stores still require valid frame ownership.')
 guard=make(s,'guard',0x10083c564,0x10083c600,{9:bv(0x757b7df7),21:'((_ zero_extend 32) E)',6:'STATUS','sp':'K'},{'0x10083c5f4':('TABLE',64)},'g_')
 fit='(bvule (bvxor E #x8b3dc651) #xfffffff5)'
 add('extent_rejection_preserves_pending_status',guard,[target(guard,'0x10083c5f8',fit,0xc1cd,0x79f1),neq(guard.get('x6'),'STATUS'),neq(guard.get('w26'),'#x0000a1c8')],'All encoded u32 extents under selected entry phase; rejected payload+10 returns without allocator/cleanup entry, retaining entry marker.')
 np=make(s,'node_alloc',0x10069592c,0x10069595c,{0:'N',22:bv(0x6cf4),23:bv(0xc714),26:bv(0xa1c8),27:'TABLE','sp':'K'},ns='n_')
 add('node_result_store_and_failure_frontier',np,[neq(np.stores[0]['address'],'(bvadd K #x00000000000038a0)'),neq(np.stores[0]['value'],'N'),target(np,'0x10069594c','(= N #x0000000000000000)',0xa1c8,0xa1cb),neq(np.get('w6'),'#x74c29d85'),neq(np.get('w22'),'#x00006cf4')],'Normal allocation-result interface only; shared cleanup dereferences node before its buffer predicate, so null-node graceful cleanup is not established. No fault fixture is executed.')
 rp=make(s,'record_alloc',0x100948bfc,0x100948c24,{0:'B',20:'N',21:'TABLE',23:bv(0xc714),22:bv(0x6cf4),'sp':'K'},ns='b_')
 add('buffer_result_publication_and_failure_frontier',rp,[neq(rp.stores[0]['address'],'(bvadd N #x0000000000000018)'),neq(rp.stores[0]['value'],'B'),target(rp,'0x100948c14','(= B #x0000000000000000)',0xc766,0xc714),neq(rp.get('w6'),'#x74c29d85')],'Valid live node and normal record-allocation return; NULL buffer is explicitly stored then selects cleanup, whose first branch skips buffer free.')
 ff=make(s,'failure',0x1008c3528,0x1008c358c,{6:'STATUS',22:bv(0x6cf4),'sp':'K'},{'0x1008c3548':('N',64),'0x1008c354c':('B',64),'0x1008c3578':('TABLE',64),'0x1008c3580':('R',64),'0x1008c3584':('L',64)},'f_')
 assert not ff.stores
 add('cleanup_snapshot_owners_banks_and_buffer_partition',ff,[neq(ff.get('x25'),'STATUS'),neq(ff.get('x20'),'N'),neq(ff.get('x0'),'B'),neq(ff.get('w19'),'#x000079f1'),neq(ff.get('w21'),'#x0000a7fb'),neq(ff.get('x23'),'R'),neq(ff.get('x24'),'L'),neq(read(ff,'0x1008c3548')['address'],'(bvadd K #x00000000000038a0)'),neq(read(ff,'0x1008c354c')['address'],'(bvadd N #x0000000000000018)'),neq(read(ff,'0x1008c3580')['address'],'(bvadd K #x00000000000005e0)'),neq(read(ff,'0x1008c3584')['address'],'(bvadd K #x00000000000005f0)'),target(ff,'0x1008c357c','(= B #x0000000000000000)',0xa7fb,0xa7f7)],'Arbitrary full64-bit incoming X6 is saved, valid node owner is read before buffer predicate, and original cleanup bank pointers are loaded. Phase6cf4 only; no native ownership/NULL-dereference behavior is tested.')
 ctl0='(bvmul (bvxor (bvsub C1 C0) #x000000a6) #x0a5cd4cf)';ctl1='(bvmul (bvxor C0 C1 #x000000a6) #x0a5cd4cf)'
 for name,pc,end,controller,lbpc,rbpc,tpc,epc,key,delta in [('free_buffer',0x10078c384,0x10078c3f0,ctl0,'0x10078c3b8','0x10078c3cc','0x10078c3e4','0x10078c3e8',0x86,0x58),('free_node',0x1006b794c,0x1006b79a4,ctl1,'0x1006b7978','0x1006b7984','0x1006b7998','0x1006b799c',0x9a,0xe5)]:
  ll=({'0x10078c38c':('P0',64),'0x10078c390':('C0',32),'0x10078c394':('P1',64),'0x10078c398':('C1',32)}if name=='free_buffer'else{'0x1006b794c':('P0',64),'0x1006b7950':('C0',32),'0x1006b7954':('P1',64),'0x1006b7958':('C1',32),'0x1006b7988':('N',64)})
  ll.update({lbpc:('LB',8),rbpc:('RB',8),tpc:('TABLE',64),epc:('FN',64)});r={0:'B',20:'N',19:bv(0x79f1),21:bv(0xa7fb),23:'R',24:'L',25:'STATUS','sp':'K'};g=make(s,name,pc,end,r,ll,name+'_')
  byte='((_ extract 7 0) '+controller+')';extra=f'(assert (= RB (bvxor {byte} {bv(delta,8)})))\n'
  tt=[neq(read(g,lbpc)['address'],'(bvadd L ((_ zero_extend 56) '+byte+'))'),neq(read(g,rbpc)['address'],f'(bvadd R ((_ zero_extend 56) (bvxor LB {bv(key,8)})))'),neq(read(g,epc)['address'],at(0xcc08)),neq(g.get('x0'),'B'if name=='free_buffer'else'N'),neq(g.get('x25'),'STATUS'),neq(g.get('w19'),'#x000079f1')]
  if name=='free_node':tt.append(neq(read(g,'0x1006b7988')['address'],'(bvadd K #x00000000000038a0)'))
  add(name+'_source_selector_and_call_argument',g,tt,'All controller words and raw status. RB=controller_byte XOR delta is justified by512 concrete pinned-bank cases and the exact source byte-address/key contract; actual frame roots, normal allocator ABI and call completion remain premises.',extra)
 fb=make(s,'free_buffer',0x10078c3f4,0x10078c400,{20:'N',21:bv(0xa7fb),22:'TABLE',25:'STATUS','sp':'K'},ns='p_')
 assert len(fb.stores)==1
 add('post_buffer_call_clear_and_node_release_join',fb,[neq(fb.stores[0]['address'],'(bvadd N #x0000000000000018)'),neq(fb.stores[0]['value'],bv(0)),neq(read(fb,'0x10078c3f8')['address'],at(0xa7fb)),neq(fb.get('x25'),'STATUS')],'After normal free(B) preserving saved registers, source clears candidate+18 and selects node release; it does not clear the candidate frame cell.')
 fn=make(s,'free_node',0x1006b79a8,0x1006b79b4,{20:'TABLE',19:bv(0x79f1),25:'STATUS','sp':'K'},ns='q_');assert not fn.stores
 add('post_node_call_restore_full_status_and_return_join',fn,[neq(read(fn,'0x1006b79a8')['address'],at(0x79f1)),neq(fn.get('x6'),'STATUS')],'After normal free(N) preserving X19/X20/X25, full incoming X6 is restored and original79f1 continuation selects early return. No candidate-cell clear exists here.')
 er=make(s,'early_return',0x10076de60,0x10076de68,{6:'STATUS','sp':'K'},{'0x10076de60':('CONT',64)},'r_')
 add('saved_constructor_continuation_and_status',er,[neq(read(er,'0x10076de60')['address'],'(bvadd K #x0000000000006ed0)'),neq(er.get('x8'),'CONT'),neq(er.get('x6'),'STATUS'),neq(er.get('x17'),bv(0x151e))],'Exact source reload/transfer operands only; continuation-table root, saved frame and hardware authentication/native completion remain separate.')
 ig=make(s,'invalid_tag_join',0x100544fd0,0x100544fe4,{22:bv(0x6cf4),6:'STATUS','sp':'K'},{'0x100544fd8':('TABLE',64)},'i_')
 add('invalid_tag_and_u32_size_failure_join',ig,[neq(read(ig,'0x100544fdc')['address'],at(0x3c99)),neq(ig.get('x6'),'STATUS')],'Selected invalid-tag and u32-size failure intermediary preserves raw status into common cleanup; actual marker assignments are proved by the prior typed-scalar certificate.')
 status='((_ extract 31 0) STATUS)'
 sg=make(s,'lookup_status',0x100742a30,0x100742a70,{6:'STATUS',8:bv(0x7278),'sp':'K'},{'0x100742a64':('TABLE',64)},'ls_')
 mg=make(s,'lookup_miss',0x1009a0b64,0x1009a0ba8,{6:'STATUS',9:bv(0x3c99),'sp':'K'},{'0x1009a0b9c':('TABLE',64)},'lm_')
 hg=make(s,'lookup_found',0x10069a114,0x10069a168,{6:'STATUS',8:bv(0x7278),'sp':'K'},{'0x10069a15c':('TABLE',64)},'lh_')
 failure='(or (and (= '+read(sg,'0x100742a68')['address']+' '+at(0x72b4)+') (= '+read(hg,'0x10069a160')['address']+' '+at(0x3c99)+')) (and (= '+read(sg,'0x100742a68')['address']+' '+at(0x7278)+') (= '+read(mg,'0x1009a0ba0')['address']+' '+at(0x3c99)+')))'
 exp=f'(and (distinct {status} #x8b3dc651) (distinct {status} #x74c29ded))'
 add('lookup_other_statuses_select_cleanup',[sg,mg,hg],[neq(failure,exp),neq(hg.get('x6'),'STATUS'),neq(mg.get('x6'),'STATUS'),neq(hg.get('w22'),'#x00006cf4'),neq(mg.get('w22'),'#x00006cf4')],'All raw X6 words; signed classifier plus exact success/miss gates routes every other low32 status to common cleanup without changing X6.')
 # Source-defined cleanup writes only candidate.buf=0 after the optional buffer
 # call. The new node frame cell and old-match scratch are not zeroed here.
 add('cleanup_instruction_store_footprint',[ff,fb,fn],[neq(fb.stores[0]['address'],'(bvadd N #x0000000000000018)'),neq(fb.stores[0]['value'],bv(0))],'Only the explicit stores in these cleanup fragments are covered. Normal allocator effects and aliases/global list membership require independent owner premises.')
 slot=make(s,'record_alloc',0x100948bbc,0x100948bc0,{'sp':'K'},{'0x100948bbc':('L',64)},'slot_')
 add('corrected_record_allocator_left_slot',slot,[neq(read(slot,'0x100948bbc')['address'],'(bvadd K #x0000000000000968)')],'Original source proves the earlier 5f0 metadata label wrong. Frozen prior JSON/script remain historical; corrected report and explicit erratum supersede that label only.')
 return pp,tr

def alterations(s):
 ops=[('source_byte',lambda t:t['fragments']['failure'].__setitem__('bytes','00'+t['fragments']['failure']['bytes'][2:])),('bank_result',lambda t:t['retirement_banks'][0]['results_256'].__setitem__(0,0)),('bank_slot',lambda t:t['retirement_banks'][0].__setitem__('left_frame_slot','0x968')),('erratum_regression',lambda t:t['metadata_erratum'].__setitem__('correct_value','0x5f0')),('pointer_target',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0)),('status_clobber',lambda t:t['liveness_intervals'][0]['written_registers'].append('x25')),('cleanup_as_observed',lambda t:t['retained_profiles'][0]['cleanup_target_occurrences'].__setitem__('failure',1)),('native_relabel',lambda t:t['retained_profiles'][0].__setitem__('native_evidence',True)),('null_result_relabel',lambda t:t['retained_profiles'][0]['node_result_pointers'].__setitem__(0,'0x0'))]
 aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:aa.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return aa

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s);counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'translated_instruction_instances':sum(len(g['source_sites'])for gs in tr.values()for g in gs),'SSA_definitions':sum(g['SSA_definitions']for gs in tr.values()for g in gs),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_constructor_inputs.py':sha(ROOT/'validate_daemon_constructor_inputs.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
