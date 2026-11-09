#!/usr/bin/env python3
"""Static constructor field/guard/count contracts; never runs target code."""
import copy,json,subprocess
from recover_daemon_constructor_inputs import ROOT,P,SCOPE,FLAGS,IMAGE,CS,sha,h,build
from validate_daemon_header_codec import SSA as ParentSSA,bv,split
class SSA(ParentSSA):
 def operand(self,token,width,shift=None):
  if shift and shift.split()[0]in('uxtb','uxth','sxtb','sxth'):
   kind,*rest=shift.split();bits=8 if kind.endswith('b')else 16;e=self.get(token,bits);ext='sign_extend'if kind.startswith('s')else'zero_extend';e=f'((_ {ext} {width-bits}) {e})'
   return f'(bvshl {e} {bv(int(rest[0][1:],0),width)})'if rest else e
  return super().operand(token,width,shift)
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='strh':
    p=split(i['operands']);self.stores.append({'site':i['ea'],'address':self.address(p[1]),'value':f'((_ extract 15 0) {self.get(p[0],32)})','width_bits':16});self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in['K','C','S','W','N','B','TABLE','CONT','FN','CELL']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in['H','E','V','Q','IX'])+'(declare-fun T () (_ BitVec 16))\n'
def z32(e):return'((_ zero_extend 32) '+e+')'
PL='(bvxor E #x8b3dc651)'
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(terms):return'(assert (or '+' '.join(terms)+'))'
def make(s,name,a,z,r,loads=None,ns='v_'):
 ii=[i for i in s['fragments'][name]['instructions']if a<=int(i['ea'],16)<z];ll=dict(loads or{});dd=[]
 for i in ii:
  if i['mnemonic']in('ldr','ldrb','ldrsh')and i['ea']not in ll:
   bits=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']=='ldrsh'else 32 if i['operands'].startswith('w')else 64
   n=ns+'L'+str(len(dd));dd.append('(declare-fun '+n+' () (_ BitVec '+str(bits)+'))');ll[i['ea']]=(n,bits)
 rr={j:'Z'+str(j)for j in range(31)};rr.update(r)
 g=SSA(rr,ll,namespace=ns).run({'instructions':ii},z);g.declarations='\n'.join(dd)+'\n';return g
def prefix(*gs):return''.join(g.declarations+g.prefix()for g in gs)
def solve(name,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(name,r.stdout,r.stderr)
 return{'name':name,'query':q,'result':'unsat','scope':scope}
def verify(s):
 assert s['static_scope']==SCOPE and len(s['retained_profiles'])==12
 for f in s['fragments'].values():
  bb=bytes.fromhex(f['bytes']);a=int(f['start'],16);assert IMAGE.read(a,len(bb))==bb and h(bb)==f['sha256']
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 for p in s['retained_profiles']:
  assert not p['native_evidence']and len(p['constructor_episodes'])==len(p['allocation_pairs'])==5
  assert sum(e['events'][0]['site']=='0x1008282cc'for e in p['constructor_episodes'])==3
  for a in p['allocation_pairs']:assert a['node_extent_bytes']==32 and a['record_extent_bytes']==a['derived_payload_extent_bytes']+10 and a['payload_extent_is_derived_not_register_snapshot']
  for e in p['constructor_episodes']:
   assert len(e['events'])==8 and e['events'][1]['target']=='0x10083c564'and e['events'][2]['target']=='0x1006958b0'
   assert all(q['authentication']=='bypassed in private synthetic model'for q in e['events'])
 for n in['entry','guard','node_alloc']:assert not {'w21','x21','w19','x19'}&set(s['register_write_sets'][n])
 for r in s['liveness_intervals']:assert not{p+str(j)for j in r['preserved_register_numbers']for p in('x','w')}&set(r['written_registers'])
 for b in s['allocation_banks']:
  l,r=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);values=[i^r[l[i]^b['key_u8']]for i in range(256)]
  assert values==b['results_256']and len(set(values))==1 and b['target']=='libSystem/_malloc'and b['slot']=='0x10109ff58'and b['modifier_u16']==0x6aa4
 assert s['malloc_binding']['symbol']=='_malloc'and s['malloc_binding']['total_addend']==0
 return True
def proofs(s):
 pp=[];tr={}
 def add(name,g,terms,scope,extra=''):
  gs=g if isinstance(g,list)else[g];pp.append(solve(name,prefix(*gs)+extra+mismatch(terms),scope));tr[name]=[x.record()for x in gs]
 entry_r={'sp':'K',0:'C',8:z32('Q'),19:z32('H'),9:'((_ zero_extend 48) T)',21:z32('E'),10:z32('V'),12:'W',20:'S',11:z32('IX')}
 entry=make(s,'entry',0x100700d80,0x100700ddc,entry_r,{'0x100700d8c':('TABLE',64),'0x100700d90':('CONT',64)},'e_')
 expected=[(0x6ed0,'CONT',64),(0x5508,'C',64),(0xa658,'H',32),(0xa65e,'T',16),(0xa660,'E',32),(0xa664,'V',32),(0xa668,'W',64),(0xa670,'S',64)];assert len(entry.stores)==8
 terms=[]
 for st,(off,value,bits)in zip(entry.stores,expected):assert st['width_bits']==bits;terms.extend([neq(st['address'],f'(bvadd K {bv(off)})'),neq(st['value'],value)])
 add('entry_saved_fields',entry,terms,'Exact internal-register-to-frame snapshot, arbitrary input fields and continuation pointer. Pointer validity/aliasing and native input production are separate.')
 add('entry_selected_phase_partition',entry,[f'(and (= Q #x00006cf4) {neq(entry.get("w8"),"(ite (= C #x0000000000000000) #x0000ab69 #x0000abaa)")})',f'(and (= Q #x00006cf4) {neq(entry.get("w9"),"#x757b7df7")})'],'Selected phase6cf4: null container and present container choose exact original targets; no failure execution performed.')
 guard=make(s,'guard',0x10083c564,0x10083c5f4,{9:entry.get('x9'),21:z32('E'),'sp':'K'},ns='g_')
 route=f'(and (= {entry.get("w8")} #x0000abaa) (= {guard.get("w8")} #x0000c1cd))'
 allowed=f'(and (= Q #x00006cf4) (bvule {PL} #xfffffff5))'
 add('selected_route_phase_and_size',[entry,guard],[neq(route,allowed)],'All u32 incoming phases and encoded payload extents, C!=0. The original entry/guard edge pair admits exactly phase6cf4 and nonwrapping payload+10. This is compatible-route inference, not native phase observation.','(assert (distinct C #x0000000000000000))\n')
 g=make(s,'guard',0x10083c564,0x10083c5e0,{9:bv(0x757b7df7),21:z32('E'),'sp':'K'},ns='b_');raw=g.get('w9');g.run({'instructions':[i for i in s['fragments']['guard']['instructions']if 0x10083c5e0<=int(i['ea'],16)<0x10083c5f4]},0x10083c5f4)
 fit=f'(bvule {PL} #xfffffff5)'
 add('guard_decode_bound_and_phase',g,[neq(raw,PL),neq(g.flags['lo'],fit),neq(g.get('w8'),f'(ite {fit} #x0000c1cd #x000079f1)'),neq(g.get('w26'),'#x0000a1c8')],'Selected predecessor phase; exact all-u32 decoded extent, carry guard and downstream phase.')
 node=make(s,'node_alloc',0x1006958b0,0x100695928,{26:bv(0xa1c8),19:z32('H'),21:z32('E'),'sp':'K'},ns='n_')
 add('node_allocator_arguments',node,[neq(node.get('w0'),'#x00000020'),neq(node.get('w22'),'#x00006cf4'),neq(node.get('w23'),'#x0000c714'),neq(node.get('w19'),'H'),neq(node.get('w21'),'E')],'Argument and phase outputs independent of named controller/bank loads. Callee identity and native result remain separate.')
 post=make(s,'node_alloc',0x10069592c,0x10069594c,{0:'N',22:bv(0x6cf4),23:bv(0xc714),26:bv(0xa1c8),'sp':'K'},ns='r_')
 add('node_result_store_and_partition',post,[neq(post.stores[0]['address'],'(bvadd K #x00000000000038a0)'),neq(post.stores[0]['value'],'N'),neq(post.get('w8'),'(ite (= N #x0000000000000000) #x0000a1c8 #x0000a1cb)')],'Normal allocation-return interface; branch destinations recorded without reproducing failure behavior.')
 alloc=make(s,'record_alloc',0x100948a8c,0x100948ba0,{0:'N',21:z32('E'),23:bv(0xc714),'sp':'K'},ns='a_');qword=alloc.get('x8');extent=f'(bvadd {PL} #x0000000a)'
 assert[len(alloc.stores),alloc.stores[0]['width_bits'],alloc.stores[1]['width_bits'],alloc.stores[2]['width_bits']]==[3,64,64,32]
 add('record_extent_and_count_codec',alloc,[neq(alloc.stores[0]['value'],bv(0)),neq(alloc.stores[1]['value'],bv(0)),neq(alloc.stores[2]['address'],'(bvadd N #x0000000000000010)'),neq(alloc.stores[2]['value'],extent),neq(alloc.get('w0'),extent),neq(qword,f'(bvadd {z32(PL)} #x3d96fe86313b0569)'),neq(alloc.get('w22'),'#x00006cf4')],'Original record prefix, all encoded u32 extents. Q is additive u64 storage, not an XOR assumption. Node/heap ownership remains a premise.')
 save=make(s,'record_alloc',0x100948bd8,0x100948be0,{8:qword,'sp':'K'},ns='s_')
 add('saved_count_field',[alloc,save],[neq(save.stores[0]['address'],'(bvadd K #x000000000000a678)'),neq(save.stores[0]['value'],f'(bvadd {z32(PL)} #x3d96fe86313b0569)')],'Source interval preserves X8 before the selected save; native callee/frame epochs remain explicit.')
 relay=make(s,'key_setup',0x1008ecbf8,0x1008ecc14,{11:'(bvadd K #x0000000000009000)','sp':'K'},{'0x1008ecbf8':('E',32),'0x1008ecc0c':('V',32)},'f_')
 add('length_and_scalar_frame_relays',relay,[neq(relay.reads[0]['address'],'(bvadd K #x000000000000a660)'),neq(relay.stores[0]['address'],'(bvadd K #x0000000000000988)'),neq(relay.stores[0]['value'],'E'),neq(relay.reads[1]['address'],'(bvadd K #x000000000000a664)'),neq(relay.stores[1]['address'],'(bvadd K #x00000000000008f8)'),neq(relay.stores[1]['value'],'V')],'Named loads are the earlier saved entry fields under frame stability/disjoint heap and the normal call-preservation premise. Exact relay endpoints/values; no universal native owner claim.')
 pp.append(solve('allocation_header_length_agreement',f'(assert (bvule {PL} #xfffffff5))\n'+mismatch([neq(f'(bvxor E #x8b3dc651)',PL),neq(f'((_ zero_extend 32) {extent})',f'(bvadd {z32(PL)} #x000000000000000a)'),f'(bvult (bvadd {z32(PL)} #x000000000000000a) #x000000000000000a)']),'Composition: entry E preserved to allocation and relay to header field; admitted extent is P+10 without u32 wrap. Actual native malloc success is not inferred.'))
 phase=make(s,'key_setup',0x1008eccc0,0x1008eccf0,{17:bv(0x6cf4),'sp':'K'},ns='k_')
 add('span_dispatch_saved_phases',phase,[neq(phase.get('w25'),'#x000053c3'),neq(phase.stores[0]['value'],'#x000024aa'),neq(phase.stores[1]['value'],'#x00009546')],'Selected frame phase6cf4; exact type-dispatch thresholds and temporary phases.')
 ah=make(s,'after_header',0x1004f4bc4,0x1004f4be8,{'sp':'K'},{'0x1004f4bc4':(bv(0x6cf4),64),'0x1004f4bcc':('#x00004118',32),'0x1004f4bd0':('#x00009546',32)},'h_')
 sc=make(s,'span_class',0x1005e72c4,0x1005e72f8,{3:bv(0x4118),'sp':'K'},{'0x1005e72c8':('#x000024aa',32)},'t_')
 sh=make(s,'span_header',0x10058ac54,0x10058ac88,{14:sc.get('x14'),3:bv(0x4118),'sp':'K'},ns='j_')
 add('selected_span_dispatch',[sc,sh,ah],[neq(ah.get('w16'),'#x00006f0f'),neq(sc.get('w17'),'#x000024aa'),neq(sc.get('w14'),'#x000053c3'),neq(sh.get('w11'),'#x000064ae'),neq(sh.get('w9'),'#x000005bc'),neq(sh.get('w14'),'#x000053c3')],'Internal discriminator4118 follows exact original span edges and produces count-gate phase inputs. No other discriminator admission is generalized.')
 count=make(s,'count_gate',0x1004c1dd4,0x1004c1f58,{'sp':'K',14:bv(0x53c3),9:bv(0x5bc)},{'0x1004c1de8':(qword,64)},'d_')
 add('span_count_decode',[alloc,count],[neq(count.get('w13'),f'(bvxor {PL} #xcec4fa97)'),neq(count.get('w9'),f'(ite (= {PL} #x00000000) #x00004cf4 #x00004d18)'),neq(count.get('w11'),'#x00004cf4'),neq(count.get('w16'),'#x00006cf4')],'Saved Q from the same encoded input E recovers P for all u32 E. P=0 bypasses payload copying; nonzero chooses setup. Native frame stability is required.')
 setup=make(s,'payload_setup',0x1005e58cc,0x1005e5a2c,{'sp':'K',11:bv(0x4cf4),13:count.get('x13')},{'0x1005e58d4':('N',64),'0x1005e58d8':('B',64),'0x1005e58f0':('S',64)},'u_')
 add('span_setup_count_and_source',[alloc,count,setup],[neq(setup.get('x15'),z32(PL)),neq(setup.get('x12'),'S'),neq(setup.get('x9'),'B'),neq(setup.get('w11'),'#x0000b16e'),neq(setup.get('w13'),'#x000000b1')],'Header/allocator P is the actual selected span countdown; S comes from the saved entry source field. The nonzero route and valid owners are prerequisites for copying.')
 # Exact root defaults and continuation indices, conditional on caller phase6cf4.
 ur=make(s,'u32_root',0x100828290,0x1008282c8,{8:bv(0x6cf4),'sp':'K'},ns='u0_')
 sr=make(s,'span_root',0x10069d718,0x10069d748,{8:bv(0x6cf4),'sp':'K',20:'S',21:z32('E')},ns='s0_')
 add('typed_root_defaults',[ur,sr],[neq(ur.get('w11'),'#x00000222'),neq(ur.get('w9'),'#x000086b4'),neq(ur.get('w21'),'#x8b3dc655'),neq(ur.get('x20'),bv(0)),neq(ur.get('x12'),bv(0x2c220a381b62f9ab)),neq(sr.get('w11'),'#x000001ee'),neq(sr.get('w9'),'#x00004118'),neq(sr.get('w10'),'#x8b3dc651'),neq(sr.get('x12'),bv(0x2c220a381b62f9ab)),neq(sr.get('w21'),'E'),neq(sr.get('x20'),'S')],'Observed u32/span root blocks under explicit phase6cf4; defaults have no claimed application meaning outside selected fields.')
 finish=make(s,'common_finish',0x1005ae7a0,0x1005ae804,{16:bv(0x6cf4),'sp':'K'},{'0x1005ae7ac':('C',64),'0x1005ae7b4':('H',32)},'x_')
 lookup=[r for r in finish.reads if r['site']=='0x1005ae7f0'][0]
 add('common_finish_arguments',finish,[neq(finish.stores[0]['address'],'(bvadd K #x00000000000080b8)'),neq(finish.stores[0]['value'],bv(0)),neq(finish.get('x8'),'C'),neq(finish.get('w9'),'H'),neq(finish.get('x11'),'(bvadd K #x00000000000080b8)'),neq(finish.get('w22'),'#x00006cf4'),neq(lookup['address'],f'(bvadd {next(r["input"]for r in finish.reads if r["site"]=="0x1005ae7ec")} #x000000000000c710)')],'Selected common phase supplies container/identifier and an 8 B local output cell to original target index18e2. Callee behavior and final constructor result remain open.')
 return pp,tr
def alterations(s):
 ops=[('source',lambda t:t['fragments']['entry'].__setitem__('bytes','00'+t['fragments']['entry']['bytes'][2:])),('node_extent',lambda t:t['retained_profiles'][0]['allocation_pairs'][0].__setitem__('node_extent_bytes',16)),('record_extent',lambda t:t['retained_profiles'][0]['allocation_pairs'][0].__setitem__('record_extent_bytes',1)),('derived_as_observed',lambda t:t['retained_profiles'][0]['allocation_pairs'][0].__setitem__('payload_extent_is_derived_not_register_snapshot',False)),('entry_target',lambda t:t['retained_profiles'][0]['constructor_episodes'][0]['events'][1].__setitem__('target','0x100000000')),('episode_removed',lambda t:t['retained_profiles'][0]['constructor_episodes'].pop()),('phase_liveness',lambda t:t['register_write_sets']['guard'].append('w21')),('count_liveness',lambda t:t['liveness_intervals'][0]['written_registers'].append('x8')),('bank_result',lambda t:t['allocation_banks'][0]['results_256'].__setitem__(0,0))]
 out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:out.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'translated_instruction_instances':sum(len(g['source_sites'])for gs in tr.values()for g in gs),'SSA_definitions':sum(g['SSA_definitions']for gs in tr.values()for g in gs),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_header_codec.py':sha(ROOT/'validate_daemon_header_codec.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
