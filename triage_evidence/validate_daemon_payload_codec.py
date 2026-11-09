#!/usr/bin/env python3
"""Source-derived compositional codec certificate. No CPU/guest execution."""
import copy,json,subprocess
from recover_daemon_payload_codec import ROOT,P,SCOPE,FLAGS,IMAGE,CS,KEYS,CHAIN,BLOCKS,byte_mask,sha,h,build
from validate_daemon_list_output import StaticSSA,bv,split
class SSA(StaticSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='stp':
    p=split(i['operands']);assert len(p)==3 and p[0].startswith('x')and p[1].startswith('x');a=self.address(p[2])
    for j,rd in enumerate(p[:2]):self.stores.append({'site':i['ea'],'address':a if j==0 else f'(bvadd {a} {bv(8)})','value':self.get(rd,64),'width_bits':64})
    self.sites.append(i['ea'])
   elif i['mnemonic']=='ubfiz':
    p=split(i['operands']);assert p[0].startswith('x');lsb,width=int(p[2][1:],0),int(p[3][1:],0);assert 0<width and lsb+width<=64
    self.put(p[0],f'(bvshl (bvand {self.get(p[1],64)} {bv((1<<width)-1)}) {bv(lsb)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def cut(s,name,a,z):return{'instructions':[i for i in s['fragments'][name]['instructions']if a<=int(i['ea'],16)<z]}
def constants(s):
 c=SSA({},namespace='k_');c.run(cut(s,'key_setup',0x1008ecd00,0x1008ecd10),0x1008ecd10);c.run(cut(s,'key_setup',0x1008ecd30,0x1008ecd40),0x1008ecd40)
 return c.run(cut(s,'payload_setup',0x1005e5934,0x1005e5a24),0x1005e5a24)
ROUNDS=[(0x100614304,0x100614330,0x1009c3de0,0x1009c3e2c),
 (0x100614330,0x100614340,0x1009c3e2c,0x1009c3e4c),
 (0x100614340,0x100614360,0x1009c3e4c,0x1009c3e9c),
 (0x100614360,0x100614378,0x1009c3e9c,0x1009c3ee4),
 (0x100614378,0x100614398,0x1009c3ee4,0x1009c3f3c),
 (0x100614398,0x1006143c0,0x1009c3f3c,0x1009c3f5c),
 (0x1006143c0,0x1006143cc,0x1009c3f5c,0x1009c3f74)]
def verify(s):
 assert s['round_keys']==[hex(k)for k in KEYS]and s['static_scope']==SCOPE
 for f in s['fragments'].values():
  raw=bytes.fromhex(f['bytes']);a=int(f['start'],16);assert IMAGE.read(a,len(raw))==raw and h(raw)==f['sha256']
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]
 for p in s['retained_profile_summaries']:
  assert not p['native_evidence']and len(p['encoded_buffers_at_retirement'])==2
  decoded=[]
  for b in p['encoded_buffers_at_retirement']:
   raw=bytes.fromhex(b['encoded_hex']);a=int(b['pointer'],16);known=bytes.fromhex(b['known_byte_mask']);clear=bytes(v^byte_mask(a+j)for j,v in enumerate(raw))
   assert len(raw)==len(known)==b['extent_bytes']and set(known)=={1}and h(raw)==b['encoded_sha256']and clear.hex()==b['decoded_hex']and h(clear)==b['decoded_sha256'];decoded.append(clear)
   assert b['last_write_record_index']<b['final_output_first_write_record_index']<=b['final_output_last_write_record_index']<b['retirement_record_index']
  assert b''.join(decoded).hex()==p['decoded_body_hex'];packet=b''.join(decoded)+bytes.fromhex('0000000050db0000000e')+bytes(14)
  assert len(packet)==p['packet_size_bytes']and h(packet)==p['packet_sha256']
  assert len(p['key_to_payload_episodes'])==len(p['producer_payload_write_spans'])==2
  for e in p['key_to_payload_episodes']:assert[x['target']for x in e['events']]==[hex(BLOCKS[n])for n in CHAIN]+['0x100614278']
  for span in p['producer_payload_write_spans']:
   n=span['payload_extent_bytes'];assert n==span['store_count']and span['allocation_extent_bytes']==n+10 and span['first_offset_bytes']==n+9 and span['last_offset_bytes']==10
  assert len(p['node_allocations'])==5 and all(a['size_bytes']==32 for a in p['node_allocations'])
  assert len(p['node_buffer_pairs'])==5
  for pair,node,buf in zip(p['node_buffer_pairs'],p['node_allocations'],p['record_allocations']):assert pair['node']==node['pointer']and pair['buffer']==buf['pointer']and pair['extent_bytes']==buf['size_bytes']and pair['node_field_offset_bytes']==24 and pair['field_width_bytes']==8
  assert [e['target']for e in p['append_events']].count('0x1004def68')==2 and[e['target']for e in p['append_events']].count('0x10069a4a0')==3
 return True
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in ['A','U','V','I','S','SRC','O','K','NODE','TABLE','FN'])+'(declare-fun B () (_ BitVec 8))\n(declare-fun C () (_ BitVec 32))\n'
def query(body):return'(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n'
def solve(name,body,scope):
 q=query(body);r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(name,r.stdout,r.stderr)
 return{'name':name,'query':q,'result':'unsat','scope':scope}
def mismatch(terms):return'(assert (or '+' '.join(terms)+'))'
def neq(a,b):return'(distinct '+a+' '+b+')'
def proofs(s):
 c=constants(s);base=dict(c.r);out=[];translations={'constants':c.record()}
 r=dict(base);r.update({9:'(bvsub (bvsub A I) #x000000000000000a)',11:bv(0xb16e),12:'SRC',15:'(bvadd I #x0000000000000001)'})
 e=SSA(r,{'0x10061427c':('B',8)},namespace='e_').run(s['fragments']['payload'],0x100614304)
 d=SSA({11:'A',12:bv(0),13:'O',15:'(bvshl A #x0000000000000003)',10:bv(0x56af),'sp':'K'},namespace='d_').run(s['fragments']['serializer_byte'],0x1009c3de0)
 R='((_ rotate_right 8) (bvand A #xfffffffffffffff8))'
 Q=f'(bvadd (bvsub {R} (bvand (bvadd (bvshl {R} #x0000000000000001) #x4458ba66c9cbab3e) #x64b05f970e467982)) #x98848cfeec091260)'
 X=f'(bvxor {Q} #x91e690049073ef48)';Y=f'(bvxor {Q} #x8084799fb75d43b3)'
 claims=[neq(e.get('x1'),X),neq(e.get('x0'),Y),neq(d.get('x1'),X),neq(d.get('x17'),Y),neq(e.get('x15'),'A'),neq(e.reads[0]['address'],'(bvadd SRC I)')]
 out.append(solve('common_address_seed',c.prefix()+e.prefix()+d.prefix()+mismatch(claims),'Arbitrary u64 A,I; producer R=A-I-10, countdown=I+1; selected producer phase and consumer phase. Exact seed and source-byte address; modular identities do not prove native pointers.'))
 translations.update(producer_seed=e.record(),consumer_seed=d.record())
 for j,(a,z,b,y)in enumerate(ROUNDS,1):
  r=dict(base);r.update({0:'V',1:'U',2:'((_ rotate_right 8) U)'})
  e=SSA(r,namespace='e_').run(cut(s,'payload',a,z),z)
  d=SSA({1:'U',17:'V',2:'((_ rotate_right 8) U)',14:bv(0xc7095784),16:bv(0),'sp':'K'},{'0x1009c3f14':('B',8)},namespace='d_').run(cut(s,'serializer_byte',b,y),y)
  F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(KEYS[j-1])})'
  terms=[neq(e.get('x0'if j==7 else'x1'),F),neq(d.get('x17'if j==7 else'x1'),F)]
  if j<7:terms.extend([neq(e.get('x0'),f'(bvxor ((_ rotate_left 3) V) {F})'),neq(d.get('x17'),f'(bvxor ((_ rotate_left 3) V) {F})')])
  out.append(solve('common_round_'+str(j),c.prefix()+e.prefix()+d.prefix()+mismatch(terms),'Both original source slices implement the same round for arbitrary incoming u64 state U,V; precomputed ROR8(U) is an explicit cut. Round7 final unused second-word update is not required.'))
  translations['round_'+str(j)]={'producer':e.record(),'consumer':d.record(),'producer_range':[hex(a),hex(z)],'consumer_range':[hex(b),hex(y)],'state_input':'U,V; optional precomputed ROR8(U)','round_key':hex(KEYS[j-1])}
 e=SSA({0:'U',14:'((_ zero_extend 56) B)',15:'A'},namespace='e_').run(cut(s,'payload',0x1006143cc,0x1006143dc),0x1006143dc)
 d=SSA({17:'U',15:'(bvshl A #x0000000000000003)',16:'((_ zero_extend 56) B)'},namespace='d_').run(cut(s,'serializer_byte',0x1009c3f74,0x1009c3f80),0x1009c3f80)
 K8='((_ extract 7 0) (bvlshr U (bvshl (bvand A #x0000000000000007) #x0000000000000003)))'
 out.append(solve('common_byte_selection_and_XOR',e.prefix()+d.prefix()+mismatch([neq(e.stores[0]['address'],'A'),neq(e.stores[0]['value'],f'(bvxor B {K8})'),neq(f'((_ extract 7 0) {d.get("w16")})',f'(bvxor B {K8})'),neq(f'(bvxor (bvxor B {K8}) {K8})','B')]),'Same address and common round word select the same byte; XOR cancellation is universal for B and does not require a native transfer.'))
 translations['selection']={'producer':e.record(),'consumer':d.record()}
 loop=SSA({17:'I',13:bv(0xb1),11:bv(0xb16e)},namespace='l_').run(cut(s,'payload',0x1006143dc,0x1006143ec),0x1006143ec)
 out.append(solve('producer_repeat_partition',loop.prefix()+mismatch([neq(loop.get('w14'),'(ite (= I #x0000000000000000) #x0000b16e #x0000b1df)')]),'I=0 ends the payload loop; nonzero I repeats. Original next countdown MOV X15,X17 is verified separately.'))
 translations['loop']=loop.record()
 phase=SSA({'sp':'K',11:'((_ zero_extend 32) C)'},{'0x1005e58d4':('NODE',64),'0x1005e58d8':('S',64),'0x1005e58f0':('SRC',64),'0x1005e5928':('TABLE',64)},namespace='p_').run(s['fragments']['payload_setup'],0x1005e592c)
 out.append(solve('payload_entry_phase_preimage',phase.prefix()+mismatch([neq(f'(= {phase.get("w15")} #x0000b1df)','(= C #x00004cf4)'),f'(and (= C #x00004cf4) {neq(phase.get("w11"),"#x0000b16e")})']), 'Original payload target is the unique IA/990a slot b1df in the original catalog. Full u32 incoming phase preimage is4cf4; source reachability and hardware authentication remain separate.'))
 translations['phase']=phase.record()
 node=SSA({21:'((_ zero_extend 32) (bvxor C #x8b3dc651))',22:'V',20:'NODE'},namespace='n_').run(cut(s,'record_alloc',0x100948aa4,0x100948ba0),0x100948ba0)
 out.append(solve('node_stored_extent',node.prefix()+mismatch([neq(node.stores[0]['address'],'(bvadd NODE #x0000000000000010)'),neq(node.stores[0]['value'],'(bvadd C #x0000000a)')]),'Record node+16/u32 stores payload+10 modulo32. Nonwrapping allocation interpretation additionally requires payload<=fffffff5 and the preceding admission path.'))
 translations['node_extent']=node.record()
 gate=SSA({'sp':'K',8:bv(0x9c85)},{'0x1006f0218':('O',64),'0x1006f021c':('U',64),'0x1006f0228':('NODE',64)},namespace='g_').run(s['fragments']['append_gate'],0x1006f023c)
 out.append(solve('append_tail_partition',gate.prefix()+mismatch([neq(gate.get('w8'),'(ite (= U #x0000000000000000) #x00009c85 #x00009ca7)'),neq(gate.get('x12'),'U'),neq(gate.get('x11'),'NODE'),neq(gate.get('x10'),'O')]),'Compatible incoming phase9c85; loaded tail U selects empty/nonempty original slots. Native container epoch and phase production are not established.'))
 empty=SSA({10:'O',11:'NODE'},namespace='a_').run(s['fragments']['append_empty'],0x1004def6c)
 append=SSA({10:'O',11:'NODE',12:'U'},{'0x10069a4a4':('V',64)},namespace='b_').run(s['fragments']['append'],0x10069a4b0)
 terms=[]
 for st,addr,val in[(empty.stores[0],'O','NODE'),(empty.stores[1],'(bvadd O #x0000000000000008)','NODE'),(append.stores[0],'U','NODE'),(append.stores[1],'(bvadd NODE #x0000000000000008)','V'),(append.stores[2],'(bvadd O #x0000000000000008)','NODE')]:terms.extend([neq(st['address'],addr),neq(st['value'],val)])
 out.append(solve('append_exact_stores',empty.prefix()+append.prefix()+mismatch(terms),'Empty sets head/tail to NODE; nonempty writes first tail.next, NODE.prev from the later tail reload V, then tail. Stable-tail interpretation requires U=V and disjoint valid owners; no atomicity is implied.'))
 translations['append_gate']=gate.record();translations['append_empty']=empty.record();translations['append_nonempty']=append.record()
 return out,translations
def monolithic(s):
 c=constants(s);r=dict(c.r);r.update({9:'S',11:bv(0xb16e),12:'SRC',15:'(bvadd I #x0000000000000001)'})
 e=SSA(r,{'0x10061427c':('B',8)},namespace='e_').run(s['fragments']['payload'],0x1006143dc)
 d=SSA({11:'S',12:'(bvadd I #x000000000000000a)',13:'O',15:'(bvshl (bvadd S I #x000000000000000a) #x0000000000000003)',10:bv(0x56af),'sp':'K'},{'0x1009c3f14':(e.stores[0]['value'],8)},namespace='d_').run(s['fragments']['serializer_byte'],0x1009c3f90)
 return query(c.prefix()+e.prefix()+d.prefix()+'(assert '+neq(d.stores[0]['value'],'B')+')')
def alterations(s):
 ops=[('source_byte',lambda t:t['fragments']['payload'].__setitem__('bytes','00'+t['fragments']['payload']['bytes'][2:])),
 ('round_key',lambda t:t['round_keys'].__setitem__(0,'0x0')),
 ('encoded_byte',lambda t:t['retained_profile_summaries'][0]['encoded_buffers_at_retirement'][0].__setitem__('encoded_hex','00'+t['retained_profile_summaries'][0]['encoded_buffers_at_retirement'][0]['encoded_hex'][2:])),
 ('known_mask',lambda t:t['retained_profile_summaries'][0]['encoded_buffers_at_retirement'][0].__setitem__('known_byte_mask','00'*14)),
 ('decoded_body',lambda t:t['retained_profile_summaries'][0].__setitem__('decoded_body_hex','00')),
 ('store_offset',lambda t:t['retained_profile_summaries'][0]['producer_payload_write_spans'][0].__setitem__('last_offset_bytes',9)),
 ('event_target',lambda t:t['retained_profile_summaries'][0]['key_to_payload_episodes'][0]['events'][0].__setitem__('target','0x100000000')),
 ('node_size',lambda t:t['retained_profile_summaries'][0]['node_allocations'][0].__setitem__('size_bytes',16))]
 out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:out.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s)
 q=monolithic(s);m=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert m.returncode==0 and not m.stderr and m.stdout.strip()in('unsat','unknown'),m.stdout
 probe={'query':q,'result':m.stdout.strip(),'timeout_ms':15000,'accepted_component_certificate':False,'interpretation':'Recorded separately; the accepted result uses universal seed,seven round,selection,loop,phase and node lemmas. unknown is not proof.'}
 counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'common_rounds':7,'rejected_alterations':len(aa),'translated_instruction_instances':sum(len(x.get('source_sites',[]))for x in tr.values())+sum(len(x[k]['source_sites'])for x in tr.values()if isinstance(x,dict)and'producer'in x for k in['producer','consumer'])}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_list_output.py':sha(ROOT/'validate_daemon_list_output.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'unaccepted_monolithic_probe':probe,'alterations':aa,'verified_counts':counts,'static_scope':SCOPE,'all_checks_pass':True,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps({'counts':counts,'monolithic_probe_result':probe['result']}),flush=True)
if __name__=='__main__':main()
