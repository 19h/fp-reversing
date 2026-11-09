#!/usr/bin/env python3
"""Static typed-constructor partition and source-linked BE64 codec certificate."""
import copy,json,subprocess
from recover_daemon_typed_scalar import ROOT,P,SCOPE,FLAGS,IMAGE,CS,sha,h,build,constants,known_states,KEYREGS,BLOCKS,TABLE,FIXUPS
from validate_daemon_constructor_inputs import SSA,make,prefix,bv,split
KEYS=[0x324a764c67af2e0e,0xe70987b7a1f527b0,0x9032dc5079388982,0x144db9b1af6b5721,0xeb8e58819a88bf30,0x7faaf81a732f68b4,0x4f99108510ad96e0]
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in['K','BUF','NODE','CELL','TABLE','FN','B','A','U','V']+['Z'+str(j)for j in range(31)]+['U'+str(j)for j in range(8)])+'(declare-fun T () (_ BitVec 16))\n(declare-fun E () (_ BitVec 32))\n'
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(tt):return'(assert (or '+' '.join(tt)+'))'
def solve(n,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(n,r.stdout,r.stderr)
 return{'name':n,'query':q,'result':'unsat','scope':scope}
def parts(s):
 ii=s['fragments']['u64_writer']['instructions'];seeds=[j for j,i in enumerate(ii)if i['mnemonic']=='and'and'#0xfffffffffffffff8'in i['operands']];eors=[j for j,i in enumerate(ii)if i['mnemonic']=='eor'and'ror #61'in i['operands']];sel=[j for j,i in enumerate(ii)if i['mnemonic']=='ubfiz'];stores=[j for j,i in enumerate(ii)if i['mnemonic']=='strb'];assert len(seeds)==len(sel)==len(stores)==8 and len(eors)==48
 return ii,seeds,eors,sel,stores
def initial(s,pc):
 r={j:'Z'+str(j)for j in range(31)};r['sp']='K';r.update({int(j):bv(int(v,16))for j,v in s['constant_states_before_writer_sites'][pc].items()});return r
def written(i):
 if i['mnemonic'].startswith('str')or i['mnemonic']in('cmp','cmn','braa'):return set()
 return{i['operands'].split(',')[0].lstrip('xw')}
LOADS={'0x1005a2c54':('B',64),'0x1005a2c5c':('TABLE',64),'0x1005a2c60':('FN',64)}
class WordCuts(SSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in self.cuts:
    j=self.cuts.index(pc);self.put(split(i['operands'])[0],'(bvxor U7 #x6464646464646464)'if j==7 else'U'+str(j));self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def verify(s):
 assert s['static_scope']==SCOPE and s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';parts(s)
 for f in s['fragments'].values():
  bb=bytes.fromhex(f['bytes']);a=int(f['start'],16);assert IMAGE.read(a,len(bb))==bb and h(bb)==f['sha256'];assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 assert s['constant_groups']==constants(s['fragments'])and s['constant_states_before_writer_sites']==known_states(s['fragments'],s['constant_groups'])
 assert len(s['retained_profiles'])==12
 for row in s['liveness_intervals']:assert not{p+str(r)for r in row['preserved_registers']for p in('x','w')}&set(row['written_registers'])
 for row in s['pointer_records']:assert row['fixup']==FIXUPS[int(row['slot'],16)]and row['raw_bytes']==IMAGE.read(int(row['slot'],16),8).hex()
 for p in s['retained_profiles']:
  assert not p['native_evidence']and p['counts']=={'after_header':5,'u32_class':3,'u32_length':3,'u32_call':3,'span_class':2,'span_tag':2,'u64_class':0,'u64_length':0,'u64_call':0,'u64_writer':0,'failure_gate':0,'failure_entry':0}
  assert all(e['authentication']=='bypassed in private synthetic model'for e in p['events'])
  assert p['counts']=={n:sum(e.get('target')==hex(BLOCKS[n])for e in p['events'])for n in p['counts']}
 for row in s['prior_key_preservation']:assert not{p+str(r)for r in KEYREGS for p in('x','w')}&set(row['written_registers'])
 return True
def codec(s):
 pp=[];tr={};ii,seeds,eors,sels,stores=parts(s)
 R='((_ rotate_right 8) (bvand A #xfffffffffffffff8))';S=f'(bvadd {R} #x622c5d3364e5d59f)';X=f'(bvxor {S} #xa7bebfcf1750d389)';Y=f'(bvxor {S} #xb6dc5654307e7f72)'
 for b,(a,z)in enumerate(zip(seeds,sels)):
  ee=eors[6*b:6*b+6];yr=split(ii[ee[0]]['operands'])[0];mix=next(j for j in range(ee[0]-1,a,-1)if ii[j]['mnemonic']=='add'and split(ii[j]['operands'])[2]==yr);ops=split(ii[mix]['operands']);r=initial(s,ii[a]['ea']);r[int(split(ii[a]['operands'])[1][1:])]='A'
  g=SSA(r,LOADS,namespace='s_').run({'instructions':ii[a:mix]},int(ii[mix]['ea'],16));n='byte'+str(b)+'_seed';pp.append(solve(n,g.prefix()+mismatch([neq(g.get(ops[1]),f'((_ rotate_right 8) {X})'),neq(g.get(yr),Y)]),'Exact source seed for arbitrary u64 address; only source-live literal constants supplied. No address-domain guess.'));tr[n]=[g.record()];start=mix
  for j in range(7):
   stop=ee[j]+1 if j<6 else z;r=initial(s,ii[start]['ea'])
   if j==0:r[int(ops[1][1:])]='((_ rotate_right 8) U)';r[int(yr[1:])]='V'
   else:
    old=split(ii[ee[j-1]]['operands']);xr,yr0=old[1],old[0];r[int(xr[1:])]='U';r[int(yr0[1:])]='V'
    for k in range(a,start):
     q=ii[k];p=split(q['operands'])
     if q['mnemonic']=='ror'and p[1]==xr and p[2]=='#8'and p[0]!=yr0 and all(xr[1:]not in written(v)and p[0][1:]not in written(v)for v in ii[k+1:start]):r[int(p[0][1:])]='((_ rotate_right 8) U)'
   g=SSA(r,LOADS,namespace='r_').run({'instructions':ii[start:stop]},int(ii[stop-1]['ea'],16)+4);key=KEYS[j]^(0x6464646464646464 if b==7 and j==6 else 0);F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(key)})'
   if j<6:
    op=split(ii[ee[j]]['operands']);tt=[neq(g.get(op[1]),F),neq(g.get(op[0]),f'(bvxor ((_ rotate_left 3) V) {F})')]
   else:tt=[neq(g.get(split(ii[z+1]['operands'])[1]),F)]
   n='byte'+str(b)+'_round'+str(j+1);pp.append(solve(n,g.prefix()+mismatch(tt),'Arbitrary u64 carried round states; source-live constants and precomputed rotates only. Byte7 final word has uniform XOR6464 delta, composed at selection.'));tr[n]=[g.record()];start=stop
  r=initial(s,ii[z]['ea']);p=split(ii[z]['operands']);r[int(p[1][1:])]='A';word=split(ii[z+1]['operands'])[1];r[int(word[1:])]='(bvxor U #x6464646464646464)'if b==7 else'U';raw='(bvxor B #x56b0cedea8e1a866)';r[16]=raw;r[14]='BUF'
  if b in[0,1,2,3]:r[[1,17,17,2][b]]=f'(bvlshr {raw} {bv(56-8*b)})'
  g=SSA(r,LOADS,namespace='t_').run({'instructions':ii[z:stores[b]+1]},int(ii[stores[b]]['ea'],16)+4)
  mask='((_ extract 7 0) (bvlshr U (bvshl (bvand A #x0000000000000007) #x0000000000000003)))';byte=f'((_ extract {63-8*b} {56-8*b}) (bvxor B #x2c220a381b62f9ab))';st=g.stores[0];assert st['width_bits']==8
  n='byte'+str(b)+'_selection';pp.append(solve(n,g.prefix()+mismatch([neq(st['address'],f'(bvadd BUF {bv(10+b)})'),neq(st['value'],f'(bvxor {byte} {mask})')]),'Exact BE64 payload byte/address; canonical mask word U and raw scalar B remain arbitrary. The byte7 word delta cancels its different byte XOR.'));tr[n]=[g.record()]
 return pp,tr

def proofs(s):
 pp,tr=codec(s)
 def add(n,gs,tt,scope):
  gs=gs if isinstance(gs,list)else[gs];pp.append(solve(n,prefix(*gs)+mismatch(tt),scope));tr[n]=[g.record()for g in gs]
 def reads(g,pc):return next(v for v in g.reads if v['site']==pc)
 def at(ix):return f'(bvadd TABLE {bv(ix*8)})'
 def target(g,pc,cond,a,b):return neq(reads(g,pc)['address'],f'(ite {cond} {at(a)} {at(b)})')
 sign='((_ sign_extend 16) T)';tag='((_ zero_extend 32) '+sign+')'
 relay=make(s,'key_setup',0x1008ecb8c,0x1008ecba4,{'sp':'K'},{'0x1008ecb94':('T',16)},'r_')
 add('discriminator_signed_frame_relay',relay,[neq(relay.stores[0]['address'],'(bvadd K #x0000000000000978)'),neq(relay.stores[0]['value'],sign),neq(relay.reads[0]['address'],'(bvadd K #x000000000000a65e)')],'Entry u16 T becomes signed u32 at frame978; this is the actual source operand of the ordered tree.')
 phase=make(s,'key_setup',0x1008eccc0,0x1008eccf0,{17:bv(0x6cf4),'sp':'K'},ns='p_')
 add('selected_dispatch_phases',phase,[neq(phase.get('w25'),'#x000053c3'),neq(phase.stores[0]['value'],'#x000024aa'),neq(phase.stores[1]['value'],'#x00009546')],'Original key-setup phases under explicit core6cf4; actual native production is not inferred.')
 ah=make(s,'after_header',0x1004f4bc4,0x1004f4bf4,{'sp':'K'},{'0x1004f4bc4':(bv(0x6cf4),64),'0x1004f4bcc':(sign,32),'0x1004f4bd0':('#x00009546',32),'0x1004f4be8':('TABLE',64)},'a_')
 add('signed_discriminator_lower_partition',ah,[target(ah,'0x1004f4bec','(bvslt T #x9546)',0x6f57,0x6f0f),neq(ah.get('w3'),sign)],'All u16 T; source uses signed compare against SXTH9546, not unsigned wire order.')
 uc=make(s,'u32_class',0x100609b18,0x100609b50,{3:tag,25:bv(0x53c3),'sp':'K'},{'0x100609b3c':('TABLE',64)},'u_')
 add('u32_exact_tag_gate',uc,[target(uc,'0x100609b40','(= T #x86b4)',0xc0cd,0x53c3),neq(uc.get('w22'),'#x00006cf4'),neq(uc.get('w6'),'#x74c29d88')],'Exact sign-extended86b4 match; other values select common invalid-tag frontier.')
 sc=make(s,'span_class',0x1005e72c4,0x1005e7304,{3:tag,'sp':'K'},{'0x1005e72c8':('#x000024aa',32),'0x1005e72f8':('TABLE',64)},'s_')
 add('upper_signed_partition',sc,[target(sc,'0x1005e72fc','(bvslt T #x4118)',0x24e6,0x24aa),neq(sc.get('w16'),'#x000053aa'),neq(sc.get('w14'),'#x000053c3')],'All u16 T, source signed order; exact span/u64 gates follow.')
 dc=make(s,'u64_class',0x100546360,0x1005463a0,{3:tag,16:bv(0x53aa),'sp':'K'},{'0x10054638c':('TABLE',64)},'d_')
 add('u64_exact_tag_gate',dc,[target(dc,'0x100546390','(= T #x9546)',0x53aa,0x53c3),neq(dc.get('w22'),'#x00006cf4'),neq(dc.get('w6'),'#x74c29d88')],'Exact sign-extended9546 match, full-u16 input domain.')
 st=make(s,'span_tag',0x10058ac54,0x10058ac9c,{3:tag,14:bv(0x53c3),'sp':'K'},{'0x10058ac88':('TABLE',64)},'t_')
 add('span_exact_tag_gate',st,[target(st,'0x10058ac8c','(= T #x4118)',0x64ae,0x53c3),neq(st.get('w22'),'#x00006cf4'),neq(st.get('w6'),'#x74c29d88')],'Low16 equality following signed partition; its conjunction admits exactly internal4118.')
 ul=make(s,'u32_length',0x1005c96d4,0x1005c9710,{25:bv(0x53c3),'sp':'K'},{'0x1005c96d4':('E',32),'0x1005c96fc':('TABLE',64)},'l_')
 add('u32_exact_payload_extent_gate',ul,[target(ul,'0x1005c9700','(= E #x8b3dc655)',0xc864,0x53c3),neq(ul.get('w22'),'#x00006cf4'),neq(ul.get('w6'),'#x74c29d8f'),neq(reads(ul,'0x1005c96d4')['address'],'(bvadd K #x0000000000000988)')],'All u32 encoded E; exact comparison is equivalent to decoded payload extent4 B.')
 dl=make(s,'u64_length',0x10079d560,0x10079d5bc,{22:bv(0x6cf4),'sp':'K'},{'0x10079d584':('E',32),'0x10079d5a8':('TABLE',64)},'v_')
 add('u64_exact_payload_extent_gate',dl,[target(dl,'0x10079d5ac','(= E #x8b3dc659)',0xcb61,0xa1c8),neq(dl.get('w22'),'#x00006cf4'),neq(dl.get('w14'),'#x00006cf4'),neq(dl.get('w6'),'#x74c29d8f'),neq(reads(dl,'0x10079d584')['address'],'(bvadd K #x000000000000a660)')],'All u32 E; direct saved entry field at a660, exact decoded payload extent8 B.')
 branches=[ah,uc,sc,dc,st,ul,dl]
 def eq(g,pc,ix):return'(= '+reads(g,pc)['address']+' '+at(ix)+')'
 u32='(and '+eq(ah,'0x1004f4bec',0x6f57)+' '+eq(uc,'0x100609b40',0xc0cd)+' '+eq(ul,'0x1005c9700',0xc864)+')'
 u64='(and '+eq(ah,'0x1004f4bec',0x6f0f)+' '+eq(sc,'0x1005e72fc',0x24e6)+' '+eq(dc,'0x100546390',0x53aa)+' '+eq(dl,'0x10079d5ac',0xcb61)+')'
 span='(and '+eq(ah,'0x1004f4bec',0x6f0f)+' '+eq(sc,'0x1005e72fc',0x24aa)+' '+eq(st,'0x10058ac8c',0x64ae)+')'
 accepted='(or '+u32+' '+u64+' '+span+')';expected='(or (and (= T #x86b4) (= E #x8b3dc655)) (and (= T #x9546) (= E #x8b3dc659)) (= T #x4118))'
 fit='(bvule (bvxor E #x8b3dc651) #xfffffff5)'
 add('whole_selected_type_extent_partition',branches,[neq(accepted,expected),neq('(and '+fit+' '+accepted+')','(and '+fit+' '+expected+')'),'(and (= E #x8b3dc655) (distinct (bvxor E #x8b3dc651) #x00000004))','(and (= E #x8b3dc659) (distinct (bvxor E #x8b3dc651) #x00000008))'],'Universal source-expression composition over all65536 u16 tags and all2^32 extents; selected type/size acceptance only, not allocator success, readable source, native phase or transport.')
 fg=make(s,'failure_gate',0x100544fd0,0x100544fe4,{22:bv(0x6cf4),'sp':'K'},{'0x100544fd8':('TABLE',64)},'f_')
 add('invalid_tag_common_failure_join',fg,[neq(reads(fg,'0x100544fdc')['address'],at(0x3c99))],'Invalid-tag gate reaches8c3528 under source phase6cf4; full failure retirement/return remains outside certificate.')
 call=make(s,'u64_call',0x1004cdd70,0x1004cddac,{14:bv(0x6cf4),'sp':'K'},{'0x1004cdd80':('TABLE',64)},'c_')
 add('u64_saved_operand_call_interface',call,[neq(call.get('w0'),'#x0000134c'),neq(call.get('x1'),'(bvadd K #x000000000000a668)'),neq(call.get('x14'),'(bvadd K #x00000000000038a0)'),neq(call.get('x16'),'#x56b0cedea8e1a866'),neq(reads(call,'0x1004cdd84')['address'],at(0x7d2d))],'Source supplies address of saved entry X12/u64, node cell, encoded scalar XOR and original writer continuation.')
 ent=make(s,'u64_writer',0x1005a2c2c,0x1005a2c68,{14:'CELL',1:'(bvadd K #x000000000000a668)',16:bv(0x56b0cedea8e1a866),0:bv(0x134c),'sp':'K'},{'0x1005a2c2c':('NODE',64),'0x1005a2c30':('BUF',64),'0x1005a2c54':('B',64),'0x1005a2c5c':('TABLE',64),'0x1005a2c60':('FN',64)},'e_')
 add('u64_writer_owner_value_continuation_inputs',ent,[neq(reads(ent,'0x1005a2c2c')['address'],'CELL'),neq(reads(ent,'0x1005a2c30')['address'],'(bvadd NODE #x0000000000000018)'),neq(reads(ent,'0x1005a2c54')['address'],'(bvadd K #x000000000000a668)'),neq(ent.get('x16'),'(bvxor B #x56b0cedea8e1a866)'),neq(reads(ent,'0x1005a2c60')['address'],at(0x134c)),neq(ent.get('x0'),'FN'),neq(ent.get('x1'),'(bvlshr (bvxor B #x56b0cedea8e1a866) #x0000000000000038)')],'Named owner/value loads match earlier constructor fields; valid nonaliasing owners and selected saved fields remain premises.')
 ii,seeds,eors,sels,stores=parts(s);gs=[];tt=[]
 for j,k in enumerate(seeds):
  # Each immediately preceding ADD forms the address used by this byte seed.
  ins=ii[k-1];assert ins['mnemonic']=='add'and split(ins['operands'])[1]=='x14';pc=int(ins['ea'],16);g=make(s,'u64_writer',pc,pc+4,{14:'BUF','sp':'K'},ns='ad'+str(j)+'_');gs.append(g);tt.append(neq(g.get(split(ins['operands'])[0]),f'(bvadd BUF {bv(10+j)})'))
 for j,pc,reg in[(0,0x1005a2c64,1),(1,0x1005a2e50,17),(2,0x1005a2f30,17),(3,0x1005a309c,2)]:
  g=make(s,'u64_writer',pc,pc+4,{16:'(bvxor B #x56b0cedea8e1a866)','sp':'K'},ns='sl'+str(j)+'_');gs.append(g);tt.append(neq(g.get('x'+str(reg)),f'(bvlshr (bvxor B #x56b0cedea8e1a866) {bv(56-8*j)})'))
 add('eight_payload_addresses_and_four_carried_scalar_slices',gs,tt,'Exact source definitions feeding seed/selection components; remaining scalar slices occur directly inside their selection proofs.')
 end=make(s,'u64_writer',0x1005a37c4,0x1005a37d0,{0:'FN','sp':'K'},{'0x1005a37c4':(bv(0x6cf4),64)},'x_')
 add('u64_writer_common_finish_return',end,[neq(end.get('x16'),bv(0x6cf4)),neq(end.get('x22'),bv(0x6cf4)),neq(end.get('x0'),'FN')],'Normal source exit reloads core phase and transfers through original134c continuation to common finish with modifierd08c; native PAC/completion not inferred.')
 origins=[];terms=[]
 for j,cg in enumerate(s['constant_groups']):
  g=SSA({},namespace='k'+str(j)+'_').run(cg,int(cg['end'],16));g.declarations='';origins.append(g);terms.append(neq(g.get('x'+str(cg['register'])),bv(int(cg['value_u64'],16))))
 add('literal_key_origins',origins,terms,'Ten exact original four-instruction literal groups supply nine preserved key registers and word-writer residual X20.')
 r=initial(s,s['fragments']['u64_writer']['start']);r.update({14:'CELL',1:'(bvadd K #x000000000000a668)',16:bv(0x56b0cedea8e1a866),0:bv(0x134c)})
 ll={**LOADS,'0x1005a2c2c':('NODE',64),'0x1005a2c30':('BUF',64),'0x1005a37c4':(bv(0x6cf4),64)}
 whole=WordCuts(r,ll,namespace='w_');whole.declarations='';whole.cuts=[int(ii[z-1]['ea'],16)for z in sels];whole.run(s['fragments']['u64_writer'],0x1005a37d0);terms=[];assert len(whole.stores)==8
 for j,st in enumerate(whole.stores):
  a=f'(bvadd BUF {bv(10+j)})';m=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} #x0000000000000007) #x0000000000000003)))';b=f'((_ extract {63-8*j} {56-8*j}) (bvxor B #x2c220a381b62f9ab))';terms.extend([neq(st['address'],a),neq(st['value'],f'(bvxor {b} {m})')]);assert st['width_bits']==8
 terms.extend([neq(whole.get('x0'),'FN'),neq(whole.get('x16'),bv(0x6cf4)),neq(whole.get('x22'),bv(0x6cf4))]);add('whole_writer_eight_word_cut_composition',whole,terms,'All source instructions before BRAA, with eight final mask-word cuts justified by source seed/round lemmas. Proves all eight exact store bytes/addresses and return state together, not native memory validity or whole-path execution.')
 saved=make(s,'failure_entry',0x1008c3528,0x1008c352c,{6:'((_ zero_extend 32) E)','sp':'K'},ns='fs_');add('failure_marker_preservation_frontier',saved,[neq(saved.get('x25'),'((_ zero_extend 32) E)')],'Failure entry snapshots arbitrary raw W6 into X25; later release/return behavior remains unknown.')
 return pp,tr

def alterations(s):
 ops=[('carried_scalar_clobber',lambda t:t['liveness_intervals'][4]['written_registers'].append('x1')),('pointer_target',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0)),('event_target',lambda t:t['retained_profiles'][0]['events'][0].__setitem__('target','0x100000000')),('source_byte',lambda t:t['fragments']['u64_writer'].__setitem__('bytes','00'+t['fragments']['u64_writer']['bytes'][2:])),('live_constant',lambda t:t['constant_states_before_writer_sites']['0x1005a2e58'].__setitem__('9','0x0')),('constant_origin',lambda t:t['constant_groups'][0].__setitem__('value_u64','0x0')),('u64_as_observed',lambda t:t['retained_profiles'][0]['counts'].__setitem__('u64_writer',1)),('u32_count',lambda t:t['retained_profiles'][0]['counts'].__setitem__('u32_length',4)),('prior_key_clobber',lambda t:t['prior_key_preservation'][0]['written_registers'].append('x8')),('native_relabel',lambda t:t['retained_profiles'][0].__setitem__('native_evidence',True))]
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
