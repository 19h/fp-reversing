#!/usr/bin/env python3
"""Static header/word-writer certificate; no CPU, guest or target operations."""
import copy,json,subprocess
from recover_daemon_header_codec import ROOT,P,SCOPE,FLAGS,IMAGE,CS,WORD_PCS,TAG_PCS,sha,h,build
from validate_daemon_payload_codec import SSA as ParentSSA,bv,split
class SSA(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='ubfx':
    p=split(i['operands']);w=32 if p[0].startswith('w')else 64;lsb,width=int(p[2][1:],0),int(p[3][1:],0)
    assert 0<width and lsb+width<=w;self.put(p[0],f'(bvand (bvlshr {self.get(p[1],w)} {bv(lsb,w)}) {bv((1<<width)-1,w)})');self.sites.append(i['ea'])
   elif i['mnemonic']=='ldrsh':
    value,bits=self.loads[i['ea']];assert bits==16 and i['operands'].startswith('w');p=split(i['operands']);self.reads.append({'site':i['ea'],'address':self.address(p[1]),'width_bits':16,'input':value,'signed':True});self.put(p[0],f'((_ sign_extend 16) {value})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
KEYS=[0x324a764c67af2e0e,0xe70987b7a1f527b0,0x9032dc5079388982,0x144db9b1af6b5721,0xeb8e58819a88bf30,0x7faaf81a732f68b4,0x4f99108510ad96e0]
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in ['A','BUF','O','U','V','K','TABLE','FN','NODE','CELL']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in ['F','H','L','Q'])+'(declare-fun T () (_ BitVec 16))\n'
def cut(s,n,a,z):return{'instructions':[i for i in s['fragments'][n]['instructions']if a<=int(i['ea'],16)<z]}
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(terms):return'(assert (or '+' '.join(terms)+'))'
def solve(name,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(name,r.stdout,r.stderr)
 return{'name':name,'query':q,'result':'unsat','scope':scope}
def constants(s):
 g=SSA({},namespace='k_')
 for c in s['constant_groups']:g.run(c,int(c['end'],16))
 return g
def chunks(s):
 out=[]
 for n in['word','tag']:
  ii=s['fragments'][n]['instructions'];previous=0
  for j,st in enumerate(i for i in ii if i['mnemonic']=='strb'):
   end=ii.index(st)+1;seg=ii[previous:end];previous=end
   start=next(k for k,i in enumerate(seg)if i['mnemonic']=='and'and '#0xfffffffffffffff8'in i['operands']);seg=seg[start:]
   eors=[k for k,i in enumerate(seg)if i['mnemonic']=='eor'and'ror #61'in i['operands']];assert len(eors)==6
   yreg=split(seg[eors[0]]['operands'])[0]
   mix=next(k for k in range(eors[0]-1,-1,-1)if seg[k]['mnemonic']=='add'and split(seg[k]['operands'])[2]==yreg)
   sel=next(k for k,i in enumerate(seg)if i['mnemonic']=='ubfiz');out.append({'role':n,'byte':j,'instructions':seg,'eors':eors,'mix':mix,'selection':sel})
 return out
def written(i):
 if i['mnemonic'].startswith(('str','stp'))or i['mnemonic']in('cmp','cmn','tst','braa'):return set()
 return{i['operands'].split(',')[0].lstrip('xw')}
def verify(s):
 assert s['static_scope']==SCOPE and len(chunks(s))==6
 for f in s['fragments'].values():
  bb=bytes.fromhex(f['bytes']);a=int(f['start'],16);assert h(bb)==f['sha256']and IMAGE.read(a,len(bb))==bb
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 for p in s['retained_profiles']:
  assert not p['native_evidence']and len(p['records'])==5 and len(p['word_entry_events'])==13 and len(p['tag_entry_events'])==5
  for r in p['records']:
   exp=list(zip(WORD_PCS,range(4)))+list(zip(TAG_PCS,[4,5]))+list(zip(WORD_PCS,range(6,10)))
   assert[(w['pc'],w['offset_bytes'])for w in r['header_stores']]==exp and all(w['size_bytes']==1 for w in r['header_stores'])
   assert[(w['pc'],w['offset_bytes'])for w in r['scalar_word_stores']]==(list(zip(WORD_PCS,range(10,14)))if r['allocation_extent_bytes']==14 else[])
 for n in['word','tag','after_identifier','after_tag']:
  assert not {'x7','w7','x21','w21'}&set(s['register_write_sets'][n])
 return True
def proofs(s):
 c=constants(s);pp=[];tr={'constants':c.record()}
 def initial():
  r={j:'Z'+str(j)for j in range(31)};r.update(c.r);r.update({19:'O',22:'((_ zero_extend 32) F)','sp':'K'});return r
 R='((_ rotate_right 8) (bvand A #xfffffffffffffff8))';B=f'(bvadd {R} #x622c5d3364e5d59f)';X=f'(bvxor {B} #xa7bebfcf1750d389)';Y=f'(bvxor {B} #xb6dc5654307e7f72)'
 Q=f'(bvadd (bvsub {R} (bvand (bvadd (bvshl {R} #x0000000000000001) #x4458ba66c9cbab3e) #x64b05f970e467982)) #x98848cfeec091260)'
 pp.append(solve('short_seed_equals_prior_payload_seed',mismatch([neq(f'(bvxor {Q} #x91e690049073ef48)',X),neq(f'(bvxor {Q} #x8084799fb75d43b3)',Y)]),'All u64 A; compact seed is equivalent to the prior producer/consumer seed. Native ownership is outside scalar scope.'))
 loads={'0x1007b299c':('TABLE',64),'0x1007b29a0':('FN',64)}
 for ch in chunks(s):
  seg=ch['instructions'];mix=ch['mix'];eors=ch['eors'];n=ch['role']+str(ch['byte']);mops=split(seg[mix]['operands']);yreg=split(seg[eors[0]]['operands'])[0]
  r=initial();r[2]='A';seed=SSA(r,namespace='s_').run({'instructions':seg[:mix]},int(seg[mix]['ea'],16));tr[n+'_seed']=seed.record()
  pp.append(solve(n+'_seed',c.prefix()+seed.prefix()+mismatch([neq(seed.get(mops[1]),f'((_ rotate_right 8) {X})'),neq(seed.get(yreg),Y)]),'Original byte-specific source seed, arbitrary u64 A and raw field F, pinned constant origins. First rotate is already computed at this cut.'))
  start=mix
  for j in range(7):
   stop=eors[j]+1 if j<6 else ch['selection'];r=initial()
   if j==0:r[int(mops[1][1:])]='((_ rotate_right 8) U)';r[int(yreg[1:])]='V'
   else:
    old=split(seg[eors[j-1]]['operands']);xr,yr=old[1],old[0];r[int(xr[1:])]='U';r[int(yr[1:])]='V'
    for k in range(start):
     i=seg[k];p=split(i['operands'])
     if i['mnemonic']=='ror'and p[1]==xr and p[2]=='#8'and p[0]!=yr and all(xr[1:]not in written(q)and p[0][1:]not in written(q)for q in seg[k+1:start]):r[int(p[0][1:])]='((_ rotate_right 8) U)'
   g=SSA(r,loads,namespace='r_').run({'instructions':seg[start:stop]},int(seg[stop-1]['ea'],16)+4)
   F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(KEYS[j])})'
   if j<6:
    new=split(seg[eors[j]]['operands']);terms=[neq(g.get(new[1]),F),neq(g.get(new[0]),f'(bvxor ((_ rotate_left 3) V) {F})')]
   else:terms=[neq(g.get(split(seg[stop+1]['operands'])[1]),F)]
   label=n+'_round'+str(j+1);pp.append(solve(label,c.prefix()+g.prefix()+mismatch(terms),'Arbitrary u64 U,V; both word states match the canonical round, with explicit source-carried precomputed rotations. Final unused y update omitted.'));tr[label]=g.record();start=stop
  r=initial();r[2]='A';r[int(split(seg[ch['selection']+1]['operands'])[1][1:])]='U'
  if ch['role']=='word':expected=f'((_ extract {31-8*ch["byte"]} {24-8*ch["byte"]}) (bvxor F #x8a1bf900))'
  else:
   j=ch['byte'];r[17]=f'(bvsub A {bv(4+j)})';r[19]='((_ zero_extend 32) (bvand (bvlshr F #x00000008) #x000000ff))';r[16]='((_ zero_extend 32) F)'
   expected=f'(bvxor ((_ extract {15-8*j} {8-8*j}) F) '+('#x8c)'if j==0 else'#x60)')
  g=SSA(r,namespace='b_').run({'instructions':seg[ch['selection']:]},int(seg[-1]['ea'],16)+4)
  mask='((_ extract 7 0) (bvlshr U (bvshl (bvand A #x0000000000000007) #x0000000000000003)))'
  pp.append(solve(n+'_selection',c.prefix()+g.prefix()+mismatch([neq(g.stores[0]['address'],'A'),neq(g.stores[0]['value'],f'(bvxor {expected} {mask})')]),'Exact store byte and address, arbitrary raw field F and canonical word U. No native memory/whole-path claim.'));tr[n+'_selection']=g.record()
 # The generic word writer forms BUF+O+j with an encoded offset, not a plain O.
 addr_starts=[0x100546c9c,0x100546e58,0x100546fec,0x1005471b8];addr_ends=[0x100546cb4,0x100546e70,0x100547004,0x1005471d0];gs=[]
 for j,(a,z)in enumerate(zip(addr_starts,addr_ends)):
  g=SSA({19:'(bvadd O #x71134a47fbd9f0b7)',17:'BUF'},namespace='a'+str(j)+'_').run(cut(s,'word',a,z),z);gs.append(g);tr['address_'+str(j)]=g.record()
 pp.append(solve('word_address_offsets',''.join(g.prefix()for g in gs)+mismatch([neq(g.get('x2'),f'(bvadd BUF O {bv(j)})')for j,g in enumerate(gs)]),'All u64 BUF,O modulo64; physical nonwrapping owners are separate.'))
 prep=SSA({20:'NODE',19:'((_ zero_extend 32) H)',23:'((_ zero_extend 32) Q)'},namespace='p_').run(s['fragments']['prepare'],0x100831518)
 cond='(= Q #x0000c714)';terms=[neq(f'(= {prep.get("w8")} #x000054e5)',cond)]
 for a,b in[(prep.get('w24'),'#x0000029a'),(prep.get('w21'),'#x00006cf4'),(prep.get('w22'),'(bvxor H #x01263f51)'),(prep.get('x16'),'(bvadd NODE #x0000000000000018)')]:terms.append(f'(and {cond} {neq(a,b)})')
 pp.append(solve('identifier_call_phase_and_arguments',prep.prefix()+mismatch(terms),'Original key-setup target54e5 constrains incoming W23=c714; no native phase production inferred. H is raw caller W19.'));tr['prepare']=prep.record()
 tagframe=SSA({'sp':'K'},{'0x1008ecb94':('T',16)},namespace='t_').run(cut(s,'key_setup',0x1008ecb8c,0x1008ecba4),0x1008ecba4)
 pp.append(solve('tag_frame_encoding',tagframe.prefix()+mismatch([neq(tagframe.get('w9'),'(bvxor ((_ sign_extend 16) T) #xffff9da3)')]),'Original signed16 argument load and frame958 encoding; T is arbitrary internal discriminator.'));tr['tag_frame']=tagframe.record()
 after=SSA({'sp':'K'},{'0x100617400':('(bvxor ((_ sign_extend 16) T) #xffff9da3)',32),'0x100617408':(bv(0x6cf4),64),'0x10061741c':('TABLE',64),'0x100617420':('FN',64),'0x100617424':('CELL',64)},namespace='c_').run(s['fragments']['after_identifier'],0x100617430)
 pp.append(solve('tag_call_arguments',after.prefix()+mismatch([neq(after.get('w22'),'#x00000a6f'),neq(after.get('x24'),'CELL'),neq(after.get('w16'),'(bvxor ((_ sign_extend 16) T) #xffff9da3)'),neq(after.get('w19'),'(bvand (bvlshr (bvxor ((_ sign_extend 16) T) #xffff9da3) #x00000008) #x000000ff)'),neq(after.reads[3]['address'],'(bvadd TABLE #x00000000000167f8)')]),'Frame9d0=6cf4 is an explicit epoch premise; tag target index2cff, return a6f. CELL is the saved node-buffer pointer cell.'));tr['tag_call']=after.record()
 for n,offset,ret,fieldsite in[('after_tag',6,0x2a2,'0x100597a04'),('scalar_call',10,0x282,'0x100534f50')]:
  load={'0x1005979d4':(bv(0x6cf4),64),'0x1005979e8':('TABLE',64),'0x1005979ec':('FN',64),'0x1005979f0':('CELL',64),fieldsite:('L',32)}if n=='after_tag'else{'0x100534f34':('TABLE',64),'0x100534f38':('FN',64),'0x100534f3c':('CELL',64),fieldsite:('L',32)}
  g=SSA({'sp':'K',22:bv(0x6cf4)},load,namespace='c_').run(s['fragments'][n],int(s['fragments'][n]['end'],16)-4)
  pp.append(solve(n+'_word_arguments',g.prefix()+mismatch([neq(g.get('w24'),bv(ret,32)),neq(g.get('x19'),bv(0x71134a47fbd9f0b7+offset)),neq(g.get('x16'),'CELL'),neq(g.get('w20'),'L'),neq(g.get('w22'),'#x00006cf4')]),'Selected core phase6cf4; raw field L comes from frame988 for extent or frame8f8 for scalar; native values/ownership remain unknown.'));tr[n+'_arguments']=g.record()
 call=SSA({22:bv(0x6cf4),21:bv(0x30b3),20:'((_ zero_extend 32) L)',7:bv(0x01263f51)},namespace='w_').run(s['fragments']['word_call'],0x10061500c)
 pp.append(solve('common_word_call',call.prefix()+mismatch([neq(call.get('w17'),'#x00009da7'),neq(call.get('w22'),'(bvxor L #x01263f51)')]),'Key-setup literal W21=30b3 and W7=01263f51 survive intervening helpers. Index9da7 is the original word writer.'));tr['word_call']=call.record()
 pp.append(solve('wire_field_codecs',mismatch([neq('(bvxor H #x01263f51 #x8a1bf900)','(bvxor H #x8b3dc651)'),neq('(bvxor L #x01263f51 #x8a1bf900)','(bvxor L #x8b3dc651)'),neq('(bvxor T #x9da3 #x8c60)','(bvxor T #x11c3)')]),'Identifier/extent/scalar field XOR composition and internal16-to-wire16 discriminator; no application field names inferred.'))
 # Replay accepted prior scalar queries only; never invoke the legacy producer.
 old=json.loads((ROOT/'daemon_payload_codec_checks.json').read_text());names=['common_address_seed']+['common_round_'+str(j)for j in range(1,8)]+['common_byte_selection_and_XOR']
 for p in old['proofs']:
  if p['name']in names:
   r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat'
   pp.append({'name':'prior_'+p['name'],'query':p['query'],'result':'unsat','prior_sha256':sha(ROOT/'daemon_payload_codec_checks.json'),'scope':p['scope']})
 return pp,tr
def alterations(s):
 ops=[('source_byte',lambda t:t['fragments']['word'].__setitem__('bytes','00'+t['fragments']['word']['bytes'][2:])),('header_offset',lambda t:t['retained_profiles'][0]['records'][0]['header_stores'][0].__setitem__('offset_bytes',1)),('header_pc',lambda t:t['retained_profiles'][0]['records'][0]['header_stores'][0].__setitem__('pc','0x100000000')),('header_width',lambda t:t['retained_profiles'][0]['records'][0]['header_stores'][0].__setitem__('size_bytes',8)),('scalar_offset',lambda t:t['retained_profiles'][0]['records'][0]['scalar_word_stores'][0].__setitem__('offset_bytes',9)),('word_event',lambda t:t['retained_profiles'][0]['word_entry_events'].pop()),('tag_event',lambda t:t['retained_profiles'][0]['tag_entry_events'].pop()),('key_liveness',lambda t:t['register_write_sets']['word'].append('x7'))]
 out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:out.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'byte_seeds':6,'byte_round_lemmas':42,'byte_selection_lemmas':6,'translated_instruction_instances':sum(len(g['source_sites'])for g in tr.values()),'SSA_definitions':sum(g['SSA_definitions']for g in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_payload_codec.py':sha(ROOT/'validate_daemon_payload_codec.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
