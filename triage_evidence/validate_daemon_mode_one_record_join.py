#!/usr/bin/env python3
"""Complete source SSA,workspace-linked forwarding,fixed planes and count fork."""
import copy,json,re,subprocess,shutil,hashlib,functools
from recover_daemon_mode_one_record_join import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_mode_one_handoff_tools import FrameSSA,parse
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['COUNT']+['WW'+str(j)for j in range(32)]+['BA'+str(j)for j in range(4)]+['BS'+str(j)for j in range(4)])
INDEXED={0x100c81afc:0x7fc,0x100c83748:0x860,0x100c8432c:0x7a8,0x100c8434c:0x7c0}
COPIES={0x5c:16,0x6c:17,0x60:18,0x78:19,0x70:20,0x90:21,0xb8:22,0xd0:23,0x40:24,0x64:25,0x68:26,0x74:27,0x8c:28,0x88:29,0xbc:30,0xd8:31}
class JoinSSA(FrameSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.aliases={'sp':0};self.alias_records=[];self.pairs=[];self.indexed_records=[]
 def put(self,rd,e):
  super().put(rd,e);self.aliases.pop(rd if rd=='sp'else'x'+rd[1:],None)
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);mn=i['mnemonic'];before=dict(self.aliases);row=i;aw=32 if p[0].startswith('w')else 64
   if mn in ['ldr','str','strb']:
    m=re.fullmatch(r'\[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]',p[1])
    if m and m[1]in before:
     off=before[m[1]]+(int(m[2],0)if m[2]else 0);assert off>=0
     self.alias_records.append({'site':i['ea'],'original_address':self.address(p[1]),'frame_offset':off,'mnemonic':mn});row={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   if pc in INDEXED:
    assert mn=='ldr'and p[0].startswith('w');off=INDEXED[pc]
    self.indexed_records.append({'site':i['ea'],'original_address':self.address(p[1]),'frame_offset':off,'mnemonic':mn})
    row={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   if mn=='stp':
    assert len(p)==3 and p[0].startswith('w')and p[1].startswith('w');m=re.fullmatch(r'\[sp, #(0x[0-9a-f]+)\]',p[2]);assert m;off=int(m[1],16)
    for j in range(2):super().run({'instructions':[{**i,'mnemonic':'str','operands':p[j]+', [sp, #'+hex(off+4*j)+']'}]},pc+4)
    self.sites.pop();self.pairs.append({'site':i['ea'],'frame_offsets':[off,off+4]})
   elif mn in ['bfi','bfxil']:
    l,n=int(p[2][1:],0),int(p[3][1:],0);assert l+n<=aw
    if mn=='bfi':mask=((1<<n)-1)<<l;e=f'(bvor (bvand {self.get(p[0],aw)} {bv(~mask,aw)}) (bvshl (bvand {self.get(p[1],aw)} {bv((1<<n)-1,aw)}) {bv(l,aw)}))'
    else:mask=(1<<n)-1;e=f'(bvor (bvand {self.get(p[0],aw)} {bv(~mask,aw)}) (bvand (bvlshr {self.get(p[1],aw)} {bv(l,aw)}) {bv(mask,aw)}))'
    self.put(p[0],e);self.sites.append(i['ea'])
   else:super().run({'instructions':[row]},pc+4)
   if mn in ['mov','add','sub']and p[0].startswith('x'):
    key=p[1]if p[1]=='sp'else'x'+p[1][1:]if p[1].startswith('x')else None
    if key in before:
     off=before[key]
     if mn!='mov':
      if not p[2].startswith('#'):continue
      imm=int(p[2][1:],0)
      if len(p)>3:assert p[3]=='lsl #12';imm<<=12
      off+=imm if mn=='add'else-imm
     self.aliases[p[0]]=off
  return self
 def record_full(self):
  obj=super().record_full();obj['alias_normalizations']=self.alias_records;obj['indexed_word_normalizations']=self.indexed_records;obj['pair_store_lowerings']=self.pairs
  obj['external_reads']=[{k:v for k,v in row.items()if k!='supplied_from_original_image'}|{'component_input_supplied':row['supplied_from_original_image']}for row in obj['external_reads']]
  return obj
def certificates(s):
 pp=[]
 def solve(name,body,result='unsat',cc=(),values=None):
  query='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n'
  if values is not None:query+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr
  entry={'name':name,'query':query,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout)
  else:
   assert result=='sat'and r.stdout.startswith('sat\n');rows=parse(r.stdout[4:]);assert len(rows)==len(values)
   entry['model_value_hex']=[v[-1]for v in rows];assert all(re.fullmatch('#x[0-9a-f]+',v)for v in entry['model_value_hex'])
  pp.append(entry);print(name,result,flush=True);return entry
 def pre(g):return ''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
 def cert(name,g,terms,cc=()):return solve(name,pre(g)+'(assert (or '+' '.join(terms)+'))',cc=cc)
 from recover_daemon_mode_one_record_rescan import build as previous_build
 from validate_daemon_mode_one_record_rescan import certificates as previous_certificates
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]));bp,bs=previous_certificates(old)
 assert bp==prior['proofs']and json.loads(json.dumps(bs))==prior['semantics'];pp.extend({**p,'name':'replayed_rescan_'+p['name'],'replayed_query':True}for p in bp)
 from recover_daemon_mode_one_phase_handoff import build as phase_build
 phase_source=phase_build();assert phase_source==json.loads(read(ROOT/DEPS[2]));phase=json.loads(read(ROOT/DEPS[3]));ps=phase['semantics']
 selected={'workspace_all_literal_values_including_cancelled_input','workspace_all_private_frame_store_addresses','unaligned_STUR_is_private_F834'};done=set()
 for p in phase['proofs']:
  if p['name']not in selected:continue
  r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat'
  pp.append({**p,'name':'replayed_workspace_'+p['name'],'replayed_query':True});done.add(p['name']);print('replayed_workspace_'+p['name'],'unsat',flush=True)
 assert done==selected
 # Earlier source contracts cover all selected-path stores before the gate,
 # and the rescan certificates cover the two post-table loops and restore.
 # Their only byte stores lie at/above F+d10;other selected-path stores end
 # below F+768. This preserves the original296-byte workspace.
 scan=json.loads(read(ROOT/'daemon_mode_one_record_scan_checks.json'));scan_source=json.loads(read(ROOT/'daemon_mode_one_record_scan_source.json'));selected_models=['seed','decode','next','payload_gate','length_gate'];selected_store_sites=set();scan_writes=[]
 for label in selected_models:
  model=scan['semantics']['source_models']['full'if label=='decode'else label]
  assert len(model['stores'])==len(model['frame_writes'])
  for row in model['frame_writes']:
   assert row['frame_offset']+row['width_bits']//8<=0x768;selected_store_sites.add(row['site']);scan_writes.append(row)
 assert selected_store_sites=={i['ea']for n in selected_models for i in scan_source['fragments'][n]['instructions']if i['mnemonic'].startswith('st')}
 assert bs['lineage_distinct_source_store_sites']==70
 for row in bs['source_store_ledger']:assert row['frame_offset']+row['width_bits']//8<=0x768
 presets={0x740:('TABLE',64),0x728:('COUNT',32),0x730:(bv(0x4923,32),32),0x738:('BS3',32)}
 for j in range(32):presets[0x768+4*j]=('WW'+str(j),32)
 literal_bytes={};literal_rows=[]
 for row in ps['workspace_literal_ledger']:
  off=row['frame_offset'];w=row['width_bits']
  if not 0x7e8<=off<0x890:continue
  presets[off]=(bv(row['constant_u64'],w),w);literal_rows.append(row)
  for j in range(w//8):assert off+j not in literal_bytes;literal_bytes[off+j]=(row['constant_u64']>>(8*j))&255
 assert set(literal_bytes)==set(range(0x7e8,0x890))and ps['workspace_total_bytes']==296
 regs={j:z('BA'+str(k))for k,j in enumerate([12,13,11,10])};regs.update({j:z('BS'+str(k))for k,j in enumerate([0,1,2])})
 g=JoinSSA('join',regs,presets=presets,loads={'0x100c84358':('FN',64)});f=s['fragments']['join'];g.run(f,int(f['instructions'][-1]['ea'],16));assert not g.initial
 assert len(g.alias_records)==27 and len(g.indexed_records)==4 and len(g.pairs)==6
 assert [(v['site'],v['frame_offsets'])for v in g.pairs]==[(v['site'],v['frame_offsets'])for v in s['pair_store_decode_checks']]
 cert('all27_literal_frame_aliases_match_original_addresses',g,[neq(v['original_address'],frame(v['frame_offset']))for v in g.alias_records])
 cert('all_four_indirect_workspace_words_match_original_addresses',g,[neq(v['original_address'],frame(v['frame_offset']))for v in g.indexed_records])
 assert len(g.stores)==len(g.frame_writes)==595
 cert('all595_store_effects_have_exact_private_frame_addresses',g,[neq(row['address'],frame(fr['frame_offset']))for row,fr in zip(g.stores,g.frame_writes)])
 cert('all_workspace_and_frame_reads_match_forwarded_addresses',g,[neq(next(row for row in g.reads if row['site']==fr['site'])['address'],frame(fr['frame_offset']))for fr in g.frame_reads])
 assert len(g.frame_reads)==389 and len(g.reads)==390 and len(g.external)==1 and g.external[0]['site']=='0x100c84358'
 cert('original_bank_entry_spills_and_retained_second_fourth_word',g,[neq(g.stores[j]['value'],value)for j,value in enumerate(['BA3','BS0','BA0','BA2','BA1','BS2','BS1'])]+[neq(g.loadframe(0x738,32),'BS3')])
 byte_rows=[v for v in g.frame_writes if v['width_bits']==8];assert len(byte_rows)==128
 values=solve('fixed_plane_candidate_values',pre(g),result='sat',values=[v['value']for v in byte_rows])['model_value_hex'];candidates=[int(v[2:],16)for v in values]
 cert('all128_fixed_plane_values_for_every_word_bank_and_count',g,[neq(row['value'],bv(value,8))for row,value in zip(byte_rows,candidates)])
 # Candidate evaluation is followed by the universal source check above.
 # The declared-leaf census independently confirms source-level separation.
 defs={a[1]:a[-1]for a in map(parse,g.prefix().splitlines())};declared=set(re.findall(r'\(declare-fun (\w+) ',DECL+EXTRA))|set(g.decl)
 @functools.lru_cache(None)
 def atom(a):return walk(defs[a])if a in defs else{a}if a in declared else set()
 def walk(a):return set().union(*(walk(v)for v in a))if isinstance(a,list)else atom(a)
 assert all(not walk(parse(row['value']))for row in byte_rows)
 inv=pow(866,-1,961);plane={};ledger=[]
 for row,value in zip(byte_rows,candidates):
  label=(row['frame_offset']-0xd10)*inv%961;assert label not in plane;plane[label]=value;ledger.append({**row,'coordinate_label':label,'constant_u8':value})
 assert set(plane)==set(range(896,960))|set(range(827,891))
 first=bytes(plane[896+j]for j in range(64));second=bytes(plane[827+j]for j in range(64));assert bytes(v^0xe9 for v in first)==second
 cert('all_sixteen_encoded_workspace_word_transfers',g,[neq(g.loadframe(off,32),'WW'+str(j))for off,j in COPIES.items()])
 branch=next(v for v in g.reads if v['site']=='0x100c84358')
 cert('unsigned_COUNT64_controls_original_branch_slots',g,[neq(branch['address'],f'(ite (bvult COUNT #x00000040) {at(0x7e42)} {at(0x7e1a)})')])
 cert('outgoing_constant_words_and_branch_ABI',g,[neq(g.get('x0'),'FN'),neq(g.get('x17'),bv(0x1c91)),neq(g.get('x8'),bv(0x7f3081c2)),neq(g.get('x23'),bv(0x7f3081c2)),neq(g.get('w25'),bv(0x58,32)),neq(g.get('w24'),bv(0x23,32)),neq(g.get('w6'),bv(0x53921748,32)),neq(g.get('w4'),bv(0x39c7500a,32)),neq(g.loadframe(0x4d8,64),bv(0x7f3081c2)),neq(g.loadframe(0x2cc,32),bv(0x0c392ed3,32))])
 for name,count in [('zero',0),('last_below64',63),('first_at64',64),('max',0xffffffff)]:solve(name+'_COUNT_domain','(assert (= COUNT '+bv(count,32)+'))',result='sat')
 written={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert len(written)==1552
 banks={name:{0xd10+(base+866*j)%961 for j in range(n)}for name,base,n in [('A',0xbd700,16),('B',0xaed96,16),('C',0x77086,256),('D',0x368c4,256),('E',0,256),('H',0x73704,16),('I',0x6e272,16)]}
 overlaps={n:sorted(v&written)for n,v in banks.items()};assert len(overlaps['A'])==len(overlaps['B'])==16 and all(not overlaps[n]for n in ['C','D','E','H','I'])
 retained=set.union(*(banks[n]for n in ['C','D','E','H','I']));plane_cells={r['frame_offset']for r in byte_rows};assert len(retained)==800 and not retained&plane_cells and len(retained|plane_cells)==928
 protected=[(0x2b8,8),(0x2c0,8),(0x388,8),(0x568,8),(0x580,8),(0x588,8),(0x728,4),(0x730,4),(0x738,4),(0x740,8),(0x748,8),(0x750,8),(0x768,296),(0x1210,8)]
 assert all(not written&set(range(off,off+w))for off,w in protected)
 actual=set(g.sites);expected={i['ea']for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(g.sites)==len(actual)==7106
 state_outputs={str(j):sorted(walk(parse(g.get('x'+str(j)))))for j in range(31)}
 sem={'source_model':g.record_full(),'source_nonbranch_sites_translated':len(actual),'workspace_word_symbols':['WW'+str(j)for j in range(32)],'workspace_literal_bytes':168,'workspace_literal_ledger':literal_rows,'selected_scan_frame_write_ledger':scan_writes,'prejoin_workspace_preserved_under_parent_contracts':True,'state_input_bank_A':['BA'+str(j)for j in range(4)],'state_input_bank_B':['BS'+str(j)for j in range(4)],'indexed_workspace_reads':g.indexed_records,'plane_store_ledger':ledger,'plane0_coordinate_base':896,'plane1_coordinate_base':827,'plane_coordinate_rule':'F+0xd10+((866*(base+j))mod961),0<=j<64','plane0_bytes':first.hex(),'plane1_bytes':second.hex(),'plane0_sha256':hashlib.sha256(first).hexdigest(),'plane1_sha256':hashlib.sha256(second).hexdigest(),'plane_bytewise_XOR':'0xe9','fixed_planes_independent_of_words_banks_and_COUNT':True,'raw_A_and_B_banks_fully_replaced':True,'retained_arithmetic_and_codebook_cells':800,'known_cells_after_replacement':928,'unused_cells_in961_domain':33,'prior_bank_write_intersections':overlaps,'encoded_word_transfer_ledger':[{'frame_offset':off,'workspace_index':j,'workspace_frame_offset':0x768+4*j}for off,j in COPIES.items()],'outgoing_register_declared_dependencies':state_outputs,'dependency_membership_is_not_a_proof_of_influence':True,'COUNT_lt64_target':'0x100c4a194','COUNT_ge64_target':'0x100c4ff88','outgoing_X8_X23_and_F4d8_u64':'0x000000007f3081c2;numeric word,not an established pointer','logical_store_effects':595,'source_store_instructions':589,'byte_store_effects':128,'u32_store_effects':464,'u64_store_effects':3,'store_bytes':2008,'distinct_bytes_written':1552,'source_load_operations':390,'read_bytes':sum(r['width_bits']//8 for r in g.reads),'fixed_workspace_and_saved_context_preserved':True,'Mach_port_emissions':0,'complete_compact_state_recurrence_proved':False,'whole_algorithm_identity_proved':False,'native_reachability_proved':False,'successful_output_publication_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['join'].__setitem__('bytes','00'+q['fragments']['join']['bytes'][2:])),('wrong_count_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('wrong_pair_offset',lambda q:q['pair_store_decode_checks'][0]['frame_offsets'].__setitem__(1,0)),('wrong_bitfield_width',lambda q:q['bitfield_decode_checks'][0].__setitem__('source_count',0)),('wrong_workspace_lineage',lambda q:q['prior_recaptures'][-1].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':7106,'frame_alias_normalizations':27,'indexed_word_normalizations':4,'pair_store_lowerings':6,'workspace_bytes_preserved':296,'fixed_plane_bytes':128,'encoded_word_transfers':16,'raw_permutation_cells_replaced':32,'arithmetic_and_codebook_cells_retained':800,'known_scratch_cells_after_replacement':928,'logical_store_effects':595,'source_loads':390,'store_bytes':2008,'distinct_bytes_written':1552,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_rescan.py','validate_daemon_mode_one_record_rescan.py','recover_daemon_mode_one_phase_handoff.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_mode_one_plane_consumer.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'record_join_fixed_planes_and_COUNT64_fork_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
