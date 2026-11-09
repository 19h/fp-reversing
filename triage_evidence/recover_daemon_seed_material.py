#!/usr/bin/env python3
"""Recover seed/key, comparison, state, owner and first-twist interfaces.
O(source+trace byte events+256*banks+SDK bytes) time,O(largest journal)
space. Original bytes and SDK documentation are primary evidence.
"""
import hashlib,json,struct
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from daemon_import_bindings import binding
from daemon_context_transfer_symbolic import SEGMENTS
from replay_daemon_context_transfer import unpack
LESS_MIX=0x0179fa0fe732d262;LESS_COEFF=0xba209ef7

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def scalar(s):assert'hex'in s;return int.from_bytes(bytes.fromhex(s['hex']),'little')
def at(t,pc):return next(s for s in t['steps']if s['pc']==hex(pc))
def read_scalar(t,pc):return scalar(next(e['value']for e in at(t,pc)['events']if e['kind']=='read'))
def summarize(c,prefix,entropy,base):
 t=unpack(c);F=int(c['frame_SP'],16);H=int(c['heap_base'],16);R=F+0xaf8;writes=[{'pc':s['pc'],**e}for s in t['steps']for e in s['events']if e['kind']=='write'];state=[w for w in writes if 0x1010c784c<=int(w['address'],16)<0x1010c820c];cur=read_scalar(t,0x1002dc418);assert H<=cur<H+90000
 # Loader-tail probes from the inherited engine are not definitions when
 # bytes were already cached. Reconstruct cache availability independently.
 cache=set()
 for w in base['initial_image_fixtures']+base['source_writes']:
  a=int(w['address'],16)
  if a<0x6400000000:cache.update(range(a,a+len(bytes.fromhex(w.get('bytes_hex',w.get('after_hex',''))))))
 for journal in [prefix,entropy]:
  for row in journal['steps']:
   for e in row['events']:
    a=int(e['address'],16)
    if a<0x6400000000:cache.update(range(a,a+e['size_bytes']))
 fresh=[];cached_tail=0
 for row in t['steps']:
  for e in row['events']:
   a=int(e['address'],16);n=e['size_bytes']
   if a>=0x6400000000:continue
   if e['kind']=='read'and any(va<=a<a+n<=va+vs and a+n>va+fs for va,vs,fo,fs in SEGMENTS):
    if all(x in cache for x in range(a,a+n)):cached_tail+=1
    else:fresh.append({'pc':row['pc'],'address':hex(a),'size_bytes':n})
   cache.update(range(a,a+n))
 # Decode each leaf's exact private input record and check the result store.
 mem={};stats={};active=None;recent_fixups=[];regs={}
 for row in t['steps']:
  pc=row['pc']
  if row['mnemonic']=='blraa':
   assert active is None and scalar(regs['x0'])==R
   target=int(row['target'],16);kind='less36'if target==0x100427514 else'compare48';assert target in [0x100427514,0x10041a5e0]
   def u(off,n):return int.from_bytes(bytes(mem[R+off+j]for j in range(n)),'little')
   K=((R^LESS_MIX)*LESS_COEFF if kind=='less36'else(R^0x4de3a292f9d49974)*0xda51a827)&((1<<64)-1);k=K&0xffffffff
   if kind=='less36':
    mode=u(8,4)^k;A=(u(0,8)+K)&((1<<64)-1);B=u(0x18,8)^K;mask=u(0x20,4)^k;yes=u(0x10,4)^k;no=(u(0x14,4)+k)&0xffffffff;signed=lambda x:x-(1<<64)if x>>63 else x;choose=signed(A)<signed(B)if mode&1 else A<B;result_off=0xc
   else:
    mode=(u(0,4)-k)&0xffffffff;A=(u(8,8)-K)&((1<<64)-1);B=u(0x20,8)^K;mask=(u(0x14,4)-k)&0xffffffff;yes=u(0x2c,4)^k;no=(u(0x28,4)+k)&0xffffffff;choose=A>B if mode&1 else A==B;result_off=0x10
   expected=mask^(yes if choose else no);slot=next(a for a in reversed(recent_fixups)if FIXUPS[a]['target']==target);s=stats.setdefault(pc,{'target':hex(target),'kind':kind,'slot':hex(slot),'calls':0,'decoded_modes':set(),'predicate_true':0,'A_min':A,'A_max':A,'B_values':set(),'result_indices':set(),'first_record':None,'last_record':None});s['calls']+=1;s['decoded_modes'].add(mode);s['predicate_true']+=int(choose);s['A_min']=min(s['A_min'],A);s['A_max']=max(s['A_max'],A);s['B_values'].add(B);s['result_indices'].add(expected);sample={'A':hex(A),'B':hex(B),'mode':hex(mode),'choose':choose,'result':hex(expected)};s['first_record']=s['first_record']or sample;s['last_record']=sample;active=(R+result_off,expected)
  for e in row['events']:
   a=int(e['address'],16);n=e['size_bytes']
   if e['kind']=='read'and n==8 and a in FIXUPS:recent_fixups.append(a)
   if e['kind']=='write':
    if active and a==active[0]and n==4:assert scalar(e['value'])==active[1];active=None
    if R<=a<a+n<=R+48:
     raw=bytes.fromhex(e['value']['hex']);mem.update({a+j:b for j,b in enumerate(raw)})
  regs.update(row['registers_after'])
 assert active is None
 for s in stats.values():
  for name in ['decoded_modes','B_values','result_indices']:s[name]=[hex(x)for x in sorted(s[name])]
  s['A_min']=hex(s['A_min']);s['A_max']=hex(s['A_max']);s['predicate_false']=s['calls']-s['predicate_true']
 table=[]
 prior_writes=[{'pc':s['pc'],**e}for journal in [prefix,entropy]for s in journal['steps']for e in s['events']if e['kind']=='write']
 for address in [F+0x6d8,F+0x6dc]:
  vals=[w for w in prior_writes+writes if int(w['address'],16)<=address and address+4<=int(w['address'],16)+w['size_bytes']];assert vals;w=vals[-1];offset=address-int(w['address'],16);raw=bytes.fromhex(w['value']['hex'])[offset:offset+4];table.append({'address':hex(address),'write_PC':w['pc'],'write_size_bytes':w['size_bytes'],'raw_u32':hex(int.from_bytes(raw,'little'))})
 seed_writes=Counter(w['pc']for w in state);key_writes=Counter((w['pc'],int(w['address'],16)-(F+0x670))for w in writes if F+0x670<=int(w['address'],16)<F+0x680)
 return {'prior_case_index':c['prior_case_index'],'frame_SP':hex(F),'heap_base':hex(H),'source_visits':len(t['steps']),'SSA_definitions':len(t['definitions']),'arena_pointer':hex(cur),'arena_pointer_owner_offset_bytes':cur-H,'arena_pointer_low32':hex(cur&0xffffffff),'state_word_write_sites':dict(seed_writes),'key_word_write_sites':[{'pc':pc,'record_offset_bytes':off,'visits':count}for(pc,off),count in sorted(key_writes.items())],'leaf_callers':stats,'time_output_reads':[{'pc':s['pc'],**e}for s in t['steps']for e in s['events']if e['kind']=='read'and F+0x680<=int(e['address'],16)<F+0x690],'first_twist_table':table,'boundary':t['boundary'],'loader_tail_probes':len(c['loader_zero_reads']),'cached_source_state_tail_reads':cached_tail,'fresh_tail_materializations':fresh,'new_symbolic_input_bytes':len(t['origins'])-112,'gate_word_stores':[w for w in writes if int(w['address'],16)==0x1010b5de0],'bank_roots':{'secondary_left':hex(read_scalar(t,0x1002dc370)),'secondary_right':hex(read_scalar(t,0x1002dc384)),'third_left':hex(read_scalar(t,0x1002dc3d0)),'third_right':hex(read_scalar(t,0x1002dc3e4))}}

def main():
 p=json.loads((ROOT/'daemon_seed_material_profiles.json').read_text());prefix=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());entropy=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());summaries=[]
 for row in p['cases']:
  index=row['prior_case_index'];s=summarize(row,unpack(next(x for x in prefix['cases']if x['prior_case_index']==index)),unpack(next(x for x in entropy['cases']if x['prior_case_index']==index)),base['cases'][index]);summaries.append(s);print(json.dumps({'case':index,'visits':s['source_visits'],'arena_pointer':s['arena_pointer'],'fresh_tail_reads':len(s['fresh_tail_materializations']),'helper_calls':sum(x['calls']for x in s['leaf_callers'].values())}),flush=True)
 specs=[('context_material_reservation',0x1002dc094,0x1002dc0c4),('less_caller_prekey',0x10032ca54,0x10032ca98),('less_complete_leaf',0x100427514,0x1004275b4),('time_to_material',0x1002dc30c,0x1002dc354),('entropy_material_fields',0x1002dc3a4,0x1002dc418),('key_cursor_fields',0x1002dc418,0x1002dc464),('first_mix_and_record',0x1002fbb00,0x1002fbc40),('key_next',0x100288aa4,0x100288aec),('key_wrap',0x10038ec80,0x10038ecb8),('second_mix_and_record',0x1003068b4,0x1003069e8),('state_wrap1',0x1004694e4,0x100469504),('state_wrap2',0x100396ec0,0x100396ee0),('state_force',0x1002f0ee8,0x1002f0f38),('twist_interface',0x10035c6d8,0x10035c72c),('ready_mode_gate',0x10035380c,0x10035387c),('conditional_control',0x1002c4588,0x1002c45e4)];spans=[native(n,a,z)for n,a,z in specs]
 roots=summaries[0]['bank_roots'];banks=[selected(int(roots['secondary_left'],16),int(roots['secondary_right'],16),key,add,TABLE,0)for key,add in [(0xbb,0xcb71),(0x4e,0xcb0a)]];banks.append(selected(int(roots['third_left'],16),int(roots['third_right'],16),0x0a,0xcb42,TABLE,0));banks.append(selected(0x100fc4230,0x101031fa0,0xf3,0xcbc6,TABLE,0))
 fix={int(a,16)for c in p['cases']for a in c['fixup_addresses']};live=[];coverage={}
 for name in ['daemon_seed_material_live_ida.json','daemon_seed_mixing_live_ida.json','daemon_seed_table_setup_live_ida.json']:
  obj=json.loads((ROOT/name).read_text());assert obj['target']=='6b117c693e3b'and not obj['idb_mutated']
  for row in obj['instructions']:
   a=int(row['address'],16);raw=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(raw))==raw
   for j,b in enumerate(raw,a):assert j not in coverage or coverage[j]==b;coverage[j]=b
   live.append(row)
 covered=sum(all(int(x['pc'],16)+j in coverage for j in range(4))for x in p['instruction_pool']);man=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/share/man/man2/gettimeofday.2');lines=man.read_text().splitlines();clauses=[{'line':j+1,'text':line}for j,line in enumerate(lines)if line.startswith(('A 0 return value','A -1 return value'))or line.strip()=='errno'];assert len(clauses)>=2
 deps=['daemon_seed_material_profiles.json','daemon_seed_material_symbolic.py','daemon_seed_material_failure.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_arena_storage_profiles.json','daemon_seed_material_live_ida.json','daemon_seed_mixing_live_ida.json','daemon_seed_table_setup_live_ida.json','replay_daemon_seed_material.py','daemon_import_bindings.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'entropy_binding':binding(0x1010a0050),'source_fixup_records':verify_original_fixups(fix),'live_IDB_rows_matched':len(live),'original_path_pool_instructions':len(p['instruction_pool']),'path_pool_instructions_live_IDB_covered':covered,'source_phase_contexts':summaries,'SDK_time_documentation':{'path':str(man),'sha256':sha(man),'return_clauses':clauses,'scope':'Installed SDK primary manpage; build/version identity and native failure outputs unknown.'},'native_target_executed':False,'native_entropy_or_time_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_seed_material_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'bank_inputs':256*len(banks),'fixups':len(fix),'live_IDB_rows':len(live),'live_IDB_path_coverage':covered,'contexts':len(summaries)}),flush=True)
if __name__=='__main__':main()
