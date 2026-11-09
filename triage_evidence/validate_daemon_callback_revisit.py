#!/usr/bin/env python3
"""Independent artifact, original-opcode, state, record and reader verification.
O(snapshot+journal+SMT+one fresh A64 run) time, O(snapshot+journal) space.
Logical PAC abstraction only; no native target/API or IDB mutation.
"""
import hashlib,json,zlib,base64,struct
from collections import Counter
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from recover_daemon_callback_revisit import verify_fixups,snapshot_read
from replay_daemon_callback_revisit import Replay
from replay_daemon_prng_output import twist,temper
from validate_daemon_callback_payload import encode,decode,source

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def raw(t):return zlib.decompress(base64.b64decode(t))
def checked(n,g):
 q=json.loads((ROOT/n).read_text());assert q['generator_sha256']==sha(ROOT/g)and q['full_goal_complete']is False
 for f,h in q.get('dependencies',{}).items():assert sha(ROOT/f)==h,(n,f)
 if 'source_sha256'in q:assert sha(SOURCE)==q['source_sha256']
 return q
def integer(shape):return int.from_bytes(bytes.fromhex(shape['hex']),'little')
def main():
 snap=checked('daemon_callback_revisit_snapshot.json','capture_daemon_callback_revisit.py');p=checked('daemon_callback_revisit_profiles.json','probe_daemon_callback_revisit.py');c=checked('daemon_callback_revisit_contracts.json','recover_daemon_callback_revisit.py');q=checked('daemon_callback_revisit_proofs.json','prove_daemon_callback_revisit.py');replays=checked('daemon_callback_revisit_replays.json','replay_daemon_callback_revisit.py');simd=checked('daemon_callback_simd_checks.json','validate_daemon_callback_simd.py');payload=checked('daemon_callback_payload_checks.json','validate_daemon_callback_payload.py');reader=checked('daemon_callback_reader_checks.json','validate_daemon_callback_readers.py');b=raw(p['payload_zlib_base64']);assert hashlib.sha256(b).hexdigest()==p['payload_sha256'];t=json.loads(b);F=int(snap['frame_SP'],16);H=int(snap['arena_owner'],16);R=F+0xaf8;D=int(c['cached_table_address'],16);A=int(c['selected_code_address'],16);counts={};ram={}
 for region in snap['regions']:
  b=raw(region['bytes_zlib_base64']);assert len(b)==region['size_bytes']and hashlib.sha256(b).hexdigest()==region['sha256'];a=int(region['address'],16);ram.update((a+j,v)for j,v in enumerate(b))
 for name in ['private_owner','heap_owner']:
  row=snap[name];mask=raw(row['known_mask_zlib_base64']);assert len(mask)==row['size_bytes']and set(mask)<={0,1}
 assert snap['snapshot_is_before_unknown_read_effects']and snap['unknown_backing_is_not_source_definition']
 assert len(snap['unknown_stack_aliases'])==8 and len(snap['inherited_unknown_backing'])==112
 counts['snapshot_regions_checked']=len(snap['regions']);counts['snapshot_bytes_checked']=len(ram)
 for s in c['spans']:
  b=bytes.fromhex(s['bytes_hex']);assert IMAGE.read(int(s['start'],16),len(b))==b and hashlib.sha256(b).hexdigest()==s['sha256']
 assert verify_fixups([int(r['address'],16)for r in c['source_fixups']['records']])==c['source_fixups'];counts['source_spans_checked']=len(c['spans']);counts['source_fixups_checked']=len(c['source_fixups']['records'])
 for row in t['source_pool'].values():assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
 assert not t['definitions']and len(t['steps'])==160048 and len(t['source_pool'])==3013 and len(t['origins'])==48
 assert {x['offset']for x in t['origins']}=={o+j for o in [0x468,0x480,0x4a0,0x4a8,0x4c0,0x588]for j in range(8)}
 counts.update(source_visits_checked=160048,source_pool_opcodes_checked=3013,arbitrary_origin_bytes=48,SSA_arithmetic_definitions=0)
 for row in q['proofs']:
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   fp=ROOT/row[fk];assert sha(fp)==row[hk];s=z3.Solver();s.set(timeout=30000);s.from_file(str(fp));assert str(s.check())=='unsat',row['name']
 assert len(q['proofs'])==13 and len(q['nonempty_premise_witnesses'])==3;counts.update(source_proof_pairs_unsat=13,SMT_queries_unsat=26,nonempty_premise_witnesses=3)
 def read(a,n):return bytes(ram[a+j]for j in range(n))
 def num(a,n=8):return int.from_bytes(read(a,n),'little')
 regs=t['initial_registers'].copy();state=list(struct.unpack('<624I',read(0x1010c784c,2496)));state_expected=twist(state);state_writes=0;words=[];records=[];adapter=[];codefold=None;code_reads=[];cachewrites=[];fills=[];bytewrites=[];creatorstores={};current=None;canary_reads=0;canary_GOT_reads=0
 assert num(0x1010b1e18)==0x6400001000 and num(0x6400001000)==0xfedcba9876543210
 for idx,step in enumerate(t['steps']):
  pc=int(step['pc'],16);assert t['source_pool'][step['pc']]['bytes_hex']==step['bytes_hex']
  def reg(n):return integer(regs[n])
  if pc==0x100add594:
   current={'caller_state_cell':hex(reg('x1')),'old_state':num(reg('x1'))};assert current['old_state']==num(0x1010b8d78);adapter.append(current)
  if pc==0x100add72c:
   C=current['old_state'];C1=(C*0x2ec5+1)&((1<<64)-1);assert reg('x21')==C and reg('x2')==C1 and num(0x1010b8d78)==C1;current['next_state']=hex(C1);current['reserve_bytes']=16*((C1>>60)+1)
  if pc==0x100add7d4:
   assert reg('sp')==F-64-current['reserve_bytes']and reg('x0')==R and reg('x1')==reg('sp')and num(reg('sp'))==(current['old_state']-0xb0)&((1<<64)-1)
  if pc==0x100acd9c4:
   K=((R^0xeaae0ac9)*0x7398180b)&0xffffffff;rec={'record':hex(R),'output':hex(num(R+8)),'encoded_length16':hex(num(R+16,2)),'encoded_control32':hex(num(R+20,4)),'key32':hex(K),'decoded_length':(num(R+16,2)-K-0x153b)&65535,'decoded_control':hex((num(R+20,4)+K)&0xffffffff)};assert rec['decoded_length']==4 and rec['decoded_control']=='0xb399';records.append(rec)
  if pc==0x100add7d8:assert num(reg('x20'))==current['old_state'];current['return_delta_bytes']=0
  if pc==0x100a0c9bc:
   j=len(words)
   if j==0 or words[-1]['word']!=reg('x9'):words.append({'word':reg('x9'),'index':130+len(words)})
  if pc==0x100462674:codefold=reg('x9');assert codefold==0xf72a8ff6
  for e in step['events']:
   a=int(e['address'],16);n=e['size_bytes'];shape=e['value']
   if 'terms'in shape:assert all(isinstance(v,int)or set(v)=={'origin'}for v in shape['terms'])
   if e['kind']=='read'and a==0x1010b1e18:assert integer(shape)==0x6400001000;canary_GOT_reads+=1
   if e['kind']=='read'and a==0x6400001000:assert integer(shape)==0xfedcba9876543210;canary_reads+=1
   if e['kind']=='read'and A<=a<A+32768:
    b=bytes.fromhex(shape['hex']);assert b==IMAGE.read(a,n);code_reads.append({'pc':step['pc'],'address':hex(a),'size_bytes':n})
    if n==4:assert a==A+(codefold&32767);codefold^=int.from_bytes(b,'little')
   if e['kind']!='write':continue
   if max(a,D)<min(a+n,D+512):cachewrites.append(step['pc'])
   if 'hex'in shape:
    b=bytes.fromhex(shape['hex']);assert len(b)==n
    if 0x1010c784c<=a<0x1010c784c+2496:
     assert n==4 and a==0x1010c784c+(state_writes%624)*4 and int.from_bytes(b,'little')==state_expected[state_writes%624];state_writes+=1
     if state_writes==624:state=state_expected;state_expected=twist(state)
    if pc==0x1004c8398:fills.append(a)
    if pc==0x100a0ca74:bytewrites.append((a,b.hex()))
    if pc in [0x1004925cc,0x1004925e4]:creatorstores[hex(pc)]={'address':hex(a),'size_bytes':n,'value_hex':b.hex()}
    ram.update((a+j,v)for j,v in enumerate(b))
   else:
    for j,v in enumerate(shape['terms']):
     if isinstance(v,int):ram[a+j]=v
     else:ram.pop(a+j,None)
  regs.update(step['registers_after'])
 assert canary_reads==canary_GOT_reads==4
 counts.update(reference_canary_reads=canary_reads,reference_canary_GOT_reads=canary_GOT_reads)
 assert state_writes==1248 and list(struct.unpack('<624I',read(0x1010c784c,2496)))==state_expected
 assert num(0x1010c67dc,4)==num(0x1010c8258,4)==132
 expected_words=[temper(state[130]),temper(state_expected[131])];assert [v['word']for v in words]==expected_words==[0x9cd51d84,0x15c5bd81]
 assert codefold==0x487b0e7b and int(c['context_payload']['seed32'],16)==((0x115274*0x41da4f94)^codefold)&0xffffffff
 assert not cachewrites and len(code_reads)==24 and len(fills)==2904 and len(set(fills))==2856
 assert set(fills)==set(range(H+0x1522c,H+0x15b08))|set(range(H+0x15ad8,H+0x15d54))and H+0x15d54==D-24
 for j,r in enumerate(records):
  out=int(r['output'],16);b=bytes.fromhex('be38733c'if j==0 else '3a0ee2ca');assert read(out,4)==b
  writes=bytewrites[j*4:j*4+4];assert [a for a,v in writes]==list(range(out+3,out-1,-1))
 assert len(adapter)==len(records)==2 and code_reads==[{'pc':e['pc'],'address':e['address'],'size_bytes':e['size_bytes']}for e in c['selected_code_reads']]
 rawctl=num(R,4);dest=num(R+8);key=(R^0xdc40790b)&0xffffffff;decoded=(rawctl+key*0x5973a279)&0xffffffff
 assert rawctl==0x31c22edc and decoded==0xaed7 and dest==H+0x15b28 and t['boundary']['target']=='0x10043a240'and t['boundary']['pc']=='0x100492644'
 assert c['creator_boundary']==t['boundary'];counts.update(twist_state_writes_checked=1248,twists_checked=2,generated_words_checked=2,byte_output_calls=2,byte_output_writes=8,descending_fill_writes=2904,distinct_fill_bytes=2856,cached_table_overwrite_bytes=0,self_text_reads_checked=24,self_text_byte_reads=16,self_text_u32_reads=8,new_creator_calls=1)
 assert replays['all_checks_pass']and len(replays['cases'])==4 and all(x['all_checks_pass']and x['verified_counts']['source_visits']==160048 for x in replays['cases']);totals=Counter()
 for x in replays['cases']:totals.update(x['verified_counts'])
 assert simd['all_checks_pass']and simd['verified_counts']['source_opcodes']==70 and simd['verified_counts']['isolated_instruction_cases']==3008;counts.update(simd['verified_counts']);counts.update(payload['verified_counts']);counts.update(reader['verified_counts'])
 cp=c['context_payload'];before=bytes.fromhex(cp['before_hex']);after=bytes.fromhex(cp['after_hex']);seed=int(cp['seed32'],16);assert encode(before,seed)==after and decode(after,seed)==before and source(before,seed,cp['vector_constants'])==after;counts['fresh_compact_A64_codec_checks']=1
 fresh=Replay(snap,t,3).run();assert fresh['all_checks_pass'];counts['fresh_A64_continuation_visits']=fresh['verified_counts']['source_visits']
 deps=['daemon_callback_revisit_snapshot.json','daemon_callback_revisit_profiles.json','daemon_callback_revisit_contracts.json','daemon_callback_revisit_proofs.json','daemon_callback_revisit_replays.json','daemon_callback_simd_checks.json','daemon_callback_payload_checks.json','daemon_callback_reader_checks.json','replay_daemon_callback_revisit.py','validate_daemon_callback_payload.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':counts,'independent_A64_totals':dict(totals),'byte_output_records':records,'adapter_calls':adapter,'word_reader':{'initial32':'0xf72a8ff6','chained_u32_reads':8,'final32':hex(codefold),'address_coefficient32':'0x41da4f94','context_seed32':hex(seed)},'creator_record':{'R':hex(R),'raw_control32':hex(rawctl),'key32':hex(key),'decoded_control32':hex(decoded),'destination':hex(dest),'source_stores':creatorstores,'native_creator_executed':False},'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_callback_revisit_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':counts,'independent_A64_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
