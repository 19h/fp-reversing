#!/usr/bin/env python3
"""Follow post-block metadata and mode-dependent consumers from retained states.

O(restored prefixes+cases*(visits+effects)) time/space;30 s/proof query.
Declared private interior states; no native API, IPC, hardware PAC or admission.
"""
import json
from pathlib import Path
from collections import Counter
import z3
from lskd_values_symbolic import mem,cell,resize
from daemon_receive_tools import ROOT,IMAGE,CS,TABLE,POOL,FIXUPS,selected
from daemon_callback_revisit_symbolic import ALLOWED_CALLS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_nested_helper_processing as Parent
P='daemon_postblock_dispatch';ENTRY=Parent.STOP;HELPER=0x1004601d0
PINS={**Parent.PINS,'daemon_nested_helper_processing_checks.json':'16df39b49898247cb851f0a4110537ae68c014eebad9e330304ba1b0a440efdd',
 'daemon_nested_helper_processing_audit.json':'4744bb1b70ae274d76b081ee3ba6115a7bbc842e42088ef3560dc3828b5ebe06'}
DEPS=Parent.DEPS+['recover_daemon_nested_helper_processing.py','audit_daemon_nested_helper_processing.py']
SPECS=[('metadata',ENTRY,0x100383760),('mode_gate',0x10052e9bc,0x10052e9f8),('mode5_gate',0x100461d78,0x100461da8),
 ('mode5_span',0x10031619c,0x100316280),('call_record',0x1006206d8,0x1006207bc),('helper_entry',HELPER,0x100460428),
 ('helper_result',0x100336fcc,0x100337008),('IOKit_arguments',0x100478988,0x100478a08)]

class Run(Parent.Run):
 def one(self,i):
  if i.address==ENTRY:return Parent.Parent.R.Run.one(self,i)
  return super().one(i)

def inputs():
 pins,old,ingress,preparation=Parent.inputs()
 for n,d in PINS.items():assert sha(ROOT/n)==d,n
 return pins,old,ingress,preparation,json.loads(read(ROOT/'daemon_nested_helper_processing_checks.json'))

def restore(snapshot,old,original,preparation,previous):
 assert previous['configuration']['operand_profile']=='baseline'
 v,cut=Parent.restore(snapshot,old,original,preparation);Parent.Parent.R.R.H.advance(v,previous['trace']['steps']);v.__class__=Run;return v,cut

def source():
 return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,b-a),a)]}for n,a,b in SPECS]

def obligations():
 f,r,a,g=z3.BitVecs('post_frame64 post_record64 post_input64 post_helperSP64',64);mode,random,count,phase,raw,status,connection=z3.BitVecs('post_mode32 post_random32 post_count32 post_phase32 post_raw32 post_status32 post_connection32',32);qs=[];Algebra=Parent.Parent.R.Algebra
 v=Algebra();v.seed('sp',f);v.seed('w20',0x553e)
 for off,x in [(0x38c,count),(0x37c,mode),(0x3b4,random)]:mem(v,f+off,4,x)
 v.run_block(ENTRY,0x100383754)
 qs.append(('metadata_mode_literal_random_and_count_fields',z3.Or(cell(v,f+0x6a8,4)!=mode,cell(v,f+0x6ac,4)!=0xb4d3a486,cell(v,f+0x6b0,4)!=(random^0x8b3dc651),cell(v,f+0x8c8,4)!=(count^0x8b3dc651),v.read('x20')!=f+0x698,v.read('w8')!=0x68a7,v.read('w9')!=0x84ce)))
 v=Algebra();v.seed('w9',0x84ce);v.seed('w22',mode);v.run_block(0x10052e9bc,0x10052e9ec)
 qs.append(('signed_mode_below8_gate',z3.Or(v.read('w8')!=0x32b0,v.read('w10')!=z3.If(mode<8,z3.BitVecVal(0x8526,32),z3.BitVecVal(0x84ce,32)))))
 v=Algebra();v.seed('w8',0x32b0);v.seed('w22',mode);v.run_block(0x100461d78,0x100461d9c)
 qs.append(('mode5_selects_span_copy_and_same_next_phase',z3.Or(v.read('w21')!=0x8eb0,v.read('w9')!=z3.If(mode==5,z3.BitVecVal(0x7cf1,32),z3.BitVecVal(0x32b0,32)))))
 v=Algebra();v.seed('sp',f);v.seed('w8',0x32b0);mem(v,f+0x480,8,a);bb=[z3.BitVec('post_span_byte_'+str(j),8)for j in range(16)]
 for j,b in enumerate(bb):mem(v,a+j,1,b)
 v.run_block(0x10031619c,0x100316274)
 qs.append(('mode5_span_is_sixteen_byte_XOR98',z3.Or(*[cell(v,f+0x6b4+j,1)!=(b^0x98)for j,b in enumerate(bb)])))
 v=Algebra();v.seed('x29',r+0x98);v.run_block(0x1006206e4,0x100620710);canonical=resize(r,32)^0x966e5812
 qs.append(('producer_prekey_agrees_iff_record_even',(v.read('w9')==canonical)!=(r&1==0)))
 v=Algebra();v.seed('w19',resize(r,32));v.run_block(0x10046031c,0x100460344)
 qs.append(('decoder_prekey_for_all_record_addresses',v.read('w12')!=canonical))
 v=Algebra();v.seed('x0',r);v.seed('w12',canonical);v.seed('w13',0x592e2f77);mem(v,r,4,canonical*0x592e2f77+phase-0x372c);v.run_block(0x100460378,0x10046037c);v.run_block(0x100460380,0x100460384)
 qs.append(('record_operation_decode_after_key_agreement',v.read('w12')!=phase-0x372c))
 oldc,oldd=z3.BitVecs('post_globalC64 post_globalD64',64);v=Algebra();v.seed('sp',g);v.seed('x22',a);v.seed('x25',r);v.seed('x12',oldc);v.seed('x9',0x0a5cd4cf);mem(v,r,8,oldd);v.run_block(0x1004602d8,0x10046031c);mixed=(oldd-oldc)^(g+0x80)
 qs.append(('helper_shared_u64_updates',z3.Or(cell(v,a,8)!=mixed*0x0a5cd4cf+0x98c1c57ff8a0fd3a,cell(v,r,8)!=(mixed^0x73d046208eaed1a6)*0x0a5cd4cf)))
 v=Algebra();v.seed('sp',g);v.seed('x19',r);v.seed('w11',status);saved={'x'+str(j):z3.BitVec('post_saved_'+str(j),64)for j in range(19,31)}
 for off,n in [(0xd0,'x28'),(0xd8,'x27'),(0xe0,'x26'),(0xe8,'x25'),(0xf0,'x24'),(0xf8,'x23'),(0x100,'x22'),(0x108,'x21'),(0x110,'x20'),(0x118,'x19'),(0x120,'x29'),(0x128,'x30')]:mem(v,g+off,8,saved[n])
 v.run_block(0x100336fcc,0x100336fd0);v.run_block(0x100336fe8,0x100337004)
 qs.append(('result_plus4_and_fixed_frame_return',z3.Or(cell(v,r+4,4)!=status,v.read('sp')!=g+0x130,*[v.read(n)!=x for n,x in saved.items()])))
 v=Algebra();v.seed('sp',f);v.seed('x20',f+0x698);mem(v,f+0x80,8,a);mem(v,a+4,4,connection);v.run_block(0x1004789d4,0x1004789dc);v.run_block(0x1004789ec,0x100478a04)
 qs.append(('six_IOKit_arguments_from_same_root_frame',z3.Or(v.read('x0')!=z3.ZeroExt(32,connection),v.read('x1')!=21,v.read('x2')!=f+0x6a8,v.read('x3')!=552,v.read('x4')!=f+0x6a8,v.read('x5')!=f+0x3f0)))
 out=[]
 for label,p in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(p);result=str(s.check());assert result=='unsat',(label,result);out.append({'label':label,'query':s.to_smt2(),'result':result})
 return out

def view(v,a,n):
 terms=[]
 for at in range(a,a+n):
  value=v.bytes.get(at,z3.BitVec('unknown_'+hex(at),8));shape=v.shape(value,1)
  terms.append(bytes.fromhex(shape['hex'])[0]if'hex'in shape else shape['terms'][0])
 return {'hex':bytes(terms).hex()}if all(isinstance(x,int)for x in terms)else{'terms':terms}

def api_view(v,original,preparation,previous,cut):
 f=int(previous['configuration']['caller_SP'],16)-0x9d0;a=f+0x6a8;shape=view(v,a,552);terms=list(bytes.fromhex(shape['hex']))if'hex'in shape else shape['terms'];writers={}
 for stage,rows in [('ingress',original['trace']['steps'][:cut]),('preparation',preparation['trace']['steps']),('processing',previous['trace']['steps']),('postblock',v.steps)]:
  for j,row in enumerate(rows):
   for event in row['events']:
    if event['kind']!='write':continue
    at=int(event['address'],16)
    for off in range(max(at,a)-a,min(at+event['size_bytes'],a+552)-a):writers[str(off)]={'stage':stage,'visit':j,'pc':row['pc']}
 known=[j for j,x in enumerate(terms)if isinstance(x,int)];assert set(known)==set(map(int,writers))
 return {'address':hex(a),'size_bytes':552,'source_shape':shape,'known_offsets':known,'unassigned_bytes':552-len(known),'last_writers':writers,
  'capacity_cell':{'address':hex(f+0x3f0),'value':view(v,f+0x3f0,8)},'generator_bytes':view(v,f+0x2d4,4),'encoded_generator_word':view(v,f+0x3b4,4)}

def main():
 pins,old,ingress,preparation,previous=inputs();cases=[];totals=Counter();ALLOWED_CALLS.add(HELPER)
 for prior in previous['cases']:
  c=prior['configuration']
  if c['operand_profile']!='baseline':continue
  original=next(v for v in ingress['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['parent_variant']);prep=next(v for v in preparation['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['preparation_variant'])
  v,cut=restore(pins['daemon_callback_revisit_snapshot.json'],old,original,prep,prior);c={**c,'processing_prefix_source_visits':len(prior['trace']['steps']),'entry':hex(ENTRY)}
  v.steps=[];v.pool={};v.cache={};v.fixups=set();v.zero_reads=[];v.changed=set();v.definitions=[];v.origins={};v.unknown_inputs_used={}
  initial={n:v.shape(x,16 if n.startswith('q')else 8)for n,x in v.regs.items()};flags=sum(1<<(31-j)for j,x in enumerate([v.n,v.z,v.carry,v.overflow])if z3.is_true(x));b=v.run_revisit(ENTRY,limit=200000);assert not v.definitions and b['kind']=='before_uninspected_call'and b['pc']=='0x100478a04'and b['modifier16']=='0x7a6c',b
  counts={'source_visits':len(v.steps),'source_pool_entries':len(v.pool),'read_events':sum(e['kind']=='read'for r in v.steps for e in r['events']),'write_events':sum(e['kind']=='write'for r in v.steps for e in r['events'])};totals.update(counts)
  cases.append({'configuration':c,'trace':{'steps':v.steps,'boundary':b,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),'initial_registers':initial,'initial_NZCV':flags},'api_view':api_view(v,original,prep,prior,cut),'API_models':[],'counts':counts});print(json.dumps({'epoch':c['epoch'],'variant':c['name'],**counts,'boundary_PC':b['pc']}),flush=True)
 used={int(a,16)for c in cases for a in c['trace']['used_fixups']}
 collision=[{'slot':hex(a),'target':hex(r['target'])}for a,r in sorted(FIXUPS.items())if'div=0x0A74 'in r['line']]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':Parent.Parent.R.R.H.THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_regions':source(),'source_proofs':obligations(),'source_fixups':Parent.Parent.R.R.verify_fixups(used),'modifier0a74_collision_slots':collision,'collision_fixups':Parent.Parent.R.R.verify_fixups({int(r['slot'],16)for r in collision}),'cases':cases,'verified_counts':{'cases':len(cases),'epochs':2,'variants_per_epoch':2,**dict(totals)},
  **{k:False for k in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)

if __name__=='__main__':main()
