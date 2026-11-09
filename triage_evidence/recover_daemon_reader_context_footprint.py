#!/usr/bin/env python3
"""Static decoder-preparation footprint and projected dependencies only."""
import bisect,json,re,struct,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,CS,FIXUPS,TABLE,block,sha,h,FLAGS
from resolve_kernel_collection_interfaces import commands
from validate_daemon_existing_scalar_reader import make,bv,z,CURSOR,WORD_BASE,DECL,prefix
P='daemon_reader_context_footprint'
SCOPE='Selected cursor0 decoder preparation: fixed read/write footprint,all50 affine cache relations,25 abstract input inverses and selected-output noninterference. No whole-call noninterference,native frame owner/initialization/PAC/peer or daemon-kext proof.'
OFFSETS=[0xa640,0xa638,0xa610,0x9ea8,0x9ea0,0x9e98,0x9e88,0x9e78,0xae40,0xae30,0xae20,0xae10,0xada0,0x9eb8,0x9e58,0x9e38,0x9e90,0x9e80,0x9e70,0xad90,0x9d8,None,0x959e,0x958a,0x8f7e,0x8f6e,0x8f56,0x8f46,0xa608]
CRITICAL=[0x978,0x970,0x958,0x950,0x818,0x8f8]
OBSREGS=[0,1,2,4,5,6,7,8,9,11,12,14,15,16,17,19,20,21,22,23,25,26,27,30]
def engine(f,ns='p_',side='N'):
 loads={};inputs=[];counter=0
 for i in f['instructions']:
  m=i['mnemonic']
  if m not in('ldr','ldur','ldrh'):continue
  pc=int(i['ea'],16);bits=16 if m=='ldrh'else 32 if i['operands'].startswith('w')else 64
  if pc==0x1006f6bfc:value=bv(CURSOR);role='cursor_zero'
  elif pc==0x1006f6c38:value=z('SIZE');role='node_extent_u32'
  elif pc==0x1006f7088:value='TABLE';role='dispatch_table_root'
  elif pc==0x1006f708c:value='FN';role='selected_dispatch_pointer'
  else:value=side+str(counter);counter+=1;role='nuisance_cut'
  loads[i['ea']]=(value,bits);inputs.append({'site':i['ea'],'width_bits':bits,'input':value,'role':role})
 s={'fragments':{'prepare':f}};g=make(s,'prepare',r={8:bv(0x8c3f),1:'BUF',4:bv(WORD_BASE),16:bv(0x74)},loads=loads,ns=ns);assert len(g.reads)==len(inputs)==29 and counter==25
 return g,inputs
def dependencies(g,expr):
 defs={}
 for d in g.defs:
  m=re.fullmatch(r'\(define-fun (\w+) \(\) \(_ BitVec \d+\) (.*)\)',d);assert m;defs[m[1]]=m[2]
 known={'SIZE','TABLE','FN','BUF','K'}|{'N'+str(j)for j in range(25)}|{'Z'+str(j)for j in range(31)}
 memo={}
 def walk(e):
  found=set()
  for t in re.findall(r'\b[A-Za-z_]\w*\b',e):
   if t in known:found.add(t)
   elif t in defs:
    if t not in memo:memo[t]=walk(defs[t])
    found|=memo[t]
  return found
 return sorted(walk(expr))
def affine_candidates(g,inputs):
 decl=''.join(f'(declare-fun {q["input"]} () (_ BitVec {q["width_bits"]}))\n'for q in inputs if q['role']=='nuisance_cut');values=[];queries=[]
 for value in (0,1):
  constraints='(assert (= SIZE '+bv(value,32)+'))\n'+''.join('(assert (= '+q['input']+' '+bv(value,q['width_bits'])+'))\n'for q in inputs if q['role']=='nuisance_cut')
  query='(set-logic QF_BV)\n'+DECL+decl+prefix(g)+constraints+'(check-sat)\n(get-value ('+' '.join(r['value']for r in g.stores)+'))\n';v=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.startswith('sat\n');vals=re.findall('#x([0-9a-f]+)',v.stdout);assert len(vals)==50;values.append([int(x,16)for x in vals]);queries.append(query)
 widths={q['input']:q['width_bits']for q in inputs if q['role']=='nuisance_cut'};widths['SIZE']=32;rows=[]
 for j,r in enumerate(g.stores):
  deps=dependencies(g,r['value']);assert len(deps)<=1;bits=r['width_bits'];slope=(values[1][j]-values[0][j])&((1<<bits)-1);assert slope==(1 if deps else 0)
  rows.append({'site':r['site'],'width_bits':bits,'input':deps[0]if deps else None,'input_width_bits':widths[deps[0]]if deps else None,'candidate_bias':bv(values[0][j],bits),'candidate_slope':slope})
 return {'candidates':rows,'candidate_probe_queries':queries,'candidate_probe_results_u64':[[hex(v)for v in vv]for vv in values],'solver_path':'/opt/homebrew/bin/z3','solver_sha256':sha('/opt/homebrew/bin/z3'),'scope':'Two scalar SMT assignments propose affine expressions only; each expression requires the universal source-linked validator. No target/model execution.'}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 f=block(0x1006f6bf0,0x4000);f['sha256']=h(bytes.fromhex(f['bytes']));assert len(f['instructions'])==386 and f['instructions'][-1]['ea']=='0x1006f71f4'
 old=json.loads((ROOT/'daemon_existing_scalar_reader_source.json').read_text());assert old['fragments']['prepare']==f
 word=old['fragments']['word'];raw=bytes.fromhex(word['bytes']);assert IMAGE.read(int(word['start'],16),len(raw))==raw
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;defined={'sp'};incoming=set();first=[]
 def norm(r):return 'x'+r[1:]if r.startswith('w')and r[1:].isdigit()else {'lr':'x30','fp':'x29'}.get(r,r)
 for i in dc.disasm(raw,int(word['start'],16)):
  rr,ww=i.regs_access();rr={norm(i.reg_name(r))for r in rr};ww={norm(i.reg_name(r))for r in ww};new=rr-defined-incoming
  for r in sorted(new):first.append({'site':hex(i.address),'register':r})
  incoming|=rr-defined;defined|=ww
 assert incoming=={'x'+str(j)for j in OBSREGS if j not in(17,22)}
 census={'reference':'daemon_existing_scalar_reader_source.json /fragments/word','bytes_checked':len(raw),'sha256':h(raw),'instructions':len(word['instructions']),'incoming_GPR_numbers':sorted(int(r[1:])for r in incoming),'first_read_before_definition':first,'scope':'Explicit/implicit register-access census,not a memory alias proof. Projection additionally includes branch targetX22 and modifierX17.'}
 g,inputs=engine(f);reads=[];writes=[]
 for row,inp,off in zip(g.reads,inputs,OFFSETS):
  assert row['site']==inp['site']and row['width_bits']==inp['width_bits']
  reads.append({**inp,'address_base':'TABLE'if off is None else'K','offset_bytes':8*0x8c3f if off is None else off,'extent_bytes':row['width_bits']//8,'source_address_expression':row['address']})
 bypc={i['ea']:i for i in f['instructions']}
 for row in g.stores:
  i=bypc[row['site']];m=re.fullmatch(r'[xw]\d+, \[sp, #(0x[0-9a-f]+|[0-9]+)\]',i['operands']);assert m
  off=int(m[1],0);writes.append({'site':row['site'],'offset_bytes':off,'extent_bytes':row['width_bits']//8,'width_bits':row['width_bits'],'source_address_expression':row['address'],'source_value_expression':row['value'],'syntactic_transitive_inputs':dependencies(g,row['value']),'selected_critical_field':off in CRITICAL})
 rb={r['offset_bytes']+j for r in reads if r['address_base']=='K'for j in range(r['extent_bytes'])};wb={r['offset_bytes']+j for r in writes for j in range(r['extent_bytes'])};assert len(rb)==188 and len(wb)==376 and not rb&wb and max(wb)+1==0x9bc and max(rb)+1==0xae48
 assert sum(r['extent_bytes']for r in writes)==len(wb)and sum(r['extent_bytes']for r in reads if r['address_base']=='K')==len(rb)
 starts=[]
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x26:continue
  off,n=struct.unpack_from('<II',IMAGE.data,at+8);raw=IMAGE.data[off:off+n];p=0;cur=0x100000000
  while p<len(raw):
   value=shift=0
   while True:
    b=raw[p];p+=1;value|=(b&127)<<shift;shift+=7
    if not b&128:break
   if not value:break
   cur+=value;starts.append(cur)
 j=bisect.bisect_right(starts,0x1006f6bf0)-1;assert starts[j]==0x10065ffd8 and starts[j+1]==0x100873194
 a=starts[j];bb=IMAGE.read(a,24);prologue={'start':hex(a),'end':hex(a+24),'bytes':bb.hex(),'sha256':h(bb),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]};assert len(prologue['instructions'])==6 and prologue['instructions'][1]['operands']=='x22, x21, [sp, #-0x30]!'and prologue['instructions'][-1]['operands']=='sp, sp, #0x10'
 row=next(r for r in old['pointer_records']if r['index']=='0x8c3f');slot=int(row['slot'],16);assert IMAGE.read(slot,8).hex()==row['raw_bytes']and FIXUPS[slot]==row['fixup']and row['fixup']['target']==0x100800004
 observations={'critical_stores':[r for r in writes if r['selected_critical_field']],'terminal_registers':[{'register':'x'+str(j),'expression':g.get('x'+str(j)),'syntactic_transitive_inputs':dependencies(g,g.get('x'+str(j)))}for j in OBSREGS],'scope':'Projection only. The other cache stores remain observable memory effects and may depend on nuisance inputs.'};affine=affine_candidates(g,inputs)
 assert not any(x.startswith('N')for r in observations['critical_stores']for x in r['syntactic_transitive_inputs'])and not any(x.startswith('N')for r in observations['terminal_registers']for x in r['syntactic_transitive_inputs'])
 deps=['daemon_existing_scalar_reader_source.json','daemon_existing_scalar_reader_checks.json','validate_daemon_existing_scalar_reader.py','daemon_scalar_field_population_source.json','daemon_constructor_lookup_source.json','daemon_receive_fixups.txt']
 counts={'source_ranges':2,'source_instructions':392,'source_bytes':1568,'preparation_instructions':386,'preparation_translated_nonbranch_instructions':385,'loads':29,'frame_loads':28,'table_loads':1,'u64_frame_loads':22,'u16_frame_loads':6,'frame_read_bytes':188,'table_read_bytes':8,'stores':50,'u64_stores':44,'u32_stores':6,'frame_write_bytes':376,'frame_read_upper_bound_bytes':0xae48,'frame_write_lower_bound_bytes':0x7e8,'frame_write_upper_bound_bytes':0x9bc,'nuisance_loads':25,'critical_store_fields':6,'projected_terminal_registers':len(OBSREGS),'word_input_census_instructions':484,'word_input_census_bytes':1936,'word_input_GPRs':22,'compiler_container_extent_bytes':starts[j+1]-starts[j],'prefix_stack_reservation_bytes':64,'retained_found_entries':0}
 counts.update(affine_cache_candidates=50,affine_candidate_probe_assignments=2,nuisance_cache_stores=44,abstract_nuisance_input_bits=1312)
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'preparation':f,'read_ledger':reads,'write_ledger':writes,'selected_projection':observations,'affine_recovery':affine,'word_input_register_census':census,'original_dispatch_pointer':row,'compiler_container':{'start':hex(starts[j]),'next_start':hex(starts[j+1]),'entry_prefix':prologue,'scope':'LC_FUNCTION_STARTS container and six-instruction prefix only. They do not establish the working-SP owner at the preparation; internal entries,calls and stack-delta epochs remain unjoined.'},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
