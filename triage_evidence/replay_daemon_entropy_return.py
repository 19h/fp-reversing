#!/usr/bin/env python3
"""Independent A64 replay through the declared entropy return to time query.
Six seeds, two caller-clobber/unknown-byte patterns, four incoming contexts.
Ordinary source instructions run in Unicorn; external APIs/PAC do not.
O(C*S*(prefix+V+byte effects+SSA bytes)) time,O(largest trace+owner bytes)
space, with cached parsing of bounded SSA expressions.
"""
import copy,hashlib,json
from pathlib import Path
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from replay_daemon_context_transfer import Replay,unpack
from daemon_entropy_return_symbolic import CALL
CACHE={};SEEDS=[0,1,5489,0x12345678,0x80000000,0xffffffff];ARRAY=0x1010c784c

def expr(s,values):
 if'hex'in s:return int.from_bytes(bytes.fromhex(s['hex']),'little')
 assert'expr'in s
 key=(s['expr'],s['bits'],tuple(tuple(x)for x in s['symbols']))
 if key not in CACHE:
  symbols={n:z3.BitVec(n,b)for n,b in s['symbols']};dest=z3.BitVec('__value',s['bits']);formula=z3.parse_smt2_string('(assert (= __value '+s['expr']+'))',decls={'__value':dest,**symbols})[0];CACHE[key]=(formula.arg(1),symbols)
 value,symbols=CACHE[key];v=z3.simplify(z3.substitute(value,*[(symbol,z3.BitVecVal(values[n],symbol.size()))for n,symbol in symbols.items()]));assert z3.is_bv_value(v);return v.as_long()
def concrete(obj,values):
 if isinstance(obj,dict):
  if'expr'in obj:return {'hex':expr(obj,values).to_bytes(obj['bits']//8,'little').hex()}
  return {k:concrete(v,values)for k,v in obj.items()}
 if isinstance(obj,list):return[concrete(v,values)for v in obj]
 return obj
class EntropyReplay(Replay):
 def __init__(self,c,prefix,suffix,seed,pattern):
  self.prefix=prefix;self.suffix=suffix;self.entropy_seed=seed;self.api_pending=True;self.model=None
  combined={'steps':prefix['steps']+suffix['steps'],'boundary':suffix['boundary'],'origins':prefix['origins'],'final_source_fields':prefix['final_source_fields']};super().__init__(c,combined,pattern)
 def code(self,u,a,n,d):
  if not(self.forward and self.api_pending and self.index==len(self.prefix['steps'])):return super().code(u,a,n,d)
  self.finish();assert a==CALL and bytes(u.mem_read(a,4))==IMAGE.read(a,4)and self.reg(8)==0x7c100000 and self.reg(17)==0x2692
  before={'SP':hex(self.fullreg('sp')),'X18_to_X29':[hex(self.reg(j))for j in range(18,30)],'D8_to_D15_low64':[hex(self.fullreg('q'+str(j))&((1<<64)-1))for j in range(8,16)]}
  values={};symbols={n:b for row in self.suffix['definitions']for n,b in row['expression']['symbols']if not n.startswith('value_')}
  for shape in self.suffix['api_effects'].values():symbols.update({n:b for n,b in shape.get('symbols',[])if not n.startswith('value_')})
  for name,bits in symbols.items():
   assert isinstance(bits,int)
   if name.startswith('incoming_d'):values[name]=self.fullreg('q'+name[len('incoming_d'):])&((1<<64)-1)
   else:values[name]=(0 if self.pattern==0 else int.from_bytes(hashlib.sha256(name.encode()).digest(),'little'))&((1<<bits)-1)
  values['api_entropy_u32']=self.entropy_seed
  for row in self.suffix['definitions']:
   assert row['name']not in values;values[row['name']]=expr(row['expression'],values)
  effects=concrete(self.suffix['api_effects'],values)
  for reg,shape in effects.items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg.upper()),int.from_bytes(bytes.fromhex(shape['hex']),'little'))
  u.reg_write(ar.UC_ARM64_REG_NZCV,0 if self.pattern==0 else 0xf0000000)
  after={'SP':hex(self.fullreg('sp')),'X18_to_X29':[hex(self.reg(j))for j in range(18,30)],'D8_to_D15_low64':[hex(self.fullreg('q'+str(j))&((1<<64)-1))for j in range(8,16)]};assert before==after and self.reg(0)&0xffffffff==self.entropy_seed
  suffix=concrete(self.suffix,values);self.trace={'steps':self.prefix['steps']+suffix['steps'],'boundary':suffix['boundary'],'origins':self.prefix['origins'],'final_source_fields':self.prefix['final_source_fields']};self.model={'pc':hex(CALL),'name':'arc4random','argument_count':0,'return_u32':hex(self.entropy_seed),'upper_X0_unconstrained_pattern':hex(self.reg(0)>>32),'preserved_before':before,'preserved_after':after,'SSA_definitions_evaluated':len(self.suffix['definitions']),'native_target_executed':False};self.api_pending=False;return u.reg_write(ar.UC_ARM64_REG_PC,CALL+4)
 def run_entropy(self):
  result=super().run_forward();assert not self.api_pending and self.model
  words=[self.entropy_seed]
  for i in range(1,624):words.append((0x6c078965*(words[-1]^(words[-1]>>30))+i)&0xffffffff)
  raw=bytes(self.u.mem_read(ARRAY,2496));assert raw==b''.join(w.to_bytes(4,'little')for w in words)
  assert self.reg(0)==self.F+0x680 and self.reg(1)==0 and bytes(self.u.mem_read(self.F+0x60c,4))==(624).to_bytes(4,'little')and bytes(self.u.mem_read(0x1010c8258,4))==bytes(4)
  result.update(entropy_model=self.model,state_array={'address':hex(ARRAY),'size_bytes':2496,'words':624,'sha256':hashlib.sha256(raw).hexdigest(),'head_u32':[hex(x)for x in words[:4]],'tail_u32':[hex(x)for x in words[-4:]]},time_arguments={'timeval_pointer':hex(self.F+0x680),'timezone_pointer':'0x0'},native_entropy_executed=False,native_time_executed=False);return result

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());prior=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());rows=[]
 for context in p['cases']:
  index=context['prior_case_index'];prefix=unpack(next(x for x in prior['cases']if x['prior_case_index']==index));suffix=unpack(context);cfg=base['cases'][index]['input']
  for seed in SEEDS:
   for pattern in [0,3]:
    r=EntropyReplay(cfg,prefix,suffix,seed,pattern).run_entropy();r['prior_case_index']=index;rows.append(r)
   print(json.dumps({'case':index,'seed':hex(seed),'completed_replays':len(rows)}),flush=True)
 deps=['daemon_entropy_return_profiles.json','daemon_context_transfer_profiles.json','daemon_arena_storage_profiles.json','replay_daemon_context_transfer.py','probe_daemon_arena_storage.py','daemon_entropy_return_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_entropy_return_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'replays':len(rows),'source_visits':sum(r['verified_counts']['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
