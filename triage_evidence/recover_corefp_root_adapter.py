#!/usr/bin/env python3
"""Original protected-root adapter, source census and coherent failure returns.

No native target/API/IPC or IDB mutation. API/PAC/once/allocator/lock effects
are the frozen private models. Conservative O(C*(B+P*F+V*J+R)) time/space
upper bound; C profiles, B source bytes, P pages, F fixups, V visits,
J journal records, R retained RAM. Each execution is bounded to 30000 visits.
"""
import bisect,json,struct
from pathlib import Path
from hashlib import sha256
import audit_corefp_lookup_release  # Select the retained, hash-pinned image.
from recover_corefp_lookup_release import Run as Frozen,configurations as previous_configurations,parent_inputs,DEPS as PREVIOUS_DEPS
from recover_corefp_lookup_initialization import frame,pack,ROOT,BASE,REC,DONE,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE,CS
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
ENTRY=0x8fcfa0;PARENT=0x63000800;CURSOR=0x63000e00
DEPS=PREVIOUS_DEPS+['recover_corefp_lookup_release.py']


def configurations():
    rows=[{**c,'seed_u64':'0x0'}for c in previous_configurations()]
    base=previous_configurations()[0]
    # The odd multiplier permutes u64. These seeds select every high nibble
    # of (seed*0x2edd+1) modulo 2^64, including all sixteen stack paddings.
    inv=pow(0x2edd,-1,1<<64)
    rows += [{**base,'label':'pad_'+str(n),'seed_u64':hex((((n<<60)-1)*inv)&M64)}for n in range(16)]
    rows += [{**base,'label':label,'seed_u64':hex(seed)}for label,seed in [('seed_100',0x100),('seed_max',M64)]]
    return rows


def census(s):
    text=next(v for v in s.meta['sections']if v['section']=='__text');lo=text['address'];raw=s.read(lo,text['size'])
    pattern=struct.pack('<I',0xd2800000|(0x41d4<<5)|17);sites=[]
    for off in range(0,len(raw)-4,4):
        if raw[off:off+4]!=pattern:continue
        a=lo+off;i=next(CS.disasm(raw[off+4:off+8],a+4))
        if i.mnemonic not in ['braa','blraa']:continue
        ix=bisect.bisect_right(s.starts,a)-1
        sites.append({'modifier_site':hex(a),'callsite':hex(a+4),'instruction':i.mnemonic+' '+i.op_str,
          'function_start':hex(s.starts[ix]),'function_end':hex(s.starts[ix+1])})
    rows=[r for r in s.decoded.values()if r.get('key')=='IA'and r.get('diversity')=='0x41d4'and not r['bind']]
    return {'scope':'Aligned literal MOV X17,#0x41d4 immediately followed by BRAA/BLRAA in the complete original __text; other constructions are excluded.',
      'text_address':hex(lo),'text_size_B':len(raw),'text_sha256':SHA(raw),'literal_call_candidates':sites,'same_diversity_rebase_rows':rows,
      'root_reference_rows':[r for r in s.decoded.values()if not r['bind']and r['target']=='0x8e81c8'],
      'root_is_exported':any(v.get('address')==0x8e81c8 for v in s.exports.values()),
      'adapter_is_exported':any(v.get('address')==ENTRY for v in s.exports.values()),'exports':s.exports}


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c);self.u.mem_write(CURSOR,int(c['seed_u64'],16).to_bytes(8,'little'))
        self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY);self.initial=frame(self.u)
        self.pages[REC&~4095]=bytes(self.u.mem_read(REC&~4095,4096));self.inner=None;self.adapter_points=[]
    def adapter_point(self,label):
        return {'label':label,'CPU':frame(self.u),'external_word_u64':hex(int.from_bytes(self.u.mem_read(CURSOR,8),'little')),
          'internal_word_address':None if self.inner is None else hex(self.inner),
          'internal_word_u64':None if self.inner is None else hex(int.from_bytes(self.u.mem_read(self.inner,8),'little')),
          'record48_hex':bytes(self.u.mem_read(PARENT,48)).hex(),'visits_so_far':len(self.visits)}
    def code(self,u,pc,n,d):
        self.flush()
        if pc==BASE+0x8fd1b8:self.inner=self.reg('x1');self.adapter_points.append(self.adapter_point('before_original_child_call'))
        if pc==BASE+0x8e81c8:self.adapter_points.append(self.adapter_point('original_root_entry'))
        if pc==BASE+0x8fd1bc:self.adapter_points.append(self.adapter_point('original_root_return'))
        if pc==DONE:self.adapter_points.append(self.adapter_point('outer_return'))
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=30001);self.flush();assert hasattr(self,'frontier')and not self.once
        assert self.boots==len(self.c['bootstrap_results'])
        return {'configuration':self.c,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations_attempted':self.allocs,'metadata_returns':self.metadata_returns,'daemon_children':self.children,'bootstrap_calls':self.boots,
          'handoffs':self.handoffs,'lock_events':self.lock_events,'certificate_allocation_attempts':self.certificate_attempts,
          'parent_return':self.parent_return,'adapter_points':self.adapter_points}


from unicorn import arm64_const as A


def main():
    s=Pointers();rows=[];spans={};inventory=census(s)
    for c in configurations():
        run=Run(s,c);rows.append(run.run());spans.update(run.functions)
    for r in inventory['literal_call_candidates']:
        a=int(r['function_start'],16);spans.setdefault(a,s.function(a))
    counts={'profiles':len(rows),**{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','adapter_points']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in rows),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in rows)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),'census':inventory,
      'declared_inputs_without_profile_seed':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()],
      'profiles':rows,'verified_counts':counts,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_root_adapter_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
