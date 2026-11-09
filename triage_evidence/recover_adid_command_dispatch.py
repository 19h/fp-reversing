#!/usr/bin/env python3
"""Recover the original full-width ADID command tree and constructor size gate.

The signed comparison tree starts with an encoded input word and terminates
at parser entries/rejection. This is dispatch selection, not whole-operation
acceptance. O(B+F+T+R) time/space; separate 30 s SMT timeouts. No native target.
"""
import json
from pathlib import Path
import re
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA

ENTRY=0x10016cd58
REJECT=0x10016ec20
BIAS=0x46d726


def recover(s):
    work=[(ENTRY,-(1<<31),(1<<31)-1,{},[],[])];accepted=[];rejected=[];nodes={}
    while work:
        pc,lo,hi,registers,path,conditions=work.pop();registers=dict(registers);path=list(path);conditions=list(conditions);comparison=None
        while True:
            if pc==REJECT:rejected.append({'encoded_signed_lo':lo,'encoded_signed_hi':hi,'path':path,'conditions':conditions});break
            raw=s.read(pc,4);i=next(CS.disasm(raw,pc));node={'pc':hex(pc),'bytes':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};nodes[pc]=node;path.append(hex(pc))
            assert i.mnemonic in ('mov','movk','cmp','b.gt','b.le','b.eq','b.ne'),node
            if i.mnemonic in ('mov','movk'):
                m=re.match(r'w(\d+), #(-?(?:0x[0-9a-f]+|\d+))(?:, lsl #(0x[0-9a-f]+|\d+))?$',i.op_str)
                if m:
                    reg,v,shift=m[1],int(m[2],0),int(m[3] or '0',0)
                    registers[reg]=(v&0xffffffff) if i.mnemonic=='mov' else (registers[reg]&~(65535<<shift))|((v&65535)<<shift)
            elif i.mnemonic=='cmp':
                m=re.fullmatch(r'w8, w(\d+)',i.op_str);assert m,node;value=registers[m[1]];comparison={'pc':hex(pc),'constant_u32':value,'signed_value':value-(1<<32) if value&(1<<31) else value}
            else:
                assert comparison is not None,node
                dest=int(i.op_str[1:],16);cc=i.mnemonic[2:];v=comparison['signed_value']
                def cond(taken):return {'branch_pc':hex(pc),'condition':cc,'taken':taken,**comparison}
                if cc in ('eq','ne'):
                    if lo<=v<=hi:
                        accepted.append({'wire_command_u32':((v&0xffffffff)-BIAS)&0xffffffff,'encoded_command_u32':v&0xffffffff,'parser_entry':hex(dest if cc=='eq' else pc+4),'selecting_branch_pc':hex(pc),'path':path.copy(),'conditions':conditions+[cond(cc=='eq')]})
                    for l,h in [(lo,min(hi,v-1)),(max(lo,v+1),hi)]:
                        if l<=h:work.append((pc+4 if cc=='eq' else dest,l,h,registers.copy(),path.copy(),conditions+[cond(cc!='eq')]))
                else:
                    taken=(max(lo,v+1),hi) if cc=='gt' else (lo,min(hi,v));fall=(lo,min(hi,v)) if cc=='gt' else (max(lo,v+1),hi)
                    for target,(l,h),yes in [(dest,taken,True),(pc+4,fall,False)]:
                        if l<=h:work.append((target,l,h,registers.copy(),path.copy(),conditions+[cond(yes)]))
                break
            pc+=4
    assert len({r['wire_command_u32'] for r in accepted})==len(accepted)
    intervals=[(r['encoded_signed_lo'],r['encoded_signed_hi']) for r in rejected]+[(r['encoded_command_u32']-(1<<32) if r['encoded_command_u32']&(1<<31) else r['encoded_command_u32'],)*2 for r in accepted]
    cursor=-(1<<31)
    for lo,hi in sorted(intervals):assert lo==cursor and lo<=hi;cursor=hi+1
    assert cursor==(1<<31)
    return {'entry':hex(ENTRY),'rejection_entry':hex(REJECT),'source_word_register':'w8','source_word_encoding':'BE32(request+4)+0x0046d726 modulo2^32','accepted':accepted,'rejected_signed_intervals':rejected,'decision_instructions':list(nodes.values()),'encoded_domain_cardinality':1<<32,'selected_command_count':len(accepted),'rejected_word_count':sum(r['encoded_signed_hi']-r['encoded_signed_lo']+1 for r in rejected)}


def predicate(conditions):
    out=[]
    for c in conditions:
        value='#x'+format(c['constant_u32'],'08x');cc=c['condition'];term=f'(bvsgt encoded {value})' if cc=='gt' else f'(bvsle encoded {value})' if cc=='le' else f'(= encoded {value})' if cc=='eq' else f'(distinct encoded {value})'
        out.append(term if c['taken'] else '(not '+term+')')
    return '(and '+' '.join(out)+')'


def main():
    s=Adid();tree=recover(s);body=['(declare-fun command () (_ BitVec 32))','(define-fun encoded () (_ BitVec 32) (bvadd command #x0046d726))'];checks=[];members=[]
    for r in tree['accepted']:
        exact=f'(= command #x{r["wire_command_u32"]:08x})';members.append(exact);checks.append('(distinct '+predicate(r['conditions'])+' '+exact+')')
    rejected='(or '+' '.join(predicate(r['conditions']) for r in tree['rejected_signed_intervals'])+')';checks.append('(distinct '+rejected+' (not (or '+' '.join(members)+')))');body.append('(assert (or '+' '.join(checks)+'))')
    queries={'adid_command_dispatch32.smt2':'\n'.join(body),
      'adid_command_allocation32.smt2':'''(declare-fun n () (_ BitVec 32))
(define-fun encoded () (_ BitVec 32) (bvadd n #x0046d726))
(define-fun request () (_ BitVec 32) (bvadd #xf7251b40 (bvshl encoded #x00000005)))
(assert (distinct request (bvmul n #x00000020)))''',
      'adid_command_blob_minimum32.smt2':'''(declare-fun length () (_ BitVec 32))
(define-fun encoded () (_ BitVec 32) (bvadd length #x0046d726))
(define-fun w21 () (_ BitVec 32) (bvmul (bvxor #x00000a20 #x00000a5f) #x00000003))
(define-fun delta () (_ BitVec 32) (bvxor (bvxor (bvsub #xffb928da #x00000441) #x00000d5b) w21))
(define-fun operand () (_ BitVec 32) (bvadd encoded delta))
(assert (or (distinct operand (bvsub length #x0000001b))
 (distinct (bvult operand #xffffffe5) (bvuge length #x0000001b))))'''}
    proofs=[]
    for name,query in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+query+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr,(name,run.stdout,run.stderr);proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full32-bit command dispatch domain under original word encoding; blob gate under observed constructor control constants.'})
    windows=[]
    for a,z,role in [(0x10016cd28,0x10016cd58,'dispatch input frame load and audit-EUID staging'),(0x10016cd58,0x10016ec38,'decision nodes and interleaved parser gates'),(0x10016ac08,0x10016ac38,'request-tail pointer,encoded length and key staging'),(0x10019cb24,0x10019cc14,'constructor tail guard and27-byte minimum'),(0x1001a1530,0x1001a1638,'first four request-tail byte reads/local byte view'),(0x100266b0c,0x100266b80,'request-controlled u32 allocation arithmetic and original post-call BRK')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    old=json.loads((ROOT/'adid_context_contracts.json').read_text());prior=[r for r in old['proofs'] if r['path']=='adid_context_header32.smt2']
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'command_tree':tree,'proofs':proofs,'prior_header_proof':prior,'original_windows':windows,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_context_contracts.json']},'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_command_dispatch_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'selected_commands':len(tree['accepted']),'decision_instructions':len(tree['decision_instructions']),'rejected_word_count':tree['rejected_word_count'],'full_domain_words':tree['encoded_domain_cardinality'],'new_proofs':len(proofs),'prior_header_proofs':len(prior)}))


if __name__=='__main__':main()
