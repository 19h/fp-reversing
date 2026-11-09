; benchmark generated from python API
(set-info :status unknown)
(declare-fun ent_flow_phase32 () (_ BitVec 32))
(declare-fun ent_flow_composed_key32 () (_ BitVec 32))
(assert
 (let ((?x566 (bvadd ent_flow_phase32 (_ bv27440 32))))
(and (distinct (bvxor (bvxor ?x566 ent_flow_composed_key32) ent_flow_composed_key32) ?x566) true)))
(check-sat)
