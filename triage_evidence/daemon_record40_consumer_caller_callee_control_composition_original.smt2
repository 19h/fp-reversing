; benchmark generated from python API
(set-info :status unknown)
(declare-fun record40_phase32 () (_ BitVec 32))
(declare-fun record40_key32 () (_ BitVec 32))
(assert
 (let ((?x56 (bvadd (bvsub (bvsub record40_phase32 record40_key32) (_ bv2653 32)) record40_key32)))
(and (distinct ?x56 (bvsub record40_phase32 (_ bv2653 32))) true)))
(check-sat)
