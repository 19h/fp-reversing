; benchmark generated from python API
(set-info :status unknown)
(declare-fun owning_task32 () (_ BitVec 32))
(assert
 (let ((?x140 ((_ zero_extend 32) owning_task32)))
(and (distinct ?x140 ?x140) true)))
(check-sat)
