; benchmark generated from python API
(set-info :status unknown)
(declare-fun iterator32 () (_ BitVec 32))
(assert
 (let ((?x109 ((_ zero_extend 32) iterator32)))
(and (distinct ?x109 ?x109) true)))
(check-sat)
