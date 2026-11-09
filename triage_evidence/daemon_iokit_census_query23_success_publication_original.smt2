; benchmark generated from python API
(set-info :status unknown)
(declare-fun query_output32 () (_ BitVec 32))
(assert
 (let (($x123 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv20212 32))) (_ bv20212 32)) true)))
(or $x123 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) query_output32)) query_output32) true))))
(check-sat)
