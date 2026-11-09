; benchmark generated from python API
(set-info :status unknown)
(declare-fun query_saved_result32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) query_saved_result32)) query_saved_result32) true))
(check-sat)
