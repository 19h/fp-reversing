; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_result32 () (_ BitVec 32))
(assert
 (and true (and (distinct ((_ extract 31 0) ((_ zero_extend 32) release_result32)) release_result32) true)))
(check-sat)
