; benchmark generated from python API
(set-info :status unknown)
(declare-fun independent_index_key32 () (_ BitVec 32))
(assert
 (and (distinct ((_ zero_extend 32) (concat (_ bv0 22) ((_ extract 9 0) independent_index_key32))) ((_ zero_extend 32) (bvand independent_index_key32 (_ bv1023 32)))) true))
(check-sat)
