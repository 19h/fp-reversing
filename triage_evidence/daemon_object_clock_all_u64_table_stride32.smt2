; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_index64 () (_ BitVec 64))
(assert
 (not (= (concat ((_ extract 58 0) clock_index64) (_ bv0 5)) (bvmul (_ bv32 64) clock_index64))))
(check-sat)
