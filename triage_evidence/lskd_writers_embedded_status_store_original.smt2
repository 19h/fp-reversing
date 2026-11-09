; benchmark generated from python API
(set-info :status unknown)
(declare-fun writers_status32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) writers_status32)) writers_status32) true))
(check-sat)
