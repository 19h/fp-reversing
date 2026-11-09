; benchmark generated from python API
(set-info :status unknown)
(declare-fun fields_raw32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) fields_raw32)) fields_raw32) true))
(check-sat)
