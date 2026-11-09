; benchmark generated from python API
(set-info :status unknown)
(declare-fun sync_return32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) sync_return32)) sync_return32) true))
(check-sat)
