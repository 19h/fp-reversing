; benchmark generated from python API
(set-info :status unknown)
(declare-fun readback_raw_status32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) readback_raw_status32)) readback_raw_status32) true))
(check-sat)
