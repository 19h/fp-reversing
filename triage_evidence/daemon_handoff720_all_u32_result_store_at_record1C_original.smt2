; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_status32 () (_ BitVec 32))
(assert
 (and true (and (distinct ((_ extract 31 0) ((_ zero_extend 32) handoff_status32)) handoff_status32) true)))
(check-sat)
