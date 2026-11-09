; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_cursor64 () (_ BitVec 64))
(assert
 (and true (and (distinct handoff_cursor64 handoff_cursor64) true)))
(check-sat)
