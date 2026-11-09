; benchmark generated from python API
(set-info :status unknown)
(declare-fun caller_record64 () (_ BitVec 64))
(assert
 (or (and (distinct caller_record64 caller_record64) true) (and (distinct (_ bv2676 64) (_ bv2676 64)) true)))
(check-sat)
