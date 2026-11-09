; benchmark generated from python API
(set-info :status unknown)
(declare-fun generic_record64 () (_ BitVec 64))
(declare-fun raw_status32 () (_ BitVec 32))
(assert
 (or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) raw_status32)) raw_status32) true) (and (distinct generic_record64 generic_record64) true)))
(check-sat)
