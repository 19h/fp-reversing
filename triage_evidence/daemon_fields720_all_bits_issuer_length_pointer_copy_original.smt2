; benchmark generated from python API
(set-info :status unknown)
(declare-fun fields_pointer64 () (_ BitVec 64))
(declare-fun fields_raw32 () (_ BitVec 32))
(assert
 (or (and (distinct ((_ extract 31 0) (concat (_ bv0 32) fields_raw32)) fields_raw32) true) (and (distinct fields_pointer64 fields_pointer64) true)))
(check-sat)
