; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_classifier32 () (_ BitVec 32))
(assert
 (and true (and (distinct ((_ extract 31 0) (concat (_ bv0 32) init_classifier32)) init_classifier32) true)))
(check-sat)
