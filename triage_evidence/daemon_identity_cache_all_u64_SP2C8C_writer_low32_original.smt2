; benchmark generated from python API
(set-info :status unknown)
(declare-fun identity_return64 () (_ BitVec 64))
(assert
 (let ((?x71 ((_ extract 31 0) identity_return64)))
(and (distinct ?x71 ?x71) true)))
(check-sat)
