; benchmark generated from python API
(set-info :status unknown)
(declare-fun entitlement_return64 () (_ BitVec 64))
(assert
 (let ((?x78 ((_ extract 7 0) entitlement_return64)))
(and (distinct ((_ extract 7 0) ((_ extract 31 0) entitlement_return64)) ?x78) true)))
(check-sat)
