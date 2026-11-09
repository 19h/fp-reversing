; benchmark generated from python API
(set-info :status unknown)
(declare-fun entitlement_marker32 () (_ BitVec 32))
(assert
 (let ((?x18 ((_ extract 7 0) entitlement_marker32)))
(and (distinct ((_ extract 7 0) ((_ extract 31 0) ((_ zero_extend 32) entitlement_marker32))) ?x18) true)))
(check-sat)
