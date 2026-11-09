; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_pointer64 () (_ BitVec 64))
(declare-fun producer_selector32 () (_ BitVec 32))
(assert
 (let ((?x221 (bvxor producer_selector32 (ite (= producer_pointer64 (_ bv0 64)) (_ bv0 32) (_ bv44 32)))))
(and true (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x221)) ?x221) true))))
(check-sat)
