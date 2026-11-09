; benchmark generated from python API
(set-info :status unknown)
(declare-fun secondary_number_return32 () (_ BitVec 32))
(assert
 (let ((?x85 (ite (= secondary_number_return32 (_ bv0 32)) (_ bv49 32) (_ bv50 32))))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x85)) ?x85) true)))
(check-sat)
