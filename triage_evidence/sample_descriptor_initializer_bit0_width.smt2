; benchmark generated from python API
(set-info :status unknown)
(declare-fun result64 () (_ BitVec 64))
(assert
 (let ((?x36 ((_ extract 0 0) result64)))
(let (($x38 (= ?x36 (_ bv1 1))))
(and (distinct $x38 (and (distinct (bvand result64 (_ bv1 64)) (_ bv0 64)) true)) true))))
(check-sat)
