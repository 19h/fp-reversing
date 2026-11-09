; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_address64 () (_ BitVec 64))
(assert
 (let ((?x123 (concat ((_ extract 7 3) init_address64) (_ bv0 3))))
(let ((?x124 (bvadd (_ bv56 8) ?x123)))
(let ((?x109 (concat (_ bv1744831232 56) ?x124)))
(let ((?x100 (bvadd (_ bv18446743627032756224 64) ?x109)))
(and true (or (bvugt ?x100 (_ bv248 64)) (and (distinct (bvand ?x100 (_ bv7 64)) (_ bv0 64)) true))))))))
(check-sat)
