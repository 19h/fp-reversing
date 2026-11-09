; benchmark generated from python API
(set-info :status unknown)
(declare-fun length64 () (_ BitVec 64))
(declare-fun destination64 () (_ BitVec 64))
(assert
 (let ((?x11 (bvand (bvneg destination64) (_ bv7 64))))
(let ((?x13 (ite (bvult length64 ?x11) length64 ?x11)))
(bvugt ?x13 length64))))
(check-sat)
