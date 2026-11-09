; benchmark generated from python API
(set-info :status unknown)
(declare-fun length64 () (_ BitVec 64))
(declare-fun destination64 () (_ BitVec 64))
(assert
 (let ((?x11 (bvand (bvneg destination64) (_ bv7 64))))
(let ((?x13 (ite (bvult length64 ?x11) length64 ?x11)))
(let ((?x14 (bvsub length64 ?x13)))
(let ((?x49 (bvadd (bvadd ?x13 (bvshl (bvlshr ?x14 (_ bv3 64)) (_ bv3 64))) (bvand ?x14 (_ bv7 64)))))
(and (distinct ?x49 length64) true))))))
(check-sat)
