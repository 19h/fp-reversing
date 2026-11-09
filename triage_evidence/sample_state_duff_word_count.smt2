; benchmark generated from python API
(set-info :status unknown)
(declare-fun destination64 () (_ BitVec 64))
(declare-fun length64 () (_ BitVec 64))
(assert
 (let ((?x11 (bvand (bvneg destination64) (_ bv7 64))))
(let ((?x13 (ite (bvult length64 ?x11) length64 ?x11)))
(let ((?x14 (bvsub length64 ?x13)))
(let ((?x16 (bvlshr ?x14 (_ bv3 64))))
(let ((?x17 (bvand ?x16 (_ bv7 64))))
(let ((?x27 (bvadd (bvmul (bvsub (bvlshr (bvadd ?x16 (_ bv7 64)) (_ bv3 64)) (_ bv1 64)) (_ bv8 64)) ?x17)))
(let ((?x28 (ite (= ?x17 (_ bv0 64)) (bvmul (bvlshr (bvadd ?x16 (_ bv7 64)) (_ bv3 64)) (_ bv8 64)) ?x27)))
(and (and (distinct ?x16 (_ bv0 64)) true) (and (distinct ?x28 ?x16) true))))))))))
(check-sat)
