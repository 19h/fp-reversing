; benchmark generated from python API
(set-info :status unknown)
(declare-fun options32 () (_ BitVec 32))
(declare-fun task64 () (_ BitVec 64))
(assert
 (let (($x53 (and (distinct (bvand (bvor (ite (= task64 (_ bv0 64)) (_ bv32 32) (_ bv16 32)) options32) (_ bv15 32)) options32) true)))
(let (($x11 (= task64 (_ bv0 64))))
(let ((?x14 (ite $x11 (_ bv32 32) (_ bv16 32))))
(let (($x47 (or (= options32 (_ bv2 32)) (= options32 (_ bv3 32)))))
(and $x47 (or (and (distinct (bvand (bvor ?x14 options32) (_ bv240 32)) ?x14) true) $x53)))))))
(check-sat)
