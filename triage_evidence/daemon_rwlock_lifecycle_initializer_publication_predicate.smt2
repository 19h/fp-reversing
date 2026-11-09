; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_init_status32 () (_ BitVec 32))
(assert
 (let (($x323 (= rw_init_status32 (_ bv0 32))))
(let ((?x293 (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))))
(let ((?x298 ((_ extract 31 16) ?x293)))
(let (($x1313 (and (= (bvnot ((_ extract 2 1) ?x293)) (_ bv3 2)) (= ((_ extract 5 3) ?x293) (_ bv0 3)) (= (bvnot ((_ extract 8 6) ?x293)) (_ bv7 3)) (= ((_ extract 9 9) ?x293) (_ bv0 1)) (= (bvnot ((_ extract 11 10) ?x293)) (_ bv3 2)) (= ((_ extract 14 12) ?x293) (_ bv0 3)) (= ((_ extract 15 15) ?x293) (_ bv0 1)) (= ?x298 (_ bv0 16)) (= (bvnot (bvmul (_ bv60 6) (ite $x323 (_ bv1 6) (_ bv0 6)))) (_ bv3 6)) (= ((_ extract 6 6) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32)))) (_ bv1 1)) (= (bvnot ((_ extract 9 7) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32))))) (_ bv5 3)) (= ((_ extract 10 10) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32)))) (_ bv0 1)) (= (bvnot ((_ extract 13 11) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32))))) (_ bv5 3)) (= ((_ extract 31 14) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32)))) (_ bv1 18)))))
(not (= $x1313 $x323)))))))
(check-sat)
