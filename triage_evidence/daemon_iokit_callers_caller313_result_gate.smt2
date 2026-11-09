; benchmark generated from python API
(set-info :status unknown)
(declare-fun caller_raw_result32 () (_ BitVec 32))
(assert
 (let (($x93 (= caller_raw_result32 (_ bv2336081489 32))))
(let ((?x131 (ite $x93 (_ bv26901 32) (_ bv26205 32))))
(let ((?x238 (concat ((_ extract 31 15) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 14 13) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32))))) ((_ extract 12 11) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 10 9) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32))))) ((_ extract 8 7) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 6 6) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32))))) ((_ extract 5 5) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 4 2) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32))))) ((_ extract 1 1) (bvmul (_ bv3912 32) (ite $x93 (_ bv1 32) (_ bv0 32)))) (_ bv1 1))))
(let (($x303 (and (= ((_ extract 0 0) caller_raw_result32) (_ bv1 1)) (= ((_ extract 3 1) caller_raw_result32) (_ bv0 3)) (= ((_ extract 4 4) caller_raw_result32) (_ bv1 1)) (= ((_ extract 5 5) caller_raw_result32) (_ bv0 1)) (= ((_ extract 6 6) caller_raw_result32) (_ bv1 1)) (= ((_ extract 8 7) caller_raw_result32) (_ bv0 2)) (= (bvnot ((_ extract 10 9) caller_raw_result32)) (_ bv0 2)) (= ((_ extract 13 11) caller_raw_result32) (_ bv0 3)) (= (bvnot ((_ extract 16 14) caller_raw_result32)) (_ bv0 3)) (= ((_ extract 17 17) caller_raw_result32) (_ bv0 1)) (= (bvnot ((_ extract 21 18) caller_raw_result32)) (_ bv0 4)) (= ((_ extract 23 22) caller_raw_result32) (_ bv0 2)) (= (bvnot ((_ extract 25 24) caller_raw_result32)) (_ bv0 2)) (= ((_ extract 26 26) caller_raw_result32) (_ bv0 1)) (= ((_ extract 27 27) caller_raw_result32) (_ bv1 1)) (= ((_ extract 30 28) caller_raw_result32) (_ bv0 3)) (= ((_ extract 31 31) caller_raw_result32) (_ bv1 1)))))
(or (not (= $x93 $x303)) (not (= ?x238 ?x131))))))))
(check-sat)
