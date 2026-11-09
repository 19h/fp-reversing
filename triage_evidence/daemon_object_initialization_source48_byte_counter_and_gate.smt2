; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_counter64 () (_ BitVec 64))
(assert
 (let (($x1174 (= init_counter64 (_ bv47 64))))
(let ((?x608 (ite $x1174 (_ bv18424 32) (_ bv18655 32))))
(let ((?x924 (bvmul (_ bv7 3) (ite $x1174 (_ bv0 3) (_ bv1 3)))))
(let ((?x1636 (bvnot ((_ extract 10 3) (bvmul (_ bv3879 32) (ite $x1174 (_ bv0 32) (_ bv1 32)))))))
(let ((?x531 (bvmul (_ bv3879 32) (ite $x1174 (_ bv0 32) (_ bv1 32)))))
(let ((?x1538 ((_ extract 13 11) ?x531)))
(let ((?x1904 (bvnot ((_ extract 14 14) ?x531))))
(let ((?x317 ((_ extract 31 15) ?x531)))
(not (= (concat ?x317 ?x1904 ?x1538 ?x1636 ?x924) ?x608)))))))))))
(check-sat)
