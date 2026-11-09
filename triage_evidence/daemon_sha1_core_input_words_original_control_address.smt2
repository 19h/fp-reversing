; benchmark generated from python API
(set-info :status unknown)
(declare-fun sha1_helper_index32 () (_ BitVec 32))
(assert
 (let (($x10734 (or (not (= ((_ extract 31 4) sha1_helper_index32) (_ bv0 28))) (= ((_ extract 3 0) sha1_helper_index32) (_ bv15 4)))))
(let (($x1103 (or (not (= ((_ extract 31 6) (bvmul (_ bv4 32) sha1_helper_index32)) (_ bv0 26))) (bvule (_ bv60 6) (bvmul (_ bv4 6) ((_ extract 5 0) sha1_helper_index32))))))
(let (($x1678 (and (bvule (bvmul (_ bv4 32) sha1_helper_index32) (_ bv4294967291 32)) $x1103)))
(let ((?x1109 (bvmul (_ bv2532 32) (ite $x1678 (_ bv0 32) (_ bv1 32)))))
(let ((?x1798 ((_ extract 31 31) ?x1109)))
(let ((?x1819 (concat ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ?x1798 ((_ extract 31 16) ?x1109) (bvnot ((_ extract 15 15) ?x1109)) ((_ extract 14 8) ?x1109) (bvnot ((_ extract 7 7) ?x1109)) (bvmul (_ bv100 7) (ite $x1678 (_ bv0 7) (_ bv1 7))) (_ bv0 3))))
(let (($x11700 (not (= ?x1819 (bvadd (_ bv18446744069397569808 64) (ite $x10734 (_ bv4312244976 64) (_ bv4312263184 64)))))))
(let (($x11378 (= ((_ extract 31 4) sha1_helper_index32) (_ bv0 28))))
(and $x11378 $x11700))))))))))
(check-sat)
