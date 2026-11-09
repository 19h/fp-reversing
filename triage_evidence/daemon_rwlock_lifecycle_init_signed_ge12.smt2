; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_init_status32 () (_ BitVec 32))
(assert
 (let ((?x307 (bvnot ((_ extract 2 1) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))))))
(let ((?x305 (bvnot ((_ extract 8 6) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))))))
(let ((?x303 (bvnot ((_ extract 11 10) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))))))
(let ((?x301 (bvnot ((_ extract 15 15) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))))))
(let ((?x315 (concat ((_ extract 31 16) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))) ?x301 ((_ extract 14 12) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))) ?x303 ((_ extract 9 9) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))) ?x305 ((_ extract 5 3) (bvmul (_ bv1014 32) (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv1 32) (_ bv0 32)))) ?x307 (_ bv0 1))))
(not (= ?x315 (ite (bvsle (_ bv12 32) rw_init_status32) (_ bv36400 32) (_ bv36294 32))))))))))
(check-sat)
