; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_init_status32 () (_ BitVec 32))
(assert
 (let ((?x387 (bvmul (_ bv4294967295 32) (concat (ite (bvsle rw_init_status32 (_ bv15 32)) (_ bv0 29) (_ bv1 29)) (_ bv0 3)))))
(let ((?x388 (bvadd (concat (ite (bvsle rw_init_status32 (_ bv15 32)) (_ bv0 26) (_ bv1 26)) (_ bv0 6)) ?x387)))
(let ((?x411 (concat ((_ extract 31 16) ?x388) (bvnot ((_ extract 15 15) ?x388)) ((_ extract 14 10) ?x388) (bvnot ((_ extract 9 9) ?x388)) ((_ extract 8 8) ?x388) (bvnot ((_ extract 7 6) ?x388)) ((_ extract 5 5) ?x388) (bvnot ((_ extract 4 4) ?x388)) ((_ extract 3 2) ?x388) (bvnot ((_ extract 1 1) ?x388)) (_ bv0 1))))
(not (= ?x411 (ite (bvsle rw_init_status32 (_ bv15 32)) (_ bv33490 32) (_ bv33514 32))))))))
(check-sat)
