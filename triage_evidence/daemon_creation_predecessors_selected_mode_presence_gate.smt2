; benchmark generated from python API
(set-info :status unknown)
(declare-fun pred_presence64 () (_ BitVec 64))
(declare-fun pred_mode32 () (_ BitVec 32))
(assert
 (let (($x39 (= pred_presence64 (_ bv0 64))))
(let ((?x74 (ite $x39 (_ bv36473 32) (_ bv36497 32))))
(let ((?x77 (concat (_ bv0 31) (bvxor (bvadd (_ bv1 1) ((_ extract 0 0) pred_mode32)) (ite $x39 (_ bv1 1) (_ bv0 1))))))
(let ((?x37 (bvxor (bvadd (_ bv18269 32) pred_mode32) (bvmul (_ bv232 32) ?x77))))
(let (($x24 (and (= ((_ extract 5 0) pred_mode32) (_ bv28 6)) (= ((_ extract 9 9) (bvadd (_ bv3801329855 32) pred_mode32)) (_ bv1 1)) (= ((_ extract 11 11) (bvadd (_ bv3801329855 32) pred_mode32)) (_ bv0 1)) (= ((_ extract 14 13) (bvadd (_ bv3801329855 32) pred_mode32)) (_ bv3 2)) (= ((_ extract 19 18) (bvadd (_ bv3801329855 32) pred_mode32)) (_ bv0 2)) (= ((_ extract 22 21) (bvadd (_ bv3801329855 32) pred_mode32)) (_ bv0 2)) (= ((_ extract 24 24) (bvadd (_ bv3801329855 32) pred_mode32)) (_ bv0 1)) (= ((_ extract 28 26) (bvadd (_ bv3801329855 32) pred_mode32)) (_ bv0 3)))))
(let (($x830 (or (not $x24) (not (= ?x37 ?x74)))))
(let (($x84 (= pred_mode32 (_ bv18204 32))))
(and $x84 $x830)))))))))
(check-sat)
