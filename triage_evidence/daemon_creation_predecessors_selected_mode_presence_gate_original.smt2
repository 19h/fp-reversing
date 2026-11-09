; benchmark generated from python API
(set-info :status unknown)
(declare-fun pred_mode32 () (_ BitVec 32))
(declare-fun pred_presence64 () (_ BitVec 64))
(assert
 (let (($x81 (and (distinct (bvand ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv3801329855 32) pred_mode32))) (_ bv493644351 32)) (_ bv25115 32)) true)))
(let (($x39 (= pred_presence64 (_ bv0 64))))
(let ((?x74 (ite $x39 (_ bv36473 32) (_ bv36497 32))))
(let ((?x77 (concat (_ bv0 31) (bvxor (bvadd (_ bv1 1) ((_ extract 0 0) pred_mode32)) (ite $x39 (_ bv1 1) (_ bv0 1))))))
(let ((?x37 (bvxor (bvadd (_ bv18269 32) pred_mode32) (bvmul (_ bv232 32) ?x77))))
(let ((?x59 ((_ extract 31 0) (concat (_ bv0 32) ?x37))))
(let (($x84 (= pred_mode32 (_ bv18204 32))))
(and $x84 (or (and (distinct ?x59 ?x74) true) $x81))))))))))
(check-sat)
