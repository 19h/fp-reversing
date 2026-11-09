; benchmark generated from python API
(set-info :status unknown)
(declare-fun pred_input32 () (_ BitVec 32))
(declare-fun pred_raw32 () (_ BitVec 32))
(assert
 (let ((?x435 ((_ extract 0 0) pred_input32)))
(let ((?x571 (concat (_ bv0 1) (bvnot ((_ extract 30 30) (bvadd (_ bv2961318918 32) pred_input32))) (_ bv3 2) ((_ extract 27 27) (bvadd (_ bv2961318918 32) pred_input32)) (bvnot ((_ extract 26 26) (bvadd (_ bv2961318918 32) pred_input32))) ((_ extract 25 24) (bvadd (_ bv2961318918 32) pred_input32)) (_ bv1 1) (bvnot ((_ extract 22 22) (bvadd (_ bv2961318918 32) pred_input32))) ((_ extract 21 18) (bvadd (_ bv2961318918 32) pred_input32)) (_ bv1 1) ((_ extract 16 16) (bvadd (_ bv2961318918 32) pred_input32)) (bvnot ((_ extract 15 14) (bvadd (_ bv2961318918 32) pred_input32))) ((_ extract 13 13) (bvadd (_ bv2961318918 32) pred_input32)) (bvnot ((_ extract 12 12) (bvadd (_ bv2961318918 32) pred_input32))) (_ bv1 1) ((_ extract 10 2) (bvadd (_ bv2961318918 32) pred_input32)) (_ bv1 1) ?x435)))
(let ((?x600 (concat (_ bv0 31) (bvnot (bvxor ?x435 (ite (= pred_raw32 ?x571) (_ bv1 1) (_ bv0 1)))))))
(let ((?x538 (bvxor pred_input32 (bvmul (_ bv46 32) ?x600))))
(let (($x468 (and (= ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv3002377790 32) pred_input32))) (_ bv25115 32)) (= ((_ extract 31 0) (concat (_ bv0 32) ?x538)) (_ bv39895 32)))))
(and true $x468)))))))
(check-sat)
