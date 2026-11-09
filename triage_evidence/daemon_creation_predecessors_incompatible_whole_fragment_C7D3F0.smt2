; benchmark generated from python API
(set-info :status unknown)
(declare-fun pred_input32 () (_ BitVec 32))
(declare-fun pred_raw32 () (_ BitVec 32))
(assert
 (let ((?x435 ((_ extract 0 0) pred_input32)))
(let ((?x670 (concat (bvnot ((_ extract 31 31) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 30 30) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 29 28) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 27 26) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 25 25) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 24 24) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 23 20) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 19 19) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 18 18) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 17 16) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 15 15) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 14 13) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 12 12) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 11 11) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 10 9) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 8 7) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 6 6) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 5 4) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 3 3) (bvadd (_ bv3002377760 32) pred_input32))) ((_ extract 2 2) (bvadd (_ bv3002377760 32) pred_input32)) (bvnot ((_ extract 1 1) (bvadd (_ bv3002377760 32) pred_input32))) ?x435)))
(let ((?x612 (bvxor pred_input32 (bvmul (_ bv18733 32) (ite (= pred_raw32 (bvadd (_ bv1958893461 32) ?x670)) (_ bv1 32) (_ bv0 32))))))
(let (($x747 (= ?x612 (_ bv39895 32))))
(let (($x1119 (= pred_input32 (_ bv1292614651 32))))
(and $x1119 $x747)))))))
(check-sat)
