; benchmark generated from python API
(set-info :status unknown)
(declare-fun main_port_status32 () (_ BitVec 32))
(assert
 (let (($x61 (= main_port_status32 (_ bv0 32))))
(let ((?x55 (ite $x61 (_ bv39579 32) (_ bv39649 32))))
(let ((?x104 (concat ((_ extract 31 16) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 15 15) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32))))) ((_ extract 14 13) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 12 11) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32))))) ((_ extract 10 10) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 9 9) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32))))) ((_ extract 8 8) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 7 7) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32))))) ((_ extract 6 5) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 4 3) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32))))) ((_ extract 2 2) (bvmul (_ bv122 32) (ite $x61 (_ bv0 32) (_ bv1 32)))) (bvnot (bvmul (_ bv2 2) (ite $x61 (_ bv0 2) (_ bv1 2)))))))
(not (= ?x104 ?x55))))))
(check-sat)
