; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_port_type8 () (_ BitVec 8))
(assert
 (let (($x1431 (or (= ((_ extract 2 0) rd_port_type8) (_ bv0 3)) (bvule (_ bv2 2) ((_ extract 1 0) rd_port_type8)) (not (= ((_ extract 2 2) rd_port_type8) (_ bv0 1))))))
(let ((?x51 ((_ extract 2 0) rd_port_type8)))
(let (($x1399 (= ?x51 (_ bv2 3))))
(= (or (= ?x51 (_ bv1 3)) $x1399) (and $x1431 (not $x1399)))))))
(check-sat)
