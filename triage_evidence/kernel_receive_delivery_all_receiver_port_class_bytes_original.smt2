; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_port_type8 () (_ BitVec 8))
(assert
 (let (($x24 (or (= (bvand rd_port_type8 (_ bv7 8)) (_ bv1 8)) (= (bvand rd_port_type8 (_ bv7 8)) (_ bv2 8)))))
(let ((?x33 ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294967295 32) (concat (_ bv0 29) ((_ extract 2 0) rd_port_type8)))))))
(and (distinct (and (bvuge ?x33 (_ bv1 32)) (not (= (bvsub ?x33 (_ bv1 32)) (_ bv0 32)))) (not $x24)) true))))
(check-sat)
