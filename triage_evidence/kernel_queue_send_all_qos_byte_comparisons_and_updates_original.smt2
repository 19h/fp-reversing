; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_new_qos8 () (_ BitVec 8))
(declare-fun qs_old_qos8 () (_ BitVec 8))
(assert
 (let (($x66 (and (distinct ((_ extract 7 0) ((_ extract 31 0) ((_ zero_extend 32) ((_ zero_extend 24) qs_new_qos8)))) qs_new_qos8) true)))
(let (($x12 (bvule qs_new_qos8 qs_old_qos8)))
(let ((?x457 ((_ extract 31 0) (concat (_ bv0 56) qs_old_qos8))))
(let ((?x455 ((_ extract 31 0) ((_ zero_extend 32) ((_ zero_extend 24) qs_new_qos8)))))
(let (($x454 (and (distinct (or (not (bvuge ?x455 ?x457)) (= (bvsub ?x455 ?x457) (_ bv0 32))) $x12) true)))
(or $x454 $x66)))))))
(check-sat)
