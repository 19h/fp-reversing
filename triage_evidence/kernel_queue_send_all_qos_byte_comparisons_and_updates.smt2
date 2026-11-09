; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_old_qos8 () (_ BitVec 8))
(declare-fun qs_new_qos8 () (_ BitVec 8))
(assert
 (let (($x12 (bvule qs_new_qos8 qs_old_qos8)))
(let (($x606 (or (not (bvule qs_old_qos8 qs_new_qos8)) (= qs_new_qos8 qs_old_qos8))))
(not (= $x606 $x12)))))
(check-sat)
