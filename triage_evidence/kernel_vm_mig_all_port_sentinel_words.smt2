; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_port_object64 () (_ BitVec 64))
(assert
 (let (($x197 (and (not (= kmig_port_object64 (_ bv0 64))) (not (= kmig_port_object64 (_ bv18446744073709551615 64))))))
(let (($x222 (or (not (= ((_ extract 63 1) kmig_port_object64) (_ bv0 63))) (= ((_ extract 0 0) kmig_port_object64) (_ bv1 1)))))
(not (= (and (bvule kmig_port_object64 (_ bv18446744073709551614 64)) $x222) $x197)))))
(check-sat)
