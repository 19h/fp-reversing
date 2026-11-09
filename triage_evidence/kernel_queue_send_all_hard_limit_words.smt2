; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_count16 () (_ BitVec 16))
(assert
 (let (($x75 (bvule qs_count16 (_ bv65533 16))))
(not (= (or (not (bvule (_ bv65533 16) qs_count16)) (= qs_count16 (_ bv65533 16))) $x75))))
(check-sat)
