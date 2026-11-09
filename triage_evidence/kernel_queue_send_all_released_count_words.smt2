; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_count16 () (_ BitVec 16))
(declare-fun qs_limit16 () (_ BitVec 16))
(assert
 (let (($x755 (or (not (bvule (bvadd (_ bv65535 16) qs_count16) qs_limit16)) (= qs_limit16 (bvadd (_ bv65535 16) qs_count16)))))
(not (= $x755 (bvule qs_limit16 (bvadd (_ bv65535 16) qs_count16))))))
(check-sat)
