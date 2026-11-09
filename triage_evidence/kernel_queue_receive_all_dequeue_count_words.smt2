; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_count16 () (_ BitVec 16))
(declare-fun qr_limit16 () (_ BitVec 16))
(assert
 (let (($x652 (or (not (bvule (bvadd (_ bv65535 16) qr_count16) qr_limit16)) (= qr_limit16 (bvadd (_ bv65535 16) qr_count16)))))
(not (= $x652 (bvule qr_limit16 (bvadd (_ bv65535 16) qr_count16))))))
(check-sat)
