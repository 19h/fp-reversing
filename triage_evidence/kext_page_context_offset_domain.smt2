(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun page_offset64 () (_ BitVec 64))
(assert
 (let (($x249 (and (= (bvand page_offset64 (_ bv4095 64)) (_ bv0 64)) (bvult page_offset64 (_ bv17592186044416 64)))))
(and (distinct (= (bvand page_offset64 (_ bv18446726481523511295 64)) (_ bv0 64)) $x249) true)))
(check-sat)
