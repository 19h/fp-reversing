; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_zone_metadata16 () (_ BitVec 16))
(assert
 (let (($x75 (= (bvsub ((_ extract 31 0) (concat (_ bv0 54) ((_ extract 9 0) rb_zone_metadata16))) (_ bv19 32)) (_ bv0 32))))
(and (distinct $x75 (= (bvand rb_zone_metadata16 (_ bv1023 16)) (_ bv19 16))) true)))
(check-sat)
