; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_copy_pointer64 () (_ BitVec 64))
(declare-fun rb_zone_metadata_base64 () (_ BitVec 64))
(assert
 (let ((?x28 (bvadd rb_zone_metadata_base64 (bvand (bvlshr rb_copy_pointer64 (_ bv10 64)) (_ bv68719476720 64)))))
(let ((?x84 ((_ extract 45 14) rb_copy_pointer64)))
(let ((?x93 (concat (_ bv0 28) ?x84 (_ bv0 4))))
(and (distinct (bvadd rb_zone_metadata_base64 ?x93) ?x28) true)))))
(check-sat)
