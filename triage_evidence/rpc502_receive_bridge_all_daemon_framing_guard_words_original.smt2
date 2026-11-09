; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_user_descriptor_type8 () (_ BitVec 8))
(declare-fun rb_user_size32 () (_ BitVec 32))
(declare-fun rb_user_descriptor_count32 () (_ BitVec 32))
(declare-fun rb_user_bits32 () (_ BitVec 32))
(assert
 (let (($x340 (= rb_user_descriptor_type8 (_ bv1 8))))
(let (($x346 (= rb_user_size32 (_ bv80 32))))
(let (($x338 (= rb_user_descriptor_count32 (_ bv1 32))))
(let (($x306 (= (bvsub ((_ extract 31 0) (concat (_ bv0 32) rb_user_descriptor_count32)) (_ bv1 32)) (_ bv0 32))))
(let (($x341 (and (and (distinct (bvand ((_ extract 31 0) (concat (_ bv0 32) rb_user_bits32)) (_ bv2147483648 32)) (_ bv0 32)) true) $x306 (= (bvsub ((_ extract 31 0) (concat (_ bv0 32) rb_user_size32)) (_ bv80 32)) (_ bv0 32)) (= (bvsub ((_ extract 31 0) (concat (_ bv0 56) rb_user_descriptor_type8)) (_ bv1 32)) (_ bv0 32)))))
(and (distinct $x341 (and (and (distinct (bvand rb_user_bits32 (_ bv2147483648 32)) (_ bv0 32)) true) $x338 $x346 $x340)) true)))))))
(check-sat)
