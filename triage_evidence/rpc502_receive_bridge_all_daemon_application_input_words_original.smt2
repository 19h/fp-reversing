; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_origin64 () (_ BitVec 64))
(declare-fun rb_subtype64 () (_ BitVec 64))
(declare-fun rb_cpu64 () (_ BitVec 64))
(declare-fun rb_descriptor_extent32 () (_ BitVec 32))
(declare-fun rb_descriptor_user_address64 () (_ BitVec 64))
(declare-fun rb_service_receive_name32 () (_ BitVec 32))
(assert
 (let ((?x94 (concat (_ bv0 32) rb_descriptor_extent32)))
(let ((?x248 ((_ extract 31 0) ?x94)))
(let (($x164 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) rb_service_receive_name32)) rb_service_receive_name32) true)))
(or $x164 (and (distinct rb_descriptor_user_address64 rb_descriptor_user_address64) true) (and (distinct ?x248 rb_descriptor_extent32) true) (and (distinct rb_cpu64 rb_cpu64) true) (and (distinct rb_subtype64 rb_subtype64) true) (and (distinct rb_origin64 rb_origin64) true))))))
(check-sat)
