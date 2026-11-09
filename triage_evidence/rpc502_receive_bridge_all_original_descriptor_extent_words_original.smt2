; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_descriptor_extent32 () (_ BitVec 32))
(assert
 (let ((?x25 ((_ zero_extend 32) rb_descriptor_extent32)))
(let ((?x94 (concat (_ bv0 32) rb_descriptor_extent32)))
(and (distinct ?x94 ?x25) true))))
(check-sat)
