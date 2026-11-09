; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_repeated_extent32 () (_ BitVec 32))
(declare-fun rb_descriptor_extent32 () (_ BitVec 32))
(assert
 (let (($x201 (= rb_descriptor_extent32 rb_repeated_extent32)))
(let ((?x94 (concat (_ bv0 32) rb_descriptor_extent32)))
(let ((?x248 ((_ extract 31 0) ?x94)))
(and (distinct (= (bvsub ?x248 ((_ extract 31 0) (concat (_ bv0 32) rb_repeated_extent32))) (_ bv0 32)) $x201) true)))))
(check-sat)
