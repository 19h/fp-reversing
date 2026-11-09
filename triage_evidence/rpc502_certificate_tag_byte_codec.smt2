(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun input_byte8 () (_ BitVec 8))
(assert
 (let ((?x174 (bvadd (bvsub input_byte8 (bvand (bvshl input_byte8 (_ bv1 8)) (_ bv68 8))) (_ bv34 8))))
(and (distinct ?x174 (bvxor input_byte8 (_ bv34 8))) true)))
(check-sat)
