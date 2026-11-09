; benchmark generated from python API
(set-info :status unknown)
(declare-fun writers_bank_input32 () (_ BitVec 32))
(assert
 (let ((?x77 ((_ extract 7 0) writers_bank_input32)))
(let ((?x84 (concat (_ bv0 56) ?x77)))
(and (distinct ?x84 ((_ zero_extend 32) (bvand writers_bank_input32 (_ bv255 32)))) true))))
(check-sat)
