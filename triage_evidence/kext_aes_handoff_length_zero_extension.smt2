; benchmark generated from python API
(set-info :status unknown)
(declare-fun input64 () (_ BitVec 64))
(assert
 (let ((?x16 (bvand input64 (_ bv4294967295 64))))
(and (distinct ((_ zero_extend 32) ((_ extract 31 0) input64)) ?x16) true)))
(check-sat)
