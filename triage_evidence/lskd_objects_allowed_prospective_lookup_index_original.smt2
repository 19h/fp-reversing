; benchmark generated from python API
(set-info :status unknown)
(declare-fun state_table_pointer64 () (_ BitVec 64))
(declare-fun state_context64 () (_ BitVec 64))
(assert
 (let (($x41 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (concat (_ bv0 22) ((_ extract 9 0) state_context64)))) (bvand ((_ extract 31 0) state_context64) (_ bv1023 32))) true)))
(let ((?x175 ((_ extract 31 0) state_context64)))
(or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x175)) ?x175) true) $x41 $x41 (and (distinct state_table_pointer64 state_table_pointer64) true)))))
(check-sat)
