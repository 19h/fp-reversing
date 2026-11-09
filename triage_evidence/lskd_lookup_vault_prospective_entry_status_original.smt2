; benchmark generated from python API
(set-info :status unknown)
(declare-fun state_lookup_key32 () (_ BitVec 32))
(declare-fun state_table_entry32 () (_ BitVec 32))
(assert
 (let ((?x129 (ite (= state_table_entry32 state_lookup_key32) (_ bv1582700617 32) (_ bv1582657948 32))))
(let ((?x142 ((_ extract 31 0) ((_ zero_extend 32) (_ bv1582657948 32)))))
(let ((?x141 ((_ extract 31 0) ((_ zero_extend 32) (_ bv1582700617 32)))))
(let (($x194 (= ((_ extract 31 0) ((_ zero_extend 32) state_table_entry32)) ((_ extract 31 0) ((_ zero_extend 32) state_lookup_key32)))))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) (ite $x194 ?x141 ?x142))) ?x129) true))))))
(check-sat)
