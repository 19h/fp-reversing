; benchmark generated from python API
(set-info :status unknown)
(declare-fun ent_flow_old_flags32 () (_ BitVec 32))
(assert
 (let (($x808 (= ent_flow_old_flags32 (_ bv0 32))))
(let ((?x772 (ite $x808 (_ bv20527 32) (_ bv20522 32))))
(and (distinct ((_ extract 31 0) (concat (_ bv2565 61) (ite $x808 (_ bv1 1) (_ bv0 1)) (_ bv1 1) (ite $x808 (_ bv1 1) (_ bv0 1)))) ?x772) true))))
(check-sat)
