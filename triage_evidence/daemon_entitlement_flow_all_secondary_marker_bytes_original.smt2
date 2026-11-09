; benchmark generated from python API
(set-info :status unknown)
(declare-fun ent_flow_secondary_marker8 () (_ BitVec 8))
(assert
 (let (($x872 (= ent_flow_secondary_marker8 (_ bv49 8))))
(let ((?x793 (ite $x872 (_ bv16491 32) (_ bv16481 32))))
(and (distinct ((_ extract 31 0) (concat (_ bv515 59) (ite $x872 (_ bv5 4) (_ bv0 4)) (_ bv1 1))) ?x793) true))))
(check-sat)
