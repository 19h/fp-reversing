; benchmark generated from python API
(set-info :status unknown)
(declare-fun bool_chain_returned_raw_status32 () (_ BitVec 32))
(assert
 (let (($x207 (= bool_chain_returned_raw_status32 (_ bv2336081489 32))))
(let ((?x233 (ite $x207 (_ bv49848 32) (_ bv0 32))))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvmul (_ bv49848 32) (ite $x207 (_ bv1 32) (_ bv0 32))))) ?x233) true))))
(check-sat)
