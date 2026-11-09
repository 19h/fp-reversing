; benchmark generated from python API
(set-info :status unknown)
(declare-fun fields_expected8 () (_ BitVec 8))
(declare-fun fields_byte8 () (_ BitVec 8))
(assert
 (let ((?x327 (concat (_ bv0 32) (ite (= (bvxor fields_byte8 fields_expected8) (_ bv17 8)) (_ bv0 32) (_ bv1 32)))))
(and (distinct ((_ extract 31 0) ?x327) (ite (= fields_byte8 (bvxor fields_expected8 (_ bv17 8))) (_ bv0 32) (_ bv1 32))) true)))
(check-sat)
