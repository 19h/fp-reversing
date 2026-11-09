; benchmark generated from python API
(set-info :status unknown)
(declare-fun secondary_old_flags32 () (_ BitVec 32))
(assert
 (let ((?x131 ((_ extract 2 0) secondary_old_flags32)))
(let ((?x76 ((_ extract 31 4) secondary_old_flags32)))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x76 (_ bv1 1) ?x131)) (bvor secondary_old_flags32 (_ bv8 32))) true))))
(check-sat)
