; benchmark generated from python API
(set-info :status unknown)
(declare-fun lifetime_debit64 () (_ BitVec 64))
(declare-fun lifetime_account64 () (_ BitVec 64))
(assert
 (let ((?x90 (bvadd lifetime_account64 (bvmul (_ bv18446744073709551615 64) lifetime_debit64))))
(and (distinct ?x90 (bvsub lifetime_account64 lifetime_debit64)) true)))
(check-sat)
