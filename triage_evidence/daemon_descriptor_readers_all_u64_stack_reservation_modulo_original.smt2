; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_SP64 () (_ BitVec 64))
(assert
 (and true (and (distinct (bvadd (_ bv18446744073709494544 64) reader_SP64) (bvsub reader_SP64 (_ bv57072 64))) true)))
(check-sat)
