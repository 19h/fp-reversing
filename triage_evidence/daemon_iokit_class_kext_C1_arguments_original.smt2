; benchmark generated from python API
(set-info :status unknown)
(declare-fun metaclass_receiver64 () (_ BitVec 64))
(assert
 (or (and (distinct metaclass_receiver64 metaclass_receiver64) true) (and (distinct (_ bv18446741874813225984 64) (_ bv18446741874813225984 64)) true) (and (distinct (_ bv18446741874899533920 64) (_ bv18446741874899533920 64)) true) (and (distinct ((_ zero_extend 32) (_ bv136 32)) (_ bv136 64)) true)))
(check-sat)
