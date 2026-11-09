; benchmark generated from python API
(set-info :status unknown)
(declare-fun shared_core_operation32 () (_ BitVec 32))
(assert
 (and (and (distinct (ite (bvsgt (_ bv2912231560 32) shared_core_operation32) (_ bv32932 32) (_ bv32865 32)) (_ bv32865 32)) true) (and (distinct (ite (bvsgt (_ bv2912231560 32) shared_core_operation32) (_ bv32932 32) (_ bv32865 32)) (_ bv32932 32)) true)))
(check-sat)
