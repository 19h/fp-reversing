; benchmark generated from python API
(set-info :status unknown)
(declare-fun shared_core_table64 () (_ BitVec 64))
(declare-fun shared_core_tag32 () (_ BitVec 32))
(assert
 (let ((?x51 (concat (_ bv0 32) shared_core_tag32)))
(or (and (distinct ?x51 ((_ zero_extend 32) shared_core_tag32)) true) (and (distinct shared_core_table64 shared_core_table64) true))))
(check-sat)
