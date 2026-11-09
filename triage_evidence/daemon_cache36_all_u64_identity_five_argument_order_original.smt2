; benchmark generated from python API
(set-info :status unknown)
(declare-fun cache36_E64 () (_ BitVec 64))
(declare-fun cache36_D64 () (_ BitVec 64))
(declare-fun cache36_C64 () (_ BitVec 64))
(declare-fun cache36_B64 () (_ BitVec 64))
(declare-fun cache36_A64 () (_ BitVec 64))
(assert
 (let (($x52 (and (distinct (_ bv65182 64) (_ bv65182 64)) true)))
(let (($x15 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(or (and (distinct cache36_A64 cache36_A64) true) (and (distinct cache36_B64 cache36_B64) true) (and (distinct cache36_C64 cache36_C64) true) (and (distinct cache36_D64 cache36_D64) true) (and (distinct cache36_E64 cache36_E64) true) $x15 $x15 (and (distinct (_ bv4312472216 64) (_ bv4312472216 64)) true) $x52))))
(check-sat)
