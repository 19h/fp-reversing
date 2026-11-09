; benchmark generated from python API
(set-info :status unknown)
(declare-fun completion_C64 () (_ BitVec 64))
(declare-fun completion_B64 () (_ BitVec 64))
(declare-fun completion_A64 () (_ BitVec 64))
(declare-fun completion_R64 () (_ BitVec 64))
(declare-fun completion_seed64 () (_ BitVec 64))
(assert
 (let ((?x1352 (bvsub completion_seed64 (_ bv32 64))))
(let ((?x1482 (bvadd (_ bv18446744073709551584 64) completion_seed64)))
(let (($x966 (or (and (distinct ?x1482 ?x1352) true) (and (distinct completion_R64 completion_R64) true) (and (distinct completion_A64 completion_A64) true) (and (distinct completion_B64 completion_B64) true) (and (distinct completion_C64 completion_C64) true) (and (distinct (_ bv4312230600 64) (_ bv4312230600 64)) true))))
(and true $x966)))))
(check-sat)
