; benchmark generated from python API
(set-info :status unknown)
(declare-fun completion_size32 () (_ BitVec 32))
(declare-fun completion_seed64 () (_ BitVec 64))
(assert
 (let ((?x1352 (bvsub completion_seed64 (_ bv32 64))))
(let (($x945 (or (and (distinct ?x1352 ?x1352) true) (and (distinct ((_ extract 7 0) ((_ extract 31 0) (_ bv1 64))) (_ bv1 8)) true) (and (distinct ((_ extract 31 0) (concat (_ bv0 32) completion_size32)) completion_size32) true) (and (distinct (_ bv4312060752 64) (_ bv4312060752 64)) true))))
(and true $x945))))
(check-sat)
