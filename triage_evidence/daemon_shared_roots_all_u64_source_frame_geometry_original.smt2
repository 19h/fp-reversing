; benchmark generated from python API
(set-info :status unknown)
(declare-fun shared_core_entry_SP64 () (_ BitVec 64))
(assert
 (let ((?x148 (bvsub (bvsub (bvsub shared_core_entry_SP64 (_ bv128 64)) (_ bv65536 64)) (_ bv3408 64))))
(let (($x74 (and (distinct (bvsub (bvadd (bvsub shared_core_entry_SP64 (_ bv128 64)) (_ bv112 64)) (_ bv136 64)) (bvadd ?x148 (_ bv68920 64))) true)))
(let ((?x151 (bvsub shared_core_entry_SP64 (_ bv128 64))))
(let ((?x158 (bvadd ?x151 (_ bv112 64))))
(or (and (distinct ?x148 (bvsub shared_core_entry_SP64 (_ bv69072 64))) true) (and (distinct ?x158 (bvadd ?x148 (_ bv69056 64))) true) $x74))))))
(check-sat)
