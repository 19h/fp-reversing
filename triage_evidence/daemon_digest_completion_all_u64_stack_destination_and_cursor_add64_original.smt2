; benchmark generated from python API
(set-info :status unknown)
(declare-fun completion_seed64 () (_ BitVec 64))
(assert
 (let (($x613 (and (distinct (bvadd (_ bv64 64) completion_seed64) (bvadd completion_seed64 (_ bv64 64))) true)))
(let ((?x232 (bvadd (_ bv468151712240 64) completion_seed64)))
(let (($x1413 (and (distinct ?x232 ?x232) true)))
(and true (or $x1413 $x613))))))
(check-sat)
