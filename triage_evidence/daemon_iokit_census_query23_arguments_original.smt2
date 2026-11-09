; benchmark generated from python API
(set-info :status unknown)
(declare-fun connection32 () (_ BitVec 32))
(assert
 (let (($x40 (and (distinct (_ bv31340 64) (_ bv31340 64)) true)))
(let (($x39 (and (distinct (_ bv1358954608 64) (_ bv1358954608 64)) true)))
(let (($x37 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(let ((?x27 ((_ zero_extend 32) connection32)))
(let (($x31 (and (distinct ?x27 ?x27) true)))
(or $x31 (and (distinct ((_ zero_extend 32) (_ bv23 32)) (_ bv23 64)) true) $x37 $x37 (and (distinct (_ bv1358954604 64) (_ bv1358954604 64)) true) $x39 $x40)))))))
(check-sat)
