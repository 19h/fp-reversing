; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_link64 () (_ BitVec 64))
(assert
 (let (($x71 (and (distinct destruct_link64 destruct_link64) true)))
(let (($x65 (and (distinct (_ bv446676729856 64) (_ bv446676729856 64)) true)))
(let (($x98 (or $x65 $x71 (and (distinct (= (_ bv0 64) destruct_link64) (= destruct_link64 (_ bv0 64))) true))))
(and true $x98)))))
(check-sat)
