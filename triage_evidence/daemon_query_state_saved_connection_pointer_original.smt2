; benchmark generated from python API
(set-info :status unknown)
(declare-fun open_return_handle64 () (_ BitVec 64))
(assert
 (let (($x617 (and (distinct (_ bv4312490884 64) (_ bv4312490884 64)) true)))
(or $x617 $x617 (and (distinct ((_ zero_extend 32) (_ bv0 32)) (_ bv0 64)) true) (and (distinct open_return_handle64 open_return_handle64) true))))
(check-sat)
