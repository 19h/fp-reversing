; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_phase32 () (_ BitVec 32))
(assert
 (let (($x162 (= reader_phase32 (_ bv17353 32))))
(and $x162 (and (distinct (bvadd reader_phase32 (_ bv5492 32)) (_ bv22845 32)) true))))
(check-sat)
