; benchmark generated from python API
(set-info :status unknown)
(declare-fun cursor64 () (_ BitVec 64))
(assert
 (let ((?x147 (bvadd cursor64 (_ bv64 64))))
(and (distinct ?x147 ?x147) true)))
(check-sat)
