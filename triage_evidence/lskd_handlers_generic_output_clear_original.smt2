; benchmark generated from python API
(set-info :status unknown)
(declare-fun request64 () (_ BitVec 64))
(assert
 (let (($x325 (and (distinct request64 request64) true)))
(let (($x864 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(let (($x865 (and (distinct ((_ extract 15 0) (_ bv0 32)) (_ bv0 16)) true)))
(or $x865 $x864 $x325)))))
(check-sat)
