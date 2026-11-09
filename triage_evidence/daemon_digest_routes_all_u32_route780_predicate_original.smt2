; benchmark generated from python API
(set-info :status unknown)
(declare-fun routes_A64 () (_ BitVec 64))
(declare-fun routes_phase32 () (_ BitVec 32))
(assert
 (let ((?x66 (bvxor routes_phase32 (ite (= routes_A64 (_ bv0 64)) (_ bv0 32) (_ bv18 32)))))
(let ((?x133 ((_ extract 0 0) routes_phase32)))
(let ((?x131 ((_ extract 3 1) routes_phase32)))
(let ((?x149 (bvxor ?x131 (ite (= routes_A64 (_ bv0 64)) (_ bv0 3) (_ bv1 3)))))
(let ((?x132 (bvxor ((_ extract 31 4) routes_phase32) (ite (= routes_A64 (_ bv0 64)) (_ bv0 28) (_ bv1 28)))))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x132 ?x149 ?x133)) ?x66) true)))))))
(check-sat)
