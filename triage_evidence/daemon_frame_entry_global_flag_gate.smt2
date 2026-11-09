; benchmark generated from python API
(set-info :status unknown)
(declare-fun gate_state32 () (_ BitVec 32))
(assert
 (let (($x154 (= gate_state32 (_ bv0 32))))
(let ((?x171 (ite $x154 (_ bv18938 32) (_ bv18941 32))))
(let ((?x248 (ite $x154 (_ bv0 1) (_ bv1 1))))
(let ((?x175 (bvadd (bvmul (_ bv4294967295 32) (concat (_ bv0 31) ?x248)) (concat (_ bv0 28) ?x248 (_ bv0 3)))))
(let ((?x174 (concat ((_ extract 31 15) ?x175) (bvnot ((_ extract 14 14) ?x175)) ((_ extract 13 12) ?x175) (bvnot ((_ extract 11 11) ?x175)) ((_ extract 10 9) ?x175) (bvnot ((_ extract 8 3) ?x175)) ((_ extract 2 2) ?x175) (bvnot ((_ extract 1 1) ?x175)) ?x248)))
(not (= ?x174 ?x171))))))))
(check-sat)
