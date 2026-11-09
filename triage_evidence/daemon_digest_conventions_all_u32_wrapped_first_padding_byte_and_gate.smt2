; benchmark generated from python API
(set-info :status unknown)
(declare-fun conventions_counter32 () (_ BitVec 32))
(assert
 (let (($x203 (and (bvule (_ bv55 6) ((_ extract 5 0) conventions_counter32)) (not (= ((_ extract 5 0) conventions_counter32) (_ bv55 6))))))
(let ((?x216 (ite $x203 (_ bv2 2) (_ bv3 2))))
(let ((?x204 (ite $x203 (_ bv1 32) (_ bv0 32))))
(let ((?x192 (bvmul (_ bv49145 32) ?x204)))
(let ((?x193 ((_ extract 2 2) ?x192)))
(let ((?x198 (bvnot ((_ extract 5 3) ?x192))))
(let ((?x191 ((_ extract 31 6) ?x192)))
(let (($x236 (= (concat ?x191 ?x198 ?x193 ?x216) (ite (bvule ((_ extract 5 0) conventions_counter32) (_ bv55 6)) (_ bv59 32) (_ bv49090 32)))))
(not $x236))))))))))
(check-sat)
