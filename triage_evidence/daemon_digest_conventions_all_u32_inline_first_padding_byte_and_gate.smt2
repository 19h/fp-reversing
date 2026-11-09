; benchmark generated from python API
(set-info :status unknown)
(declare-fun conventions_counter32 () (_ BitVec 32))
(assert
 (let (($x203 (and (bvule (_ bv55 6) ((_ extract 5 0) conventions_counter32)) (not (= ((_ extract 5 0) conventions_counter32) (_ bv55 6))))))
(let ((?x229 (bvmul (_ bv7 3) (ite $x203 (_ bv1 3) (_ bv0 3)))))
(let ((?x194 (bvnot ((_ extract 4 3) (bvmul (_ bv48687 32) (ite $x203 (_ bv1 32) (_ bv0 32)))))))
(let ((?x204 (ite $x203 (_ bv1 32) (_ bv0 32))))
(let ((?x211 (bvmul (_ bv48687 32) ?x204)))
(let ((?x221 ((_ extract 31 5) ?x211)))
(let (($x285 (= (concat ?x221 ?x194 ?x229) (ite (bvule ((_ extract 5 0) conventions_counter32) (_ bv55 6)) (_ bv24 32) (_ bv48695 32)))))
(not $x285)))))))))
(check-sat)
