; benchmark generated from python API
(set-info :status unknown)
(declare-fun matching_return_pointer64 () (_ BitVec 64))
(assert
 (let ((?x464 (bvmul (_ bv27 32) (ite (= matching_return_pointer64 (_ bv0 64)) (_ bv0 32) (_ bv1 32)))))
(let ((?x489 (concat ((_ extract 31 14) ?x464) (bvnot ((_ extract 13 13) ?x464)) ((_ extract 12 11) ?x464) (bvnot ((_ extract 10 6) ?x464)) ((_ extract 5 4) ?x464) (bvnot ((_ extract 3 1) ?x464)) (ite (= matching_return_pointer64 (_ bv0 64)) (_ bv0 1) (_ bv1 1)))))
(not (= ?x489 (ite (= matching_return_pointer64 (_ bv0 64)) (_ bv10190 32) (_ bv10197 32)))))))
(check-sat)
