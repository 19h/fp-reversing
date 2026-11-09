; benchmark generated from python API
(set-info :status unknown)
(declare-fun cached_RW_pointer64 () (_ BitVec 64))
(assert
 (let (($x126 (= cached_RW_pointer64 (_ bv0 64))))
(let ((?x163 (ite $x126 (_ bv1021 32) (_ bv480 32))))
(let ((?x200 (bvmul (_ bv29 5) (ite $x126 (_ bv1 5) (_ bv0 5)))))
(let ((?x188 (bvnot ((_ extract 8 5) (bvmul (_ bv541 32) (ite $x126 (_ bv1 32) (_ bv0 32)))))))
(let ((?x171 (bvmul (_ bv541 32) (ite $x126 (_ bv1 32) (_ bv0 32)))))
(let ((?x167 ((_ extract 31 9) ?x171)))
(let ((?x213 (concat ?x167 ?x188 ?x200)))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x213)) ?x163) true)))))))))
(check-sat)
