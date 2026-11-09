; benchmark generated from python API
(set-info :status unknown)
(declare-fun response_reference64 () (_ BitVec 64))
(assert
 (let (($x129 (and (distinct response_reference64 response_reference64) true)))
(let (($x221 (= response_reference64 (_ bv0 64))))
(let ((?x186 (ite $x221 (_ bv1379 32) (_ bv1407 32))))
(let ((?x249 (ite $x221 (_ bv0 1) (_ bv1 1))))
(let ((?x209 (concat (_ bv0 26) ?x249 (_ bv0 5))))
(let ((?x236 (bvmul (_ bv4294967295 32) (concat (_ bv0 29) ?x249 (_ bv0 2)))))
(let ((?x256 (bvadd ?x236 ?x209)))
(let ((?x239 (concat ((_ extract 31 11) ?x256) (_ bv1 1) ((_ extract 9 9) ?x256) (_ bv1 1) ((_ extract 7 7) ?x256) (_ bv3 2) ((_ extract 4 2) ?x256) (_ bv3 2))))
(or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x239)) ?x186) true) $x129))))))))))
(check-sat)
