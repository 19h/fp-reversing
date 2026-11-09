; benchmark generated from python API
(set-info :status unknown)
(declare-fun creation_return64 () (_ BitVec 64))
(declare-fun creation_phase32 () (_ BitVec 32))
(assert
 (let ((?x263 (bvxor (bvadd (_ bv1 1) ((_ extract 0 0) creation_phase32)) (ite (= creation_return64 (_ bv0 64)) (_ bv1 1) (_ bv0 1)))))
(let ((?x208 (bvadd (_ bv14644 32) creation_phase32)))
(let ((?x465 (bvxor ?x208 (bvmul (_ bv56 32) (concat (_ bv0 31) ?x263)))))
(let ((?x246 (bvxor ?x208 (bvadd (bvmul (_ bv4294967295 32) (concat (_ bv0 28) ?x263 (_ bv0 3))) (concat (_ bv0 25) ?x263 (_ bv0 6))))))
(not (= ?x246 ?x465)))))))
(check-sat)
