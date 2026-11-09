; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_limit32 () (_ BitVec 32))
(declare-fun init_cursor32 () (_ BitVec 32))
(declare-fun init_phase32 () (_ BitVec 32))
(assert
 (let ((?x1999 (bvxor init_phase32 (ite (= init_cursor32 init_limit32) (_ bv14 32) (_ bv0 32)))))
(let ((?x2069 (bvmul (_ bv4294967295 32) (concat (ite (= init_cursor32 init_limit32) (_ bv1 31) (_ bv0 31)) (_ bv0 1)))))
(let ((?x2071 (bvadd (concat (ite (= init_cursor32 init_limit32) (_ bv1 28) (_ bv0 28)) (_ bv0 4)) ?x2069)))
(let ((?x2128 (bvxor init_phase32 ?x2071)))
(and true (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x2128)) ?x1999) true)))))))
(check-sat)
