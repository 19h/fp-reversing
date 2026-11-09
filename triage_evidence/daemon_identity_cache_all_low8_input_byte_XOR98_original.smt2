; benchmark generated from python API
(set-info :status unknown)
(declare-fun identity_return64 () (_ BitVec 64))
(assert
 (let ((?x173 ((_ extract 4 3) identity_return64)))
(let ((?x184 (concat (_ bv0 26) ?x173 (_ bv0 4))))
(let ((?x186 (bvmul (_ bv4294967295 32) ?x184)))
(let ((?x71 ((_ extract 31 0) identity_return64)))
(let ((?x117 (bvadd (_ bv4294967192 32) ?x71 ?x186)))
(and (distinct ((_ extract 7 0) (concat (_ bv0 32) ?x117)) (bvxor ((_ extract 7 0) identity_return64) (_ bv152 8))) true)))))))
(check-sat)
