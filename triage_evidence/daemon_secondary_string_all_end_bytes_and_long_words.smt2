; benchmark generated from python API
(set-info :status unknown)
(declare-fun string_end_byte8 () (_ BitVec 8))
(assert
 (let ((?x64 (ite (= string_end_byte8 (_ bv0 8)) (_ bv7966 32) (_ bv7953 32))))
(let ((?x134 (bvor ((_ extract 7 7) string_end_byte8) ((_ extract 7 7) (bvmul (_ bv4294967295 32) (concat (_ bv0 24) string_end_byte8))))))
(let ((?x85 (bvmul (_ bv15 32) (concat (_ bv0 31) (bvnot ?x134)))))
(let ((?x107 ((_ extract 3 1) ?x85)))
(let ((?x138 (bvnot ((_ extract 4 4) ?x85))))
(let ((?x123 ((_ extract 7 5) ?x85)))
(let ((?x122 (bvnot ((_ extract 12 8) ?x85))))
(let ((?x135 ((_ extract 31 13) ?x85)))
(not (= (concat ?x135 ?x122 ?x123 ?x138 ?x107 ?x134) ?x64)))))))))))
(check-sat)
