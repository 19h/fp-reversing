(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun wire_word32 () (_ BitVec 32))
(assert
 (let ((?x232 (bvand wire_word32 (_ bv255 32))))
(let ((?x246 (bvadd (bvsub ?x232 (bvand (bvshl ?x232 (_ bv1 32)) (_ bv210 32))) (_ bv1640225897 32))))
(let ((?x230 (bvand wire_word32 (_ bv4294967040 32))))
(let ((?x240 (bvxor (bvadd (bvsub ?x230 (bvand (bvshl ?x230 (_ bv1 32)) (_ bv698937856 32))) (_ bv2496952796 32)) (_ bv4091015548 32))))
(let ((?x254 (bvxor (bvxor (bvand ?x240 (bvxor ?x246 (_ bv2654741398 32))) (bvand ?x246 (_ bv18271 32))) (_ bv3963488952 32))))
(and (distinct ?x254 (bvxor wire_word32 (_ bv2336081489 32))) true)))))))
(check-sat)
