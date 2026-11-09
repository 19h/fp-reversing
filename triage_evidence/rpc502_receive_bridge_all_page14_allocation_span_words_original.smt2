; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_copy_offset64 () (_ BitVec 64))
(declare-fun rb_copy_extent64 () (_ BitVec 64))
(assert
 (let ((?x141 (bvsub (bvand (bvadd (bvadd rb_copy_offset64 rb_copy_extent64) (_ bv16383 64)) (_ bv18446744073709535232 64)) (bvand rb_copy_offset64 (_ bv18446744073709535232 64)))))
(let ((?x120 (bvadd (_ bv16383 64) rb_copy_extent64 rb_copy_offset64)))
(let ((?x134 ((_ extract 63 14) ?x120)))
(let ((?x140 (concat ?x134 (_ bv0 14))))
(let ((?x138 ((_ extract 63 14) rb_copy_offset64)))
(let ((?x143 (concat ?x138 (_ bv0 14))))
(let ((?x132 (bvmul (_ bv18446744073709551615 64) ?x143)))
(and (distinct (bvadd ?x132 ?x140) ?x141) true)))))))))
(check-sat)
