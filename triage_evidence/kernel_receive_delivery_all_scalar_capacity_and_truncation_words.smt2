; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_capacity32 () (_ BitVec 32))
(declare-fun rd_user_inline32 () (_ BitVec 32))
(declare-fun rd_requested_trailer32 () (_ BitVec 32))
(assert
 (let ((?x878 (bvmul (_ bv4294967295 32) rd_user_inline32)))
(let ((?x879 (bvadd rd_capacity32 ?x878)))
(let (($x1613 (not (bvule rd_capacity32 (bvadd rd_requested_trailer32 rd_user_inline32)))))
(let (($x1525 (= (or $x1613 (= rd_requested_trailer32 ?x879)) (bvule (bvadd rd_requested_trailer32 rd_user_inline32) rd_capacity32))))
(not $x1525))))))
(check-sat)
