; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_total_copy32 () (_ BitVec 32))
(declare-fun rd_user_address64 () (_ BitVec 64))
(declare-fun rd_kernel_source64 () (_ BitVec 64))
(assert
 (let (($x872 (and (distinct rd_user_address64 rd_user_address64) true)))
(let (($x871 (and (distinct rd_kernel_source64 rd_kernel_source64) true)))
(or $x871 $x872 (and (distinct (concat (_ bv0 32) rd_total_copy32) ((_ zero_extend 32) rd_total_copy32)) true)))))
(check-sat)
