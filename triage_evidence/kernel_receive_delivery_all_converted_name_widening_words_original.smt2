; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_user_local_name32 () (_ BitVec 32))
(declare-fun rd_user_remote_name32 () (_ BitVec 32))
(assert
 (let (($x131 (= rd_user_local_name32 (_ bv4294967295 32))))
(let (($x75 (and (distinct (ite $x131 (_ bv18446744073709551615 64) (concat (_ bv0 32) rd_user_local_name32)) (ite $x131 (_ bv18446744073709551615 64) ((_ zero_extend 32) rd_user_local_name32))) true)))
(let (($x121 (= rd_user_remote_name32 (_ bv4294967295 32))))
(let (($x78 (and (distinct (ite $x121 (_ bv18446744073709551615 64) (concat (_ bv0 32) rd_user_remote_name32)) (ite $x121 (_ bv18446744073709551615 64) ((_ zero_extend 32) rd_user_remote_name32))) true)))
(or $x78 $x75))))))
(check-sat)
