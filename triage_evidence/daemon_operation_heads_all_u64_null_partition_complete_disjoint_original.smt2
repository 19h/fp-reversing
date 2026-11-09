; benchmark generated from python API
(set-info :status unknown)
(declare-fun head_null_partition_pointer64 () (_ BitVec 64))
(assert
 (let (($x1067 (and (distinct head_null_partition_pointer64 (_ bv0 64)) true)))
(let (($x816 (= head_null_partition_pointer64 (_ bv0 64))))
(or (not (or $x816 $x1067)) (and $x816 $x1067)))))
(check-sat)
