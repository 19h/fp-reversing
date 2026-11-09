; benchmark generated from python API
(set-info :status unknown)
(declare-fun vmclean_size64 () (_ BitVec 64))
(declare-fun vmclean_address64 () (_ BitVec 64))
(declare-fun vmclean_kernel_task_name32 () (_ BitVec 32))
(assert
 (let (($x20 (and (distinct vmclean_size64 vmclean_size64) true)))
(let (($x17 (and (distinct vmclean_address64 vmclean_address64) true)))
(let (($x22 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(let ((?x468 (concat (_ bv0 32) vmclean_kernel_task_name32)))
(or (and (distinct ?x468 ((_ zero_extend 32) vmclean_kernel_task_name32)) true) $x22 $x17 $x20 (and (distinct ((_ extract 31 0) (_ bv268435459 64)) (_ bv268435459 32)) true)))))))
(check-sat)
