; benchmark generated from python API
(set-info :status unknown)
(declare-fun vmclean_size64 () (_ BitVec 64))
(declare-fun vmclean_address64 () (_ BitVec 64))
(declare-fun vmclean_task_input64 () (_ BitVec 64))
(assert
 (let (($x22 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(let (($x20 (and (distinct vmclean_size64 vmclean_size64) true)))
(let (($x17 (and (distinct vmclean_address64 vmclean_address64) true)))
(let ((?x33 ((_ extract 31 0) vmclean_task_input64)))
(let ((?x35 (concat (_ bv0 32) ?x33)))
(or (and (distinct (_ bv32 64) (_ bv32 64)) true) (and (distinct ?x35 ((_ zero_extend 32) ?x33)) true) $x17 $x20 $x22 $x22)))))))
(check-sat)
