; benchmark generated from python API
(set-info :status unknown)
(declare-fun head_8f7506ee_pointer8 () (_ BitVec 64))
(declare-fun core_export_address_libSystem__os_log_type_enabled () (_ BitVec 64))
(declare-fun core_export_address_libSystem___os_log_default () (_ BitVec 64))
(declare-fun core_export_address_libSystem__mach_task_self_ () (_ BitVec 64))
(assert
 (let (($x957 (= head_8f7506ee_pointer8 (_ bv0 64))))
(let (($x627 (and (distinct core_export_address_libSystem__os_log_type_enabled (_ bv0 64)) true)))
(let (($x626 (and (distinct core_export_address_libSystem___os_log_default (_ bv0 64)) true)))
(let (($x625 (and (distinct core_export_address_libSystem__mach_task_self_ (_ bv0 64)) true)))
(let (($x703 (and $x625 $x626 $x627 $x957)))
(and $x703 (and (distinct (_ bv4300377560 64) (_ bv4300377560 64)) true))))))))
(check-sat)
