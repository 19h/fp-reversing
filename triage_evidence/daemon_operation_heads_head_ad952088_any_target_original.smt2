; benchmark generated from python API
(set-info :status unknown)
(declare-fun core_export_address_libSystem__os_log_type_enabled () (_ BitVec 64))
(declare-fun core_export_address_libSystem___os_log_default () (_ BitVec 64))
(declare-fun core_export_address_libSystem__mach_task_self_ () (_ BitVec 64))
(assert
 (let (($x627 (and (distinct core_export_address_libSystem__os_log_type_enabled (_ bv0 64)) true)))
(let (($x626 (and (distinct core_export_address_libSystem___os_log_default (_ bv0 64)) true)))
(let (($x625 (and (distinct core_export_address_libSystem__mach_task_self_ (_ bv0 64)) true)))
(let (($x682 (and $x625 $x626 $x627)))
(and $x682 (and (distinct (_ bv4299618460 64) (_ bv4299618460 64)) true)))))))
(check-sat)
