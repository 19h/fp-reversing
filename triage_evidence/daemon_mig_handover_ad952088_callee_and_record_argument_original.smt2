; benchmark generated from python API
(set-info :status unknown)
(declare-fun core_export_address_libSystem__os_log_type_enabled () (_ BitVec 64))
(declare-fun core_export_address_libSystem___os_log_default () (_ BitVec 64))
(declare-fun core_export_address_libSystem__mach_task_self_ () (_ BitVec 64))
(assert
 (let (($x380 (and (distinct core_export_address_libSystem__os_log_type_enabled (_ bv0 64)) true)))
(let (($x359 (and (distinct core_export_address_libSystem___os_log_default (_ bv0 64)) true)))
(let (($x360 (and (distinct core_export_address_libSystem__mach_task_self_ (_ bv0 64)) true)))
(let (($x613 (and $x360 $x359 $x380)))
(and $x613 (or (and (distinct (_ bv4300030568 64) (_ bv4300030568 64)) true) (and (distinct (_ bv48638 64) (_ bv48638 64)) true) (and (distinct (_ bv446676991720 64) (_ bv446676991720 64)) true))))))))
(check-sat)
