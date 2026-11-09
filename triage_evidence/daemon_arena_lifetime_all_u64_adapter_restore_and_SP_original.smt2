; benchmark generated from python API
(set-info :status unknown)
(declare-fun lifetime_adapter_saved_28 () (_ BitVec 64))
(declare-fun lifetime_adapter_saved_20 () (_ BitVec 64))
(declare-fun lifetime_adapter_saved_18 () (_ BitVec 64))
(declare-fun lifetime_adapter_saved_10 () (_ BitVec 64))
(declare-fun lifetime_adapter_saved_8 () (_ BitVec 64))
(declare-fun lifetime_adapter_saved_0 () (_ BitVec 64))
(declare-fun lifetime_X0_at_epilogue64 () (_ BitVec 64))
(assert
 (let (($x20 (and (distinct lifetime_X0_at_epilogue64 lifetime_X0_at_epilogue64) true)))
(or (and (distinct (_ bv446676729856 64) (_ bv446676729856 64)) true) $x20 (and (distinct lifetime_adapter_saved_0 lifetime_adapter_saved_0) true) (and (distinct lifetime_adapter_saved_8 lifetime_adapter_saved_8) true) (and (distinct lifetime_adapter_saved_10 lifetime_adapter_saved_10) true) (and (distinct lifetime_adapter_saved_18 lifetime_adapter_saved_18) true) (and (distinct lifetime_adapter_saved_20 lifetime_adapter_saved_20) true) (and (distinct lifetime_adapter_saved_28 lifetime_adapter_saved_28) true))))
(check-sat)
