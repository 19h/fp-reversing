; benchmark generated from python API
(set-info :status unknown)
(declare-fun adapter_record_low32 () (_ BitVec 32))
(assert
 (let ((?x22 (bvadd (bvsub (bvor adapter_record_low32 (_ bv2117121072 32)) adapter_record_low32) (bvand adapter_record_low32 (_ bv2177846223 32)))))
(let ((?x24 (bvxor ?x22 (_ bv76238261 32))))
(and (distinct ?x24 (bvxor adapter_record_low32 (_ bv2059139461 32))) true))))
(check-sat)
