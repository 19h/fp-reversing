; benchmark generated from python API
(set-info :status unknown)
(declare-fun error_status32 () (_ BitVec 32))
(assert
 (let ((?x2182 (bvsub (_ bv4294924696 32) error_status32)))
(let ((?x2191 (bvxor ?x2182 (_ bv2336081489 32))))
(let (($x1049 (bvsle error_status32 (_ bv99 32))))
(let (($x959 (bvsge error_status32 (_ bv1 32))))
(and $x959 $x1049 (and (distinct ?x2191 (bvxor (bvadd error_status32 (_ bv103 32)) (_ bv1958911918 32))) true)))))))
(check-sat)
