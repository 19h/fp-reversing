; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_N32 () (_ BitVec 32))
(declare-fun registry_i32 () (_ BitVec 32))
(assert
 (let (($x140 (bvule (bvadd (_ bv16 36) (concat registry_i32 (_ bv0 4))) (concat registry_N32 (_ bv0 4)))))
(let (($x469 (and (= ((_ extract 63 36) (bvadd (_ bv16 64) (concat (_ bv0 28) registry_i32 (_ bv0 4)))) (_ bv0 28)) $x140)))
(let (($x495 (not $x469)))
(let (($x137 (not (bvule registry_N32 registry_i32))))
(and $x137 $x495))))))
(check-sat)
