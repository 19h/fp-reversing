; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_M64 () (_ BitVec 64))
(declare-fun registry_j64 () (_ BitVec 64))
(assert
 (let (($x1163 (bvule (bvadd (_ bv32 64) (concat ((_ extract 58 0) registry_j64) (_ bv0 5))) (concat ((_ extract 58 0) registry_M64) (_ bv0 5)))))
(let (($x1017 (not $x1163)))
(let (($x555 (= ((_ extract 63 32) registry_M64) (_ bv0 32))))
(let (($x137 (not (bvule registry_M64 registry_j64))))
(and $x137 $x555 $x1017))))))
(check-sat)
