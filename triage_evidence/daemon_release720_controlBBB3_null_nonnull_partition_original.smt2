; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_pointer64 () (_ BitVec 64))
(declare-fun release_control32 () (_ BitVec 32))
(assert
 (let (($x172 (= release_pointer64 (_ bv0 64))))
(let ((?x218 (ite $x172 (_ bv48094 32) (_ bv48051 32))))
(let ((?x210 (bvxor release_control32 (ite $x172 (bvsub release_control32 (_ bv47942 32)) (_ bv0 32)))))
(let (($x220 (= release_control32 (_ bv48051 32))))
(and $x220 (and (distinct ?x210 ?x218) true)))))))
(check-sat)
