; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_control32 () (_ BitVec 32))
(declare-fun release_pointer64 () (_ BitVec 64))
(assert
 (let ((?x210 (bvxor release_control32 (ite (= release_pointer64 (_ bv0 64)) (bvsub release_control32 (_ bv47942 32)) (_ bv0 32)))))
(let (($x172 (= release_pointer64 (_ bv0 64))))
(let ((?x181 (ite $x172 (_ bv1 32) (_ bv0 32))))
(let ((?x198 (bvadd (_ bv4294919354 32) release_control32)))
(let (($x214 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvxor release_control32 (bvmul ?x198 ?x181)))) ?x210) true)))
(and true $x214)))))))
(check-sat)
