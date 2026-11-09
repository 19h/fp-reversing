; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_pointer64 () (_ BitVec 64))
(declare-fun release_control32 () (_ BitVec 32))
(assert
 (let (($x172 (= release_pointer64 (_ bv0 64))))
(let ((?x218 (ite $x172 (_ bv48094 32) (_ bv48051 32))))
(let ((?x286 (bvxor release_control32 (ite $x172 (bvadd (_ bv4294919354 32) release_control32) (_ bv0 32)))))
(let (($x855 (not (= ?x286 ?x218))))
(let (($x220 (= release_control32 (_ bv48051 32))))
(and $x220 $x855)))))))
(check-sat)
