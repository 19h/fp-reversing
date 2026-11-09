; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_active32 () (_ BitVec 32))
(declare-fun destruct_index32 () (_ BitVec 32))
(assert
 (let (($x487 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294967295 32) destruct_active32))) (bvsub destruct_active32 (_ bv1 32))) true)))
(let (($x306 (and (distinct ((_ extract 31 0) (_ bv2336081489 64)) (_ bv2336081489 32)) true)))
(and (bvult destruct_index32 (_ bv3 32)) (or (and (distinct (_ bv16409013220067847612 64) (_ bv16409013220067847612 64)) true) $x306 $x306 $x487)))))
(check-sat)
