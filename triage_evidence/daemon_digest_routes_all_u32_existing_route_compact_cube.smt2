; benchmark generated from python API
(set-info :status unknown)
(declare-fun routes_phase32 () (_ BitVec 32))
(assert
 (let (($x299 (and (= ((_ extract 1 1) routes_phase32) (_ bv0 1)) (= ((_ extract 3 3) routes_phase32) (_ bv0 1)) (= ((_ extract 7 6) routes_phase32) (_ bv1 2)) (= ((_ extract 11 9) routes_phase32) (_ bv1 3)) (= ((_ extract 14 13) routes_phase32) (_ bv0 2)))))
(let (($x468 (= (= (bvxor routes_phase32 (bvadd (_ bv27210 32) routes_phase32)) (_ bv28362 32)) $x299)))
(not $x468))))
(check-sat)
