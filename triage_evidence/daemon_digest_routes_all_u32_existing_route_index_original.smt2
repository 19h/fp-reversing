; benchmark generated from python API
(set-info :status unknown)
(declare-fun routes_phase32 () (_ BitVec 32))
(assert
 (let ((?x109 ((_ extract 31 0) (concat (_ bv0 32) (bvxor routes_phase32 (bvadd (_ bv27210 32) routes_phase32))))))
(and (distinct ?x109 (bvxor (bvadd routes_phase32 (_ bv27210 32)) routes_phase32)) true)))
(check-sat)
