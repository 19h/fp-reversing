; benchmark generated from python API
(set-info :status unknown)
(declare-fun record64 () (_ BitVec 64))
(assert
 (let ((?x210 (bvxor record64 (_ bv1112190068825103296 64))))
(let ((?x178 (bvxor (bvadd (bvsub (bvor record64 (_ bv12278428409108164642 64)) (bvor record64 (_ bv6168315664601386973 64))) (_ bv6168315664601386973 64)) (_ bv11892589809723337698 64))))
(and (distinct ?x178 ?x210) true))))
(check-sat)
