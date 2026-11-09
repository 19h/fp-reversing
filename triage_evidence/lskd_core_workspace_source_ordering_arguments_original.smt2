; benchmark generated from python API
(set-info :status unknown)
(declare-fun core_auxiliary64 () (_ BitVec 64))
(declare-fun core_workspace64 () (_ BitVec 64))
(assert
 (let (($x561 (and (distinct (bvadd (_ bv4096 64) core_auxiliary64) (bvadd core_auxiliary64 (_ bv4096 64))) true)))
(let (($x559 (and (distinct (bvadd (_ bv1024 64) core_auxiliary64) (bvadd core_auxiliary64 (_ bv1024 64))) true)))
(let (($x557 (and (distinct (bvadd (_ bv16384 64) core_workspace64) (bvadd core_workspace64 (_ bv16384 64))) true)))
(let (($x553 (and (distinct (bvadd (_ bv3328 64) core_workspace64) (bvadd core_workspace64 (_ bv3328 64))) true)))
(or $x553 $x557 $x559 $x561))))))
(check-sat)
