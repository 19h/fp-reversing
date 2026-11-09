; benchmark generated from python API
(set-info :status unknown)
(declare-fun workspace_base64 () (_ BitVec 64))
(declare-fun operation32 () (_ BitVec 32))
(assert
 (let (($x584 (and (distinct (bvadd (_ bv32 64) workspace_base64) (bvadd workspace_base64 (_ bv32 64))) true)))
(let (($x579 (and (distinct (bvadd (_ bv4 64) workspace_base64) (bvadd workspace_base64 (_ bv4 64))) true)))
(let ((?x6 ((_ zero_extend 32) operation32)))
(let ((?x11 ((_ extract 31 0) ?x6)))
(let (($x13 (and (distinct ?x11 operation32) true)))
(or $x13 (and (distinct (_ bv18446741874859498796 64) (_ bv18446741874859498796 64)) true) $x579 $x584 (and (distinct workspace_base64 workspace_base64) true))))))))
(check-sat)
