; benchmark generated from python API
(set-info :status unknown)
(declare-fun completion_size32 () (_ BitVec 32))
(assert
 (let (($x610 (and (distinct ((_ extract 31 0) (_ bv64501 64)) (_ bv64501 32)) true)))
(let (($x601 (and (distinct ((_ extract 31 0) (_ bv152 64)) (_ bv152 32)) true)))
(let ((?x1096 (concat (_ bv0 32) completion_size32)))
(let (($x292 (and (distinct (_ bv468151566336 64) (_ bv468151566336 64)) true)))
(let (($x888 (and (distinct (_ bv468151631872 64) (_ bv468151631872 64)) true)))
(let (($x309 (or $x888 $x292 (and (distinct ?x1096 ((_ zero_extend 32) completion_size32)) true) $x601 $x610 (and (distinct (_ bv4312189864 64) (_ bv4312189864 64)) true))))
(and true $x309))))))))
(check-sat)
