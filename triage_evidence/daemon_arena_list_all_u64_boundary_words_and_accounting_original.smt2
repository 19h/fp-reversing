; benchmark generated from python API
(set-info :status unknown)
(declare-fun patch_debit64 () (_ BitVec 64))
(declare-fun patch_account64 () (_ BitVec 64))
(declare-fun patch_remaining64 () (_ BitVec 64))
(assert
 (let ((?x161 (bvadd patch_account64 patch_debit64)))
(let ((?x136 (bvadd (_ bv6811567310659199978 64) (bvmul (_ bv18446744073709551615 64) patch_debit64))))
(let ((?x79 (bvadd (_ bv6811567310659199978 64) patch_remaining64)))
(let (($x58 (and (distinct ?x79 ?x79) true)))
(or $x58 $x58 (and (distinct ?x136 (bvsub (_ bv6811567310659199978 64) patch_debit64)) true) (and (distinct (_ bv6811567310659199978 64) (_ bv6811567310659199978 64)) true) (and (distinct ?x161 ?x161) true)))))))
(check-sat)
