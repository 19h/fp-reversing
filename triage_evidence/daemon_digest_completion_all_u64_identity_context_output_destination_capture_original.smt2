; benchmark generated from python API
(set-info :status unknown)
(declare-fun completion_seed64 () (_ BitVec 64))
(assert
 (let (($x888 (and (distinct (_ bv468151631872 64) (_ bv468151631872 64)) true)))
(let (($x711 (and (distinct (bvadd (_ bv32 64) completion_seed64) (bvadd completion_seed64 (_ bv32 64))) true)))
(let ((?x232 (bvadd (_ bv468151712240 64) completion_seed64)))
(let (($x1413 (and (distinct ?x232 ?x232) true)))
(let (($x213 (and (distinct (_ bv468151500800 64) (_ bv468151500800 64)) true)))
(and true (or $x213 $x1413 $x711 $x888))))))))
(check-sat)
