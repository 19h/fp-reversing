; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_counter64 () (_ BitVec 64))
(assert
 (let ((?x39 (bvadd (_ bv446676941344 64) init_counter64)))
(let (($x52 (or (and (distinct ((_ extract 31 0) (_ bv18424 64)) (_ bv18424 32)) true) (and (distinct ((_ extract 31 0) (_ bv18655 64)) (_ bv18655 32)) true) (and (distinct (bvadd (_ bv640 64) init_counter64) (bvadd init_counter64 (_ bv640 64))) true) (and (distinct (bvadd (_ bv446676941296 64) init_counter64) (bvadd (_ bv446676941296 64) init_counter64)) true) (and (distinct ?x39 (bvadd (bvadd (_ bv446676941296 64) init_counter64) (_ bv48 64))) true) (and (distinct (_ bv446676619264 64) (_ bv446676619264 64)) true))))
(and true $x52))))
(check-sat)
