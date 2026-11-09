; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_phase32 () (_ BitVec 32))
(assert
 (let ((?x205 ((_ extract 9 0) reader_phase32)))
(let ((?x208 (bvadd (_ bv249 10) ?x205)))
(let ((?x198 (bvadd (_ bv4294950137 32) reader_phase32)))
(let ((?x201 ((_ extract 14 11) ?x198)))
(let ((?x202 ((_ extract 31 16) ?x198)))
(let (($x206 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x202 (_ bv1 1) ?x201 (_ bv1 1) ?x208)) (bvor (bvsub reader_phase32 (_ bv17159 32)) (_ bv33792 32))) true)))
(and true $x206))))))))
(check-sat)
