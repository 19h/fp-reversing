; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_hash_input_integer () Int)
(assert
 (let (($x91 (>= kmig_hash_input_integer (* (+ (div (* kmig_hash_input_integer 2132903255) 2199023255552) 1) 1031))))
(let (($x87 (> (* (div (* kmig_hash_input_integer 2132903255) 2199023255552) 1031) kmig_hash_input_integer)))
(let (($x82 (>= kmig_hash_input_integer 0)))
(and $x82 (< kmig_hash_input_integer 4294967296) (or $x87 $x91))))))
(check-sat)
