	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_key_contract                   ; -- Begin function key_contract
	.p2align	2
_key_contract:                          ; @key_contract
	.cfi_startproc
; %bb.0:
                                        ; kill: def $w0 killed $w0 def $x0
	mov	w8, w1
	orr	x0, x8, x0, lsl #32
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
