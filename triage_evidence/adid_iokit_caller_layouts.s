	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_analyst_method100              ; -- Begin function analyst_method100
	.p2align	2
_analyst_method100:                     ; @analyst_method100
	.cfi_startproc
; %bb.0:
	mov	x5, x3
	mov	x3, x2
	mov	x2, x1
	mov	w1, #100                        ; =0x64
	mov	x4, x2
	b	_IOConnectCallStructMethod
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
