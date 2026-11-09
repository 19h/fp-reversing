	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_selected_result                ; -- Begin function selected_result
	.p2align	2
_selected_result:                       ; @selected_result
	.cfi_startproc
; %bb.0:
	ldr	w0, [x0, #16]
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
