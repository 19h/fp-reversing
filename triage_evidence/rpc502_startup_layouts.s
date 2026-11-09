	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_callback_type                  ; -- Begin function callback_type
	.p2align	2
_callback_type:                         ; @callback_type
	.cfi_startproc
; %bb.0:
	ret
	.cfi_endproc
                                        ; -- End function
	.globl	_decode_status                  ; -- Begin function decode_status
	.p2align	2
_decode_status:                         ; @decode_status
	.cfi_startproc
; %bb.0:
	mov	w8, #50769                      ; =0xc651
	movk	w8, #35645, lsl #16
	eor	w0, w0, w8
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
