	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_item_key                       ; -- Begin function item_key
	.p2align	2
_item_key:                              ; @item_key
	.cfi_startproc
; %bb.0:
	mov	w8, #53858                      ; =0xd262
	movk	w8, #59186, lsl #16
	eor	w8, w0, w8
	mov	w9, #40695                      ; =0x9ef7
	movk	w9, #47648, lsl #16
	mul	w0, w8, w9
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
