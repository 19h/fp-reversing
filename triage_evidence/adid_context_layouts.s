	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_analyst_data                   ; -- Begin function analyst_data
	.p2align	2
_analyst_data:                          ; @analyst_data
	.cfi_startproc
; %bb.0:
	mov	x2, x1
	mov	x1, x0
Lloh0:
	adrp	x8, _kCFAllocatorNull@GOTPAGE
Lloh1:
	ldr	x8, [x8, _kCFAllocatorNull@GOTPAGEOFF]
Lloh2:
	ldr	x3, [x8]
	mov	x0, #0                          ; =0x0
	b	_CFDataCreateWithBytesNoCopy
	.loh AdrpLdrGotLdr	Lloh0, Lloh1, Lloh2
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_parse                  ; -- Begin function analyst_parse
	.p2align	2
_analyst_parse:                         ; @analyst_parse
	.cfi_startproc
; %bb.0:
	mov	x2, #0                          ; =0x0
	mov	x3, #0                          ; =0x0
	mov	x4, #0                          ; =0x0
	b	_CFPropertyListCreateWithData
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_uid                    ; -- Begin function analyst_uid
	.p2align	2
_analyst_uid:                           ; @analyst_uid
	.cfi_startproc
; %bb.0:
	mov	x2, x1
	mov	w1, #3                          ; =0x3
	b	_CFNumberGetValue
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
