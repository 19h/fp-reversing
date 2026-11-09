	.build_version macos, 13, 0	sdk_version 27, 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	__Z17sample_read_probeP18IOMemoryDescriptoryPvy ; -- Begin function _Z17sample_read_probeP18IOMemoryDescriptoryPvy
	.p2align	2
__Z17sample_read_probeP18IOMemoryDescriptoryPvy: ; @_Z17sample_read_probeP18IOMemoryDescriptoryPvy
	.cfi_startproc
; %bb.0:
	ldr	x16, [x0]
	mov	x17, x0
	movk	x17, #52641, lsl #48
	autda	x16, x17
	mov	x17, x16
	xpacd	x17
	cmp	x16, x17
	b.eq	Lauth_success_0
	brk	#0xc472
Lauth_success_0:
	add	x4, x16, #520
	ldr	x5, [x16, #520]
	mov	x16, x4
	movk	x16, #64512, lsl #48
	braa	x5, x16
	.cfi_endproc
                                        ; -- End function
	.globl	__Z18sample_write_probeP18IOMemoryDescriptoryPKvy ; -- Begin function _Z18sample_write_probeP18IOMemoryDescriptoryPKvy
	.p2align	2
__Z18sample_write_probeP18IOMemoryDescriptoryPKvy: ; @_Z18sample_write_probeP18IOMemoryDescriptoryPKvy
	.cfi_startproc
; %bb.0:
	ldr	x16, [x0]
	mov	x17, x0
	movk	x17, #52641, lsl #48
	autda	x16, x17
	mov	x17, x16
	xpacd	x17
	cmp	x16, x17
	b.eq	Lauth_success_1
	brk	#0xc472
Lauth_success_1:
	add	x4, x16, #528
	ldr	x5, [x16, #528]
	mov	x16, x4
	movk	x16, #20603, lsl #48
	braa	x5, x16
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
