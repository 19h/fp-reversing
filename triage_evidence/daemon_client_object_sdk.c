#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
/* Reconstructed local layouts; not original exported declarations. */
struct client_object32 {
    void *field00;
    uint32_t field08, field0c, field10, field14, field18;
    unsigned char unwritten1c[4];
};
struct client_pair16 { uint64_t field00, field08; };
_Static_assert(sizeof(struct client_object32) == 32, "object extent");
_Static_assert(offsetof(struct client_object32, field14) == 20, "field14");
_Static_assert(offsetof(struct client_object32, unwritten1c) == 28, "tail");
_Static_assert(sizeof(struct client_pair16) == 16, "pair extent");
_Static_assert(sizeof(mach_port_t) == 4, "task name width");
_Static_assert(sizeof(vm_address_t) == 8, "VM address width");
_Static_assert(sizeof(vm_size_t) == 8, "VM size width");
void initialize32(struct client_object32 *p) {
    p->field00 = 0;
    p->field08 = p->field0c = p->field10 = p->field18 = UINT32_C(0x8b3dc651);
    p->field14 = UINT32_C(0x4d8916dc);
}
void initialize16(struct client_pair16 *p) { p->field00 = p->field08 = 0; }
kern_return_t cleanup_signature_probe(mach_port_t task, struct client_object32 *p) {
    return vm_deallocate(task, (vm_address_t)p->field00,
                         (vm_size_t)(p->field08 ^ UINT32_C(0x8b3dc651)));
}
