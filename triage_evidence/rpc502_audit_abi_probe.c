#include <bsm/libbsm.h>
/* Current-SDK ABI probe only; do not execute. */
void rpc502_audit_abi_probe(const audit_token_t *token, pid_t *pid_out)
{
    audit_token_to_au32(*token, 0, 0, 0, 0, 0, pid_out, 0, 0);
}
