#include <bsm/libbsm.h>
_Static_assert(sizeof(audit_token_t) == 32, "audit token width");
_Static_assert(sizeof(pid_t) == 4, "PID output width");
/* Compile-only source ABI probe; no target or host API execution. */
void extract_pid(const audit_token_t *token, pid_t *pid_out)
{
    audit_token_to_au32(*token, 0, 0, 0, 0, 0, pid_out, 0, 0);
}
