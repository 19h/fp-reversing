/* Exercise XPC audit metadata between two instances of this verifier. */
#include <assert.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xpc/xpc.h>

extern char **environ;
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t *, uint32_t);
extern xpc_object_t xpc_pipe_create_from_port(mach_port_t, uint64_t);
extern int xpc_pipe_routine(xpc_object_t, xpc_object_t, xpc_object_t *);
extern int xpc_pipe_receive(mach_port_t, xpc_object_t *, uint64_t);
extern int xpc_pipe_routine_reply(xpc_object_t);
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern void xpc_connection_get_audit_token(xpc_connection_t, audit_token_t *);

static atomic_uint requests;

static audit_token_t token_for(pid_t pid) {
    mach_port_t task_name = MACH_PORT_NULL;
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    assert(task_name_for_pid(mach_task_self(), pid, &task_name) == KERN_SUCCESS);
    assert(MACH_PORT_VALID(task_name));
    assert(task_info(task_name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) == KERN_SUCCESS);
    assert(count == TASK_AUDIT_TOKEN_COUNT && token.val[5] == (uint32_t)pid);
    assert(mach_port_deallocate(mach_task_self(), task_name) == KERN_SUCCESS);
    return token;
}

static void check_event_token(xpc_object_t event, audit_token_t expected) {
    audit_token_t observed;
    assert(event && xpc_get_type(event) == XPC_TYPE_DICTIONARY);
    xpc_dictionary_get_audit_token(event, &observed);
    assert(memcmp(&expected, &observed, sizeof(observed)) == 0);
}

static void check_peer_token(xpc_connection_t peer, audit_token_t expected) {
    audit_token_t observed;
    xpc_connection_get_audit_token(peer, &observed);
    assert(memcmp(&expected, &observed, sizeof(observed)) == 0);
}

static void run_client(void) {
    audit_token_t server = token_for(getppid());
    mach_port_array_t ports = NULL;
    mach_msg_type_number_t count = 0;
    assert(mach_ports_lookup(mach_task_self(), &ports, &count) == KERN_SUCCESS);
    assert(count == 3 && MACH_PORT_VALID(ports[0]));
    xpc_object_t pipe = xpc_pipe_create_from_port(ports[0], 0);
    assert(pipe);
    assert(mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)ports,
                             count * sizeof(mach_port_t)) == KERN_SUCCESS);
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(request, "request", "endpoint");
    xpc_object_t response = NULL;
    assert(xpc_pipe_routine(pipe, request, &response) == 0);
    check_event_token(response, server);
    xpc_endpoint_t endpoint = xpc_dictionary_get_value(response, "endpoint");
    assert(endpoint && xpc_get_type(endpoint) == XPC_TYPE_ENDPOINT);
    xpc_connection_t peer = xpc_connection_create_from_endpoint(endpoint);
    assert(peer);
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        assert(xpc_get_type(event) == XPC_TYPE_ERROR);
    });
    xpc_connection_activate(peer);
    xpc_release(response);
    xpc_release(request);
    xpc_release(pipe);

    for (uint64_t sequence = 1; sequence <= 2; sequence++) {
        request = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_uint64(request, "sequence", sequence);
        response = xpc_connection_send_message_with_reply_sync(peer, request);
        check_event_token(response, server);
        check_peer_token(peer, server);
        assert(xpc_dictionary_get_uint64(response, "sequence") == sequence);
        xpc_release(response);
        xpc_release(request);
    }
    xpc_connection_cancel(peer);
    xpc_release(peer);
}

static void run_server(const char *image) {
    audit_token_t self = token_for(getpid());
    xpc_object_t local = xpc_dictionary_create(NULL, NULL, 0);
    audit_token_t placeholder;
    xpc_dictionary_get_audit_token(local, &placeholder);
    xpc_release(local);
    for (size_t i = 0; i < 8; i++)
        assert(placeholder.val[i] == (i == 5 ? 0 : UINT32_MAX));

    mach_port_t channel = MACH_PORT_NULL;
    mach_port_options_t options = { .flags = MPO_INSERT_SEND_RIGHT };
    assert(mach_port_construct(mach_task_self(), &options, 0, &channel) == KERN_SUCCESS);
    mach_port_t registered[] = {channel, MACH_PORT_NULL, MACH_PORT_NULL};
    posix_spawnattr_t attributes;
    assert(posix_spawnattr_init(&attributes) == 0);
    assert(posix_spawnattr_set_registered_ports_np(&attributes, registered, 3) == 0);
    char *const child_args[] = {(char *)image, "client", NULL};
    pid_t child;
    assert(posix_spawn(&child, image, NULL, &attributes, child_args, environ) == 0);
    assert(posix_spawnattr_destroy(&attributes) == 0);
    audit_token_t client = token_for(child);
    assert(self.val[5] != client.val[5]);

    xpc_connection_t listener = xpc_connection_create(NULL, NULL);
    assert(listener);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION)
            return;
        xpc_connection_t peer = event;
        xpc_connection_set_event_handler(peer, ^(xpc_object_t request) {
            if (xpc_get_type(request) == XPC_TYPE_ERROR)
                return;
            check_event_token(request, client);
            check_peer_token(peer, client);
            uint64_t sequence = xpc_dictionary_get_uint64(request, "sequence");
            assert(sequence == 1 + atomic_fetch_add(&requests, 1));
            xpc_object_t response = xpc_dictionary_create_reply(request);
            assert(response);
            check_event_token(request, client);
            xpc_dictionary_set_uint64(response, "sequence", sequence);
            xpc_connection_send_message(peer, response);
            xpc_release(response);
        });
        xpc_connection_activate(peer);
    });
    xpc_connection_activate(listener);
    xpc_endpoint_t endpoint = xpc_endpoint_create(listener);
    assert(endpoint);
    xpc_object_t request = NULL;
    assert(xpc_pipe_receive(channel, &request, 0) == 0);
    check_event_token(request, client);
    const char *kind = xpc_dictionary_get_string(request, "request");
    assert(kind && strcmp(kind, "endpoint") == 0);
    xpc_object_t response = xpc_dictionary_create_reply(request);
    assert(response);
    xpc_dictionary_set_value(response, "endpoint", endpoint);
    assert(xpc_pipe_routine_reply(response) == 0);
    xpc_release(response);
    xpc_release(request);
    xpc_release(endpoint);

    int exit_status;
    assert(waitpid(child, &exit_status, 0) == child);
    assert(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0);
    assert(atomic_load(&requests) == 2);
    xpc_connection_cancel(listener);
    xpc_release(listener);
    assert(mach_port_destruct(mach_task_self(), channel, -1, 0) == KERN_SUCCESS);
    puts("{\"separate_processes\":true,\"bootstrap_token_pairs\":1,\"connection_token_pairs\":2,"
         "\"dictionary_and_peer_tokens_match\":true,\"task_info_tokens_match\":true,"
         "\"request_token_survives_reply_creation\":true,"
         "\"unattached_dictionary_has_default_token\":true}");
}

int main(int argc, char **argv) {
    _Static_assert(sizeof(audit_token_t) == 32, "expected eight token words");
    _Static_assert(sizeof(mach_msg_header_t) == 24, "Mach message header size");
    _Static_assert(offsetof(mach_msg_header_t, msgh_remote_port) == 8, "remote port offset");
    _Static_assert(offsetof(mach_msg_header_t, msgh_id) == 20, "message ID offset");
    _Static_assert(sizeof(mach_msg_audit_trailer_t) == 52, "Mach audit trailer size");
    _Static_assert(offsetof(mach_msg_audit_trailer_t, msgh_audit) == 20, "audit token offset");
    _Static_assert(MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT) == 0x03000000,
                   "receive option for an audit trailer");
    alarm(15);
    if (argc == 2 && strcmp(argv[1], "client") == 0)
        run_client();
    else {
        assert(argc == 1);
        run_server(argv[0]);
    }
    return 0;
}
