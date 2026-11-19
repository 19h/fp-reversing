/* Move an ordinary receive right between two cooperating audit tasks. */
#include <mach/mach.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expression); \
        _exit(1); \
    } \
} while (0)

enum {
    OPEN_CHANNEL = 0x465001,
    HAND_OFF_RECEIVE,
    CROSS_TASK_MARKER,
    RETURN_RECEIVE,
    RETURNED_TASK_MARKER,
    TIMEOUT_MS = 5000,
};

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t descriptor;
    uint32_t status;
} right_message_t;

typedef struct {
    mach_msg_header_t header;
    uint32_t marker;
} marker_message_t;

typedef union {
    mach_msg_header_t header;
    right_message_t right;
    marker_message_t marker;
    uint64_t reserve[32];
} receive_buffer_t;

_Static_assert(sizeof(right_message_t) == 44, "one descriptor and status word");
_Static_assert(sizeof(marker_message_t) == 28, "header and marker word");
_Static_assert(MACH_PORT_STATUS_FLAG_TEMPOWNER == 1, "temporary owner");
_Static_assert(MACH_PORT_STATUS_FLAG_IMP_DONATION == 8, "importance donation");

static mach_port_t allocate_receive(void)
{
    mach_port_t name = MACH_PORT_NULL;
    CHECK(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &name) == KERN_SUCCESS);
    return name;
}

static void add_send(mach_port_t name)
{
    CHECK(mach_port_insert_right(mach_task_self(), name, name,
        MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
}

static mach_port_type_t type_of(mach_port_t name)
{
    mach_port_type_t type = 0;
    CHECK(mach_port_type(mach_task_self(), name, &type) == KERN_SUCCESS);
    return type;
}

static mach_port_urefs_t send_refs(mach_port_t name)
{
    mach_port_urefs_t refs = 0;
    CHECK(mach_port_get_refs(mach_task_self(), name, MACH_PORT_RIGHT_SEND, &refs) == KERN_SUCCESS);
    return refs;
}

static natural_t receive_flags(mach_port_t name)
{
    mach_port_status_t status = {0};
    mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
    CHECK(mach_port_get_attributes(mach_task_self(), name, MACH_PORT_RECEIVE_STATUS,
        (mach_port_info_t)&status, &count) == KERN_SUCCESS);
    CHECK(count == MACH_PORT_RECEIVE_STATUS_COUNT);
    return status.mps_flags;
}

static void put_right(mach_port_t destination, mach_msg_id_t id, mach_port_t name,
    mach_msg_type_name_t disposition, uint32_t status)
{
    right_message_t message = {
        .header = {
            .msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
            .msgh_size = sizeof(message),
            .msgh_remote_port = destination,
            .msgh_id = id,
        },
        .body = {.msgh_descriptor_count = 1},
        .descriptor = {.name = name, .disposition = disposition, .type = MACH_MSG_PORT_DESCRIPTOR},
        .status = status,
    };
    CHECK(mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        sizeof(message), 0, MACH_PORT_NULL, TIMEOUT_MS, MACH_PORT_NULL) == MACH_MSG_SUCCESS);
}

static right_message_t get_right(mach_port_t source, mach_msg_id_t id,
    mach_msg_type_name_t disposition)
{
    receive_buffer_t buffer = {0};
    mach_msg_return_t result = mach_msg(&buffer.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
        0, sizeof(buffer), source, TIMEOUT_MS, MACH_PORT_NULL);
    if (result != MACH_MSG_SUCCESS) {
        fprintf(stderr, "right message %#x receive failed with %#x\n", id, result);
    }
    CHECK(result == MACH_MSG_SUCCESS);
    right_message_t message = buffer.right;
    CHECK(message.header.msgh_size == sizeof(message));
    CHECK(message.header.msgh_id == id && message.header.msgh_local_port == source);
    CHECK(message.header.msgh_remote_port == MACH_PORT_NULL);
    CHECK((message.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0);
    CHECK(message.body.msgh_descriptor_count == 1);
    CHECK(message.descriptor.name != MACH_PORT_NULL && message.descriptor.type == MACH_MSG_PORT_DESCRIPTOR);
    CHECK(message.descriptor.disposition == disposition);
    return message;
}

static void put_marker(mach_port_t destination, mach_msg_id_t id, uint32_t marker)
{
    marker_message_t message = {
        .header = {
            .msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
            .msgh_size = sizeof(message),
            .msgh_remote_port = destination,
            .msgh_id = id,
        },
        .marker = marker,
    };
    CHECK(mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        sizeof(message), 0, MACH_PORT_NULL, TIMEOUT_MS, MACH_PORT_NULL) == MACH_MSG_SUCCESS);
}

static void get_marker(mach_port_t source, mach_msg_id_t id, uint32_t marker)
{
    receive_buffer_t buffer = {0};
    CHECK(mach_msg(&buffer.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
        0, sizeof(buffer), source, TIMEOUT_MS, MACH_PORT_NULL) == MACH_MSG_SUCCESS);
    CHECK(buffer.header.msgh_size == sizeof(marker_message_t));
    CHECK(buffer.header.msgh_id == id && buffer.header.msgh_local_port == source);
    CHECK(buffer.header.msgh_remote_port == MACH_PORT_NULL);
    CHECK((buffer.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0);
    CHECK(buffer.marker.marker == marker);
}

static void drop_registration_copy(mach_port_array_t ports, mach_msg_type_number_t count)
{
    for (mach_msg_type_number_t index = 0; index < count; ++index) {
        if (MACH_PORT_VALID(ports[index])) {
            CHECK(mach_port_deallocate(mach_task_self(), ports[index]) == KERN_SUCCESS);
        }
    }
    if (count != 0) {
        CHECK(vm_deallocate(mach_task_self(), (vm_address_t)ports,
            count * sizeof(*ports)) == KERN_SUCCESS);
    }
}

static _Noreturn void child_main(pid_t parent, bool marked)
{
    CHECK(getpid() != parent);
    mach_port_array_t registered = NULL;
    mach_msg_type_number_t count = 0;
    CHECK(mach_ports_lookup(mach_task_self(), &registered, &count) == KERN_SUCCESS);
    CHECK(count == 3 && MACH_PORT_VALID(registered[0]));
    CHECK(registered[1] == MACH_PORT_NULL && registered[2] == MACH_PORT_NULL);
    mach_port_t rendezvous = registered[0];
    CHECK(type_of(rendezvous) == MACH_PORT_TYPE_SEND);
    mach_port_t empty[3] = {0};
    CHECK(mach_ports_register(mach_task_self(), empty, 3) == KERN_SUCCESS);

    mach_port_t delivery = allocate_receive();
    put_right(rendezvous, OPEN_CHANNEL, delivery, MACH_MSG_TYPE_MAKE_SEND, 0);
    right_message_t handed = get_right(delivery, HAND_OFF_RECEIVE, MACH_MSG_TYPE_PORT_RECEIVE);
    mach_port_t carried = handed.descriptor.name;
    CHECK(type_of(carried) == MACH_PORT_TYPE_RECEIVE);
    natural_t flags = receive_flags(carried);
    CHECK(flags == (marked ? MACH_PORT_STATUS_FLAG_IMP_DONATION : 0));
    get_marker(carried, CROSS_TASK_MARKER, 1);

    put_right(rendezvous, RETURN_RECEIVE, carried, MACH_MSG_TYPE_MOVE_RECEIVE, flags);
    mach_port_type_t invalid = 0;
    CHECK(mach_port_type(mach_task_self(), carried, &invalid) == KERN_INVALID_NAME);
    CHECK(mach_port_mod_refs(mach_task_self(), delivery, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    drop_registration_copy(registered, count);
    _exit(0);
}

static void exercise(char *executable, bool marked)
{
    mach_port_t rendezvous = allocate_receive();
    mach_port_t original = allocate_receive();
    add_send(rendezvous);
    add_send(original);
    CHECK(send_refs(original) == 1);
    CHECK(receive_flags(original) == 0);

    mach_port_array_t previous = NULL;
    mach_msg_type_number_t previous_count = 0;
    CHECK(mach_ports_lookup(mach_task_self(), &previous, &previous_count) == KERN_SUCCESS);
    mach_port_t inherited[3] = {rendezvous, MACH_PORT_NULL, MACH_PORT_NULL};
    CHECK(mach_ports_register(mach_task_self(), inherited, 3) == KERN_SUCCESS);
    mach_port_array_t installed = NULL;
    mach_msg_type_number_t installed_count = 0;
    CHECK(mach_ports_lookup(mach_task_self(), &installed, &installed_count) == KERN_SUCCESS);
    CHECK(installed_count == 3 && installed[0] == rendezvous);
    CHECK(installed[1] == MACH_PORT_NULL && installed[2] == MACH_PORT_NULL);
    drop_registration_copy(installed, installed_count);
    char parent[24];
    CHECK(snprintf(parent, sizeof(parent), "%d", getpid()) > 0);
    char *arguments[] = {executable, "--child", parent, marked ? "1" : "0", NULL};
    pid_t child = 0;
    CHECK(posix_spawn(&child, executable, NULL, NULL, arguments, environ) == 0);
    CHECK(mach_ports_register(mach_task_self(), previous, previous_count) == KERN_SUCCESS);
    drop_registration_copy(previous, previous_count);

    right_message_t channel = get_right(rendezvous, OPEN_CHANNEL, MACH_MSG_TYPE_PORT_SEND);
    mach_port_t delivery = channel.descriptor.name;
    CHECK(type_of(delivery) == MACH_PORT_TYPE_SEND);
    if (marked) {
        CHECK(mach_port_set_attributes(mach_task_self(), original,
            MACH_PORT_TEMPOWNER, NULL, 0) == KERN_SUCCESS);
    }
    natural_t before = receive_flags(original);
    CHECK(before == (marked ? MACH_PORT_STATUS_FLAG_TEMPOWNER | MACH_PORT_STATUS_FLAG_IMP_DONATION : 0));

    put_right(delivery, HAND_OFF_RECEIVE, original, MACH_MSG_TYPE_MOVE_RECEIVE, 0);
    CHECK(type_of(original) == MACH_PORT_TYPE_SEND && send_refs(original) == 1);
    put_marker(original, CROSS_TASK_MARKER, 1);

    right_message_t returned = get_right(rendezvous, RETURN_RECEIVE, MACH_MSG_TYPE_PORT_RECEIVE);
    CHECK(returned.descriptor.name == original);
    CHECK(type_of(original) == (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE));
    CHECK(send_refs(original) == 1);
    natural_t final = receive_flags(original);
    CHECK(returned.status == final && final == (marked ? MACH_PORT_STATUS_FLAG_IMP_DONATION : 0));
    put_marker(original, RETURNED_TASK_MARKER, 2);
    get_marker(original, RETURNED_TASK_MARKER, 2);

    int child_status = 0;
    CHECK(waitpid(child, &child_status, 0) == child);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    CHECK(mach_port_deallocate(mach_task_self(), delivery) == KERN_SUCCESS);
    CHECK(mach_port_deallocate(mach_task_self(), original) == KERN_SUCCESS);
    CHECK(mach_port_mod_refs(mach_task_self(), original, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    CHECK(mach_port_deallocate(mach_task_self(), rendezvous) == KERN_SUCCESS);
    CHECK(mach_port_mod_refs(mach_task_self(), rendezvous, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);

    printf("{\"marked\":%s,\"flags_before_handoff\":%u,\"flags_in_child\":%u,"
        "\"flags_after_return\":%u,\"one_retained_send_ref\":true,"
        "\"child_received_marker_on_carried_name\":true,\"original_name_reused\":true,"
        "\"second_marker_received_on_original_name\":true,\"clean_exit\":true}",
        marked ? "true" : "false", before, returned.status, final);
}

int main(int argc, char **argv)
{
    if (argc == 4) {
        CHECK(strcmp(argv[1], "--child") == 0);
        CHECK(strcmp(argv[3], "0") == 0 || strcmp(argv[3], "1") == 0);
        CHECK(getppid() == (pid_t)strtol(argv[2], NULL, 10));
        child_main(getppid(), argv[3][0] == '1');
    }
    CHECK(argc == 1);
    printf("{\"single_descriptor_message_bytes\":%zu,\"marker_message_bytes\":%zu,\"cases\":[",
        sizeof(right_message_t), sizeof(marker_message_t));
    exercise(argv[0], false);
    printf(",");
    exercise(argv[0], true);
    puts("]}");
    return 0;
}
