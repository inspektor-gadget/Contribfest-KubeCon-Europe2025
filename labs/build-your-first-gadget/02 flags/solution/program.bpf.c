// Kernel types definitions
// Check https://blog.aquasec.com/vmlinux.h-ebpf-programs for more details
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>

// Inspektor gadget helpers
// Check https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-ebpf-api/
// to learn all details
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>

// Our event structure
// First we only want to capture the timestamps when the open syscalls are called
struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	char filename[256];
    int flags;
};

// This creates our tracer map and reservers space for 256k events
GADGET_TRACER_MAP(events, 1024 * 256);
// This macro specifies that this gadget provides tracing events
//  - open: This is the name of the datasource. It can be arbitrary and we will come back later to this
//  - events: This is the name of the map we created above
//  - event: This is the name of the event structure that we will put inside the events map
GADGET_TRACER(open, events, event);


static __always_inline int handle_open(struct syscall_trace_enter *ctx, const char *filename, int flags)
{
	struct event *event;

    // This is an Inspektor Gadget helper which checks if we should discard the
    // current data based on premade filters that we can set in Inspektor Gadget itself
    // So if we to Inspektor Gadget that our gadget should only trace a container
    // named "nginx-40", this function will return 0 for all other containers
	if (gadget_should_discard_data_current())
		return 0;
    
    // First we reserve space in the events map for our event
	event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return 0;

    // We store the timestamp of the event
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    gadget_process_populate(&event->proc);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    event->flags = flags;

    // And finally we submit the event to the events map to be read by Inspektor Gadget
    // in userspace
    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_entry(struct syscall_trace_enter *ctx)
{
    return handle_open(ctx, (const char *)ctx->args[1], (int)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_open")
int open_entry(struct syscall_trace_enter *ctx)
{
    return handle_open(ctx, (const char *)ctx->args[0], (int)ctx->args[1]);
}

char LICENSE[] SEC("license") = "GPL";
