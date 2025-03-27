# Implementing our first gadget

In this track we want to create a gadget which traces every process opening a file - be it for writing or reading. With the framework provided by Inspektor Gadgets this can be achieved easily. Even better is the out of the box enrichment for containers and Kubernetes.

This lab is split into 4 tasks. In the repository you can see 4 folders, each of them having a `template` and `solution` subdirectory. You can always start a task by getting the source out of the `template` directory. If you want to compare your solution, you will find the reference implementation in `solution`.
This lab is also designed so that you can keep your own code from previous tasks and extend it too. If you choose to keep your own code, the variables might have other names of course :)

Let's start our journey and create a folder dedicated to our gadget:
```bash
~ $ mkdir mygadget
~ $ cd mygadget
~/mygadget $
```

## 00 The basic tracer

Since we want to observe everything regarding opening a file, we first need to create an `eBPF` program. These are small little programs run inside the kernel, without modifying it. We are writing them in C (with restrictions).
You can start by copying the template from `00 basic_tracer/template/program.bpf.c`.

### Compilation and running

Before we change and extend this skeleton, we should learn how we can compile our gadget and run it. When you have the local binary of Inspektor Gadget called `ig` installed the compilation is only a single line in the terminal: `sudo ig image build path/to/gadget/dir -t tag.io/for/the/docker/image`. In our case we need to do
```bash
~/mygadget $ sudo ig image build -t open .
Pulling builder image ghcr.io/inspektor-gadget/ebpf-builder@sha256:abde516ef837b9df6f8b70c9cd834cd4f0396d5b07e6a034906846c4935c7f24
ghcr.io/inspektor-gadget/ebpf-builder@sha256:abde516ef837b9df6f8b70c9cd834cd4f0396d5b07e6a034906846c4935c7f24: Pulling from inspektor-gadget/ebpf-builder
Digest: sha256:abde516ef837b9df6f8b70c9cd834cd4f0396d5b07e6a034906846c4935c7f24
Status: Image is up to date for ghcr.io/inspektor-gadget/ebpf-builder@sha256:abde516ef837b9df6f8b70c9cd834cd4f0396d5b07e6a034906846c4935c7f24
Successfully built ghcr.io/inspektor-gadget/gadget/open:latest@sha256:db3b2319b6a3ce603450a21028b809f55f4389cec8aeb9184e2e4f155602d249
```

This also downloads and uses the `ebpf-builder` image which already contains every binary, tool and header we need to build the gadget. Therefore, we don't need to locally install anything else, which keeps our systems clean and streamlined.

**Compiliation Errors** for `eBPF` can be quite cryptic. Feel free to ask for help :)

After our gadget is successfully built and tagged as `open` we can run it the following way:
```bash
~/mygadget $ sudo ig run open --verify-image=false --fields +timestamp
```

To execute the gadget, we don't need to be in the same directory (and if we push our gadget to OCI registries we can also use it on other hosts). We need the `--verifuly-image=false` parameter here, since our gadget is not signed, but we know its safe and can be trusted. Our skeleton of the gadget only has a single field called `timestamp` and by default these are not shown. In our lab we want them to be seen so we specify that the `timestamp` column should be included by giving it a `+` prefix.

To see any events we need to generate some events. To do that, leave the `sudo ig run` command running and open a second terminal or ssh session. For testing purposes, we run an interactive docker container:
```bash
~ $ docker run -it --rm busybox
/ # 
```

Just creating the container already created many events which can be seen

```bash
~ $ sudo ig run open --verify-image=false --fields +timestamp
WARN[0000] image signature verification is disabled due to using corresponding option 
WARN[0000] Builder version not found in the gadget image. Gadget could be incompatible 
WARN[0000] image signature verification is disabled due to using corresponding option 
WARN[0000] Builder version not found in the gadget image. Gadget could be incompatible 
TIMESTAMP                          
2025-03-26T16:30:59.031662244+01:00
2025-03-26T16:30:59.032459287+01:00
2025-03-26T16:30:59.032466315+01:00
...
```

For this lab we can ignore these warnings, and I will cut it out of this references console output to keep them small.
It's good to see and know how our gadget can be built and run easily. But our gadget only shows some timestamps. We want more information and now we are diving into the code.



### Tracepoints

Because we want to trace everything opening a file, we need to attach our program to the `openat` syscall:
```C
SEC("tracepoint/syscalls/sys_enter_openat")
int open_entry(struct syscall_trace_enter *ctx)
{
	return enter_open(ctx);
}
```
The `SEC(tracepoint/syscalls/` part instructs the framework to attach the following program to a syscall. The remainder of `sys_enter_openat` specifies that we want the program to be called right before the `openat` syscalls get `enter`ed /executed. If we want to trace the exit out of `openat` we would need to specify `sys_exit_openat`.
The function name itself needs to be unique inside our program. The parameter `struct syscall_trace_enter *` is required and we will need it to extract some specific information. We will get back later to the insides of that struct.

In the method body you see that we are just calling another function `enter_openat`. That function actually contains all the logic we want to write. We split that into its own separate function since there are actually **2** different syscalls to open a file. One is `openat` and the second one `open`. We don't know which of these syscalls the programs are calling so we should trace both.

Your first task is to create a new function in the same file for `open` with the correct `SEC(` and call `handle_open` in the function body.
<details>
<summary>Solution</summary>

```C
SEC("tracepoint/syscalls/sys_enter_open")
int open_entry(struct syscall_trace_enter *ctx)
{
    return handle_open(ctx);
}
```
</details>

### Event handling logic

When running our gadget we still only see some timestamps. All the logic for the events is in the `handle_open` function. Before we extend the functionality let's look what the current code does:

```C
	if (gadget_should_discard_data_current())
		return 0;
```
If you remember we needed to create a container to generate some events in our gadget. But an eBPF program attached to a syscall can see every syscall invocation on the host. Most of the time you don't want that, especially in the Kubernetes scenario. The function `gadget_should_discard_data_current` helps us to achieve that and provides premade filtering logic. For example, we can already run our gadget and trace only events for a container named `nginx-40` by running `sudo ig run open --verify-image=false  --fields +timestamp -c your_container_name`

```C
	event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return 0;

    event->timestamp_raw = bpf_ktime_get_boot_ns();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
```

Here the first lines reserves a spot for our new event in the `events` map. After setting the `timestamp_raw` member to the current timestamp we are submitting the event. At this point Inspektor Gadget can read this event from userspace and do all its magic.

Now we have all the informations and can add more information to our gadget. The most important part would be getting all the container or kubernetes information where the event originated from. Therefore, if a file was opened in a container named `MyContainer` we want to see that.
Fortunatly Inspektor Gadget helps us out again and does the heavy lifting. The framework provides us with a special structure named `gadget_process` that we need to include in our `struct event` as a member. Populating that new member can also be done by calling `gadget_process_populate(...)`. The documentation for `gadget_process_populate` can be found [on our website](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-ebpf-api#helpers)

Your next task is to add these parts in our gadget, so it can show container information alongside its events

<details>
<summary>Solution</summary>

```C
struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
};

//...

	event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return 0;

    event->timestamp_raw = bpf_ktime_get_boot_ns();
    gadget_process_populate(&event->proc);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

```
</details>

After implementing this correctly, building and running the gadget, running some commands in our test container should result in the following:
```bash
~/mygadget $ sudo ./ig run open --verify-image=false
RUNTIME.CONTAINERNAME                                                       COMM                    PID        TID
vibrant_darwin                                                              sh                  3524211    3524211
vibrant_darwin                                                              sh                  3524211    3524211
```

And it shows us the container name, the command which executed the syscall and more. Congratulations!

## 01 Filename

Now that we have some basic information about the events, we can expand our gadget more. Until know we didn't do anything with the `struct syscall_trace_enter *ctx` parameter besides passing them to some Inspektor Gadget function.

Looking at the linux kernel source code at [elixir.bootlin.com](https://elixir.bootlin.com/linux/v6.13.7/source/kernel/trace/trace.h#L137) we see that this struct also contains the arguments `args` of the system call in an array.

Therefore, we should look up at which position the filename parameter. Looking at the linux source code we see that the function definitions for [`open`](https://elixir.bootlin.com/linux/v6.13.7/source/fs/open.c#L1421) and [`openat`](https://elixir.bootlin.com/linux/v6.13.7/source/fs/open.c#L1428).

To decipher the function definition: The first macro parameter is the syscall name. Then the parameters of the syscall is appended. First the type and then the parameter name. For [`open`](https://elixir.bootlin.com/linux/v6.13.7/source/fs/open.c#L1421) the function definition is
```C
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
```
and therefore the filename should be found in `args[0]` inside the `struct syscall_trace_enter`. We also need to cast the parameter to `const char *`.

For us to see the filename in our events we of course need a new member in our `struct event`. We can't use pointers here, since we are crossing kernel and user space boundaries. So we need to use a `char[256]` array. The size limit is arbitrary and should be able to store the longest filenames.

Your task is to add the new struct member, a new `const char *` parameter to the `handle_open` function and pass the correct argument from `ctx->args` to `handle_open`. Do not try to copy the filename of the event yet, we will do that afterwards. This should still compile fine, you should be able to see the new column but it's not populated.

<details>
<summary>Solution</summary>

```C
struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	char filename[256];
};

//...
static __always_inline int handle_open(struct syscall_trace_enter *ctx, const char *filename)
//...

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_entry(struct syscall_trace_enter *ctx)
{
    return handle_open(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_open")
int open_entry(struct syscall_trace_enter *ctx)
{
    return handle_open(ctx, (const char *)ctx->args[0]);
}

```
</details>

Running some commands in our test container gives the following:
```bash
~/mygadget $ sudo ./ig run open --verify-image=false
RUNTIME.CONTAINERNAME                             COMM                    PID        TID FILENAME                 
vibrant_darwin                                    sh                  3524211    3524211                          
```

### Copying user space bytes

While looking at the `open` and `openat` you might have seen that there is a `__user` annotation for the filename:
```C
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
```
This means the provided filename pointer points to userspace memory and we can't just directly access it here. To copy bytes out of it there is a eBPF helper function called [`bpf_probe_read_user_str` (documentation link)](https://docs.ebpf.io/linux/helper-function/bpf_probe_read_user_str/).
The first parameter is the destination buffer, the second the size (including NULL terminator) and the third our userspace pointer (which is marked unsafe, since it doesn't reside inside the kernel).

Now we have the final piece to copy the filename from the `args` into our new `struct event` member. Your task is to actually copy it in the `handle_open` function.

<details>
<summary>Solution</summary>

```C
	event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return 0;

    event->timestamp_raw = bpf_ktime_get_boot_ns();
    gadget_process_populate(&event->proc);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
```
</details>

Now when running a simple `echo foo > bar` command in our test container we can see the following output when we have our gadget running:
```bash
~/mygadget $ sudo ./ig run open --verify-image=false
RUNTIME.CONTAINERNAME                             COMM                    PID        TID FILENAME                 
vibrant_darwin                                    sh                  3524211    3524211 bar                      
```

Now we are able to see which command in which container access which file on the filesystem 🎉

## 02 Flags while opening a file

There are other parameters in the `open` and `openat` systemcall, which might interest us:
```C
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
```

One of them is `flags` which specifies how the kernel should open these files. For example if a program only wants to read a file, it can be opened with the `O_RDONLY` flag. This information might be useful for us, so let's add it to our gadget.

Your task is now to add `flags` to our `struct event`. We need to read it from `struct syscall_trace_enter` for `open` and `openat`, give it as parameter to `handle_open`, where we finally write it into our event.

<details>
<summary>Solution</summary>

```C
struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	char filename[256];
    int flags;
};

//...

static __always_inline int handle_open(struct syscall_trace_enter *ctx, const char *filename, int flags)
{
//...
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    gadget_process_populate(&event->proc);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    event->flags = flags;
//...
}


//...

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
```

</details>

When building and running our gadget, we can again run some commands in our test container and see the results:
```bash
~/mygadget $ sudo ./ig run open --verify-image=false
RUNTIME.CONTAINERNAME                     COMM                    PID        TID FILENAME              FLAGS      
vibrant_darwin                            sh                  3524211    3524211 bar                   577        
```

We now can see the flags in our events. To make it more readable we can process that field in userspace with Go/WASM. This step is optional and we are doing it as a last step.

## 03 Share our gadget with the world

When you are happy with your gadget and want to share it with the world (or in your own private registry) we can upload it to any OCI compliant registry.
While developing we tagged our gadget with `open` which defaults to `ghcr.io/inspektor-gadget/gadget/open`. For local development it doesn't matter, but you can't upload it to the Inspektor Gadget repository.

For lab testing purposes we can use [the `ttl.sh` registry](https://ttl.sh/). It allows anonymous image pushing and pulling and saves the oci images for a specified time. Please choose a unique tag (best would be to use `uuidgen`).

To tag our image correctly we can specify it while building it
```bash
~/mygadget $ sudo ig image build -t ttl.sh/a_unique_tag .
```
or we can retag our existing built gadget
```bash
~/mygadget $ sudo ig image tag open ttl.sh/a_unique_tag
```

and then we can finally push it to the registry:
```bash
~/mygadget $ sudo ig image tag open ttl.sh/9272b90f-a23e-4457-bc84-e3f6106cba31
Successfully tagged with ttl.sh/9272b90f-a23e-4457-bc84-e3f6106cba31:latest@sha256:d88da3ac5e383127853c23f0caf93312d8a277bae22bd3122d4dde5212103a75

~/mygadget $ sudo ig image push ttl.sh/9272b90f-a23e-4457-bc84-e3f6106cba31 
Pushing ttl.sh/9272b90f-a23e-4457-bc84-e3f6106cba31...
Successfully pushed ttl.sh/9272b90f-a23e-4457-bc84-e3f6106cba31:latest@sha256:d88da3ac5e383127853c23f0caf93312d8a277bae22bd3122d4dde5212103a75
```

And that is all we have to do. We can go to any machine which has `ig` installed and can run our own gadget:
```
~/mygadget $ sudo ./ig run ttl.sh/9272b90f-a23e-4457-bc84-e3f6106cba31 --verify-image=false
RUNTIME.CONTAINERNAME                     COMM                    PID        TID FILENAME              FLAGS      
vibrant_darwin                            sh                  3524211    3524211 bar                   577        
```

## 04 Optional: Userspace processing with Go/WASM

If you remember, the output of our gadget looks currently like this:
```bash
~/mygadget $ sudo ./ig run open --verify-image=false
RUNTIME.CONTAINERNAME                     COMM                    PID        TID FILENAME              FLAGS      
vibrant_darwin                            sh                  3524211    3524211 bar                   577        
```

Everything is quite usable besides the `FLAGS` column. It would be optimal if we can take the integer and decode it back into the flags that were given to the `open` or `openat` syscall.

For that we can process our events in userspace with Go/WASM. We can instruct Inspektor Gadget to build the userspace component by adding a file named `build.yaml` next to our `program.bpf.c` with the following content:
```yaml
wasm: go/main.go
```
Inspektor Gadget will look at `go/main.go`, try to compile that package into WASM and include it in our gadget. Looking at the template we can see that the flag decoding function is already implemented. It takes an `int32` and returns us `[]string`, which are the decoded flags.

We also have the `flagsField`, which is the handler to read the `int flags` of our `struct event`. Additionally we create a new field named "flags_decoded" and its corresponding handler is `flagsDecodedField`. Both handlers are of type `Field`.

The function given to `ds.Subscribe` is getting called for every event. So the logic and enrichment needs to happen there. This means reading the `int32` out of `flagsField`, decoding it with `decodeFlags` and finally set the string into `flagsDecodedField`.

Your task is to implement the body of that function. It is marked in the template and you only need to extend that area.

<details>
<summary>Solution</summary>

```golang
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		flagsRaw, err := flagsField.Int32(data)
		if err != nil {
			api.Warnf("failed to get flags: %s", err)
			return
		}

		flagsStrArr := decodeFlags(flagsRaw)
		flagsDecodedField.SetString(data, strings.Join(flagsStrArr, "|"))
	}, 0)
```
</details>

After rebuilding our gadget we can see the new field with its content:
```bash
~/mygadget $ sudo ./ig run open --verify-image=false
RUNTIME.CONTAINERNAME          COMM        PID        TID     FILENAME        FLAGS    FLAGS_DECODED          
vibrant_darwin                 sh          3524211    3524211 bar             577      O_WRONLY|O_CREAT|O_TRU…
```

If your output gets truncated, you can either resize our terminal or use the `json`/`jsonpretty` output mode with `-o json`/`-o jsonpretty` which should show you all the fields currently available. Many of them we didn't see in this lab and ignored it:

```json
~/mygadget $ sudo ./ig run open --verify-image=false -o jsonpretty
{
  "filename": "bar",
  "flags": 577,
  "flags_decoded": "O_WRONLY|O_CREAT|O_TRUNC",
...
  "proc": {
    "comm": "sh",
    "creds": {
      "gid": 0,
      "group": "root",
      "uid": 0,
      "user": "root"
    },
    "mntns_id": 4026532426,
    "parent": {
      "comm": "containerd-shim",
      "pid": 3524190
    },
    "pid": 3524211,
    "tid": 3524211
  },
  "runtime": {
    "containerId": "16a5318354133f73ba4e5bfa0a19a2eaa8fb1234ef15f1867d8fd789baad6f71",
    "containerImageDigest": "sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7",
    "containerImageName": "busybox",
    "containerName": "vibrant_darwin",
    "containerPid": 3524211,
    "containerStartedAt": 1743003058982344231,
    "runtimeName": "docker"
  },
  "timestamp": "2025-03-27T18:26:41.286624603+01:00",
  "timestamp_raw": 1743096401286624603
}
```

In my example we can see that the `sh` process in the container named `vibrant_darwin`, which is a `busybox` image opened a file named `bar` with the flags `O_WRONLY|O_CREAT|O_TRUNC`

## Thanks for building your own gadgets with Inspektor Gadget
