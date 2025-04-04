# Debugging and Observability with Inspektor Gadget

## Overview

Inpsektor Gadget has powerful set of [gadgets](https://artifacthub.io/packages/search?kind=22&verified_publisher=true&official=true&cncf=true&sort=relevance&page=1) that can be used to troubleshoot and debug issues in your Kubernetes cluster. This lab will focus on highlighting some of the key gadgets
and different ways to use them to troubleshoot issues in your cluster.

### Task 1: Troubleshooting DNS Issues

DNS is a critical component in a Kubernetes cluster as it is used by various components to communicate with each other. In this lab, we will look at how to use the [trace_dns](https://inspektor-gadget.io/docs/latest/gadgets/trace_dns) gadget to troubleshoot DNS issues.

#### Step 1: Create a new namespace

Start by creating a new namespace called `dns-debug`:

```bash
kubectl create ns dns-debug
```

#### Step 2: Deploy a pod in the `dns-debug` namespace

```bash
kubectl -n dns-debug run mypod --image=wbitt/network-multitool -- sleep inf
```

#### Step 3: Start the DNS gadget

```bash
kubectl gadget run trace_dns:v0.38.1 -n dns-debug --fields src,dst,name,qr,rcode
```

#### Step 4: Generate DNS traffic

Inside the pod, run the following command to generate DNS traffic:

```bash
kubectl -n dns-debug exec mypod -- sh -c "nslookup kubernetes.default.svc.cluster.local."
```

#### Step 5: View the DNS traffic

You should see the DNS traffic generated by the `nslookup` by visiting the terminal where the DNS gadget was started.

```bash
SRC                                                  DST                                                  NAME                                                                                 QR    RCODE                 
p/dns-debug/mypod:39376                              s/kube-system/kube-dns:53                            kubernetes.default.svc.cluster.local.                                                Q                           
s/kube-system/kube-dns:53                            p/dns-debug/mypod:39376                              kubernetes.default.svc.cluster.local.                                                R     Success               
s/kube-system/kube-dns:53                            p/dns-debug/mypod:50322                              kubernetes.default.svc.cluster.local.                                                R     Success               
p/dns-debug/mypod:50322                              s/kube-system/kube-dns:53                            kubernetes.default.svc.cluster.local.                                                Q                   
```

See how `SRC` and `DST` are used to identify the source and destination of the DNS traffic with Kubernetes enrichment. The `NAME` field shows the name being resolved, while `QR` indicates whether the message is a query or a response. The `RCODE` field shows the response code.

### Challenge:

Try to filter the DNS response by using the `--filter` option. Hint: You can use `kubectl gadget run trace_dns:v0.38.1 -h` to see the how to use the `--filter` option and what `--fields`  are available to filter on.

<details>
<summary>Solution</summary>

```bash
kubectl gadget run trace_dns:v0.38.1 -n dns-debug --fields src,dst,name,qr,rcode --filter qr==R
```
</details>

#### Step 6: Clean up

```bash
kubectl delete ns dns-debug
```

### Task 2: Troubleshooting TCP Connections

TCP connections are used by various components in a Kubernetes cluster to communicate with each other. In this lab, we will look at how to use a [topper gadget](https://inspektor-gadget.io/docs/latest/gadgets/top_tcp) to understand which pod is sending and receiving the most data over TCP connections.

#### Step 1: Create a new namespace

```bash
kubectl create ns tcp-debug
```

#### Step 2: Deploy a server pods in the `tcp-debug` namespace

```bash
kubectl run iperf-server-1 -n tcp-debug --image=networkstatic/iperf3 --restart=Never --command -- iperf3 -s
kubectl run iperf-server-2 -n tcp-debug --image=networkstatic/iperf3 --restart=Never --command -- iperf3 -s
kubectl run iperf-server-3 -n tcp-debug --image=networkstatic/iperf3 --restart=Never --command -- iperf3 -s
```

#### Step 3: Expose the server pods

```bash
kubectl expose pod iperf-server-1 -n tcp-debug --port=5201
kubectl expose pod iperf-server-2 -n tcp-debug --port=5201
kubectl expose pod iperf-server-3 -n tcp-debug --port=5201
```

#### Step 3: Deploy client pods with different load in the `tcp-debug` namespace

```bash
kubectl run iperf-client-high -n tcp-debug --image=networkstatic/iperf3 --restart=Never --command -- iperf3 -c iperf-server-1.tcp-debug.svc.cluster.local -t 600 -b 100M
kubectl run iperf-client-medium -n tcp-debug --image=networkstatic/iperf3 --restart=Never --command -- iperf3 -c iperf-server-2.tcp-debug.svc.cluster.local -t 600 -b 20M
kubectl run iperf-client-low -n tcp-debug --image=networkstatic/iperf3 --restart=Never --command -- iperf3 -c iperf-server-3.tcp-debug.svc.cluster.local -t 600 -b 5M
```

#### Step 4: Start the top_tcp gadget

```bash
kubectl gadget run top_tcp:v0.38.1 -n tcp-debug
```
```
K8S.NODE                  K8S.NAMESPACE            K8S.PODNAME              K8S.CONTAINERNAME               PID        TID SRC                              DST                              COMM             SENT RECEIVED
minikube-docker           tcp-debug                iperf-server-1           iperf-server-1               697270     697270 p/tcp-debug/iperf-server-1:5201  p/tcp-debug/iperf-client-high:5… iperf3            0 B    12 MB
minikube-docker           tcp-debug                iperf-client-low         iperf-client-low             699188     699188 p/tcp-debug/iperf-client-low:57… s/tcp-debug/iperf-server-3:5201  iperf3         655 kB      0 B
minikube-docker           tcp-debug                iperf-client-medium      iperf-client-medium          698906     698906 p/tcp-debug/iperf-client-medium… s/tcp-debug/iperf-server-2:5201  iperf3         2.5 MB      0 B
minikube-docker           tcp-debug                iperf-client-high        iperf-client-high            698623     698623 p/tcp-debug/iperf-client-high:5… s/tcp-debug/iperf-server-1:5201  iperf3          12 MB      0 B
minikube-docker           tcp-debug                iperf-server-3           iperf-server-3               697847     697847 p/tcp-debug/iperf-server-3:5201  p/tcp-debug/iperf-client-low:57… iperf3            0 B   655 kB
minikube-docker           tcp-debug                iperf-server-2           iperf-server-2               697561     697561 p/tcp-debug/iperf-server-2:5201  p/tcp-debug/iperf-client-medium… iperf3            0 B   2.5 MB
```

See how we have the `SENT` and `RECEIVED` columns to see the amount of data sent and received by each pod. The `SRC` and `DST` columns show the source and destination of the TCP connection.

### Challenge:

Try to play with `--map-fetch-interval` to see how it affects the output. The default value is `1s` and you can set it to `0.5s` or `2s` to see how it affects the output.

#### Step 5: Clean up

```bash
kubectl delete ns tcp-debug
```

### Task 3 : Security Observability

Security observability is a critical component in a Kubernetes cluster as it helps to identify and mitigate security risks. In this lab, we will look at how to use the [trace_exec](https://inspektor-gadget.io/docs/latest/gadgets/trace_exec) to see if a pod is running a shell.

#### Step 1: Create a new namespace

```bash
kubectl create ns security-debug
```

#### Step 2: Deploy a pod in the `security-debug` namespace

```bash
kubectl -n security-debug run mypod --image=ubuntu -- sleep inf
```

#### Step 3: Start the exec gadget

```bash
kubectl gadget run trace_exec:v0.38.1 -n security-debug --filter "proc.comm==bash" --detach --name trace-bash
```

#### Step 4: Generate exec traffic
Inside the pod, run the following command to generate exec traffic:

```bash
kubectl -n security-debug exec mypod -- sh -c "bash"
```

#### Step 5: View the exec traffic

You should attach to the gadget

```bash
kubectl gadget attach trace-bash
```
```
K8S.NODE                               K8S.NAMESPACE                          K8S.PODNAME                           K8S.CONTAINERNAME                     COMM                    PID        TID ARGS                 ERROR
minikube-docker                        security-debug                         mypod                                 mypod                                 bash                 738990     738990 /usr/bin/bash             
```

See how we have `COMM` and `ARGS` to tell us about the processes being executed in specific pods.

#### Step 6: Clean up

```bash
kubectl delete ns security-debug
kubectl gadget delete trace-bash
```

Congratulations! You have completed all the task in this lab. Please feel free to explore other labs or ask questions if you have any.
