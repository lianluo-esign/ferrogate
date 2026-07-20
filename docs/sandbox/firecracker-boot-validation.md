<!--
Token4AI Cloud Attribution
Developed by the commercial cloud service company represented by https://token4ai.cloud.
Author: jamesduan (X: https://x.com/JamesDuanL)
Created: 2026-07-18
description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# Firecracker guest-boot validation runbook (#227)

The per-VM rootfs isolation code for #227 already landed (commit `b68ea08`):
the Firecracker backend now attaches the shared host rootfs image **read-only**
(`is_read_only: true`, boots `root=/dev/vda ro`) and gives every microVM its
**own writable workspace drive** (`/dev/vdb`) backed by a file in the VM's
private run dir — derived from `IsolationFilesystemPolicy` by
`plan_firecracker_rootfs_attachment` (`crates/agent-worker/src/backends.rs`) so
the drive layout cannot drift from the declared
`read_only_rootfs_with_prepared_workspace` policy.

The **one open acceptance** is: *guest boot validated on a real Firecracker
host with the new drive layout.* This runbook is how a maintainer with a
Firecracker host produces that acceptance evidence with a single command.

The validation is the KVM/Firecracker-gated integration test
`crates/agent-worker/tests/firecracker_boot_validation.rs`. It is **honest by
construction**: it runs the production host preflight and **skips (not fails)**
whenever `/dev/kvm` or the Firecracker binary/images are absent — as they are
in the CI sandbox — and only actually boots a microVM (through the shipped,
governed `firecracker-boot-smoke` path) when the prerequisites are present.

---

## 1. Prerequisites

### 1.1 KVM access

The runner must have `/dev/kvm` and the running user must be able to open it
read+write (the worker's preflight opens it read/write):

```bash
# Confirm the device exists (bare-metal or nested-virt host).
ls -l /dev/kvm

# Grant the current user access, then re-login / re-exec the shell.
sudo usermod -aG kvm "$USER"
newgrp kvm   # or start a fresh login session

# Verify it is now readable + writable by you.
test -r /dev/kvm && test -w /dev/kvm && echo "kvm ok"
```

Cloud VMs need nested virtualization enabled (e.g. GCP `--enable-nested-virtualization`,
or a bare-metal / `*.metal` instance).

### 1.2 Firecracker + jailer binaries

Install a released Firecracker + jailer (v1.7.0 or newer recommended; any
release whose kernel supports the `ro`/`readonly` VFS mount annotation works):

```bash
FC_VER=v1.7.0
ARCH="$(uname -m)"   # x86_64 or aarch64
curl -fsSL -o /tmp/fc.tgz \
  "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VER}/firecracker-${FC_VER}-${ARCH}.tgz"
tar -C /tmp -xzf /tmp/fc.tgz
sudo install "/tmp/release-${FC_VER}-${ARCH}/firecracker-${FC_VER}-${ARCH}" /usr/local/bin/firecracker
sudo install "/tmp/release-${FC_VER}-${ARCH}/jailer-${FC_VER}-${ARCH}"      /usr/local/bin/jailer
firecracker --version
```

### 1.3 Guest kernel + rootfs images

Any Firecracker-compatible uncompressed kernel (`vmlinux`) and an **ext4** root
filesystem image work. The Firecracker CI/demo artifacts are the quickest path:

```bash
ARCH="$(uname -m)"
mkdir -p /srv/firecracker && cd /srv/firecracker

# Kernel (vmlinux) and a Ubuntu ext4 rootfs from the Firecracker CI bucket.
curl -fsSL -o vmlinux \
  "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/kernels/${ARCH}/vmlinux-6.1.bin"
curl -fsSL -o rootfs.ext4 \
  "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/disks/${ARCH}/ubuntu-24.04.ext4"
```

The rootfs image is attached **read-only** and is never mutated by the boot
validation, so a single shared image is safe. The guest gets its own writable
`/dev/vdb` workspace, which the worker creates and formats with `mkfs.ext4`
(so `e2fsprogs` should be installed on the host):

```bash
sudo apt-get install -y e2fsprogs   # provides mkfs.ext4
```

---

## 2. Environment variables

The gated test reads the **same** `AGENT_WORKER_FIRECRACKER_*` env vars the
production backend uses (see `firecracker_host_preflight` in
`crates/agent-worker/src/backends.rs`):

```bash
export AGENT_WORKER_FIRECRACKER_BIN=/usr/local/bin/firecracker
export AGENT_WORKER_FIRECRACKER_JAILER=/usr/local/bin/jailer
export AGENT_WORKER_FIRECRACKER_KERNEL=/srv/firecracker/vmlinux
export AGENT_WORKER_FIRECRACKER_ROOTFS=/srv/firecracker/rootfs.ext4
# Optional: override the KVM device path (defaults to /dev/kvm).
# export AGENT_WORKER_FIRECRACKER_KVM_DEVICE=/dev/kvm
```

---

## 3. Run the acceptance (one command)

From the repo root, on the Firecracker host, with the env vars above exported:

```bash
cargo +1.88.0 test -p agent-worker --test firecracker_boot_validation -- --nocapture
```

That single command builds the worker binary, boots a real microVM through the
governed `firecracker-boot-smoke` path (which applies the new read-only rootfs
+ per-VM `/dev/vdb` layout), asserts the guest boots and the read-only rootfs
is honored, and tears the microVM down.

> Sanity-check prerequisites first, if you like:
> `cargo +1.88.0 run -p agent-worker -- firecracker-host-preflight`
> should print `"ready": true`.

### Expected PASS evidence

```
running 1 test
firecracker_boot_validation evidence: proves_microvm_boot=Bool(true) boot_observed=Bool(true) failure_stage=Null failure_reason=Null markers=["linux_version", "kvm_hypervisor", ... "rootfs_mounted", "rootfs_mounted_readonly", "init_started", ...]
test firecracker_guest_boots_with_read_only_rootfs_layout ... ok

test result: ok. 1 passed; 0 failed; ...
```

The acceptance-critical evidence:

- `proves_microvm_boot=Bool(true)` and `boot_observed=Bool(true)` — a real
  guest boot to userspace with the new drive layout (serial-console evidence).
- `rootfs_mounted_readonly` in the markers — the guest kernel honored
  `root=/dev/vda ro`, i.e. `IsolationFilesystemPolicy.read_only_rootfs` was
  enforced end to end.

Capture this stdout on the issue as the #227 boot-validation evidence.

### Expected SKIP (no KVM / images — e.g. the CI sandbox)

```
running 1 test
SKIP firecracker_boot_validation: Firecracker host prerequisites absent (need /dev/kvm access + AGENT_WORKER_FIRECRACKER_BIN/JAILER/KERNEL/ROOTFS): ...
test firecracker_guest_boots_with_read_only_rootfs_layout ... ok
```

A skip is a green test — it never fake-passes a boot it did not run.

---

## 4. Optional: full in-guest read-only / writable-workspace proof

The automated harness proves the read-only rootfs layout **boots** and that the
kernel mounted the rootfs read-only. Asserting the two final in-guest
properties — an in-guest write to the rootfs *fails* and `/dev/vdb` *is
writable* — requires executing commands **inside** the guest. Since #280 the
worker CAN execute commands inside the guest over the vsock channel once the
guest agent is staged (see `docs/sandbox/firecracker-agent-execution.md`);
alternatively a maintainer can confirm them manually by booting an
interactive microVM with the same drive layout and running:

```sh
# Inside the guest (root shell):

# (a) rootfs is read-only: a write to /dev/vda-backed paths must fail.
touch /root/should-fail 2>&1 | grep -qi 'read-only' && echo "ROOTFS RO: OK"

# (b) the per-VM /dev/vdb workspace is writable.
mkdir -p /mnt/workspace
mount /dev/vdb /mnt/workspace
touch /mnt/workspace/ok && echo "WORKSPACE RW: OK"
```

Expected: `(a)` reports `EROFS` / "Read-only file system" (`ROOTFS RO: OK`) and
`(b)` succeeds (`WORKSPACE RW: OK`).

---

## 5. Optional CI wiring

Default GitHub-hosted runners have **no** `/dev/kvm`, so this must never be a
required gate. An optional, manually-dispatched workflow is provided at
`.github/workflows/firecracker-boot-validation.yml`: trigger it on a
self-hosted KVM-enabled runner (label `kvm`) with the images staged and the
`AGENT_WORKER_FIRECRACKER_*` env configured. On any runner lacking KVM the same
test skips cleanly, so the job is safe (but pointless) elsewhere. If you have no
such runner, run the one command in section 3 on your Firecracker host instead.
