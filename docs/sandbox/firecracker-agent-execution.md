<!--
Token4AI Cloud Attribution
Developed by the commercial cloud service company represented by https://token4ai.cloud.
Author: jamesduan (X: https://x.com/JamesDuanL)
Created: 2026-07-20
description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# Firecracker real agent execution runbook (#280)

This runbook is the KVM-host companion to the shipped #280 implementation:
real agent-workload execution inside a Firecracker microVM over the vsock
guest channel, with the gateway capability envelope **enforced at the VM
boundary** (denials block execution inside the guest — never report-only),
and explicit fail-closed degradation for microVM-required workloads on
non-KVM hosts.

## What already ships (proven without KVM, in-sandbox)

- **Guest execution protocol** (`crates/agent-worker/src/firecracker_guest_exec.rs`):
  vsock JSON-lines channel (`vsock-json-lines`) — handshake, one
  identity/policy-bound `start_handler` request carrying a bounded command
  envelope (`workload`) plus a gateway capability envelope
  (`capability_envelope`, `enforcement=enforced_at_microvm_boundary`),
  streamed normalized framework events, one identity-bound response.
- **Capability enforcement at the VM boundary**: the guest agent refuses to
  spawn a workload whose `capability_action` is not in
  `granted_capabilities` (or whose envelope declares any other enforcement
  mode) and returns enforced `capability_denied` evidence
  (`capability_denial_enforced=true`, `executed=false`, a
  `capability.denied` event). Unit-proven over socket pairs and a fake
  Firecracker vsock mux speaking the exact `CONNECT <port>` / `OK <port>`
  preamble (`firecracker_guest_exec_test.rs`).
- **Host lifecycle integration**: `exec_or_attach` against a retained
  microVM uses the vsock path when
  `AGENT_WORKER_FIRECRACKER_GUEST_VSOCK_PORT` is set; the granted
  capabilities come from a REAL gateway authorizer decision (managed mode:
  denied/approval-required/unavailable gateway ⇒ empty grant set ⇒ enforced
  in-guest denial). Transport failures return
  `outcome=guest_vsock_unavailable` and keep the VM retained.
- **Fail-closed degradation (#280 acceptance 2, fully proven here)**:
  `AGENT_WORKER_REQUIRE_MICROVM_ISOLATION=1` pins provisioning to
  `firecracker_micro_vm`. When the KVM/bundle preflight is unavailable,
  provision fails with the distinct
  `microvm_required_backend_unavailable` `incompatible_backend` error and
  never selects local_process/docker — covered by
  `management_test.rs::microvm_required_*` and the ungated
  `tests/firecracker_agent_execution.rs::microvm_required_workload_fails_closed_without_kvm_never_local_process`.

## What this runbook proves on a real KVM host (acceptance 1)

An agent run executing **inside** a Firecracker microVM, with capability
denials enforced (not report-only) by the guest agent, through
`agent-worker firecracker-agent-exec-smoke` and the gated test
`tests/firecracker_agent_execution.rs`.

---

## 1. Host prerequisites

Identical to `docs/sandbox/firecracker-boot-validation.md` sections 1–2:
`/dev/kvm` access, firecracker + jailer binaries, kernel + ext4 rootfs, and
the `AGENT_WORKER_FIRECRACKER_*` env vars exported. Verify with:

```bash
cargo +1.88.0 run -p agent-worker -- firecracker-host-preflight   # "ready": true
```

## 2. Stage the guest agent into the rootfs

The guest agent is the **same `agent-worker` binary** (hidden entrypoint
`--ferrogate-guest-agent-serve-vsock`, AF_VSOCK listener). Stage it into the
rootfs image and start it from init. Minimal staging for the Ubuntu CI
rootfs (adjust paths for your image):

```bash
# Build a static-enough binary for the guest (musl if the rootfs libc differs).
cargo +1.88.0 build -p agent-worker --release

# Mount the rootfs and stage the binary + a boot-time service.
sudo mkdir -p /mnt/fc-rootfs
sudo mount -o loop /srv/firecracker/rootfs.ext4 /mnt/fc-rootfs
sudo install target/release/agent-worker /mnt/fc-rootfs/usr/local/bin/agent-worker

# systemd unit (the Ubuntu CI rootfs boots systemd):
sudo tee /mnt/fc-rootfs/etc/systemd/system/ferrogate-guest-agent.service >/dev/null <<'EOF'
[Unit]
Description=FerroGate agent-worker guest agent (vsock)
After=local-fs.target

[Service]
Environment=FERROGATE_AGENT_WORKER_GUEST_VSOCK_PORT=5252
Environment=FERROGATE_AGENT_WORKER_GUEST_WORKSPACE=/mnt/workspace
ExecStartPre=/bin/sh -c 'mkdir -p /mnt/workspace && (mount /dev/vdb /mnt/workspace || true)'
ExecStart=/usr/local/bin/agent-worker --ferrogate-guest-agent-serve-vsock
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo ln -sf ../ferrogate-guest-agent.service \
  /mnt/fc-rootfs/etc/systemd/system/multi-user.target.wants/ferrogate-guest-agent.service
sudo umount /mnt/fc-rootfs
```

Notes:

- The rootfs is attached read-only at runtime (#227); staging happens
  offline as above. The guest workspace is the per-VM writable `/dev/vdb`.
- The vsock device is already attached by the worker at provision
  (`guest_cid=3`, host UDS `firecracker-guest-rpc.sock` in the VM run dir);
  no extra Firecracker configuration is needed.
- The guest kernel must have `CONFIG_VIRTIO_VSOCKETS` (the Firecracker CI
  kernels do).

## 3. Run the acceptance (one command)

```bash
export AGENT_WORKER_FIRECRACKER_GUEST_AGENT_STAGED=1   # declares step 2 done
export AGENT_WORKER_FIRECRACKER_GUEST_VSOCK_PORT=5252
cargo +1.88.0 test -p agent-worker --test firecracker_agent_execution -- --nocapture
```

or the smoke directly:

```bash
cargo +1.88.0 run -p agent-worker -- firecracker-agent-exec-smoke --timeout-millis 90000
```

### Expected PASS evidence (KVM host)

```json
{
  "ready": true,
  "proves_microvm_boot": true,
  "allowed": {
    "status": "completed",
    "proves_handler_execution": true,
    "workload_result": { "executed": true, "exit_code": 0,
      "output_excerpt": "ferrogate-firecracker-guest-exec-allowed", ... },
    "event_kinds": ["capability.allowed", "run.started", "run.completed"]
  },
  "denied": {
    "status": "capability_denied",
    "proves_handler_execution": false,
    "workload_result": { "executed": false, "capability_denial_enforced": true, ... },
    "event_kinds": ["capability.denied"]
  }
}
```

The acceptance-critical facts: `allowed.workload_result.executed=true` with
the in-guest echo output, and `denied.workload_result` proving the denial
was enforced with **no** execution.

### Expected SKIP (no KVM — e.g. the CI sandbox)

```
SKIP firecracker_agent_execution: Firecracker host prerequisites absent (need /dev/kvm access + AGENT_WORKER_FIRECRACKER_BIN/JAILER/KERNEL/ROOTFS): ...
```

A skip is a green test; it never fake-passes an execution it did not run.
The same test binary still RUNS (not skips) the fail-closed degradation
test and the local-process fallback test on non-KVM hosts.

## 4. Adversarial isolation suite against the real backend

After section 3 passes, run the adversarial suite and the boot validation on
the same host for the full #280 acceptance-1 evidence set:

```bash
cargo +1.88.0 test -p agent-worker --test firecracker_boot_validation -- --nocapture
cargo +1.88.0 test -p agent-worker -- isolation_adversarial --nocapture
cargo +1.88.0 test -p agent-worker --test firecracker_agent_execution -- --nocapture
```

## 5. What remains to prove on a KVM host (exact list)

Everything below is implemented and host-side-tested in-sandbox; only the
in-guest topology needs the real host:

1. The staged guest agent boots under init and listens on AF_VSOCK port 5252
   inside the guest (section 2 staging + section 3 PASS).
2. `firecracker-agent-exec-smoke` allowed-run evidence: `status=completed`,
   `executed=true`, in-guest echo output (real execution INSIDE the microVM).
3. `firecracker-agent-exec-smoke` denied-run evidence:
   `status=capability_denied`, `capability_denial_enforced=true`,
   `executed=false` (denial enforced at the VM boundary on real hardware).
4. The gated `firecracker_agent_execution` test passing (asserts 2 + 3).
5. The #227 boot validation and the adversarial isolation suite green on the
   same host (section 4).
6. Adapter-set variants (Codex CLI / Claude Code) of the guest workload:
   stage the adapter binaries into the rootfs and re-run the smoke with the
   corresponding `framework_adapter`; the envelope/enforcement path is
   adapter-agnostic (`adapter_launch_profile` is already carried and echoed).

Capture the section 3 + 4 stdout on issue #280 as the acceptance-1 evidence
chain (per the issue-closure evidence-chain policy).
