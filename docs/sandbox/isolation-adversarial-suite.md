<!--
Token4AI Cloud Attribution
Developed by the commercial cloud service company represented by https://token4ai.cloud.
Author: jamesduan (X: https://x.com/JamesDuanL)
Created: 2026-07-18
description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# Isolation adversarial containment suite (#205)

This document is the containment matrix for the FerroGate managed-worker
isolation proof. It records what each containment dimension asserts, which
backend enforces it today, and the promotion criteria required to flip
acceptance from the in-sandbox **local-process** backend to a production
(gVisor / Firecracker) backend on a real security runner.

The acceptance requirement of #205 is: *a real isolation backend passing the
documented adversarial containment suite (filesystem / network / process /
namespace / resource / secret) through the governed Agent action path, with
backend-version / image-digest evidence.* Per the maintainer's standing
sandbox-closure policy, a **local-process / Linux-namespace backend exercised
by a real local-process E2E is an accepted substitute for the Docker / gVisor
E2E** when no daemon or hypervisor is available.

## Backends and the governed action path

The worker registers a replaceable set of isolation backends
(`crates/agent-worker/src/backends.rs`). Each speaks the same runtime
`IsolationBackendLifecycle` contract
(`crates/ferrogate-runtime/src/isolation.rs`) and is chosen by the fail-closed
`select_isolation_backend` selector. Backends are ranked; the local-process
tier is ranked **last**, so it can never outrank a real hypervisor or
container backend when one is ready.

| Backend | Kind | Host impl | In-sandbox | Notes |
|---|---|---|---|---|
| Firecracker microVM | `firecracker_micro_vm` | yes | needs KVM + bundle | production high-isolation default |
| Kata Containers | `kata_containers` | no (registered) | n/a | fails closed until implemented |
| gVisor | `gvisor` | no (registered) | n/a | fails closed until implemented |
| Rootless Docker | `rootless_docker` | yes | needs daemon | opt-in low-risk tier |
| **Local process** | `local_process` | **yes** | **yes** | namespaced, unprivileged; sandbox/CI substitute |

The local-process backend is opt-in via
`AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND=1` and is only *selectable* when a
real `unshare` probe proves the full unprivileged namespace stack is available;
otherwise it is registered but fails closed.

The adversarial suite
(`crates/agent-worker/src/isolation_adversarial_test.rs`) provisions a workload
by sending **signed management envelopes** (`Provision` → `ExecOrAttach` →
`SnapshotOrCheckpoint` → `CollectArtifacts` → `StreamStatus` → `Stop` →
`Cleanup`) through the exact governed action path the gateway uses, then attacks
each containment dimension from inside the provisioned workload.

## What the local-process backend enforces

Every workload exec runs inside a fresh namespace stack created with
`unshare -U -r -m -n -p -f --mount-proc --kill-child`, and a `set -e`
confinement script applies the mounts and rlimits **before** the workload is
exec'd. If any confinement step fails, the workload is never exec'd unconfined
— the exec fails closed.

- **namespace**: new user + mount + pid + network namespaces per workload,
  with `/proc` remounted for the pid namespace.
- **network**: the network namespace contains only a loopback device and no
  routes — no direct public egress. Gateway-mediated egress (#86) is the only
  sanctioned path (same posture as `docker --network none`).
- **filesystem**: private mount namespace; the prepared workspace is
  bind-mounted at `/mnt` (the only writable escape hatch), a read-only tmpfs
  shrouds `/home`, and a private tmpfs covers `/tmp`. The rest of the host
  rootfs is protected by DAC (workload uid maps to the unprivileged worker
  uid).
- **resource**: `RLIMIT_AS` from the policy memory budget, `RLIMIT_CPU`, and a
  wall-clock kill (the whole namespace is reaped via `--kill-child`) derived
  from the policy max runtime.
- **secret**: the workload environment is fully cleared (`env_clear`) and
  replaced by a small fixed set of `FERROGATE_*` / `HOME` / `PATH` / `TMPDIR`
  variables. The SHA-256 fingerprint of that exact injected environment is
  recorded as run evidence, so any drift is detectable and no host secret can
  leak in.

## Containment matrix

Each row lists what the suite asserts and the current status on the
local-process backend in this sandbox.

| Dimension | The suite asserts (adversarial) | Local-process status |
|---|---|---|
| **filesystem** | `pwd == /mnt`; writes to `/etc`, `/usr`, `/home` all fail; `/home` is empty (shroud); host `$HOME` and a host `/tmp` marker are invisible; the only visible write lands in the prepared workspace | **PASS — enforced** |
| **network** | only `lo` exists in `/proc/net/dev`; a `/dev/tcp` egress attempt against a real host loopback listener fails | **PASS — enforced** |
| **process** | a real host `sleep` pid is absent from `/proc`; the in-namespace process table has ≤ 5 pids | **PASS — enforced** |
| **namespace** | `user`/`net`/`pid`/`mnt` ns ids inside differ from the host ns ids | **PASS — enforced** |
| **resource** | `ulimit -v` / `ulimit -t` reflect the governed policy; a `sleep 30` workload is killed by the wall-clock budget in < 10 s | **PASS — enforced** |
| **secret** | host secret env var is absent inside; only the allow-listed fingerprinted env is present; `HOME=/mnt` | **PASS — enforced** |
| rootfs read-only remount | full read-only rootfs (beyond the `/home` + `/tmp` shrouds and DAC) | **DEGRADED — prod-gated** (not possible unprivileged) |
| cgroup pids/IO caps | hard cgroup-v2 pids/IO limits (beyond rlimits + `--kill-child`) | **DEGRADED — prod-gated** (needs a cgroup-v2 delegated runner) |

The degraded controls are reported **loudly** in every lifecycle evidence
string via the `degraded_controls=[...]` marker — they are never silently
skipped. The fail-closed negative test asserts that when the namespace stack is
unavailable, the governed `Provision` is rejected with a non-retryable
`incompatible_backend` error and no host work runs.

## Evidence emitted in the run report

The `Provision` lifecycle message carries the backend-version + containment
evidence, for example:

```
backend_version=unshare from util-linux 2.41.3; image_digest=none(host-userspace-no-image);
namespaces=user,mount,pid,net,proc;
filesystem=workspace-bind(/mnt)+ro-tmpfs(/home)+private-tmpfs(/tmp)+host-dac;
network=netns-loopback-only-no-egress;
resource=rlimit_as:512MiB,rlimit_cpu:2s,wall_clock:1500ms;
secret=env-cleared,env_fingerprint=sha256:<64-hex>;
degraded_controls=[rootfs_not_remounted_read_only(prod-gated:gvisor/firecracker),no_cgroup_pids_or_io_limit(prod-gated:cgroup-v2-runner)]
```

- **backend-version evidence**: the real probed `unshare --version` output,
  never a placeholder.
- **image-digest evidence**: the local-process backend has no image, so the
  digest field is the explicit sentinel `none(host-userspace-no-image)` rather
  than being omitted. Image-based backends (Docker / gVisor / Firecracker
  rootfs) MUST emit a real digest here.

The suite prints a one-line `containment-matrix:` summary at the end of the
run for capture into CI logs.

## What remains strictly production-backend-only

The local-process backend is the sanctioned *substitute* in a daemon-less,
unprivileged sandbox. It does **not** discharge the following, which require a
production backend on a real security runner:

1. **Kernel-level isolation.** Namespaces share the host kernel; a kernel
   exploit is not contained. gVisor (user-space kernel) or Firecracker
   (hardware-virtualized microVM) is required for a real trust boundary.
2. **Read-only rootfs.** A full read-only root filesystem cannot be remounted
   unprivileged; only the `/home` + `/tmp` shrouds plus DAC apply today.
3. **Hard cgroup resource caps.** pids/IO/memory cgroup-v2 limits need a
   delegated cgroup runner; today only rlimits + wall-clock reaping apply.
4. **Image-digest supply-chain evidence.** A pinned rootfs/image digest is
   only meaningful for an image-based backend.

### Promotion criteria (flip acceptance to a production backend)

Acceptance moves off the local-process substitute when **all** of the
following hold:

- A real gVisor or Firecracker backend reports `ready` through the same
  registry + `select_isolation_backend` path (it already outranks
  local-process).
- The identical adversarial suite runs against that backend on a CI or
  approved security runner (KVM for Firecracker; runsc for gVisor) and every
  dimension reports **PASS — enforced**, including the two rows currently
  **DEGRADED — prod-gated** (rootfs read-only, cgroup caps).
- The run report emits a real **image/rootfs digest** in place of
  `image_digest=none(...)`, plus the backend version.
- No dimension is skipped; any control that still cannot be enforced makes the
  provision fail closed.

Until then, the local-process backend + this suite is the accepted in-sandbox
proof that the governed action path enforces every containment dimension it can
unprivileged, and fails closed on the rest.
