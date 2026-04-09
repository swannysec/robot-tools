# Docker Sandbox Custom Environments & Templates

## Table of Contents

- [Shell Sandbox](#shell-sandbox)
- [Base Image Variants](#base-image-variants)
- [Custom Dockerfile Pattern](#custom-dockerfile-pattern)
- [Build, Push, Run Workflow](#build-push-run-workflow)
- [Saving Sandbox State](#saving-sandbox-state)
- [Docker Daemon Inside Sandbox](#docker-daemon-inside-sandbox)
- [Memory Configuration](#memory-configuration)
- [Troubleshooting Custom Templates](#troubleshooting-custom-templates)

## Shell Sandbox

A shell sandbox provides a bare Linux environment with no agent pre-installed:

```bash
sbx run shell ~/project
```

Use cases:

- Manual exploration of a project in an isolated environment
- Running custom toolchains or agents not directly supported by `sbx`
- Testing scripts in a clean Linux environment without affecting the host
- Debugging sandbox behavior without agent overhead

The shell sandbox has the same isolation model (hypervisor, network proxy, credential proxying) as agent sandboxes. The only difference is that no agent CLI is pre-installed.

## Base Image Variants

Each agent has a standard image and a `-docker` variant that includes a Docker daemon inside the sandbox.

| Image | Includes | Use When |
|-------|----------|----------|
| `docker/sandbox-templates:claude-code` | Claude Code CLI | Running Claude Code agent |
| `docker/sandbox-templates:claude-code-docker` | Claude Code CLI + Docker daemon | Claude Code needs to build/run containers |
| `docker/sandbox-templates:codex` | Codex CLI | Running Codex agent |
| `docker/sandbox-templates:codex-docker` | Codex CLI + Docker daemon | Codex needs containers |
| `docker/sandbox-templates:copilot` | Copilot CLI | Running Copilot agent |
| `docker/sandbox-templates:copilot-docker` | Copilot CLI + Docker daemon | Copilot needs containers |
| `docker/sandbox-templates:gemini` | Gemini CLI | Running Gemini agent |
| `docker/sandbox-templates:gemini-docker` | Gemini CLI + Docker daemon | Gemini needs containers |
| `docker/sandbox-templates:base` | Bare Linux (no agent) | Custom toolchain, manual use |
| `docker/sandbox-templates:base-docker` | Bare Linux + Docker daemon | Custom toolchain with Docker |

The `-docker` variants include a full Docker daemon inside the sandbox. This inner daemon is completely isolated from the host Docker daemon -- they share no images, containers, volumes, or networks.

## Custom Dockerfile Pattern

Extend a base image to create a custom sandbox environment with your preferred tools pre-installed:

```dockerfile
# Use a base image as the starting point
FROM docker/sandbox-templates:claude-code

# Install system packages as root
USER root
RUN apt-get update && apt-get install -y \
    ripgrep \
    fd-find \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Switch back to the agent user for user-level tools
USER agent
RUN pip install --user poetry \
    && npm install -g typescript
```

Key points:

- Always extend a `docker/sandbox-templates:*` base image. These images include the proxy integration, networking configuration, and user setup that sandboxes require.
- Use `USER root` for system packages installed via `apt-get`.
- Use `USER agent` for user-level tools installed via `pip install --user`, `npm install -g`, `cargo install`, etc.
- The `agent` user is the default non-root user inside the sandbox. End your Dockerfile on `USER agent` so the sandbox starts as the correct user.
- Clean up `apt` cache (`rm -rf /var/lib/apt/lists/*`) to keep image size down.
- Do not override the `ENTRYPOINT` or `CMD` -- the base images set these for sandbox integration.

## Build, Push, Run Workflow

Custom images must be pushed to a registry that the host machine can pull from.

```bash
# Build the custom image
docker build -t myregistry.io/my-org/my-sandbox:v1.0 .

# Push to a registry
docker push myregistry.io/my-org/my-sandbox:v1.0

# Run a sandbox with the custom template
sbx run claude --template myregistry.io/my-org/my-sandbox:v1.0 ~/project
```

Requirements:

- The `--template` / `-t` flag requires a fully qualified registry path (e.g., `docker.io/org/image:tag` or `myregistry.io/org/image:tag`). A bare `image:tag` without a registry prefix will not resolve.
- The image must be accessible from the host machine. If using a private registry, ensure Docker is authenticated (`docker login`) before running `sbx run`.
- Tags are recommended for reproducibility. Using `:latest` works but makes it harder to roll back.

## Saving Sandbox State

Use `sbx save` to snapshot the current state of a running sandbox as a new template image. This captures all filesystem changes, installed packages, and configuration modifications made since the sandbox started.

```bash
# Snapshot current sandbox state — loads into host Docker daemon
sbx save my-sandbox myimage:v1.0

# Save as a tar file instead (works without host Docker running)
sbx save -o snapshot.tar my-sandbox myimage:v1.0

# Later, use the saved snapshot as a template
sbx run claude --template myimage:v1.0 ~/project
```

By default, `sbx save` loads the image into the host's Docker daemon (requires
Docker to be running). Use `--output` to save as a tar file instead.

When to use `sbx save`:

- After manually installing and configuring tools inside a shell sandbox, save the state so you can reuse it without repeating the setup.
- When iterating on an environment: start a sandbox, install tools, test them, then save once everything works.
- The tar output (`-o`) is useful for local testing, sharing with teammates, or environments without host Docker.

The saved image includes everything in the sandbox filesystem. Workspace files mounted from the host are NOT included in the snapshot -- only changes to the sandbox's own filesystem (installed packages, config files, etc.) are captured.

## Docker Daemon Inside Sandbox

When using `-docker` image variants, the sandbox includes a full Docker daemon that the agent can use to build and run containers.

```bash
# Run with a Docker-enabled image
sbx run claude --template docker/sandbox-templates:claude-code-docker ~/project

# Control Docker daemon disk allocation (default 8192 MB)
DOCKER_SANDBOXES_DOCKER_SIZE=16384 sbx run claude ~/project
```

Properties of the inner Docker daemon:

- Completely isolated from the host Docker daemon. No shared images, containers, volumes, or networks.
- The agent can `docker build`, `docker run`, `docker compose up`, etc. inside the sandbox.
- Disk for Docker images and layers is allocated from the sandbox's disk budget. Increase `DOCKER_SANDBOXES_DOCKER_SIZE` if you need space for large images.
- The inner Docker daemon is subject to the same network policy as the sandbox itself. Containers inside the sandbox that make outbound HTTP/HTTPS requests go through the proxy.

```bash
# Verify Docker is available inside a running sandbox
sbx exec -it my-sandbox docker info

# Check disk usage of the inner Docker daemon
sbx exec -it my-sandbox docker system df
```

## Memory Configuration

Control how much RAM is allocated to a sandbox VM:

```bash
# Default memory is 50% of host RAM, max 32 GiB
sbx run claude ~/project

# Explicitly set memory for large projects
sbx run claude -m 8g ~/project

# Check current memory inside a running sandbox
sbx exec -it my-sandbox free -h
```

Guidelines for memory sizing:

- **Default (50% of host RAM, max 32 GiB)** -- Sufficient for most agent tasks: code editing, running tests, linting, small builds.
- **`-m 8g`** -- Explicit 8 GiB. Useful for projects with large build systems, heavy test suites, or multiple concurrent processes.
- **`-m 16g`** -- For builds that require significant memory (e.g., compiling large Rust/C++ projects, running memory-intensive data processing).

If the agent reports out-of-memory errors or processes are killed unexpectedly, increase the memory allocation.

## Troubleshooting Custom Templates

Common issues when working with custom images and templates:

**Image not found:**

```text
Error: failed to pull image "myimage:v1.0"
```

The `--template` flag requires a fully qualified registry path. Use `myregistry.io/org/image:tag`, not just `image:tag`.

**Permission denied during build:**

```text
Permission denied: /usr/local/bin/some-tool
```

System-level installs require `USER root`. Switch to root before `apt-get` or writing to system paths, then switch back to `USER agent`.

**Agent fails to start:**

If overriding `ENTRYPOINT` or `CMD` in your Dockerfile, the sandbox integration may break. Remove any `ENTRYPOINT` or `CMD` overrides and let the base image handle startup.

**Disk space errors with inner Docker:**

```text
no space left on device
```

Increase the Docker disk allocation:

```bash
DOCKER_SANDBOXES_DOCKER_SIZE=16384 sbx run claude ~/project
```

**Network errors from containers inside the sandbox:**

Containers running inside the sandbox's inner Docker daemon are subject to the same network policies as the sandbox itself. Check `sbx policy log` for blocked requests and add allow rules as needed.
