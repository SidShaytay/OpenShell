# Linux live-share confinement prototype

This directory preserves the tested Vega implementation supporting
[OpenShell #5437](https://github.com/NVIDIA/OpenShell/issues/5437). It is a local
0.1.7 prototype, not an upstream-supported installation or a proposed final API.

## Inspect the implementation

- The applied driver change is in
  [`crates/openshell-driver-vm/src/main.rs`](../../crates/openshell-driver-vm/src/main.rs).
  It requires an operator-selected launcher instead of using the default worker.
- [`openshell-vm-worker`](scripts/openshell-vm-worker) establishes the host-side
  filesystem/user/PID/network namespaces before running the vendor libkrun worker.
  It permits one selected project, exact disk/log files, runtime files and the
  VM's control endpoint. It does not expose the gateway's credential directory.
- [`openshell-vm-reaper`](scripts/openshell-vm-reaper) preserves the vendor worker's
  parent-death checks inside the private PID namespace.
- [`openshell-project`](scripts/openshell-project) is the `osh` client wrapper.
  Projects are live-shared. Snapshot download/apply commands have been removed.
  Deletion waits for gateway cleanup and removes the completed session record
  and generated policy.
- [`build-confined-driver`](scripts/build-confined-driver) verifies pinned 0.1.7
  inputs, reuses vendor runtime artifacts and builds the patched control-plane
  driver. The [resource manifest](runtime/v0.1.7-resources.json) records those inputs.

The source patch is already applied in this branch. The retained
[`require-host-launcher.patch`](runtime/require-host-launcher.patch) is for the
archive-based build recipe; do not apply it a second time to this worktree.

## Live host agent tools

New `osh` sessions mount `~/.local/share/openshell/agent-tools` read-only at
`/opt/host-tools`. The project remains the separate read/write mount.
`openshell-agent-tools` publishes the installed host Claude, Codex, Pi and Node
versions, their required helper files, and Pi's dependency closure. It never
copies host auth, settings, histories, or the host home directory.

The enabled user service `openshell-agent-tools.service` uses eight non-recursive
inotify watches: `~/.local/bin` (claude/codex), Claude's `versions` directory,
Codex's `standalone` directory (current), `~/.bun/bin` (pi), Bun's global install
root (lockfiles/package.json/node_modules), its `@earendil-works` scope (Pi
packages only), and Homebrew's `bin` and `opt` directories (node only). It does
not recursively watch dependencies or system libraries. Changes sync after two
quiet seconds. A fallback sync runs after six hours without a completed sync to
catch in-place dependency updates the small watch set misses. It also syncs at
startup. Run `osh tools` for immediate manual sync. Enable the service with
`systemctl --user enable --now openshell-agent-tools.service` (already enabled).
Each new tool
invocation in an already-running tools-enabled VM resolves its current release.
Existing processes keep their files; no VM restart or image rebuild is needed
for subsequent tool updates. VMs predating the tools mount need to be recreated
once to acquire the share.

Publishing uses atomic per-tool pointers and validates candidate versions before
switching. Old releases remain available for running processes and are not
removed automatically. Node includes its host shared libraries. The publisher
uses host `patchelf` (installed with `uv tool install patchelf==0.19.3.0`) to
relocate copied Node and Claude binaries; host executables are unchanged.
Guest authentication and state remain guest-local. The host watcher publishes
installed updates; it does not download newer agent versions itself.

The worker accepts only the selected project as `osfs0` and the exact read-only
tools directory as `osfs1`. Existing network endpoint grants stay unchanged;
network policy admits the corresponding host-published executable paths.

## Run the preserved tests

From the repository root, on Linux with bubblewrap and Python 3.11+ available:

```shell
uv run --no-project --python /usr/bin/python3 python -B -m unittest discover \
  -s examples/host-confined-live-vm/tests -p 'test_*.py'
```

The tests include direct host-process canary checks,
symlink/ancestor/proc/descriptor escape attempts, deployment-provenance checks and
live sharing and session cleanup regressions. They are not guest-kernel exploit tests or a formal
security proof. The imported driver file is byte-identical to the source used by
the deployed 0.1.7 build; this import did not rebuild or redeploy the runtime.

## Deployment and ownership

The scripts and sample configuration preserve Vega-specific paths, UID/GID,
service names and installed vendor artifacts. This is the relevant implementation
and test bundle, not a standalone portable installer. The original home-config
module retains deployment ownership for now, so cloning or checking out this
branch does not change any running service. Its installer, browser/image recipe,
project descriptors and private runtime state were not imported here.

`IMPORT-MANIFEST.json` records SHA-256 hashes of the unchanged imported files and
the home-config commits that introduced them. The applied Rust patch is against
the upstream `v0.1.7` tag. A future contribution should be adapted to current
upstream after maintainers agree on the supported design. In particular, #5176
already proposes a launcher hook, while #5437 requests the confinement guarantees.
