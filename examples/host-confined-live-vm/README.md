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
  New sessions use live sharing; older snapshot sessions retain copy-back safeguards.
- [`build-confined-driver`](scripts/build-confined-driver) verifies pinned 0.1.7
  inputs, reuses vendor runtime artifacts and builds the patched control-plane
  driver. The [resource manifest](runtime/v0.1.7-resources.json) records those inputs.

The source patch is already applied in this branch. The retained
[`require-host-launcher.patch`](runtime/require-host-launcher.patch) is for the
archive-based build recipe; do not apply it a second time to this worktree.

## Run the preserved tests

From the repository root, on Linux with bubblewrap and Python 3.11+ available:

```shell
uv run --no-project --python /usr/bin/python3 python -B -m unittest discover \
  -s examples/host-confined-live-vm/tests -p 'test_*.py'
```

All 55 tests passed after import. Tests include direct host-process canary checks,
symlink/ancestor/proc/descriptor escape attempts, deployment-provenance checks and
legacy snapshot regressions. They are not guest-kernel exploit tests or a formal
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
