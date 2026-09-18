# Disposable sandbox infrastructure

## Linux QEMU worker

Provision a dedicated Ubuntu/Debian host with `deploy/install-linux-host.sh`, then
install Sandworm's full extra as an unprivileged worker user. KVM accelerates
execution; QEMU TCG software emulation also works but is slower. Use a supported,
patched host/hypervisor. Do not run QEMU as root or give it host-directory mounts.

Download an Ubuntu 24.04 amd64 cloud image from
[Canonical](https://cloud-images.ubuntu.com/noble/current/) and verify the image
against its published signed SHA256SUMS. Pass the verified digest explicitly:

```bash
sudo bash deploy/install-linux-host.sh
sandworm sandbox-build ubuntu-cloud.img VERIFIED_SHA256 /var/lib/sandworm/images/linux-v1
export SANDWORM_PROFILES=/var/lib/sandworm/images/linux-v1/profiles.json
sandworm analyze samples/synthetic/benign_dropper.sh --profile linux
```

Provisioning is the only phase with a user-mode network adapter. It contains no
submitted sample, installs Python/PHP/Node/strace, disables SSH and serial login,
installs the root-owned guest agent, and shuts down. The output image is flattened
and hash-pinned in `profiles.json`. Every analysis verifies this hash and creates
a disposable qcow2 overlay. The guest receives sample bytes through a read-only
ISO. QEMU has **no network device**, no shared host folders and no forwarded ports.
The sample runs as an unprivileged guest account; the root guest agent captures
strace output separately from sample stdout and emits a bounded serial report.
Overlay and payload ISO are removed when the backend releases the VM.

Set `capture_memory: true` in a profile to pause the guest and capture physical
memory through QMP. Process the resulting image with Volatility and matching
offline symbols; compatibility depends on image format, kernel and plugins.
`options.canaries: "true"` places fake credentials/history tokens in the guest.
Different profiles can select engines, timeouts and canaries for differential
analysis. Supported engines: ELF, shell, PHP, Python and JavaScript.

The QEMU backend intentionally rejects `network: simulated` until a separate,
validated simulated-network deployment is supplied. It never falls back to host
networking. Guest compromise is possible: a VM boundary reduces exposure but does
not make the guest's observations cryptographically trustworthy.

For relocated unprivileged QEMU installs, set `PATH`, the library/module lookup
paths required by your distribution, and `SANDWORM_QEMU_DATA` to its QEMU firmware
directory. Normal system package installations do not need these overrides.

## Windows CAPE host and guest

Sandworm integrates the actual CAPE project rather than implementing a substitute.
The installation wrapper prepares its official installer at an explicit commit:

```bash
bash deploy/install-cape-host.sh FULL_CAPE_COMMIT_SHA /opt/cape-source
# Review the pinned installer on a dedicated host, then:
cd /opt/cape-source
sudo bash installer/cape2.sh base cape
```

Follow the [CAPE host installation guide](https://capev2.readthedocs.io/en/latest/installation/host/installation.html)
and [guest preparation guide](https://capev2.readthedocs.io/en/latest/installation/guest/).
Supply your Windows installation image/license, prepare a disposable Windows VM,
install CAPE's guest agent/analysis dependencies, and register a clean snapshot.
Configure the CAPE machinery and disabled/simulated routes, API token, immutable
image identifier and containment rules before enabling Sandworm's attestation.

```bash
export SANDWORM_CAPE_URL=https://cape.example/apiv2/
export SANDWORM_CAPE_TOKEN='<scoped API token>'
export SANDWORM_CAPE_IMAGE_ID='<registered clean snapshot identifier>'
export SANDWORM_CAPE_ISOLATION_VERIFIED=true
sandworm analyze benign-windows-test.exe --backend cape --sandbox-network disabled
```

The installation wrapper does not supply a Windows license, fabricate a clean
snapshot or automatically assert isolation. Validate with benign samples first:
job submission, artifact SHA-256 matching, guest reset, absence of public egress,
and successful teardown after a timeout or failure. Deployment needs administrator
access on that dedicated host. A WSL2 host without exposed virtualization cannot
provide hardware Intel-PT tracing or native KVM acceleration.

## Hardware traces

Sandworm imports **decoded** CPU branch traces in sample-bound runtime reports,
including instruction address, module identity/load base and process/thread IDs.
It correlates those events with static functions. Raw Intel PT packets must first
be decoded using a compatible capture environment and decoder (for example
perf/libipt). DRAKVUF requires its own Xen deployment. Neither hardware availability
nor a custom hypervisor/SMM instrumentation engine is provided by a Python package.
