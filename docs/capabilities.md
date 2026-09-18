# Capability and validation checklist — 0.2.0

This checklist distinguishes shipped functionality from external infrastructure
and research work. “Implemented” does not mean every malware family, file variant
or deployment has been validated. Sandworm is an analysis aid, not an independent
proof of containment or a replacement for analyst review.

Measurement and hardening additions: a hash-pinned ATT&CK regression harness,
Brier/ECE/reliability reports, real-engine YARA-X goodware audits, constrained
copilot evidence selection, detection review bundles with optional Sigma KQL/SPL
conversion, an indexed SQLite corpus snapshot, and optional Aho–Corasick ransom
matching. See [measurement methods and remaining proposals](measurement.md).

## Shipped platform

| Area | Implemented | Validation / boundary |
| --- | --- | --- |
| Browser workspace | Login, uploads, profile selection, job search/paging, graph exploration, evidence search, grounded questions, downloads and exports | Chromium desktop/mobile workflow; no external asset dependencies |
| Authentication | Password sessions, CSRF checks, hashed expiring API keys, rotation/revocation, four roles, workspace boundaries | API tests; keys are shown once, never stored in plaintext |
| Administration | Member creation/disable, audit events, queue metrics | Local workspace administration; not enterprise SSO/SCIM |
| Durable jobs | Atomic leases, heartbeats, stale-job recovery, attempt fencing, cancellation and deadlines | SQLite transaction/concurrency tests; database must reside on local disk |
| Distributed execution | HTTPS worker protocol, worker-scoped credentials, sample hash checks, regenerated reports | Real loopback server/worker roundtrip; remote workers are trusted executors |
| Scheduling / retention | Delayed submissions, recurring analysis, missed-interval coalescing, dry-run retention, active-schedule source preservation | Automated schedule tests; retention is operator-invoked |
| Deployment | Wheel/sdist, Docker Compose TLS gateway, systemd units, host installers, environment diagnostics | Python packaging tested locally; container build/run covered by CI, not locally run without Docker |

## Shipped analysis

| Area | Implemented | Validation / boundary |
| --- | --- | --- |
| Core analysis | PE/ELF/script/document/archive routing, strings/IOCs, entropy, fingerprinting, disassembly, rules and plugins | Synthetic/unit fixtures; optional parser dependencies |
| Additional formats | Bounded JAR/APK string/API/member analysis, Mach-O slices/segments/imports, UEFI volume/FFS inventory | Synthetic malformed/bounds fixtures; not full Android execution, firmware authenticity or SMM analysis |
| Decompilation | Ghidra headless C/p-code export and instruction ranges, sample-bound ingestion | Live benign ELF on Ghidra 12.1.3; requires separately installed Ghidra/JDK |
| Emulation | Bounded Unicorn execution, selected memory-allocation/protection/copy API models, written executable-range recovery | Synthetic import/allocation tests; unknown OS APIs stop execution |
| Correlation | Runtime/static instruction and function matching with explicit address spaces and module identity | Boundary/gap/foreign-module tests; no fabricated matches |
| Runtime artifacts | CAPE reports, Linux strace, PHP/shell traces, decoded CPU events, process differences and canary correlations | Recorded artifacts plus Linux VM workflow; raw CPU trace packets not decoded |
| Memory | Offline Volatility collection and report ingestion for Windows/Linux, partial-error reporting, optional QMP capture | Report fixtures and installed CLI; actual dump/symbol compatibility needs deployment validation |
| Intelligence | Offline source-dated indicator snapshots, evidence citations, stale-data discounting | Tests; no automatic paid feeds or external uploads |
| ML grouping | Graph-neighborhood features and cosine DBSCAN clusters/outliers | Synthetic graph tests; not a trained family classifier or GNN |
| Copilot | Evidence-grounded answers and separately labeled, citation-validated speculative hypotheses | Evidence/citation tests; live LLM hypotheses require configured provider |
| Reporting | HTML/JSON/JSONL, graph, STIX/MISP/OpenIOC/CSV/Navigator, YARA/Sigma output | Regression fixtures; generated detections require analyst tuning |

## Sandbox infrastructure

The Linux image builder provisions a real QEMU guest from a verified Ubuntu cloud
image, installs an unprivileged execution account and guest collector, and emits
a hash-pinned image/profile. Analysis uses a fresh disposable overlay, read-only
payload ISO, no network adapter and no host directory mounts. TCG works without
KVM; hardware acceleration is optional. The image was built locally under TCG,
and a benign shell script returned nine runtime events in a live guest test.
Large guest images and downloaded tools are not committed to Git.

The CAPE installer wrapper pins the upstream source and provides deployment
instructions. A **live Windows CAPE deployment is not built or validated here**:
it needs a dedicated administrator-controlled host, a licensed Windows image,
guest preparation and verified snapshot/network isolation. Setting an environment
flag does not independently verify containment.

## Not complete / requires additional work

- Raw Intel PT acquisition/decoding, a Xen/DRAKVUF deployment, custom hypervisor
  instrumentation and SMM execution are not implemented. Decoded trace import is
  available; hardware capture cannot be substituted with fabricated observations.
- A trained GNN/family attribution model, labeled dataset, evaluation pipeline
  and measured accuracy are not provided. Clustering is exploratory similarity.
- Complete symbolic execution, universal unpacking, comprehensive OS API models,
  full Android/firmware emulation and every packed-file variant are not provided.
- Enterprise SSO/SCIM, high-availability database orchestration, object-store
  replication, Kubernetes autoscaling and managed threat-feed connectors are not
  included. The shipped service supports local durable storage and remote workers.
- Real Windows detonation, physical-memory symbol compatibility, production TLS
  and network containment, live external LLM providers, and hardware tracing need
  validation in the operator's deployment before production use.

See [platform setup](platform.md), [sandbox deployment](sandbox-deployment.md),
and [advanced analysis](advanced-analysis.md) for exact commands and prerequisites.
