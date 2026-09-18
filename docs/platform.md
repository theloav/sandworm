# Sandworm operational platform

## Local start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[full]'
export SANDWORM_WORK_DIR="$PWD/.sandworm"
# Set SANDWORM_SAMPLE_PASSWORD from your secret manager for private deployments.
sandworm user-add analyst --workspace lab --role admin
sandworm serve --local-http
```

In a second terminal with the same environment:

```bash
sandworm worker
```

Open http://127.0.0.1:8000. Log in, submit a sample, inspect its evidence/graph,
ask questions, and download reports and defender exports. The UI polls job status.
`--local-http` is restricted to loopback; deployments use HTTPS and secure cookies.

## Accounts and service keys

Passwords use salted scrypt. Session cookies are HttpOnly/SameSite=Strict, expire
after eight hours, and require CSRF headers for changes. Service keys use 256-bit
random values with SHA-256 hashes stored server-side; raw keys are shown once.
Keys expire after 30 days and can be revoked or rotated. Credentials inherit the
account's workspace and role. Disabling an account immediately disables its keys
and sessions. Rate limits cover login, submissions and authenticated requests.

Roles: `viewer` reads workspace results; `analyst` submits/cancels/schedules;
`admin` also manages workspace accounts and reads its audit trail; `worker` claims
and executes its workspace's jobs. Workers are trusted executors and can read
samples assigned to them and submit analysis evidence. Never distribute a worker
key to an untrusted machine.

The workspace boundary is enforced on every job, evidence, graph, download,
export, schedule, user-management and worker endpoint. Reports download as
attachments so sample-derived HTML is not served in the application's origin.

## API

Authenticate scripts with `Authorization: Bearer <key>`. The browser uses session
cookies. Authenticated API schema: `GET /api/openapi.json`.

| Endpoint | Function |
|---|---|
| `POST /api/jobs?name=example.php&profile=static&delay=0` | Raw sample bytes, maximum 32 MiB; returns queued job |
| `GET /api/jobs?q=...&offset=0` | Workspace search, pages of 100 |
| `GET /api/jobs/{id}` | Status, findings, error, worker timestamps |
| `POST /api/jobs/{id}/cancel` | Cancel queued/running job |
| `GET /api/jobs/{id}/evidence?q=...&offset=0` | Searchable evidence |
| `GET /api/jobs/{id}/graph` | Nodes and edges |
| `GET /api/jobs/{id}/download/{html,json,jsonl}` | Download report/findings/evidence |
| `GET /api/jobs/{id}/export/{stix,misp,navigator,openioc,csv}` | Defender exports |
| `POST /api/jobs/{id}/ask` | JSON `{"question":"..."}` |
| `POST /api/jobs/{id}/schedule` | JSON `{"interval_seconds":3600}` |
| `GET /api/schedules`, `DELETE /api/schedules/{id}` | List/disable recurring schedules |
| `GET /api/metrics`, `GET /api/events` | Workspace queue metrics and admin audit trail |
| `GET/POST /api/keys`, `DELETE /api/keys/{id}`, `POST /api/keys/{id}/rotate` | Key lifecycle |
| `GET/POST /api/users`, `DELETE /api/users/{id}` | Admin account management/deactivation |

Only named, operator-configured profiles are accepted. Users cannot submit shell
commands or host paths as job options. Delayed jobs wait until their due time.
Recurring schedules coalesce missed intervals into one run. Their encrypted
source samples remain retained while the schedule is enabled.

## Workers and recovery

The API never executes sample bytes. Worker controller processes perform static
parsing and submit live execution to QEMU/CAPE. Each analysis attempt has an
independent subprocess, wall-clock deadline, output directory and fencing token.
Cancellation stops the attempt's process group. A worker missing its heartbeat
for 90 seconds loses its lease; stale result publication is rejected. Jobs retry
up to three claims after worker loss. Ordinary analysis failures remain visible
as failed jobs instead of silently retrying indefinitely.

Run multiple local `sandworm worker` processes against the same work directory.
SQLite's queue uses atomic transactions; keep the database on a local filesystem,
not NFS. Remote machines use HTTPS rather than sharing SQLite:

```bash
# On the API host; password is prompted without echo.
sandworm user-add linux-worker --workspace lab --role worker
sandworm key-issue linux-worker

# On the worker; configure matching profile names locally.
export SANDWORM_WORKER_KEY='<the issued key>'
export SANDWORM_PROFILES=/etc/sandworm/profiles.json
sandworm worker --url https://your-sandworm-host
```

A remote worker checks the downloaded sample hash, stores it encrypted during
processing, and uploads structured evidence. The API regenerates reports and
detections from that evidence. Do not put keys in URLs or command-line arguments.

## Deployment and retention

Systemd units are in `deploy/`. Use an unprivileged `sandworm` account and a private
`/var/lib/sandworm` directory. Put configuration in `/etc/sandworm/environment` with
mode 0600. Serve behind a TLS reverse proxy. The provided Docker Compose deployment
includes Caddy with a local CA; trust that CA locally or replace its TLS settings
with your organization's certificate. Container workers provide static analysis;
use a dedicated remote sandbox host for QEMU/CAPE.

```bash
export SANDWORM_SAMPLE_PASSWORD='<strong private archive password>'
docker compose -f deploy/compose.yml up --build -d
docker compose -f deploy/compose.yml exec api sandworm user-add analyst --workspace lab
# https://localhost:8443 (trust the local Caddy CA first)

sandworm retention --days 30           # dry run
sandworm retention --days 30 --apply   # permanently remove expired job artifacts
```

Back up the SQLite database using SQLite's backup API together with the encrypted
job artifacts and secret-manager configuration. Audit events remain after
retention, but are not cryptographically tamper-proof. No SSO, multi-region database,
or regulatory compliance certification is implied by this deployment.
