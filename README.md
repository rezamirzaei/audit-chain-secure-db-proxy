# Database Server & Proxy Clone System

**Two completely separate projects** demonstrating:
1. A secure database server with multi-factor authentication (MFA)
2. A proxy clone used for **security education** *(demo mode only)*

## Important: These are Separate Projects!

- **Container 1 (Database Server)**: A standalone application with its own codebase. Contains the real database, authentication logic, and TOTP secrets.
- **Container 2 (Proxy Clone)**: A completely separate application that ONLY knows about Container 1's public HTTP interface. It has NO access to Container 1's internal code, secrets, or database.

In **demo mode**, the proxy captures credentials by:
1. Acting as a "man-in-the-middle" between the user and the database server
2. Capturing credentials as users enter them through the proxy's interface
3. Storing captured credentials to maintain persistent access

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          END USER                                    │
│                              │                                       │
│              ┌───────────────┴───────────────┐                       │
│              ▼                               ▼                       │
├─────────────────────────────────────────────────────────────────────┤
│  CONTAINER 2: Proxy Clone (Port 8080, HTTPS)                         │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                                                                  ││
│  │  ┌──────────────────────┐    ┌───────────────────────────────┐  ││
│  │  │   HOME Interface     │    │   MIRROR Mode                 │  ││
│  │  │   (QueryGate)        │    │   /mirror/*                   │  ││
│  │  │                      │    │                               │  ││
│  │  │  • Query Editor      │    │  Dynamically fetches and      │  ││
│  │  │  • Schema Browser    │    │  displays the original UI     │  ││
│  │  │  • Results Display   │    │  from Container 1 with a      │  ││
│  │  │  • Dark Theme UI     │    │  "PROXY MIRROR" banner        │  ││
│  │  └──────────────────────┘    └───────────────────────────────┘  ││
│  │                                                                  ││
│  │  ┌──────────────────────────────────────────────────────────┐   ││
│  │  │  Credential Vault (The "Breach")                         │   ││
│  │  │  • Captures and stores username/password                 │   ││
│  │  │  • Maintains session cookies from database server        │   ││
│  │  │  • Auto re-authenticates when sessions expire            │   ││
│  │  └──────────────────────────────────────────────────────────┘   ││
│  │                              │                                   ││
│  └──────────────────────────────┼───────────────────────────────────┘│
│                                 │ Proxied Requests                   │
│                                 ▼                                    │
├─────────────────────────────────────────────────────────────────────┤
│  CONTAINER 1: Database Server (Port 5002)                            │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │  Full MVC Architecture                                          ││
│  │                                                                  ││
│  │  ┌────────────┐ ┌────────────┐ ┌──────────────────────────────┐ ││
│  │  │   Views    │ │ Controller │ │     Model (PostgreSQL/SQLite)│ ││
│  │  │            │ │   (Flask)  │ │                              │ ││
│  │  │ • Login    │ │            │ │  Tables:                     │ ││
│  │  │ • Dashboard│ │ • Auth     │ │  • employees                 │ ││
│  │  │ • Employees│ │ • CRUD     │ │  • departments               │ ││
│  │  │ • Depts    │ │ • Query    │ │  • projects                  │ ││
│  │  │ • Projects │ │ • Audit    │ │  • audit_log                 │ ││
│  │  │ • Query    │ │            │ │                              │ ││
│  │  │ • Audit    │ │            │ │  Users:                      │ ││
│  │  └────────────┘ └────────────┘ │  • admin / SecurePass123!    │ ││
│  │                                │  • analyst / AnalystPass456! │ ││
│  │                                └──────────────────────────────┘ ││
│  │                                                                  ││
│  │  Session-based authentication (cookies expire after 2 hours)    ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start (Demo Mode)

```bash
# Build and start both containers (demo mode)
docker-compose up --build

# Access the applications:
# - Database Server (HTTPS): https://localhost:5002 (accept self-signed cert warning)
# - Proxy Clone (QueryGate):  https://localhost:8080 (accept self-signed cert warning)
```

## Production Mode

Production mode runs behind **Gunicorn + Nginx** with **Redis-backed sessions**.
Demo-only endpoints are disabled by default, but the proxy clone can be enabled
explicitly with `PROXY_FEATURES_ENABLED=true`.

Start the production stack:

```bash
docker-compose -f docker-compose.prod.yml up --build -d
```

Access:
- Proxy clone: `https://localhost/`
- Database server (direct): `https://localhost/db/`

Replace the TLS certs at `nginx/certs/` with your production certificates.

If you must keep demo endpoints in production, explicitly enable:
- `ENABLE_TOTP_TEST_ENDPOINT=true`
- `ENABLE_QUERY_CONSOLE=true`

## Seeding Demo Data

You can seed additional demo data (idempotent):

```bash
# Docker
docker exec database-server python /app/seed_data.py

# Local
python database_server/seed_data.py
```

## Audit Integrity Verification

Verify the tamper‑evident audit chain:

```bash
# Docker
docker exec database-server python /app/verify_audit_chain.py

# Local
python database_server/verify_audit_chain.py
```

## How to Use

### Option 1: Direct Access to Database Server (HTTPS)
1. Open https://localhost:5002 (accept the self-signed certificate warning)
2. Login with credentials:
   - **Admin**: `admin` / `SecurePass123!`
   - **Analyst**: `analyst` / `AnalystPass456!`
3. Enter your 2FA code from authenticator app (check server logs for TOTP secret)
4. Answer security question (admin: "blue", analyst: "fluffy")
5. Browse the dashboard, employees, departments, projects
6. Use the Query Console to run SQL queries

### Option 2: Through the Proxy (QueryGate) *(demo mode only)*
1. Open https://localhost:8080 (accept the self-signed certificate warning)
2. Go to "Connection" page
3. Enter credentials → proxy captures them and forwards to HTTPS server
4. Enter 2FA code when prompted → proxy captures and forwards
5. Answer security question → proxy captures and stores for future use
6. Use the HOME interface to write and execute queries
7. Click "Mirror Original UI" to see the database server's UI through the proxy

## Features

### Container 1: Database Server
- **HTTPS with SSL/TLS** - Self-signed certificate for secure communication
- **PostgreSQL (Docker default)** with persistent storage *(SQLite fallback for local/dev)*
- **MVC Architecture** with proper separation of concerns
- **Beautiful UI** with Bootstrap 5 and sidebar navigation
- **Password & Security Answer Hashing** (Argon2)
- **CSRF protection** for HTML forms
- **Basic rate limiting** on authentication endpoints
- **Security headers** (HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
- **Multi-Factor Authentication**:
  - Step 1: Password authentication
  - Step 2: TOTP 2FA (Time-based One-Time Password)
  - Step 3: Security Question verification
- **Session-based Auth** using secure cookies (2-hour expiry)
- **Server-side sessions** via Redis (Flask-Session)
- **Audit Logging** of all queries and actions
- **Tamper‑evident audit chain** (hash‑linked entries)
- **Disaster Recovery (Barman)** - streaming backups + WAL for point-in-time restore (PITR)
- **Query Console** for running SQL queries
- **Pages**: Login, 2FA Verify, Security Question, Dashboard, Employees, Departments, Projects, Audit Log

## Disaster Recovery (PostgreSQL + Barman)

This repo ships a working **PostgreSQL + Barman** setup to support the full DR lifecycle:
**regular backups**, **WAL archiving**, and **point-in-time restore (PITR)**.

In the Docker stack:
- `postgres` = primary database (the app connects here)
- `barman` = backup server (takes base backups + stores WAL for PITR)
- WAL archiving is enabled via PostgreSQL `archive_command` in `docker-compose.yml` and stored on a shared `wal-archive` volume (demo-friendly).

Notes:
- The app uses Postgres by default when `DATABASE_URL` is set; otherwise it falls back to SQLite.
- `pg_basebackup` does **not** copy config files outside `PGDATA`. In this repo `pg_hba.conf` is mounted separately, so Barman will warn about it during backup (expected).

Common commands:

```bash
# Use `docker compose` instead of `docker-compose` if you're on Compose v2

# Validate configuration/connectivity
docker-compose exec barman barman check main

# Take a base backup
docker-compose exec barman barman backup main

# List available backups
docker-compose exec barman barman list-backup main

# (Optional) force a WAL switch then let Barman ingest it
docker-compose exec postgres psql -U postgres -d appdb -c "SELECT pg_switch_wal();"
docker-compose exec barman barman cron
```

Recovery (PITR, high-level):
1. Pick a backup id: `docker-compose exec barman barman list-backup main`
2. Optionally create a restore point on the primary:
   `docker-compose exec postgres psql -U postgres -d appdb -c "SELECT pg_create_restore_point('my_point');"`
3. Recover: `docker-compose exec barman barman recover --target-name my_point --target-action promote main <BACKUP_ID> <DEST_DIR>`
4. Start a new Postgres instance pointing at `<DEST_DIR>`, then repoint the app to it.

Hands-on verification:
- `./scripts/test_setup.sh` runs a Barman `check` + `backup`.
- `bash scripts/dr_restore_drill.sh` runs an end-to-end PITR drill:
  - takes a backup
  - creates a restore point
  - writes a marker row after the restore point
  - restores to the restore point
  - asserts the marker row is **absent** in the recovered database
  - use `KEEP_RESTORED=1` to keep the recovered Postgres container running on `localhost:55432`

### Container 2: Proxy Clone
- **Own HOME Interface** (QueryGate) - dark themed, modern UI
- **Mirror Mode** *(demo only)* - dynamically clones the original database server UI via HTTPS
- **Credential Vault** *(demo only)* - stores captured credentials (simulates breach)
- **Multi-Step Auth Handler** *(demo only)* - captures password, 2FA codes, and security answers
- **Session Management** - maintains and refreshes session cookies
- **Server-side sessions** via Redis (Flask-Session)
- **HTTPS Client** - connects to database server via HTTPS (ignores self-signed cert)
- **Query Editor** with schema browser and results display
- **Transparent Proxying** - all requests go through with stored auth

## Default Credentials

| User | Username | Password | Role |
|------|----------|----------|------|
| Admin | admin | SecurePass123! | admin |
| Analyst | analyst | AnalystPass456! | analyst |

## API Endpoints

### Database Server (Port 5002)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/` | Home (redirects) | No |
| GET/POST | `/login` | Login page | No |
| GET | `/dashboard` | Dashboard | Yes |
| GET | `/employees` | Employees list | Yes |
| GET | `/departments` | Departments list | Yes |
| GET | `/projects` | Projects list | Yes |
| GET | `/query` | Query console *(demo only)* | Yes |
| GET | `/audit` | Audit log (admin) | Yes |
| GET | `/api/audit/verify` | Verify audit chain (admin) | Yes |
| GET | `/api/health` | Health check | No |
| GET | `/api/session` | Session info | No |
| POST | `/api/login` | API login | No |
| GET | `/api/tables` | List tables *(demo only)* | Yes |
| POST | `/api/query` | Execute query *(demo only)* | Yes |

**Demo-only test endpoint**: `GET /api/totp/current?username=admin` (only when `ENABLE_TOTP_TEST_ENDPOINT=true`)

### Proxy Clone (Port 8080, HTTPS) *(demo mode only)*

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | QueryGate home |
| GET/POST | `/connect` | Enter credentials |
| POST | `/disconnect` | Clear credentials |
| GET | `/mirror/*` | Mirror original UI |
| GET | `/api/health` | Proxy health (non-sensitive) |
| GET | `/api/status` | Proxy status (requires local proxy session) |
| POST | `/api/connect` | API connect |
| POST | `/api/query` | Execute query (proxied) |
| GET | `/api/tables` | Get tables (proxied) |

## Project Structure

```
.
├── docker-compose.yml
├── docker-compose.prod.yml
├── nginx/
│   ├── nginx.conf
│   └── certs/
├── database_server/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── gunicorn.conf.py
│   ├── app.py
│   ├── verify_audit_chain.py
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html
│       ├── employees.html
│       ├── departments.html
│       ├── projects.html
│       ├── query.html
│       └── audit.html
└── proxy_clone/
    ├── Dockerfile
    ├── requirements.txt
    ├── gunicorn.conf.py
    ├── app.py
    ├── certs/
    └── templates/
        ├── base.html
        ├── home.html
        └── connect.html
```

## Demo Mode vs Production Mode

This project now supports **production-safe defaults**. The proxy clone, query console,
and test TOTP endpoint are **disabled in production** and only available in **demo mode**.

**Demo mode (default in docker-compose/run scripts)**:
- Proxy clone UI, mirror mode, and credential capture flows enabled
- Query console enabled
- `/api/totp/current` test endpoint enabled

**Production mode**:
- Proxy demo features disabled by default (enable with `PROXY_FEATURES_ENABLED=true`)
- Query console disabled
- Test TOTP endpoint disabled
- Passwords and security answers hashed
- Secure cookies + security headers enabled
- Server-side sessions via Redis

Set `APP_ENV=production` to enable production mode. For demo behavior set:
`APP_ENV=demo`, `ENABLE_TOTP_TEST_ENDPOINT=true`, `ENABLE_QUERY_CONSOLE=true`.

To keep the proxy clone enabled in production:
`PROXY_FEATURES_ENABLED=true`

## How the "Breach" Works (Demo Mode Only)

The proxy has **NO internal access** to the database server. It only:

1. **Intercepts User Input**: When a user enters credentials through the proxy, they are captured
2. **Forwards Authentication**: The proxy forwards authentication requests to the real server
3. **Handles Multi-Step Auth**: 
   - Step 1: Captures username + password
   - Step 2: Prompts user for 2FA code, captures it, forwards to server
   - Step 3: Shows security question (from server), captures answer, forwards to server
4. **Stores Everything**: All captured credentials are stored for future re-authentication
5. **Maintains Session**: Uses captured cookies to maintain access
6. **Auto Re-login**: When session expires, uses stored credentials (including security answer) to re-authenticate

**Key Point**: The proxy cannot bypass 2FA on its own. It must capture a valid TOTP code from a legitimate user each time a 2FA step is required. Stored security answers can only be used after a fresh 2FA code is provided.

## Security Note

⚠️ **This is for educational/demonstration purposes only!**

This demonstrates:
- How credentials can be captured by a malicious proxy
- How sessions can be hijacked and maintained
- How UIs can be cloned/mirrored
- The importance of verifying you're on the correct server

In production:
- Always verify SSL certificates
- Use HTTPS everywhere
- Implement 2FA
- Monitor for unauthorized access
- Use secrets management
