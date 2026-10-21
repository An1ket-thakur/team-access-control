# Team Access Control API

A multi-tenant, IAM-style backend for a SaaS product: authentication, organizations, memberships, roles, permissions, invitations, sessions, API keys and audit logs.

Built with Node.js, TypeScript, Express 5, PostgreSQL (Drizzle ORM), Redis, Zod, Jest and Supertest.

## Features

**Core**

- Signup, login, logout
- Argon2id password hashing
- Short-lived JWT access token (15 minutes)
- Refresh token rotation with reuse detection
- Only refresh token **hashes** are stored
- Organizations and team membership
- Roles: `owner`, `admin`, `member`, `viewer`
- Permissions: `users.read`, `users.invite`, `projects.write`, `billing.read` (plus a few more needed to manage the system)
- Route-level permission guards (deny by default)
- Resource-level ownership checks
- Invitations with expiring, single-use, hashed tokens and an accept flow
- Session list and revoke (instant, via a Redis denylist)
- Audit log: login, invite, role change, permission change (and more)
- Redis rate limiting on auth routes
- Swagger / OpenAPI at `/docs`
- Integration tests for auth and permission failure cases
- Password reset flow
- API keys for machine-to-machine access
- Soft delete for users, organizations and projects
- ABAC-style ownership rule (`src/lib/policy.ts`)
- Request ID middleware
- Structured errors
- Pagination and filtering on list endpoints

## Quick start

Requirements: Node 22, Docker (for PostgreSQL and Redis).

```bash
docker compose up -d        # PostgreSQL 16 + Redis 7
npm install
npm run db:setup            # migrations + seed of roles and permissions
npm run dev                 # http://localhost:3000   (API docs at /docs)
```

Configuration lives in `.env` (see [Configuration](#configuration)). The defaults work for local development.

### Tests

The tests use a separate `tac_test` database and Redis db `1`, so they never touch your development data. Migrations and the seed run automatically before the suite.

```bash
docker compose exec postgres createdb -U tac tac_test     # once
npm test
```

### Scripts

| Script                        | What it does                                                      |
| ----------------------------- | ----------------------------------------------------------------- |
| `npm run dev`                 | Start the API with auto-reload                                    |
| `npm run build` / `npm start` | Compile to `dist/` and run it                                     |
| `npm run typecheck`           | `tsc --noEmit` (includes tests)                                   |
| `npm run db:migrate`          | Apply pending SQL migrations (advisory-locked, in filename order) |
| `npm run db:seed`             | Upsert the permission catalog and role templates (idempotent)     |
| `npm run db:setup`            | Both of the above                                                 |
| `npm test`                    | Jest + Supertest integration tests                                |

## Configuration

All settings are validated at startup; the server refuses to boot on a bad value and never prints secrets.

| Variable                                    | Default       | Notes                                                                                                                |
| ------------------------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------- |
| `NODE_ENV`                                  | `development` | `development`, `test` or `production`                                                                                |
| `PORT`                                      | `3000`        |                                                                                                                      |
| `TRUST_PROXY`                               | `false`       | Set to `1` behind a reverse proxy so `req.ip` and rate limiting use `X-Forwarded-For`                                |
| `LOG_LEVEL`                                 | `info`        | pino level                                                                                                           |
| `DATABASE_URL`                              | required      | e.g. `postgres://tac:tac@localhost:5432/tac`                                                                         |
| `REDIS_URL`                                 | required      | e.g. `redis://localhost:6379`                                                                                        |
| `JWT_SECRET`                                | required      | At least 32 characters. Generate one with `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `ACCESS_TOKEN_TTL_SECONDS`                  | `900`         |                                                                                                                      |
| `REFRESH_TOKEN_TTL_DAYS`                    | `7`           |                                                                                                                      |
| `INVITE_TTL_HOURS`                          | `72`          |                                                                                                                      |
| `PASSWORD_RESET_TTL_MINUTES`                | `30`          |                                                                                                                      |
| `RATE_LIMIT_AUTH_MAX` / `_WINDOW_SECONDS`   | `10` / `60`   | Auth routes                                                                                                          |
| `RATE_LIMIT_GLOBAL_MAX` / `_WINDOW_SECONDS` | `300` / `60`  | Per-IP ceiling for everything else                                                                                   |
| `EXPOSE_DEV_TOKENS`                         | `false`       | See the note below                                                                                                   |

> There is **no email service**. With `EXPOSE_DEV_TOKENS=true` (the local development setting), invitation and password-reset tokens are returned in the API response so you can try the flows. In production it must be `false` (the server refuses to start otherwise), and the token should be sent by email at the marked integration points.

## Try it

Open `http://localhost:3000/docs`, call `POST /auth/signup`, press **Authorize** and paste the `accessToken`.

Or follow the whole story with `curl` (bodies below use `jq` only to pick values out of responses):

```bash
API=http://localhost:3000
json='content-type: application/json'
PW='correct-horse-battery'

# 1. Two users: an owner and a teammate
OWNER=$(curl -s $API/auth/signup -H "$json" -d "{\"email\":\"owner@example.com\",\"password\":\"$PW\",\"name\":\"Owner\"}" | jq -r .accessToken)
MATE=$(curl -s  $API/auth/signup -H "$json" -d "{\"email\":\"mate@example.com\",\"password\":\"$PW\",\"name\":\"Mate\"}"  | jq -r .accessToken)
MATE_ID=$(curl -s $API/me -H "authorization: Bearer $MATE" | jq -r .user.id)

# 2. The owner creates an organization
ORG=$(curl -s $API/orgs -H "authorization: Bearer $OWNER" -H "$json" -d '{"name":"Acme Inc"}' | jq -r .organization.id)

# 3. Invite the teammate as a viewer, and accept (the token is returned because EXPOSE_DEV_TOKENS=true)
TOKEN=$(curl -s $API/orgs/$ORG/invitations -H "authorization: Bearer $OWNER" -H "$json" \
  -d '{"email":"mate@example.com","role":"viewer"}' | jq -r .inviteToken)
curl -s $API/invitations/accept -H "authorization: Bearer $MATE" -H "$json" -d "{\"token\":\"$TOKEN\"}"

# 4. A viewer cannot read billing -> 403, and the response names the missing permission
curl -s $API/orgs/$ORG/billing -H "authorization: Bearer $MATE"

# 5. The owner promotes the teammate to admin -> the same call is now 200
curl -s -X PATCH $API/orgs/$ORG/members/$MATE_ID -H "authorization: Bearer $OWNER" -H "$json" -d '{"role":"admin"}'
curl -s $API/orgs/$ORG/billing -H "authorization: Bearer $MATE"

# 6. Who did what
curl -s "$API/orgs/$ORG/audit-logs?limit=20" -H "authorization: Bearer $OWNER"
```

## Architecture

```
src/
  app.ts                 express wiring, health check, docs
  server.ts              process entry point and graceful shutdown
  config.ts              validated env (fails fast)
  schema.ts / db.ts      Drizzle tables, pg pool
  redis.ts               rate limiting and session denylist
  openapi.ts             OpenAPI 3 document (auth bodies generated from Zod)
  middleware/
    requestId.ts         X-Request-Id in and out
    auth.ts              Bearer JWT or X-API-Key -> req.principal
    permissions.ts       orgContext (membership / key scope) + requirePermission()
    rateLimit.ts         Redis fixed-window limiter
    errorHandler.ts      structured, non-leaky errors
  lib/                   errors, crypto, password, audit, policy (ABAC), pagination, permissions
  modules/               auth, sessions, users, orgs, members, roles, invitations,
                         apikeys, projects, audit
migrations/              001_users ... 008_audit_logs (plain SQL, applied in order)
scripts/                 migrate, seed
tests/                   Jest + Supertest integration tests
```

### Migrations

| File                        | Adds                                    |
| --------------------------- | --------------------------------------- |
| `001_users.sql`             | `users`                                 |
| `002_sessions.sql`          | `sessions`                              |
| `003_password_reset.sql`    | `password_reset_tokens`                 |
| `004_organizations.sql`     | `organizations`, `roles`, `memberships` |
| `005_permissions.sql`       | `permissions`, `role_permissions`       |
| `006_invitations.sql`       | `invitations`                           |
| `007_projects_apikeys.sql` | `projects`, `api_keys`                  |
| `008_audit_logs.sql`        | `audit_logs`                            |

### Data model

`users`, `organizations`, `memberships`, `roles`, `permissions`, `role_permissions`, `sessions`, `invitations`, `audit_logs`, plus `password_reset_tokens`, `api_keys` and `projects`.

**Roles are per organization.** `roles` rows with `org_id IS NULL` are system templates, copied (with their permissions) into every new organization. Editing a role's permissions in one tenant therefore never affects another.

### Auth flow

1. `POST /auth/login` verifies the Argon2id hash (a dummy hash is checked for unknown emails, so timing does not reveal which accounts exist) and creates a `sessions` row.
2. The response has a 15-minute JWT (`sub` = user, `sid` = session) and a refresh token `<sessionId>.<secret>`. Only `sha256(refreshToken)` is stored.
3. `POST /auth/refresh` swaps the refresh token for a new one (a compare-and-swap in SQL, so only one concurrent request wins). The previous hash is kept; if an **old** token is presented again, the whole session is revoked and `session.reuse_detected` is audited.
4. Revoking a session (logout, `DELETE /me/sessions/:id`, password reset, account deletion) sets `revoked_at` and writes a Redis denylist key lasting as long as any access token could live, so access tokens stop working immediately instead of at expiry.

### Permission flow

```
request -> requestId -> rate limit -> authenticate (JWT or API key)
        -> orgContext (is the caller a member of :orgId? load role permissions;
                       an API key must belong to that org)         non-members get 404
        -> requirePermission('x')   all required permissions, else 403
        -> handler: resource-level rule (ownership / ABAC), always scoped by org_id
```

- **Deny by default.** A missing principal is 401, a missing permission is 403, and a guard used without org context denies.
- **No privilege escalation.** You can only assign or modify roles below your own (owners excepted), cannot change your own role, and cannot grant permissions you do not hold. An API key can never hold more than its creator. The `owner` role is immutable, and the last owner cannot leave or be demoted.
- **ABAC rule for projects** (`src/lib/policy.ts`). `projects.manage_any` can modify anything. Otherwise you must be the project's owner **and** the project must not be archived.
- **People vs. keys.** API keys carry permissions but no role, so member, role and invitation management, account endpoints and key management are user-only. Keys work on resource endpoints such as projects, within their scope.

### Default roles

| Permission            | owner | admin | member | viewer |
| --------------------- | :---: | :---: | :----: | :----: |
| `users.read`          |   ✓   |   ✓   |   ✓    |   ✓    |
| `users.invite`        |   ✓   |   ✓   |        |        |
| `users.manage`        |   ✓   |   ✓   |        |        |
| `projects.read`       |   ✓   |   ✓   |   ✓    |   ✓    |
| `projects.write`      |   ✓   |   ✓   |   ✓    |        |
| `projects.manage_any` |   ✓   |   ✓   |        |        |
| `billing.read`        |   ✓   |   ✓   |        |        |
| `audit.read`          |   ✓   |   ✓   |        |        |
| `apikeys.manage`      |   ✓   |   ✓   |        |        |
| `roles.manage`        |   ✓   |       |        |        |
| `org.manage`          |   ✓   |       |        |        |

Roles can be edited per organization with `PUT /orgs/:orgId/roles/:roleName/permissions`; every grant and revoke is audited.

### API keys

Keys look like `tak_<8 chars>_<secret>` and are sent as the `X-API-Key` header. The full key is shown **once** at creation; only its SHA-256 is stored, and the short prefix is just a lookup handle. A key belongs to one organization, carries its own permission list, can expire, and can be revoked.

### Audit log

Every sensitive action writes an `audit_logs` row with the actor (user or API key), the target, a small metadata object, the request ID and the IP. Read it at `GET /orgs/:orgId/audit-logs` (needs `audit.read`; filter by action, action prefix, actor, target type and date range) or your own activity at `GET /me/audit-logs`. Never put secrets in audit metadata.

## Security notes

- Passwords: Argon2id (OWASP-recommended parameters), length-only policy (10 to 128 characters).
- High-entropy tokens (refresh, invite, reset, API keys) are stored as SHA-256; the raw value is shown or sent once.
- JWT algorithm pinned to HS256 with issuer and audience checks; the secret must be at least 32 characters.
- Invite, reset and accept failures return one generic error each; login failures never say which part was wrong.
- Rate limits: per IP **and** per email on login and forgot-password; per IP on signup, refresh, reset and invitation accept; plus a global per-IP ceiling. Behind a proxy set `TRUST_PROXY=1`.
- Errors never include stack traces or SQL. Every error carries a `requestId` that matches the server logs. Authorization headers, API keys and tokens are redacted from logs.
- State changes and their audit rows commit in the same transaction. Login, logout, signup and session-revoke audit rows are written right after the action, not in a shared transaction.

Known trade-offs:

- If Redis is down when a session is revoked, its access token stays valid until it expires (at most 15 minutes).
- The rate limiter fails open if Redis is unreachable, so a cache outage does not take the API down.
- Signup reveals whether an email is already registered (it is rate limited).

## API reference

Browse `/docs` (Swagger UI) or fetch `/openapi.json`. Groups: Auth, Me & Sessions, Organizations, Members, Roles & Permissions, Invitations, API Keys, Projects, Audit.

Every error response has the same shape:

```json
{ "error": { "code": "FORBIDDEN", "message": "...", "details": {}, "requestId": "..." } }
```

with `code` one of `VALIDATION_ERROR`, `UNAUTHENTICATED`, `INVALID_CREDENTIALS`, `INVALID_TOKEN`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `RATE_LIMITED`, `INVITATION_INVALID` or `INTERNAL_ERROR`. List endpoints accept `page` and `limit` (max 100) and return `{ data, meta: { page, limit, total, totalPages } }`.
