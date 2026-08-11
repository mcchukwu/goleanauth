# GoleanAuth

A production-grade authentication and authorization service written in Go.
GoleanAuth is an OAuth 2.0 / OpenID Connect provider with email/password and
social sign-in (Google, Apple), refresh-token rotation, session management,
an interactive consent flow, admin tooling, and a full audit trail.

---

## Features

- **Email/password auth** — registration and login with normalized identifiers
  (email or phone), `bcrypt` password hashing, and user verification flags.
- **Social sign-in** — Sign in with Google and Apple (Apple is
  placeholder-tolerant so it runs without a paid developer account).
- **Sessions** — refresh-token rotation on every refresh, per-device logout,
  and revoke-all-devices.
- **OAuth 2.0 provider** — authorization code + [PKCE (S256)][rfc7636],
  client credentials, and refresh grants; token introspection
  ([RFC 7662][rfc7662]) and revocation ([RFC 7009][rfc7009]).
- **OpenID Connect** — `/userinfo`, `/.well-known/openid-configuration`, and
  `/.well-known/jwks.json` (Ed25519 signing).
- **Interactive consent** — self-hosted login, consent, and error pages for
  the browser authorization flow.
- **Admin tooling** — client registration via an admin API (gated by a static
  `X-Admin-Key`) or the `create-client` CLI.
- **Audit logging** — an append-only action trail (`users`, `sessions`, and
  `clients` are traced) for enterprise accountability.
- **Operational hygiene** — rate limiting, security headers, request IDs,
  structured logging, graceful shutdown, and health/readiness/liveness
  endpoints.
- **Tested against Postgres** — unit tests (sqlmock) plus an integration
  suite that runs migrations against a real PostgreSQL 18 container.

[rfc7636]: https://www.rfc-editor.org/rfc/rfc7636
[rfc7662]: https://www.rfc-editor.org/rfc/rfc7662
[rfc7009]: https://www.rfc-editor.org/rfc/rfc7009

## Tech stack

| Layer      | Choice                                                    |
| ---------- | --------------------------------------------------------- |
| Language   | Go 1.26 (`net/http` with Go 1.22+ method-based routes)    |
| Database   | PostgreSQL 18, driven through `pgx/v5` (stdlib driver)    |
| Tokens     | Ed25519-signed JWTs (`golang-jwt/jwt/v5`)                 |
| Migrations | `pressly/goose/v3` with embedded SQL                      |
| Config     | Environment variables via `godotenv`                      |
| Validation | `go-playground/validator/v10` plus custom rules           |
| Infra      | `docker compose` for local Postgres                       |

## Quick start

Prerequisites: Go 1.26+, Docker (for Postgres), and optionally `openssl`.

```sh
# 1. Configure the environment
cp .env.example .env          # then fill in DB_* and GOOGLE_* values

# 2. Start Postgres 18
docker compose up -d postgres

# 3. Apply migrations
make migrate-up

# 4. Run the server
make run
```

Verify it is up:

```sh
curl http://localhost:8080/v1/live
```

Browse the interactive API reference at http://localhost:8080/docs (ReDoc),
or fetch the raw spec at http://localhost:8080/docs/openapi.yaml.

## Configuration

Configuration is read from the environment (and `.env`). The table below
lists every option; `.env.example` documents each with usage notes.

| Variable                 | Default                      | Description                                                        |
| ------------------------ | ---------------------------- | ------------------------------------------------------------------ |
| `APP_ENV`                | `development`                | `development` or `production` (changes cookie, key, and docs behavior). |
| `APP_PORT`               | `8080`                       | HTTP listen port.                                                  |
| `DB_URL`                 | — (required)                 | Postgres connection string.                                        |
| `ISSUER`                 | `http://localhost:8080`      | Public base URL issued in tokens and discovery documents.          |
| `JWT_PRIVATE_KEY`        | empty                        | Ed25519 private key (PKCS#8 PEM). Empty in dev = ephemeral key; **required in production**. |
| `JWT_PUBLIC_KEYS`        | empty                        | Extra public keys (PKIX PEM) kept for verification during rotation.|
| `ACCESS_TOKEN_TTL_MINUTES` | `15`                       | Access-token lifetime.                                             |
| `REFRESH_TOKEN_TTL_HOURS`  | `720`                      | Refresh-token (session) lifetime.                                  |
| `TRUST_PROXY`            | `false`                      | Trust `X-Forwarded-For`/`X-Real-IP`. **Never enable when exposed directly.** |
| `SERVE_DOCS`             | on in dev, off in prod       | Serve `/docs` (ReDoc) and `/docs/openapi.yaml`.                    |
| `CORS_ALLOWED_ORIGINS`   | empty                        | Comma-separated allowed origins.                                   |
| `GOOGLE_CLIENT_ID`       | — (required)                 | Google OAuth client ID.                                            |
| `GOOGLE_CLIENT_SECRET`   | — (required)                 | Google OAuth client secret.                                        |
| `GOOGLE_REDIRECT_URL`    | — (required)                 | Google redirect URI (must match the console configuration).        |
| `ADMIN_API_KEY`          | empty                        | Static key for the admin API (`X-Admin-Key`). When unset the admin endpoints return 404. |
| `APPLE_CLIENT_ID`        | empty                        | Apple service identifier. Empty disables Apple sign-in.            |
| `APPLE_TEAM_ID`          | empty                        | Apple Developer team ID.                                           |
| `APPLE_KEY_ID`           | empty                        | Signing key ID for the ES256 client secret.                        |
| `APPLE_PRIVATE_KEY`      | empty                        | Full PKCS#8 PEM contents of the `.p8` key.                         |
| `APPLE_REDIRECT_URL`     | empty                        | Apple redirect URI (e.g. `http://localhost:8080/v1/auth/apple/callback`). |

## Commands

| Command                  | Description                                                      |
| ------------------------ | ---------------------------------------------------------------- |
| `make run`               | Run the server (`go run ./cmd`).                                 |
| `make build`             | Build a binary into `bin/`.                                      |
| `make test`              | Run the unit test suite.                                         |
| `make test-integration`  | Start Postgres 18, create a disposable `goleanauth_test` DB, apply migrations, and run the integration suite. |
| `make migrate-up`        | Apply pending migrations.                                        |
| `make migrate-down`      | Roll back the most recent migration.                             |
| `make migrate-status`    | Show applied/pending migrations.                                 |
| `make create-client`     | Register an OAuth client (flags below).                          |

## CLI tools

**`cmd/migrate`** — migration runner (wraps goose):

```sh
go run ./cmd/migrate up        # apply all pending
go run ./cmd/migrate down 1    # roll back one
go run ./cmd/migrate status    # list applied/pending
```

**`cmd/create-client`** — register an OAuth client and print its credentials
(the secret is shown once and never stored in plaintext):

```sh
go run ./cmd/create-client \
  -name "My App" \
  -scope "openid profile email" \
  -redirect-uri "https://app.example.com/callback" \
  -redirect-uri "http://localhost:3000/callback"
```

## API reference

Interactive docs are served at `/docs` (ReDoc) and the raw OpenAPI spec at
`/docs/openapi.yaml` — both embedded into the binary and gated by
`SERVE_DOCS`. The spec is the source of truth for request/response shapes;
the summary below maps the surface area.

### Auth & sessions

| Method | Path                  | Auth              | Description                                        |
| ------ | --------------------- | ----------------- | -------------------------------------------------- |
| POST   | `/v1/auth/register`   | —                 | Create an account (email or phone).                |
| POST   | `/v1/auth/login`      | —                 | Sign in; sets the refresh cookie.                  |
| POST   | `/v1/auth/refresh`    | Bearer + cookie   | Rotate the refresh token and issue a new access token. |
| POST   | `/v1/auth/logout`     | Bearer            | Revoke the current session.                        |
| POST   | `/v1/auth/logout-all` | Bearer            | Revoke every session for the user.                 |

### Social providers

| Method | Path                            | Description                  |
| ------ | ------------------------------- | ---------------------------- |
| GET    | `/v1/auth/google/login`         | Redirect to Google.          |
| GET    | `/v1/auth/google/callback`      | Google OAuth callback.       |
| GET    | `/v1/auth/apple/login`          | Redirect to Apple.           |
| GET    | `/v1/auth/apple/callback`       | Apple callback.              |

### OAuth 2.0 / OIDC

| Method   | Path                   | Auth        | Description                                           |
| -------- | ---------------------- | ----------- | ----------------------------------------------------- |
| POST     | `/v1/oauth/token`      | Basic / form| Token grants (`client_credentials`, `refresh_token`, `authorization_code`). |
| POST     | `/v1/oauth/revoke`     | Basic / form| Revoke a refresh token (RFC 7009).                    |
| POST     | `/v1/oauth/introspect` | Basic / form| Inspect a token's state (RFC 7662).                   |
| GET      | `/v1/userinfo`         | Bearer      | OIDC user info claims.                                |
| GET      | `/v1/oauth/authorize`  | browser     | Start the interactive authorization code flow.        |
| POST     | `/v1/oauth/approve`    | browser     | Approve (or deny) the consent screen.                 |
| GET/POST | `/login`               | browser     | Interactive login page.                               |

### Discovery, docs, admin, health

| Method | Path                               | Auth          | Description                    |
| ------ | ---------------------------------- | ------------- | ------------------------------ |
| GET    | `/.well-known/openid-configuration`| —             | OIDC discovery document.       |
| GET    | `/.well-known/jwks.json`           | —             | Public signing keys.           |
| GET    | `/docs`                            | —             | ReDoc interactive reference.   |
| GET    | `/docs/openapi.yaml`               | —             | Raw OpenAPI spec.              |
| POST   | `/v1/admin/clients`                | `X-Admin-Key` | Register a client.             |
| GET    | `/v1/admin/clients`                | `X-Admin-Key` | List clients.                  |
| GET    | `/v1/health`, `/v1/ready`, `/v1/live` | —          | Health / readiness / liveness. |

## Auth flow walkthrough

The refresh token lives in an `HttpOnly` cookie; responses return the access
token in the JSON body.

```sh
# Register
curl -s -X POST http://localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"hunter2-secure","first_name":"Ada","last_name":"Lovelace"}'

# Login (cookie jar stores the refresh token)
curl -s -c /tmp/jar -X POST http://localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"ada@example.com","password":"hunter2-secure"}'
# -> {"data":{"access_token":"<jwt>"},"message":"login successful"}

# Refresh (rotates the session; old refresh token is revoked)
curl -s -b /tmp/jar -X POST http://localhost:8080/v1/auth/refresh \
  -H 'Authorization: Bearer <access_token>'
# -> {"data":{"access_token":"<new-jwt>"}}

# Logout (revokes the current session and clears the cookie)
curl -s -b /tmp/jar -X POST http://localhost:8080/v1/auth/logout \
  -H 'Authorization: Bearer <access_token>'
```

## OAuth / OIDC walkthrough

### Client credentials (machine-to-machine)

```sh
# 1. Register a client (admin API or CLI) and capture CLIENT_ID / CLIENT_SECRET

# 2. Get a token (HTTP Basic with client_id:client_secret)
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d 'grant_type=client_credentials&scope=read' \
  http://localhost:8080/v1/oauth/token
# -> {"access_token":"<jwt>","token_type":"Bearer","expires_in":900,"refresh_token":"...","scope":"read"}

# 3. Introspect it
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN" \
  http://localhost:8080/v1/oauth/introspect
# -> {"active":true,...}

# 4. Revoke the refresh token when done
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$REFRESH_TOKEN" \
  http://localhost:8080/v1/oauth/revoke
```

### Authorization code + PKCE (browser apps)

1. Open the authorize URL in a browser (or redirect your app's user there):

   ```
   http://localhost:8080/v1/oauth/authorize?client_id=<CLIENT_ID>&redirect_uri=<REDIRECT>&scope=openid%20profile%20email&state=<opaque>&code_challenge=<S256-challenge>&code_challenge_method=S256
   ```

2. The user logs in at `/login` and approves the consent screen.
3. The browser is redirected to `redirect_uri?code=<code>&state=<opaque>`.
4. Exchange the code with the PKCE verifier:

   ```sh
   curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
     -d "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&code_verifier=$VERIFIER" \
     http://localhost:8080/v1/oauth/token
   ```

5. Call the user info endpoint with the access token:

   ```sh
   curl -s http://localhost:8080/v1/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"
   # -> {"sub":"<uuid>","email":"ada@example.com",...}
   ```

> **PKCE note:** only `S256` is accepted. A verifier is required whenever a
> challenge was recorded, and codes are single-use with a 10-minute TTL.

### OIDC discovery

```sh
curl -s http://localhost:8080/.well-known/openid-configuration | jq
curl -s http://localhost:8080/.well-known/jwks.json | jq
```

## Testing

```sh
make test               # unit tests (sqlmock, no database required)
make test-integration   # full stack against PostgreSQL 18
```

`make test-integration` brings up the `postgres` compose service, creates a
disposable `goleanauth_test` database, applies the embedded migrations, and
runs the service-level integration suite in `internal/integration` (register,
login, refresh rotation, logout, client credentials, introspection, revocation,
and the PKCE authorization-code flow). Tests that need a real database are
compiled behind the `integration` build tag, so `make test` never touches
Postgres.

## Project layout

```
cmd/
  main.go             # HTTP server, middleware chain, route wiring
  migrate/            # goose migration runner (up/down/status)
  create-client/      # OAuth client registration CLI
internal/
  auth/               # auth + OAuth services, handlers, interactive pages
  docs/               # embedded OpenAPI spec + ReDoc reference UI
  health/             # /v1/health, /v1/ready, /v1/live
  middleware/         # recovery, request ID, logging, security, CORS, rate limits
  integration/        # integration test suite (build tag: integration)
  apperror/           # typed errors + HTTP mapping
  audit/              # audit log service
  response/           # JSON success/error helpers
  validation/         # request validation (+ custom rules)
  normalize/          # email/phone/identifier normalization
  requestctx/         # request-scoped context helpers
pkg/
  config/             # environment configuration + validation
  db/                 # database bootstrap and helpers
  jwks/               # Ed25519 JWT signing/verification key set
  logger/             # structured logger
migrations/           # embedded goose SQL migrations
scripts/              # test-database bootstrap (setup_test_db.sh)
compose.yaml          # local PostgreSQL 18
```

## Security notes

- **Secrets at rest** — passwords are hashed with `bcrypt`; refresh tokens and
  authorization codes are stored as SHA-256 hashes only. Client secrets are
  never stored in plaintext.
- **Signing keys** — Ed25519 tokens. Development may use an ephemeral key
  (tokens invalidate on restart); production **requires** an explicit
  `JWT_PRIVATE_KEY`. Retired public keys can be listed in `JWT_PUBLIC_KEYS`
  so old tokens stay valid across rotation.
- **Cookie flags** — refresh tokens are `HttpOnly`, `SameSite=Lax`, and
  `Secure` in production.
- **PKCE** — only `S256`; plaintext challenges are rejected.
- **Trust proxy** — `TRUST_PROXY` must remain `false` unless the service is
  only reachable through a trusted reverse proxy.
- **Admin API** — gated by `ADMIN_API_KEY` via `X-Admin-Key`, compared in
  constant time; endpoints are hidden (404) when the key is unset.
- **Docs** — disabled by default in production via `SERVE_DOCS`.
- **Rate limiting** — the global and per-route limiters guard auth, OAuth,
  and admin endpoints.

## License

MIT
