# API Layer Redesign — Mattermost-Style Architecture

**Date:** 2026-05-17
**Author:** Snehal Dangroshiya
**Status:** Approved

## Goal

Rewrite the `api/` layer to match the architectural patterns of the Mattermost `api4` package:
typed `BaseRoutes` struct, centralized `ApiParams`, `Context` error-setter methods, a `model/`
package that is the single source of truth for all types, and `FromJson`/`ToJson` on every
HTTP-boundary type. Full rewrite in one pass — no incremental migration.

---

## 1. Package Structure

### New `model/` package

Replaces `internal/domain/` entirely. Contains all domain entity types and all HTTP
request/response types. No dependency on any `internal/` package — only stdlib, `uuid`, `jwt`.

```
model/
  secret.go          # Secret, SecretVersion, export/import types + req/resp + FromJson/ToJson
  user.go            # User, Claims, role constants + req/resp + FromJson/ToJson
  key.go             # Key types + req/resp + FromJson/ToJson
  certificate.go     # Certificate types + req/resp + FromJson/ToJson
  access_policy.go   # AccessPolicy types + req/resp + FromJson/ToJson
  session.go         # Session type + FromJson/ToJson
  oauth2_client.go   # OAuth2Client types + req/resp + FromJson/ToJson
  utils.go           # NewId(), GetMillis(), shared validation helpers
```

### Deleted

`internal/domain/` — all 8 files removed after migration is complete.

### Unchanged structure

`internal/services/`, `internal/repositories/`, `internal/container/`, `common/`, `cmd/`,
`app/`, `bootstrap/` — structure unchanged. Only import paths updated where they referenced
`rocketvault/internal/domain`.

### Updated `api/` package

```
api/
  api.go                    # Routes struct, Init(), Handle404(), ReturnStatusOK()
  context.go                # Context, ApiHandler(), ApiSessionRequired(), error setters, service accessors
  params.go                 # ApiParams struct, ApiParamsFromRequest()
  users.go                  # InitUsers() + all user handlers
  secrets.go                # InitSecrets() + all secret handlers
  keys.go                   # InitKeys() + all key handlers
  certificates.go           # InitCertificates() + all cert handlers
  health.go                 # InitHealth() + health handlers
  vault.go                  # InitVault() placeholder
  soft_delete.go            # InitDeleted() + soft-delete handlers
  access_policies.go        # InitAccessPolicies() + handlers
  oauth2.go                 # InitOAuth2() + handlers
  versioning.go             # versioning middleware (unchanged)
  context_test.go           # updated to reflect renamed wrappers and new error setters
  context_accessors_test.go # updated to reflect ApiParams field names
```

---

## 2. `model/` Package Design

### Pattern for every type

Every type that crosses the HTTP boundary gets `FromJson(io.Reader)` and `ToJson() string`.
Domain entity types retain their business methods. No HTTP imports in `model/`.

```go
// Domain type example (model/secret.go)
type Secret struct {
    ID              uuid.UUID  `json:"id"`
    UserID          uuid.UUID  `json:"user_id"`
    Name            string     `json:"name"`
    Value           string     `json:"value"`
    Version         int        `json:"version"`
    Tags            []string   `json:"tags"`
    CreatedAt       time.Time  `json:"created_at"`
    DeletedAt       *time.Time `json:"deleted_at,omitempty"`
    PurgeProtection bool       `json:"purge_protection"`
    ExpiresAt       *time.Time `json:"expires_at,omitempty"`
    NotBefore       *time.Time `json:"not_before,omitempty"`
    Enabled         bool       `json:"enabled"`
    ContentType     string     `json:"content_type,omitempty"`
    ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

func (s *Secret) IsExpired() bool { ... }  // business methods retained
func (s *Secret) IsActive() bool  { ... }
func (s *Secret) IsAccessible() bool { ... }

// HTTP request/response types
type CreateSecretRequest struct {
    Name        string   `json:"name"`
    Value       string   `json:"value"`
    Tags        []string `json:"tags,omitempty"`
    ContentType string   `json:"content_type,omitempty"`
}

func CreateSecretRequestFromJson(data io.Reader) (*CreateSecretRequest, error) {
    var r CreateSecretRequest
    return &r, json.NewDecoder(data).Decode(&r)
}

type SecretResponse struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Value       string   `json:"value,omitempty"`
    Tags        []string `json:"tags,omitempty"`
    Version     int      `json:"version"`
    ContentType string   `json:"content_type,omitempty"`
    CreatedAt   string   `json:"created_at"`
    UpdatedAt   string   `json:"updated_at,omitempty"`
}

func (r *SecretResponse) ToJson() string {
    b, _ := json.Marshal(r)
    return string(b)
}
```

### Boundary rule

Service layer request/response structs (e.g. `internal/services/secrets.CreateSecretRequest`)
stay in their packages — they carry service-internal fields (`uuid.UUID UserID`, etc.) and are
not API contracts. `model/` types are the HTTP wire contract only.

### CLI impact

`cmd/` files that import `rocketvault/internal/domain` are updated to import `rocketvault/model`.
No logic changes — only the import path changes.

---

## 3. `api/params.go`

### Route variable standardization

All routes are updated to use descriptive variable names. Current `{id}` is replaced per domain:

| Domain | Route pattern | Variable |
|---|---|---|
| Users | `/users/{user_id}` | `user_id` |
| Secrets | `/secrets/{secret_id}` | `secret_id` |
| Keys | `/keys/{key_id}` | `key_id` |
| Certificates | `/certificates/{certificate_id}` | `certificate_id` |
| Access Policies | `/access-policies/{policy_id}` | `policy_id` |
| Service Accounts | `/service-accounts/{service_account_id}` | `service_account_id` |
| Sessions | `/users/sessions/{session_id}` | `session_id` |
| Principal | `/access-policies/principal/{principal_id}` | `principal_id` |
| Secret versions | `/secrets/{secret_id}/versions/{version}` | `secret_id`, `version` |

### `ApiParams` struct

```go
type ApiParams struct {
    // Path variables
    UserID           string
    SecretID         string
    KeyID            string
    CertificateID    string
    PolicyID         string
    ServiceAccountID string
    SessionID        string
    PrincipalID      string
    Version          int    // parsed to int, 0 if absent

    // Pagination (from query string)
    Page    int // default: 0, floor: 0
    PerPage int // default: 60, max: 200

    // Filters
    Tags      []string // ?tags=a,b split on comma
    Permanent bool     // ?permanent=true
}

func ApiParamsFromRequest(r *http.Request) *ApiParams {
    vars := mux.Vars(r)
    p := &ApiParams{
        UserID:           vars["user_id"],
        SecretID:         vars["secret_id"],
        KeyID:            vars["key_id"],
        CertificateID:    vars["certificate_id"],
        PolicyID:         vars["policy_id"],
        ServiceAccountID: vars["service_account_id"],
        SessionID:        vars["session_id"],
        PrincipalID:      vars["principal_id"],
    }
    // version parsed as int with fallback to 0
    // page/per_page clamped to sane defaults
    // tags split from comma-separated query param
    return p
}
```

`ApiParamsFromRequest` is called once inside `ApiHandler` and `ApiSessionRequired` — stored
on `c.Params`. No handler body ever calls `mux.Vars(r)` directly.

---

## 4. `api/context.go`

### Renamed wrappers

| Old name | New name |
|---|---|
| `Handler()` | `ApiHandler()` |
| `SessionRequired()` | `ApiSessionRequired()` |

Both call `ApiParamsFromRequest(r)` and store the result on `c.Params`.

### Error setter methods

```go
func (c *Context) SetInvalidParam(parameter string)   // 400
func (c *Context) SetPermissionError(permission string) // 403
func (c *Context) SetNotFound(resource string)          // 404
func (c *Context) SetInternalError(err error)           // 500
```

### Handler body — before vs after

```go
// Before
vars := mux.Vars(r)
secretID, err := uuid.Parse(vars["id"])
if err != nil {
    c.Err = common.NewAppError("getSecret", "Invalid secret ID", nil, err.Error(), http.StatusBadRequest)
    return
}

// After
secretID, err := uuid.Parse(c.Params.SecretID)
if err != nil {
    c.SetInvalidParam("secret_id")
    return
}
```

### Service accessors

Unchanged: `c.secretSvc()`, `c.userSvc()`, `c.keySvc()`, `c.certSvc()`, `c.authSvc()`,
`c.sessionRepo()`.

---

## 5. `api/api.go`

### Typed `Routes` struct

Replaces `map[string]*mux.Router` with a typed struct — compile-time safety, IDE autocomplete.
Paired singular/plural pattern: plural for collection routes, singular for resource routes.

```go
type Routes struct {
    ApiRoot         *mux.Router // /api/v1
    Vault           *mux.Router // /api/v1/vault
    Secrets         *mux.Router // /api/v1/secrets
    Secret          *mux.Router // /api/v1/secrets/{secret_id}
    Users           *mux.Router // /api/v1/users
    User            *mux.Router // /api/v1/users/{user_id}
    Keys            *mux.Router // /api/v1/keys
    Key             *mux.Router // /api/v1/keys/{key_id}
    Certificates    *mux.Router // /api/v1/certificates
    Certificate     *mux.Router // /api/v1/certificates/{certificate_id}
    Health          *mux.Router // /api/v1/health
    Deleted         *mux.Router // /api/v1/deleted
    AccessPolicies  *mux.Router // /api/v1/access-policies
    AccessPolicy    *mux.Router // /api/v1/access-policies/{policy_id}
    ServiceAccounts *mux.Router // /api/v1/service-accounts
    ServiceAccount  *mux.Router // /api/v1/service-accounts/{service_account_id}
    OAuth2          *mux.Router // /api/v1/oauth2 (public, bypasses auth middleware)
}
```

### `API` struct

```go
type API struct {
    App        *app.App
    BaseRoutes *Routes
    basePath   string
    rootRouter *mux.Router
    Logger     *logging.Logger
}
```

### New helpers

```go
func Handle404(w http.ResponseWriter, r *http.Request)
func ReturnStatusOK(w http.ResponseWriter)
```

### `Init*()` signature change

`Init*()` functions no longer take a `*mux.Router` argument. They read directly from
`api.BaseRoutes`. Collection routes go on the plural router; resource routes go on the
singular router.

```go
func (api *API) InitSecrets() {
    api.BaseRoutes.Secrets.Handle("", ApiSessionRequired(api.App, createSecret)).Methods("POST")
    api.BaseRoutes.Secrets.Handle("", ApiSessionRequired(api.App, listSecrets)).Methods("GET")

    api.BaseRoutes.Secret.Handle("", ApiSessionRequired(api.App, getSecret)).Methods("GET")
    api.BaseRoutes.Secret.Handle("", ApiSessionRequired(api.App, updateSecret)).Methods("PUT")
    api.BaseRoutes.Secret.Handle("", ApiSessionRequired(api.App, deleteSecret)).Methods("DELETE")
    api.BaseRoutes.Secret.Handle("/versions", ApiSessionRequired(api.App, listSecretVersions)).Methods("GET")
    api.BaseRoutes.Secret.Handle("/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getSecretVersion)).Methods("GET")
    api.BaseRoutes.Secret.Handle("/versions/latest", ApiSessionRequired(api.App, getLatestSecretVersion)).Methods("GET")
}
```

---

## 6. Error Handling & Response Consistency

### Single error response shape

Every error response from every handler has this exact shape:

```json
{
    "id":             "api.secrets.get_secret.not_found",
    "message":        "Secret not found",
    "detailed_error": "record not found",
    "status_code":    404,
    "request_id":     "req-a1b2c3d4"
}
```

`request_id` is included in every error response for log correlation.

### Contract

- Handlers set `c.Err` and return — they never write error responses directly.
- `ApiHandler`/`ApiSessionRequired` wrappers write the error response after handler returns.
- Success responses use `model.ToJson()`: `w.Write([]byte(response.ToJson()))`.
- Delete/revoke operations that previously returned `{"message": "...", "status": "success"}`
  are standardized to `ReturnStatusOK(w)`.
- `tokenHandler` in `oauth2.go` is exempt — it is a raw `http.HandlerFunc` outside the auth
  middleware chain and writes its own response.

---

## 7. Migration Scope & Step Order

Each step must compile cleanly before the next begins.

| Step | Action | Files |
|---|---|---|
| 1 | Create `model/` — copy + extend types, add `FromJson`/`ToJson` | 8 new files |
| 2 | Update `internal/` imports: `internal/domain` → `model` | ~13 files (import only) |
| 3 | Update `cmd/` imports: `internal/domain` → `model` | ~12 files (import only) |
| 4 | Rewrite `api/` — params, context, api, all handlers | 15 files |
| 5 | Delete `internal/domain/` | 8 files deleted |

### Import graph after migration

```
cmd/      → model/, internal/services/*, internal/container/
api/      → model/, app/, internal/services/*, internal/container/
internal/ → model/
model/    → stdlib, uuid, jwt only
```

`model/` has zero dependency on any `internal/` package. This is the key invariant.

### Total files touched: ~48

- ~25 are mechanical import path changes (zero logic changes)
- ~15 are full rewrites (`api/` handlers)
- ~8 are new files (`model/`)
- ~8 are deletions (`internal/domain/`)

---

## Key Invariants

1. `model/` never imports `internal/` — it is a pure data + encoding layer.
2. No handler body ever calls `mux.Vars(r)` — always use `c.Params`.
3. No handler body ever writes an error response — always set `c.Err` and return.
4. Every HTTP-boundary type has `FromJson`/`ToJson`.
5. Service layer request/response structs stay in `internal/services/*/` — not in `model/`.
