# 0factor

A **zero-factor** mock OIDC provider for local development, built so coding agents can sign in.

Login is just an email address. No password, no MFA. The login page lists existing users with notes written by agents, so an agent can sign in with one click without remembering anything. URLs, discovery, tokens and realm config are **Keycloak-compatible**, so 0factor swaps in for Keycloak in dev, and it works with Aspire in one line.

> [!WARNING]
> **Never use this in production.** Anyone who can reach it can sign in as anyone.

> [!NOTE]
> **Status: planned, not yet implemented.** This README describes the target behavior. Work is tracked in [#1](https://github.com/c4l3b/0factor/issues/1) and on the [project board](https://github.com/users/c4l3b/projects/6).

## Why

Coding agents won't type usernames and passwords into login forms. That blocks them from testing any app behind auth. 0factor removes the password entirely:

- **Login page:** type an email, or click an existing user from the list. Each user shows its roles and *agent notes* (for example "admin in tenant acme, used for billing tests").
- **Unknown email:** goes to a registration page with configurable fields, roles, custom claims and agent notes.
- **No browser needed:** the `password` grant takes a username and ignores the password, so `curl` can get a token.

## Quick start

```bash
docker run --rm -p 8080:8080 -v zf-data:/data ghcr.io/c4l3b/0factor
```

No config needed. Any realm is created on first use:

- Discovery: `http://localhost:8080/realms/myrealm/.well-known/openid-configuration`
- Management page: `http://localhost:8080/_0factor/`

The image is a Native AOT binary on a distroless (`runtime-deps` chiseled) base, runs as non-root, and targets under 40 MB.

## Aspire

Swap one line in the AppHost:

```csharp
// dotnet add package ZeroFactor.Aspire.Hosting
var keycloak = builder.AddZeroFactor("keycloak", port: 8080)   // was: builder.AddKeycloak("keycloak", 8080)
    .WithRealmImport("./Realms")                               // same realm files Keycloak uses
    .WithDataVolume();

builder.AddProject<Projects.Web>("web")
    .WithReference(keycloak)
    .WaitFor(keycloak);
```

App projects keep the official `Aspire.Keycloak.Authentication` package unchanged:

```csharp
builder.Services.AddAuthentication()
    .AddKeycloakOpenIdConnect("keycloak", realm: "shop", options => { /* ... */ });
```

## Keycloak compatibility

All endpoints live under `/realms/{realm}`, the same as Keycloak:

| Endpoint | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/protocol/openid-connect/certs` |
| Realm info | `/realms/{realm}` |
| Authorize | `/protocol/openid-connect/auth` |
| Token | `/protocol/openid-connect/token` |
| Userinfo | `/protocol/openid-connect/userinfo` |
| Introspection | `/protocol/openid-connect/token/introspect` |
| Revocation | `/protocol/openid-connect/revoke` |
| Logout | `/protocol/openid-connect/logout` |

**Grants:**
- `authorization_code`, with PKCE
- `refresh_token`
- `client_credentials`
- `password` (username only; the password is ignored)

**Tokens** use Keycloak's claim shapes: `realm_access.roles`, `resource_access.{client}.roles`, `preferred_username`, `azp`, `sid`, and audience mappers.

**Realm import:** Keycloak realm-export JSON files are read from `/opt/keycloak/data/import` at startup. Unknown properties are ignored.

### Known divergences from Keycloak

- No admin REST API, SAML, identity brokering, back-channel logout, token exchange or device flow.
- No keycloak-js login-status iframe. Set `checkLoginIframe: false`.
- Revocation is a no-op, and refresh tokens still work after logout.
- Logout has no confirmation page.
- Refresh tokens are RS256 (Keycloak uses HS512) and stateless. Offline tokens expire after 30 days instead of never.
- Token `scope` is the requested scopes plus `profile email`; client scopes aren't modeled. Default-role composites are fixed to Keycloak's defaults.
- The `password` grant ignores the password.

## Roles and custom claims

Any user can have:

- **Realm roles** and **client roles**. Free entry; missing roles are created automatically.
- **Extra claims:** any JSON object, merged into the access token, ID token and userinfo. Values can be strings, arrays or nested objects.

You can set them in three places: on the registration page, on the management page, or in realm-import JSON:

```json
{
  "realm": "shop",
  "registrationAllowed": true,
  "users": [
    {
      "username": "alice@example.com",
      "email": "alice@example.com",
      "firstName": "Alice",
      "realmRoles": ["admin"],
      "clientRoles": { "store.api": ["orders.write"] },
      "claims": { "tenant_id": "acme", "permissions": ["orders:read"] },
      "agentNotes": "Admin in tenant acme. Use for order management tests."
    }
  ]
}
```

Some claim names can't be set, because they would break token validation or bypass the role fields: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `auth_time`, `azp`, `typ`, `sid`, `session_state`, `nonce`, `at_hash`, `acr`, `scope`, `realm_access`, `resource_access`.

## Configuration

### Realm JSON extensions

These fields are ignored by real Keycloak:

| Field | Purpose |
|---|---|
| `registrationFields` | Extra fields on the registration page. Types: `text`, `email`, `tel`, `number`, `date`, `checkbox`, `select`, `textarea`. A field's optional `claim` puts its value in tokens. |
| `agentNotesRequired` | Default `true`. |
| `users[].claims`, `users[].agentNotes` | Per-user extra claims and notes. |

```json
"registrationFields": [
  { "name": "firstName", "label": "First name", "required": true },
  { "name": "tenant", "label": "Tenant", "type": "select", "options": ["acme", "globex"], "claim": "tenant" }
]
```

### Realm modes

- **Lenient (default):** unknown realms are auto-created. A realm with no imported clients accepts any `client_id`, redirect URI and secret.
- **Strict:** imported realms check clients strictly. `ZF_STRICT=true` turns off auto-creation entirely.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ZF_DATA_DIR` | `/data` | Folder holding `0factor.json`. Delete the file to reset. |
| `ZF_IMPORT_DIR` | `/opt/keycloak/data/import` | Realm-export JSON loaded at startup |
| `ZF_HOSTNAME` | *(from request)* | Fixed base URL for the issuer, like `KC_HOSTNAME` |
| `ZF_STRICT` | `false` | Disable auto-created realms and clients |
| `ZF_REGISTRATION_FIELDS` | *(unset)* | JSON array of registration fields for auto-created realms |

## For coding agents

Paste this into your app's `CLAUDE.md` / `AGENTS.md`, replacing the placeholders:

```markdown
## Local auth

Local auth is 0factor (mock Keycloak) at http://localhost:8080, realm `<realm>`. There are no passwords.

- **Sign in through the app:** on the login page, click an existing user. Read the agent notes and roles to pick the right one.
- **Create a user:** type a new email and fill the registration form. Set roles and claims if the test needs them, and write agent notes saying what the user is for.
- **Change a user's roles, claims or notes:** use http://localhost:8080/_0factor/realms/<realm>.
- **Get a token without a browser:**
  `curl -s -d grant_type=password -d client_id=<client> -d username=<email> http://localhost:8080/realms/<realm>/protocol/openid-connect/token`
```

## Contributing

See [AGENTS.md](AGENTS.md) for constraints, layout and commands.

## License

[MIT](LICENSE)
