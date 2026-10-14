# 0factor

A **zero-factor** mock OIDC provider for local development, built so coding agents can sign in.

Login is just an email address. No password, no MFA. The login page lists existing users with notes written by agents, so an agent can sign in with one click without remembering anything. URLs, discovery, tokens and realm config are **Keycloak-compatible**, so 0factor swaps in for Keycloak in dev, and it works with Aspire in one line.

> [!WARNING]
> **Never use this in production.** Anyone who can reach it can sign in as anyone.

> [!NOTE]
> The container image is available on [GHCR](https://github.com/c4l3b/0factor/pkgs/container/0factor), and the hosting package on [NuGet](https://www.nuget.org/packages/ZeroFactor.Aspire.Hosting). Publishing a [GitHub release](https://github.com/c4l3b/0factor/releases) with a `vX.Y.Z` tag builds and publishes matching image and package versions. Draft releases and tag pushes alone do not publish packages.

[Quick start](#quick-start) · [Aspire](#aspire) · [Seed users](#seed-realms-users-and-claims) · [Tokens for tests](#tokens-for-tests) · [Configuration](#configuration) · [Troubleshooting](#troubleshooting)

## Quick start

```bash
docker run --rm -p 8080:8080 -v zf-data:/data ghcr.io/c4l3b/0factor:latest
```

Configure your app's OIDC client with:

| Setting | Value |
|---|---|
| Authority / issuer | `http://localhost:8080/realms/myrealm` |
| Discovery URL (if requested separately) | `http://localhost:8080/realms/myrealm/.well-known/openid-configuration` |
| Client ID | `myapp` (or your existing client ID) |
| Flow / scopes | Authorization code with PKCE; `openid profile email` |
| Redirect URI | Your app's OIDC callback URL |

Allow HTTP discovery for local development. With no realm import, 0factor creates the realm and accepts any client ID, redirect URI and secret.

Start sign-in **from your app**. Pick an existing user, or enter a new email and complete registration. Leave User ID blank to generate a `sub`, or supply the ID your development data already uses. You return to the app signed in; subsequent apps in the same realm can reuse the session.

Open `http://localhost:8080/_0factor/` to view realms and manage users. To start with predefined accounts, [import a realm file](#seed-realms-users-and-claims).

Get a token without a browser, for a user that already exists (register one through the login page, or [import it](#seed-realms-users-and-claims)):

```bash
curl -fsS -d grant_type=password -d client_id=myapp --data-urlencode username=alice@example.com \
  http://localhost:8080/realms/myrealm/protocol/openid-connect/token
```

The image runs as non-root (UID 1654). The named volume preserves users and signing keys when the container is replaced. Docker examples use `:latest`; pull it again to update an existing local image. To pin a release, replace `latest` with its Git tag without the leading `v`. Aspire automatically uses the image version matching the installed hosting package.

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

[`samples/`](samples) is a runnable Aspire app (`aspire run --apphost samples/AppHost/AppHost.csproj`, needs Docker): a Razor Pages Web app that signs in with `AddKeycloakOpenIdConnect` and calls an Api protected by `AddKeycloakJwtBearer`, with a role-gated page and a claim-gated endpoint. Its AppHost differs from the Keycloak version by one line.

`WithRealmImport` accepts a file or directory, relative to the AppHost directory. `WithDataVolume()` preserves data in a named Docker volume; `WithDataBindMount("./zf-data")` stores it in a host directory. The hosting package uses a matching image version and checks `/health`. Use a stable port so browser cookies and the issuer survive restarts.

### Issuer references and integration tests

The hosting package supports Aspire **13.4.6 and later**. It sets `ZF_HOSTNAME` to the allocated host endpoint automatically, so discovery and tokens use the same issuer even when requests arrive through another address. Override it with `.WithEnvironment("ZF_HOSTNAME", "https://auth.example.test")` when using a reverse proxy.

With a fixed `port`, the endpoint is **unproxied** by default. This keeps the port stable under `DistributedApplicationTestingBuilder`, which randomizes proxied host ports. Without `port`, Aspire allocates a proxied port. Override either default with `isProxied: true` or `false`; use the allocated endpoint rather than a hard-coded authority when ports are dynamic. Parallel test AppHosts need distinct fixed ports, or dynamic ports.

Apps using stock OIDC/JwtBearer handlers can reference the issuer directly:

```csharp
// AppHost: also adds realm users and discovery links to the dashboard.
builder.AddProject<Projects.Api>("api")
    .WithReference(keycloak, realm: "shop")
    .WaitFor(keycloak);

// API: ConnectionStrings__keycloak contains the complete issuer URL.
builder.Services.AddAuthentication("Bearer").AddJwtBearer(options =>
{
    options.Authority = builder.Configuration.GetConnectionString("keycloak");
    options.Audience = "shop.api"; // include this in the issuing client's audience list
    options.RequireHttpsMetadata = false; // local HTTP only
});
```

For another setting name, use `.WithEnvironment("Auth__Authority", keycloak.GetIssuer("shop"))`. `GetIssuer` is an Aspire expression, resolved after endpoint allocation. These helpers use the host URL, so consuming apps must be able to reach that address (local project resources can). The provider always has a dashboard link to user management; realm links are added by the realm-aware `WithReference` overload. The existing `.WithReference(keycloak)` service-discovery behavior remains available.

## Seed realms, users and claims

Save the following as `realms/shop-realm.json`. It seeds an admin with a stable user ID and adds `shop.api` to access tokens issued for `web`. `lenient: true` keeps other development clients working too.

Any user can have:

- **Realm roles** and **client roles**. Free entry; missing roles are created automatically.
- **Extra claims:** any JSON object, merged into the access token, ID token and userinfo. Values can be strings, arrays or nested objects.

Set them on the registration page, on the management page, or in the import:

```json
{
  "realm": "shop",
  "registrationAllowed": true,
  "lenient": true,
  "clients": [{ "clientId": "web", "audience": ["shop.api"] }],
  "users": [
    {
      "id": "alice-dev",
      "username": "alice@example.com",
      "email": "alice@example.com",
      "firstName": "Alice",
      "lastName": "Admin",
      "pinned": true,
      "realmRoles": ["admin"],
      "clientRoles": { "shop.api": ["orders.write"] },
      "claims": { "tenant_id": "acme", "permissions": ["orders:read"] },
      "agentNotes": "Admin in tenant acme. Use for order management tests."
    }
  ]
}
```

Start the container with the import directory mounted (stop the quick-start container first):

```bash
docker run --rm -p 8080:8080 -v zf-data:/data \
  -v "$(pwd)/realms:/opt/keycloak/data/import:ro" \
  ghcr.io/c4l3b/0factor:latest
```

With Aspire, use `.WithRealmImport("./realms")` instead. Imports run at startup; restart after changing a file. Imported realms default to registration disabled, so include `registrationAllowed: true` if new emails should be able to register.

For strict client validation, set `lenient` to `false` and replace the client entry with:

```json
{
  "clientId": "web",
  "secret": "dev-secret",
  "redirectUris": ["http://localhost:3000/signin-oidc"],
  "directAccessGrantsEnabled": true,
  "audience": ["shop.api"]
}
```

Use your app's actual callback URL. A browser-only public client uses `publicClient: true` instead of a secret. Add `serviceAccountsEnabled: true` if the client needs the `client_credentials` grant.

Some claim names can't be set, because they would break token validation or bypass the role fields: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `auth_time`, `azp`, `typ`, `sid`, `session_state`, `nonce`, `at_hash`, `acr`, `scope`, `realm_access`, `resource_access`.

## Manage users

Open `http://localhost:8080/_0factor/realms/shop` to edit roles, JSON claims and agent notes, or to pin, hide or delete a user. Realm roles use comma-separated names; client roles use `client:role` pairs, such as `shop.api:orders.write`.

Pinned users appear first on the login page. Hidden users can still sign in by email; hiding is only a display preference. Changes affect newly issued and refreshed tokens, not tokens already issued. Imported user values may be restored on restart; see [import precedence](#import-versus-saved-data).

## Tokens for tests

The password grant requires an existing, enabled user; it does not register one. Using the seed above:

```bash
curl -fsS http://localhost:8080/realms/shop/protocol/openid-connect/token \
  -d grant_type=password -d client_id=web \
  --data-urlencode username=alice@example.com -d scope=openid
```

The JSON response contains `access_token`, `id_token` (because `openid` was requested), `refresh_token` and expiry values. Send the access token to your API as `Authorization: Bearer <access_token>`. Configure the API to validate issuer `http://localhost:8080/realms/shop` and audience `shop.api`.

To refresh, use the same client ID and the returned refresh token:

```bash
curl -fsS http://localhost:8080/realms/shop/protocol/openid-connect/token \
  -d grant_type=refresh_token -d client_id=web \
  --data-urlencode refresh_token='<refresh_token>'
```

Strict confidential clients also send `client_secret=dev-secret` (or HTTP Basic authentication). For a service token, send `grant_type=client_credentials` with the client credentials; its user is `service-account-<client_id>`, whose roles and claims can be edited on the management page. Service tokens do not include refresh tokens.

## Configuration

### Realm JSON extensions

These fields are ignored by real Keycloak:

| Field | Purpose |
|---|---|
| `lenient` | Explicitly accept any client, redirect URI and secret, even when clients are configured. If omitted, defaults to `true` only when the import has no clients. |
| `clients[].audience` | Array of extra access-token audiences, e.g. `["shop.api"]`; combines with Keycloak audience mappers and role audiences. ID-token audience stays the client ID. |
| `registrationFields` | Extra fields on the registration page. Types: `text`, `email`, `tel`, `number`, `date`, `checkbox`, `select`, `textarea`. A field's optional `claim` puts its value in tokens. |
| `agentNotesRequired` | Default `false`. `true` makes agent notes required on registration and the management page. |
| `users[].claims`, `users[].agentNotes` | Per-user extra claims and notes. |
| `users[].pinned`, `users[].hidden` | `pinned` lists the user first on the login page; `hidden` leaves it off the list (typing the email still signs in). Kept across restarts when the file sets neither. |

```json
"registrationFields": [
  { "name": "firstName", "label": "First name", "required": true },
  { "name": "tenant", "label": "Tenant", "type": "select", "options": ["acme", "globex"], "claim": "tenant" }
]
```

### Realm modes

- **Lenient (default):** unknown realms are auto-created. Imports with no clients accept any `client_id`, redirect URI and secret. Set `"lenient": true` to keep this behavior while configuring clients, such as `"clients": [{ "clientId": "web", "audience": ["shop.api"] }]`.
- **Strict:** imports containing clients validate clients, redirect URIs and secrets unless `lenient` is explicitly `true`. Set `"lenient": false` to reject unknown clients even with an empty client list.
- `ZF_STRICT=true` disables auto-creating unknown realms and clients, including in explicitly lenient realms. Existing realms retain their configured redirect/secret behavior.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ZF_DATA_DIR` | `/data` | Folder holding `0factor.json`. Delete the file to reset. |
| `ZF_IMPORT_DIR` | `/opt/keycloak/data/import` | Realm-export JSON loaded at startup |
| `ZF_HOSTNAME` | *(from request)* | Fixed public base URL for realm endpoints and the default issuer, like `KC_HOSTNAME` |
| `ZF_ISSUER` | *(unset)* | Exact issuer override for discovery and signed tokens; endpoint URLs still use `ZF_HOSTNAME` or the request |
| `ZF_STRICT` | `false` | Disable auto-created realms and clients |
| `ZF_REGISTRATION_FIELDS` | *(unset)* | JSON array of registration fields for auto-created realms |

### Import versus saved data

On every startup, 0factor loads `0factor.json`, then re-imports `*.json` files in filename order. Later files for the same realm win for settings and clients; their users merge in order.

- Imported realm settings, role definitions and the **entire client list** replace saved values, including omitted settings reverting to defaults. Users' roles recreate any missing role definitions.
- Imported users match saved users by case-insensitive username (or email when username is absent). File values replace profile fields, roles, claims, attributes, enabled state and agent notes; omitted fields revert to defaults.
- For a matched user, omitted `id`, `createdTimestamp` and `lastLoginAt` preserve the saved values. If both `pinned` and `hidden` are false or omitted, both saved flags are preserved; setting either true replaces both flags. To clear both, edit the management page.
- Users found only in saved data remain. An imported user's explicit ID wins over another saved user with that ID, replacing that other user.
- A saved signing key is kept unless the import supplies one. Removing a realm file does not delete its saved realm or users. Removing a user from an import does not delete the saved user.

With `WithDataVolume`, editing an import therefore updates matching users on the next start, while registered users remain. Back up the volume before changing IDs or importing another provider's users. A malformed saved file fails startup and is never overwritten.

## Keycloak compatibility

All endpoints live under `/realms/{realm}`, the same as Keycloak:

| Endpoint | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/protocol/openid-connect/certs` |
| Realm info | *(the realm root)* |
| Authorize | `/protocol/openid-connect/auth` |
| Token | `/protocol/openid-connect/token` |
| Userinfo | `/protocol/openid-connect/userinfo` |
| Introspection | `/protocol/openid-connect/token/introspect` |
| Revocation | `/protocol/openid-connect/revoke` |
| Logout | `/protocol/openid-connect/logout` |
| Session-status iframe | `/protocol/openid-connect/login-status-iframe.html` |
| Third-party cookie probes | `/protocol/openid-connect/3p-cookies/step1.html` and `step2.html` |

**Grants:**
- `authorization_code`, with PKCE
- `refresh_token`
- `client_credentials`
- `password` (username only; the password is ignored)

**Tokens** use Keycloak's claim shapes: `realm_access.roles`, `resource_access.{client}.roles`, `preferred_username`, `azp`, `sid`, and audience mappers.

**Realm import:** Keycloak realm-export JSON files are read from `/opt/keycloak/data/import` at startup. Unknown properties are ignored.

### Known divergences from Keycloak

- Optional `ZF_ISSUER` overrides the issuer independently of realm endpoint URLs, for migration from other mocks.

- No admin REST API, SAML, identity brokering, back-channel logout, token exchange or device flow.
- Revocation is a no-op, and refresh tokens (and userinfo with an unexpired access token) still work after logout.
- Logout has no confirmation page: it signs out right away and shows "You are signed out." when there is no `post_logout_redirect_uri`.
- Refresh tokens are RS256 (Keycloak uses HS512) and stateless. Offline tokens expire after 30 days instead of never.
- Token `scope` is the requested scopes plus `profile email`; client scopes aren't modeled. Default-role composites are fixed to Keycloak's defaults.
- The `password` grant ignores the password.
- `response_mode=form_post` (the ASP.NET Core default) auto-submits using a small inline script. A visible **Continue** button works without JavaScript. Login and registration use no JavaScript. Hidden session-status and cookie-probe iframes also require scripts. A proxy CSP must allow these scripts and embedding the iframes; `form_post` can fall back to Continue.

### Client compatibility

- **ASP.NET Core OIDC and JwtBearer** (via `Aspire.Keycloak.Authentication`): tested end to end in CI against the [`samples/`](samples) app and the real container.
- **keycloak-js:** supports the default session-status iframe checks, including logout/account changes in other tabs. Browsers that block third-party cookies automatically disable these checks, as with Keycloak. Cross-site iframe cookies require HTTPS. Endpoint/cookie and script protocol tests cover this feature; a full browser adapter flow is not part of the automated suite. Refresh tokens still work after logout (see above).
- **Others** (oidc-client-ts, Auth.js Keycloak provider): should work through discovery. Untested; tests welcome.

## Migrating from other mocks

Applications commonly identify users by **both `(iss, sub)`**. Preserve the user IDs in your realm import and set `ZF_ISSUER` to the exact old issuer to keep those development identities, including any trailing slash. For example, when replacing a root-issuer mock:

```csharp
// AppHost
var keycloak = builder.AddZeroFactor("keycloak", port: 8080)
    .WithEnvironment("ZF_ISSUER", "http://localhost:8080")
    .WithRealmImport("./Realms");

// Consuming app: keep issuer validation enabled; fetch metadata from the realm.
builder.Services.AddAuthentication().AddOpenIdConnect(options =>
{
    options.Authority = "http://localhost:8080";
    options.MetadataAddress = "http://localhost:8080/realms/shop/.well-known/openid-configuration";
    options.RequireHttpsMetadata = false; // local development over HTTP
    options.ClientId = "web";
    options.ResponseType = "code";
});
```

For Docker, use `-e ZF_ISSUER=http://localhost:8080`. The override applies to every realm; use it with a single realm when preserving identities from another mock. Discovery stays at `/realms/{realm}/.well-known/openid-configuration` and advertises the working realm endpoints. Configure a separate metadata address in OIDC and JWT bearer clients rather than deriving it from the old authority. Aspire's `GetIssuer` and realm-aware `WithReference` return the realm URL; configure the old authority explicitly when using this override.

`ZF_HOSTNAME` fixes the public endpoint base URL; without `ZF_ISSUER`, the issuer is that base plus `/realms/{realm}`. A stable port prevents future issuer changes from random host ports. If you choose to change the issuer instead, migrate your application's development identity records with a backup. Update token URLs and audiences as needed, and clear old sign-in cookies and cached tokens when switching providers.

### Soluto oidc-server-mock field mapping

Translate the [Soluto config](https://github.com/Soluto/oidc-server-mock#simple-configuration) into one realm-export JSON file:

| Soluto field | 0factor field |
|---|---|
| User `SubjectId` | `users[].id` (preserves `sub`) |
| User `Username` | `users[].username`; prefer the email for browser sign-in |
| User `Password` | Omit |
| Claims `email`, `given_name`, `family_name` | `email`, `firstName`, `lastName` on the user |
| Claim `name` | `users[].claims.name`; otherwise `name` is composed from first and last name |
| Other `Claims` entries (`Type` / `Value`) | Properties of `users[].claims`; repeated types become arrays; parse JSON values before copying |
| `ClientId`, `RedirectUris`, `AllowedCorsOrigins` | Client `clientId`, `redirectUris`, `webOrigins` |
| `ClientSecrets` | Client `secret` (one plaintext dev secret) |
| `RequireClientSecret: false` | Client `publicClient: true` |
| `AllowedGrantTypes` includes `password` / `client_credentials` | `directAccessGrantsEnabled` / `serviceAccountsEnabled: true` |
| API resource name used as audience | Client `audience: ["api-name"]` |

0factor supports authorization code with PKCE rather than implicit or hybrid flows. Allowed scopes and per-client token lifetimes are not modeled; `accessTokenLifespan` is realm-wide. Reserved protocol claims must use 0factor's corresponding settings rather than `claims`. There is no conversion CLI.

```json
{
  "realm": "shop",
  "lenient": true,
  "clients": [{ "clientId": "web", "audience": ["shop.api"] }],
  "users": [{
    "id": "1",
    "username": "sam@example.com",
    "email": "sam@example.com",
    "claims": { "name": "Sam Tailor" }
  }]
}
```

A single display name belongs in `claims.name`; `firstName` is the `given_name` claim, and `lastName` is `family_name`. Extra claims override composed profile claims in access tokens, ID tokens and userinfo.

## Troubleshooting

| Symptom | Check |
|---|---|
| API returns 401 | Compare the token's `iss` with the API authority and its `aud` with the API audience. Make sure discovery is reachable from the API. |
| Password grant returns `Invalid user credentials` | Register or import the email first. Check that the user is enabled. |
| `Client not found` or `Invalid parameter: redirect_uri` | Check the imported client and exact callback URL, or use `lenient: true` for permissive development. |
| Direct access or service-account grant rejected | In a strict realm, enable `directAccessGrantsEnabled` or `serviceAccountsEnabled` on the client. |
| Edited claims do not appear | Obtain a new token or refresh it. Check whether a restart re-imported the user's old values. |

Data lives in `/data/0factor.json`. Back up that file before resetting it; deleting it while the server is stopped resets saved users and signing keys. Mounted realm files will seed the store again at the next start.

## For coding agents

Paste this into your app's `CLAUDE.md` / `AGENTS.md`, replacing the placeholders:

```markdown
## Local auth

Local auth is 0factor (mock Keycloak) at http://localhost:8080, realm `<realm>`. There are no passwords.

- **Sign in through the app:** on the login page, click an existing user. Read the agent notes and roles to pick the right one. The return form auto-submits; if a **Continue** button stays visible, click it.
- **Create a user:** type a new email and fill the registration form. Set roles and claims if the test needs them. Agent notes are optional; write a line saying what the user is for. Leave User ID blank unless test data already references a user ID: whatever you enter becomes the `sub` claim.
- **Change a user's roles, claims or notes, or pin or hide it on the login page:** use http://localhost:8080/_0factor/realms/<realm>.
- **Get a token without a browser:**
  `curl -s -d grant_type=password -d client_id=<client> -d username=<email> http://localhost:8080/realms/<realm>/protocol/openid-connect/token`
```

## Contributing

See [AGENTS.md](AGENTS.md) for constraints, layout and commands.

## License

[MIT](LICENSE)
