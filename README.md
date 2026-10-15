# 0factor

A mock OIDC provider for local development that coding agents can sign in to.

Login with an email address—no password or MFA. Pick existing users with one click; agent notes explain which account to use. Run with Aspire or Docker and connect a standard OpenID Connect client.

> [!WARNING]
> **Never use this in production.** Anyone who can reach it can sign in as anyone.

[Docker Hub](https://hub.docker.com/r/c4l3b/0factor) · [NuGet](https://www.nuget.org/packages/ZeroFactor.Aspire.Hosting)

[Quick start](#quick-start) · [Docker](#run-with-docker) · [Aspire](#aspire) · [Keycloak migration](#replacing-keycloak) · [Seed users](#seed-realms-users-and-claims) · [Tokens for tests](#tokens-for-tests) · [Configuration](#configuration) · [Troubleshooting](#troubleshooting)

## Quick start

Add `ZeroFactor.Aspire.Hosting` to your Aspire AppHost (requires Docker):

```csharp
// dotnet add package ZeroFactor.Aspire.Hosting
var auth = builder.AddZeroFactor("auth")
    .WithDataVolume();

builder.AddProject<Projects.Web>("web")
    .WithReference(auth, realm: "myapp")
    .WaitFor(auth);
```

`WithReference` supplies the issuer URL as `ConnectionStrings__auth`. Realms and clients are created on demand; no import or client registration is needed.

In your ASP.NET Core web project, install `Microsoft.AspNetCore.Authentication.OpenIdConnect` matching your .NET version. In `Program.cs`:

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority = builder.Configuration.GetConnectionString("auth");
        options.ClientId = "web";
        options.ResponseType = "code";
        options.UsePkce = true;
        options.RequireHttpsMetadata = false; // 0factor uses HTTP locally
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext context) => $"Signed in as {context.User.Identity?.Name}")
    .RequireAuthorization();

app.Run();
```

Run the AppHost and open the web app's **HTTPS** endpoint; the default OIDC cookies require it. Visiting `/` starts sign-in. Pick a user or enter an email to register. The OIDC middleware handles `/signin-oidc` and returns you to the app.

The dashboard links to user management and discovery. `.WithDataVolume()` preserves users and signing keys. Keep production authentication configured separately.

Run [`samples/Basic`](samples/Basic) for a home page with login, name/email display and sign-out:

```bash
aspire run --apphost samples/Basic/AppHost/BasicAppHost.csproj
```

## Run with Docker

```bash
docker run --rm -p 8080:8080 -v zf-data:/data c4l3b/0factor:latest
```

Configure your app's OIDC client with:

| Setting | Value |
|---|---|
| Authority / issuer | `http://localhost:8080/realms/myrealm` |
| Discovery URL (if requested separately) | `http://localhost:8080/realms/myrealm/.well-known/openid-configuration` |
| Client ID | `myapp` (or your existing client ID) |
| Flow / scopes | Authorization code with PKCE; `openid profile email` |
| Redirect URI | Your app's OIDC callback URL |

Allow HTTP discovery. Without an import, any realm, client ID, redirect URI and secret is accepted.

Start sign-in **from your app**. Pick a user or register a new email. Leave User ID blank to generate a `sub`, or enter the ID your development data uses. Apps in the same realm share the sign-in session.

Manage users at `http://localhost:8080/_0factor/`, [seed accounts](#seed-realms-users-and-claims), or [get tokens without a browser](#tokens-for-tests).

The image runs as non-root (UID 1654); the volume preserves users and signing keys. Pull `:latest` to update, or pin a release using its tag without the leading `v`. Aspire uses the image version matching its hosting package.

## Aspire

`WithRealmImport` accepts a file or directory relative to the AppHost. Use `WithDataVolume()` for a named volume or `WithDataBindMount("./zf-data")` for a host directory. Health checks use `/health`.

The default port is derived from the AppHost directory and resource name (20000–29999), keeping the issuer stable across restarts. Set `port: 8080` to choose one explicitly or resolve a collision. Browser cookies ignore ports; use distinct realm names to separate projects' sessions.

### Issuer references and integration tests

Requires Aspire **13.4.6+**. `ZF_HOSTNAME` is set to the host endpoint so discovery and tokens agree on the issuer. For a reverse proxy, override it with `.WithEnvironment("ZF_HOSTNAME", "https://auth.example.test")`.

The endpoint is **unproxied**, keeping its port stable under `DistributedApplicationTestingBuilder`. For dynamic ports, use `AddZeroFactor(name, port: null, isProxied: true)` and read the allocated endpoint. Parallel runs need distinct or dynamic ports.

Apps using stock OIDC/JwtBearer handlers can reference the issuer directly:

```csharp
// AppHost: also adds realm users and discovery links to the dashboard.
builder.AddProject<Projects.Api>("api")
    .WithReference(auth, realm: "shop")
    .WaitFor(auth);

// API: ConnectionStrings__auth contains the complete issuer URL.
builder.Services.AddAuthentication("Bearer").AddJwtBearer(options =>
{
    options.Authority = builder.Configuration.GetConnectionString("auth");
    options.Audience = "shop.api"; // include this in the issuing client's audience list
    options.RequireHttpsMetadata = false; // local HTTP only
});
```

For another setting name, use `.WithEnvironment("Auth__Authority", auth.GetIssuer("shop"))`. The issuer resolves after endpoint allocation and uses the host URL, which consumers must be able to reach. The realm-aware `WithReference` adds dashboard links; omit the realm for service discovery alone.

## Seed realms, users and claims

Save as `realms/shop-realm.json` to seed an admin and add the `shop.api` audience to `web` access tokens. `lenient: true` accepts other development clients.

Set roles and JSON claims during registration, in user management, or in an import. Missing roles are created automatically; claims appear in access tokens, ID tokens and userinfo.

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

Start the container with the import directory mounted (stop the earlier Docker container first):

```bash
docker run --rm -p 8080:8080 -v zf-data:/data \
  -v "$(pwd)/realms:/opt/keycloak/data/import:ro" \
  c4l3b/0factor:latest
```

With Aspire, use `.WithRealmImport("./realms")`. Restart after changing imports. Imported realms disable registration unless `registrationAllowed: true`.

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

Reserved claims (use the corresponding protocol settings or role fields): `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `auth_time`, `azp`, `typ`, `sid`, `session_state`, `nonce`, `at_hash`, `acr`, `scope`, `realm_access`, `resource_access`.

## Manage users

Open `http://localhost:8080/_0factor/realms/shop` to edit roles, JSON claims and agent notes, or to pin, hide or delete a user. Realm roles use comma-separated names; client roles use `client:role` pairs, such as `shop.api:orders.write`.

Pinned users appear first; hidden users can still sign in by email. Changes apply to new and refreshed tokens. Imports may restore user values on restart; see [import precedence](#import-versus-saved-data).

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

Back up data before changing IDs or importing another provider's users. A malformed saved file fails startup and is never overwritten.

## Keycloak compatibility

URLs, discovery, token shapes and realm imports are Keycloak-compatible.

### Replacing Keycloak

Swap one line in the AppHost:

```csharp
// dotnet add package ZeroFactor.Aspire.Hosting
var keycloak = builder.AddZeroFactor("keycloak")    // was: builder.AddKeycloak("keycloak", 8080)
    .WithRealmImport("./Realms")                    // same realm files Keycloak uses
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

Run `aspire run --apphost samples/AppHost/AppHost.csproj` for the [Keycloak compatibility sample](samples/AppHost): OIDC sign-in, JWT-protected API calls, roles and claims.

### Endpoints and tokens

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

**Grants:** `authorization_code` with PKCE, `refresh_token`, `client_credentials`, and `password`.

**Tokens** use Keycloak's claim shapes: `realm_access.roles`, `resource_access.{client}.roles`, `preferred_username`, `azp`, `sid`, and audience mappers.

**Realm import:** Keycloak exports; unknown properties are ignored.

### Known divergences from Keycloak

- `ZF_ISSUER` can override the issuer independently of endpoint URLs.
- The `password` grant ignores passwords.
- No admin REST API, SAML, identity brokering, back-channel logout, token exchange or device flow.
- Revocation is a no-op, and refresh tokens (and userinfo with an unexpired access token) still work after logout.
- Logout has no confirmation page: it signs out right away and shows "You are signed out." when there is no `post_logout_redirect_uri`.
- Refresh tokens are RS256 (Keycloak uses HS512) and stateless. Offline tokens expire after 30 days instead of never.
- Token `scope` is the requested scopes plus `profile email`; client scopes aren't modeled. Default-role composites are fixed to Keycloak's defaults.
- Login and registration need no JavaScript. `form_post` uses an auto-submit script with a **Continue** fallback. Session-status and cookie-probe iframes require scripts. Proxy CSPs must allow those scripts and iframe embedding.

### Client compatibility

- **ASP.NET Core:** standard OIDC tested in [`samples/Basic`](samples/Basic); OIDC and JwtBearer via `Aspire.Keycloak.Authentication` in the [compatibility sample](samples/AppHost). Both run end to end against the container.
- **keycloak-js:** session-status checks detect logout/account changes in other tabs; blocked third-party cookies disable them. Cross-site iframe cookies require HTTPS. Endpoint and script protocols are tested; the full browser adapter flow is not.
- **oidc-client-ts, Auth.js Keycloak provider:** expected to work through discovery; untested.

## Migrating from other mocks

To preserve development identities keyed by **`(iss, sub)`**, retain user IDs in your import and set `ZF_ISSUER` to the exact old issuer, including any trailing slash:

```csharp
// AppHost
var auth = builder.AddZeroFactor("auth", port: 8080)
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

For Docker, use `-e ZF_ISSUER=http://localhost:8080`. This applies to every realm; use a single realm when preserving identities. Discovery stays at `/realms/{realm}/.well-known/openid-configuration`, so configure metadata separately from the old authority. Aspire's issuer helpers return the realm URL; set the old authority explicitly.

Without `ZF_ISSUER`, the issuer is `ZF_HOSTNAME` (or the request base URL) plus `/realms/{realm}`. Keep the port stable. If changing the issuer, back up and migrate development identity records. Update token URLs and audiences, and clear old cookies and cached tokens.

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

Extra claims override composed profile claims in access tokens, ID tokens and userinfo.

## Troubleshooting

| Symptom | Check |
|---|---|
| API returns 401 | Compare the token's `iss` with the API authority and its `aud` with the API audience. Make sure discovery is reachable from the API. |
| Password grant returns `Invalid user credentials` | Register or import the email first. Check that the user is enabled. |
| `Client not found` or `Invalid parameter: redirect_uri` | Check the imported client and exact callback URL, or use `lenient: true` for permissive development. |
| Direct access or service-account grant rejected | In a strict realm, enable `directAccessGrantsEnabled` or `serviceAccountsEnabled` on the client. |
| Edited claims do not appear | Obtain a new token or refresh it. Check whether a restart re-imported the user's old values. |

To reset, stop the server and delete `/data/0factor.json` (back it up first). This removes saved users and signing keys; imports run again on startup.

## For coding agents

Paste this into your app's `CLAUDE.md` / `AGENTS.md`, replacing the placeholders:

```markdown
## Local auth

Local auth is 0factor (mock OIDC provider) at http://localhost:8080, realm `<realm>`. There are no passwords.

- **Sign in through the app:** on the login page, click an existing user. Read the agent notes and roles to pick the right one. The return form auto-submits; if a **Continue** button stays visible, click it.
- **Create a user:** type a new email and fill the registration form. Set roles and claims if the test needs them. Agent notes are optional; write a line saying what the user is for. Leave User ID blank unless test data already references a user ID: whatever you enter becomes the `sub` claim.
- **Change a user's roles, claims or notes, or pin or hide it on the login page:** use http://localhost:8080/_0factor/realms/<realm>.
- **Get a token without a browser:**
  `curl -s -d grant_type=password -d client_id=<client> -d username=<email> http://localhost:8080/realms/<realm>/protocol/openid-connect/token`
```

## Contributing

See [AGENTS.md](AGENTS.md) for constraints, layout and commands.

Publishing a [GitHub release](https://github.com/c4l3b/0factor/releases) tagged `vX.Y.Z` publishes matching image and package versions. Draft releases and tag pushes alone do not publish.

## License

[MIT](LICENSE)
