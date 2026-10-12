# ZeroFactor.Aspire.Hosting

Aspire hosting integration for [0factor](https://github.com/c4l3b/0factor), a mock OIDC provider for local development. Login is an email address only. URLs, discovery, tokens and realm import are Keycloak-compatible, so swapping Keycloak for 0factor is one line in the AppHost.

**Never use 0factor in production.**

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

| Method | Container |
|---|---|
| `AddZeroFactor(name, port)` | `ghcr.io/c4l3b/0factor:<package version>`, endpoint `http` → 8080, health check `/health` |
| `WithRealmImport(path)` | copies files to `/opt/keycloak/data/import` |
| `WithDataVolume(name)` / `WithDataBindMount(source)` | mounts `/data` (holds `0factor.json`) |

Use a stable `port`: OIDC cookies and the token issuer include it.
