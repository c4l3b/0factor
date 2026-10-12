# AGENTS.md

Guidance for coding agents working **on** this repo. For how to *use* 0factor from another project, see the "For coding agents" section of [README.md](README.md).

## What this is

0factor is a mock OIDC provider for local development. Login is an email address only: no password, no MFA. URLs, discovery, token shapes and realm config are Keycloak-compatible so it can replace Keycloak in dev, especially under Aspire. It must never be used in production.

## Work tracking

- Issues live in `c4l3b/0factor` and on the project board https://github.com/users/c4l3b/projects/6.
- #1 is the tracking issue. It has the decisions table and links every task as a sub-issue.
- Read the issue before starting: `gh issue view <n> -R c4l3b/0factor`. Each issue lists its dependencies, design and acceptance tests.
- Build order: #2 scaffold → #3 store → #4 keys/discovery → #5 login → #6 registration → #7 token. #10 Docker can start once #2 is done. Then #11 Aspire package → #12 end-to-end tests → #13 docs.
- PRs reference their issue (`Closes #n`). If you diverge from an issue's design, say so in the PR and update the issue.

## Hard constraints

These follow from decisions in #1. Don't change them without updating #1 first.

- **Native AOT.** The server publishes with `PublishAot=true`. Trim/AOT warnings (`IL*`) are errors. That means:
  - System.Text.Json source generation only (`JsonSerializerContext`), never reflection-based serialization.
  - Configuration binding through the config binding source generator.
  - No Blazor, MVC, Razor Pages or ASP.NET cookie authentication: none of them support Native AOT in .NET 10.
- **UI = RazorSlices.** Server-rendered, plain HTML forms, inline CSS.
- **Agent-friendly pages.** Every page must follow these rules; tests enforce them:
  - No `<input type="password">` anywhere. Agents refuse to fill password fields, which is the reason this project exists.
  - No JavaScript, no CAPTCHA, no consent or confirmation screens.
  - Real `<label>` elements, visible text on every action, stable `id`/`name`/`data-testid` attributes.
  - Every flow works with plain `curl` form POSTs.
- **Keycloak parity.** Use Keycloak's paths, parameter names, JSON property names, error codes and error messages. When unsure how Keycloak behaves, check Keycloak 26 behavior or docs rather than guessing. Deliberate divergences go in the README's divergences list.
- **Persistence** is one JSON file (`$ZF_DATA_DIR/0factor.json`), written atomically (temp file + move). Never overwrite a file that failed to parse.
- **Tokens** are real RS256 JWTs signed with `System.Security.Cryptography`. Signatures are always real: the "zero factor" part is the login, not the crypto. `Microsoft.IdentityModel.*` is allowed in tests only.

## Style

- Fewest dependencies possible. Justify any new NuGet package in the PR; prefer the BCL.
- No speculative abstractions: no interface with one implementation, no options that nobody sets.
- Mark deliberate shortcuts with a `ponytail:` comment that names the limit and the upgrade path, e.g. `// ponytail: global lock; per-realm locks if contention ever shows up`.
- Match the surrounding code's naming and comment density.

## Layout

```
0factor.slnx
apphost.cs                       # dev-only Aspire AppHost (file-based), run with `aspire run`
aspire.config.json
src/ZeroFactor/                  # server (Native AOT)
src/ZeroFactor.Aspire.Hosting/   # Aspire hosting package (AddZeroFactor)
tests/ZeroFactor.Tests/          # xUnit v3 + WebApplicationFactory
samples/                         # Aspire AppHost + Web + Api proving the drop-in swap
Dockerfile
```

## Commands

```bash
aspire run                                              # dev: dashboard + server at http://localhost:8080
dotnet build
dotnet test                                             # end-to-end test skipped unless ZF_E2E_IMAGE is set
docker build -t 0factor:e2e . && ZF_E2E_IMAGE=0factor:e2e dotnet test   # also runs samples/ end to end
dotnet publish src/ZeroFactor -c Release -r linux-x64   # must finish with 0 warnings
docker build -t 0factor .
docker run --rm -p 8080:8080 0factor
```

## Testing

- Prove compatibility with real clients: run flows through ASP.NET Core's `AddOpenIdConnect` / `AddJwtBearer` (or `Aspire.Keycloak.Authentication`) handlers, not only hand-written assertions.
- Browser flows are tested with `HttpClient` + cookies + form posts. No Playwright.
- Realm-import tests use a real Keycloak export under `tests/fixtures/`.
- Run `dotnet publish` (AOT) before calling work done. Tests run JIT and won't catch AOT breakage.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ZF_DATA_DIR` | `/data` | Folder holding `0factor.json` |
| `ZF_IMPORT_DIR` | `/opt/keycloak/data/import` | Keycloak realm-export JSON files loaded at startup |
| `ZF_HOSTNAME` | *(from request)* | Fixed base URL for the issuer, like Keycloak's `KC_HOSTNAME` |
| `ZF_STRICT` | `false` | `true` disables auto-creating unknown realms and clients |
| `ZF_REGISTRATION_FIELDS` | *(unset)* | JSON array of registration fields for auto-created realms |
