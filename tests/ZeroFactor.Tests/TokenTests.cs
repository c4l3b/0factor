using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using static ZeroFactor.Tests.AuthorizeTests;

namespace ZeroFactor.Tests;

public sealed class TokenTests : IDisposable
{
    const string Shop = "http://localhost/realms/shop";
    const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const string WebSignIn = "client_id=store.web&redirect_uri=https://localhost:7001/signin-oidc&response_type=code&scope=openid&nonce=n1"
        + $"&code_challenge={Challenge}&code_challenge_method=S256";
    readonly string dataDir = Directory.CreateTempSubdirectory("zf-data-").FullName;
    readonly string importDir = Directory.CreateTempSubdirectory("zf-import-").FullName;
    readonly List<IDisposable> disposables = [];
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        disposables.ForEach(d => d.Dispose());
        Directory.Delete(dataDir, true);
        Directory.Delete(importDir, true);
    }

    WebApplicationFactory<Program> Start()
    {
        File.Copy(Path.Combine(AppContext.BaseDirectory, "fixtures", "shop-realm.json"), Path.Combine(importDir, "shop-realm.json"));
        File.WriteAllText(Path.Combine(importDir, "test.json"), """
            {
              "realm": "test",
              "registrationFields": [{ "name": "dept", "label": "Department", "claim": "department" }],
              "users": [
                { "username": "alice@example.com", "email": "alice@example.com", "firstName": "Alice", "attributes": { "dept": ["ops"] },
                  "claims": { "email": "override@example.com", "tenant_id": "acme", "permissions": ["orders:read", "orders:write"],
                    "org": { "id": 42, "admin": true } } },
                { "username": "off@example.com", "email": "off@example.com", "enabled": false }
              ]
            }
            """);
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", importDir));
        disposables.Add(factory);
        return factory;
    }

    internal static JsonObject Payload(string jwt) => JsonNode.Parse(Base64Url.DecodeFromChars(jwt.Split('.')[1]))!.AsObject();

    static Task<HttpResponseMessage> Send(HttpClient client, string realm, (string Name, string Value)[] form, AuthenticationHeaderValue? auth = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"/realms/{realm}/protocol/openid-connect/token")
        {
            Content = new FormUrlEncodedContent(form.Select(f => new KeyValuePair<string, string>(f.Name, f.Value))),
        };
        request.Headers.Authorization = auth;
        return client.SendAsync(request, Ct);
    }

    static async Task<JsonObject> Body(HttpResponseMessage response)
    {
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!.AsObject();
    }

    internal static async Task<JsonObject> Exchange(HttpClient client, string realm, params (string Name, string Value)[] form)
    {
        var response = await Send(client, realm, form);
        var body = await Body(response);
        Assert.True(response.StatusCode == HttpStatusCode.OK, body.ToJsonString());
        return body;
    }

    static async Task Fails(HttpClient client, string realm, HttpStatusCode status, string error, string description,
        params (string Name, string Value)[] form)
    {
        var response = await Send(client, realm, form);
        Assert.Equal(status, response.StatusCode);
        var body = await Body(response);
        Assert.Equal((error, description), ((string?)body["error"], (string?)body["error_description"]));
        Assert.Equal(2, body.Count);
    }

    static AuthenticationHeaderValue Basic(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    static List<string?> Strings(JsonNode? array) => array!.AsArray().Select(n => (string?)n).ToList();

    [Fact]
    public async Task Lenient_imported_client_accepts_any_redirect_and_secret_and_adds_audience_shorthand()
    {
        File.WriteAllText(Path.Combine(importDir, "local.json"), """
            { "realm": "local", "lenient": true,
              "clients": [{ "clientId": "web", "audience": ["api", "api"], "protocolMappers": [
                { "protocolMapper": "oidc-audience-mapper", "config": { "included.custom.audience": "mapped" } }
              ] }],
              "users": [{ "id": "existing", "username": "alice@example.com", "claims": { "name": "Local Admin" } }] }
            """);
        var client = Start().CreateClient(new() { AllowAutoRedirect = false });
        var login = await client.GetAsync(Auth("local", "client_id=web&redirect_uri=http://localhost:9876/callback&response_type=code"), Ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var tokens = await Exchange(client, "local", ("grant_type", "password"), ("client_id", "web"),
            ("client_secret", "anything"), ("username", "alice@example.com"), ("scope", "openid"));
        var access = Payload((string)tokens["access_token"]!);
        Assert.Equal(["mapped", "api", "account"], Strings(access["aud"]));
        Assert.Equal("existing", (string?)access["sub"]);
        Assert.Equal("Local Admin", (string?)access["name"]);
        Assert.Equal("web", (string?)Payload((string)tokens["id_token"]!)["aud"]);
        await Exchange(client, "local", ("grant_type", "password"), ("client_id", "unlisted-test-client"), ("username", "alice@example.com"));
    }

    [Fact]
    public async Task Password_grant_ignores_the_password_and_returns_keycloak_shaped_tokens()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var store = factory.Services.GetRequiredService<Store>();
        var shop = store.GetRealm("shop")!;
        var alice = shop.FindUser("alice@example.com")!;

        var response = await Send(client, "shop", [("grant_type", "password"), ("username", "alice@example.com"), ("password", "anything"),
            ("scope", "openid")], Basic("store.web", "web-secret"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        var body = await Body(response);
        Assert.Equal(["access_token", "expires_in", "refresh_expires_in", "refresh_token", "token_type", "id_token", "not-before-policy",
            "session_state", "scope"], body.Select(p => p.Key));
        Assert.Equal((600, 1800, "Bearer", 0, "openid profile email"), ((int)body["expires_in"]!, (int)body["refresh_expires_in"]!,
            (string)body["token_type"]!, (int)body["not-before-policy"]!, (string)body["scope"]!));

        var key = RealmKey.For(store, shop);
        foreach (var name in new[] { "access_token", "id_token", "refresh_token" })
            Assert.NotNull(Jwt.Validate(key, (string)body[name]!, Shop));

        var access = Payload((string)body["access_token"]!);
        Assert.Equal(["exp", "iat", "auth_time", "jti", "iss", "aud", "sub", "typ", "azp", "sid", "acr", "allowed-origins", "realm_access",
            "resource_access", "scope", "email_verified", "name", "preferred_username", "given_name", "family_name", "email"], access.Select(p => p.Key));
        Assert.Equal((Shop, alice.Id, "Bearer", "store.web", (string?)body["session_state"], "1"), ((string?)access["iss"], (string?)access["sub"],
            (string?)access["typ"], (string?)access["azp"], (string?)access["sid"], (string?)access["acr"]));
        Assert.Equal(600, (long)access["exp"]! - (long)access["iat"]!);
        Assert.Equal(["store.api", "account"], Strings(access["aud"]));
        Assert.Equal(["https://localhost:7001"], Strings(access["allowed-origins"]));
        Assert.Equal(["offline_access", "default-roles-shop", "admin", "uma_authorization"], Strings(access["realm_access"]!["roles"]));
        Assert.Equal("""{"store.api":{"roles":["orders.read","orders.write"]},"account":{"roles":["manage-account","manage-account-links","view-profile"]}}""",
            access["resource_access"]!.ToJsonString());
        Assert.Equal((true, "Alice Admin", "alice@example.com", "Alice", "Admin", "alice@example.com"), ((bool)access["email_verified"]!,
            (string?)access["name"], (string?)access["preferred_username"], (string?)access["given_name"], (string?)access["family_name"], (string?)access["email"]));

        var id = Payload((string)body["id_token"]!);
        Assert.Equal(("ID", "store.web", "store.web", access["sid"]!.ToString()), ((string?)id["typ"], (string?)id["aud"], (string?)id["azp"], (string?)id["sid"]));
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes((string)body["access_token"]!));
        Assert.Equal(Base64Url.EncodeToString(hash.AsSpan(0, 16)), (string?)id["at_hash"]);
        Assert.Null(id["nonce"]);
        Assert.Equal("Alice Admin", (string?)id["name"]);

        var refresh = Payload((string)body["refresh_token"]!);
        Assert.Equal(("Refresh", Shop, "store.web"), ((string?)refresh["typ"], (string?)refresh["aud"], (string?)refresh["azp"]));
        Assert.NotNull(alice.LastLoginAt);

        // client_secret_post works too; errors match Keycloak.
        (string, string)[] Form(string clientId, params (string, string)[] extra) =>
            [("grant_type", "password"), ("client_id", clientId), ("client_secret", "web-secret"), .. extra];
        await Exchange(client, "shop", Form("store.web", ("username", "bob@example.com")));
        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_grant", "Invalid user credentials", Form("store.web", ("username", "zed@example.com")));
        await Fails(client, "shop", HttpStatusCode.Unauthorized, "invalid_request", "Missing parameter: username", Form("store.web"));
        await Fails(client, "shop", HttpStatusCode.BadRequest, "unauthorized_client", "Client not allowed for direct access grants",
            Form("store.spa", ("username", "bob@example.com")));
        await Fails(client, "shop", HttpStatusCode.Unauthorized, "invalid_client", "Invalid client or Invalid client credentials",
            Form("nope", ("username", "bob@example.com")));
        await Fails(client, "shop", HttpStatusCode.Unauthorized, "unauthorized_client", "Invalid client or Invalid client credentials",
            [("grant_type", "password"), ("client_id", "store.web"), ("client_secret", "wrong"), ("username", "bob@example.com")]);
        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_request", "Missing form parameter: grant_type", [("client_id", "store.web")]);
        await Fails(client, "shop", HttpStatusCode.BadRequest, "unsupported_grant_type", "Unsupported grant_type",
            [("grant_type", "implicit"), ("client_id", "store.spa")]);
        await Fails(client, "test", HttpStatusCode.BadRequest, "invalid_grant", "Account disabled",
            [("grant_type", "password"), ("client_id", "web"), ("username", "off@example.com")]);
    }

    [Fact]
    public async Task Extra_claims_keep_their_json_types_override_profile_claims_and_skip_reserved_names()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var store = factory.Services.GetRequiredService<Store>();
        var alice = store.GetRealm("test")!.FindUser("alice@example.com")!;
        // Bypasses the store's validation, as a hand-edited data file could.
        store.Update(_ => alice.Claims!["sub"] = "hijacked");

        // The README one-liner: lenient realm, any client, no secret, no password.
        var plain = await Exchange(client, "test", ("grant_type", "password"), ("client_id", "web"), ("username", "alice@example.com"));
        Assert.Null(plain["id_token"]);
        Assert.Equal("profile email", (string?)plain["scope"]);

        var body = await Exchange(client, "test", ("grant_type", "password"), ("client_id", "web"), ("username", "ALICE@example.com"),
            ("scope", "openid"));
        foreach (var token in new[] { Payload((string)body["access_token"]!), Payload((string)body["id_token"]!) })
        {
            Assert.Equal(alice.Id, (string?)token["sub"]);
            Assert.Equal(("override@example.com", "ops", "Alice", "acme"),
                ((string?)token["email"], (string?)token["department"], (string?)token["name"], (string?)token["tenant_id"]));
            Assert.Equal("""["orders:read","orders:write"]""", token["permissions"]!.ToJsonString());
            Assert.Equal("""{"id":42,"admin":true}""", token["org"]!.ToJsonString());
        }
        Assert.Equal("account", (string?)Payload((string)body["access_token"]!)["aud"]);
    }

    [Fact]
    public async Task Authorization_code_grant_checks_code_client_redirect_uri_and_pkce()
    {
        var factory = Start();
        var browser = Browser(factory);
        var client = factory.CreateClient();

        var first = Query(await SignIn(browser, WebSignIn, "bob@example.com", "shop"));
        async Task<string> NewCode() => Query(await browser.GetAsync(Auth("shop", WebSignIn), Ct))["code"]!;
        (string, string)[] Form(string code, string clientId = "store.web", string secret = "web-secret",
            string redirectUri = "https://localhost:7001/signin-oidc", string? verifier = Verifier) =>
            [("grant_type", "authorization_code"), ("client_id", clientId), ("client_secret", secret), ("code", code),
                ("redirect_uri", redirectUri), .. verifier is null ? Array.Empty<(string, string)>() : [("code_verifier", verifier)]];

        var body = await Exchange(client, "shop", Form(first["code"]!));
        Assert.Equal(first["session_state"], (string?)body["session_state"]);
        var id = Payload((string)body["id_token"]!);
        Assert.Equal(("n1", (string?)first["session_state"]), ((string?)id["nonce"], (string?)id["sid"]));
        Assert.Equal((long)id["auth_time"]!, (long)Payload((string)body["access_token"]!)["auth_time"]!);

        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_grant", "Code not valid", Form(first["code"]!));
        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_grant", "Auth error: Found different client_id in clientSession",
            Form(await NewCode(), "store.api", "api-secret"));
        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_grant", "Incorrect redirect_uri",
            Form(await NewCode(), redirectUri: "https://localhost:7001/other"));
        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_grant", "PKCE code verifier not specified", Form(await NewCode(), verifier: null));
        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_grant", "PKCE verification failed: Code mismatch",
            Form(await NewCode(), verifier: Verifier[..^1] + "X"));
        await Fails(client, "shop", HttpStatusCode.BadRequest, "invalid_request", "Missing parameter: code",
            [("grant_type", "authorization_code"), ("client_id", "store.web"), ("client_secret", "web-secret")]);

        // Plain PKCE in a lenient realm, public client.
        var plain = Query(await SignIn(Browser(factory), Request + "&code_challenge=abc&code_challenge_method=plain", "alice@example.com"));
        await Exchange(client, "test", ("grant_type", "authorization_code"), ("client_id", "web"), ("code", plain["code"]!),
            ("redirect_uri", "http://app.test/cb"), ("code_verifier", "abc"));
    }

    const string Request = "client_id=web&redirect_uri=http://app.test/cb&response_type=code&state=s1";

    [Fact]
    public async Task Refresh_token_rotates_and_offline_access_outlives_the_session()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var store = factory.Services.GetRequiredService<Store>();
        (string, string)[] Refresh(string token, string clientId = "web") =>
            [("grant_type", "refresh_token"), ("client_id", clientId), ("refresh_token", token)];

        var first = await Exchange(client, "test", ("grant_type", "password"), ("client_id", "web"), ("username", "alice@example.com"),
            ("scope", "openid"));
        var second = await Exchange(client, "test", Refresh((string)first["refresh_token"]!));
        Assert.NotEqual((string?)first["refresh_token"], (string?)second["refresh_token"]);
        Assert.Equal(((string?)first["session_state"], "openid profile email"), ((string?)second["session_state"], (string?)second["scope"]));
        Assert.NotNull(second["id_token"]);
        var refreshed = Payload((string)second["access_token"]!);
        Assert.Equal((string?)first["session_state"], (string?)refreshed["sid"]);
        Assert.Equal((long)Payload((string)first["access_token"]!)["auth_time"]!, (long)refreshed["auth_time"]!);

        await Fails(client, "test", HttpStatusCode.BadRequest, "invalid_grant", "Invalid refresh token. Token client and authorized client don't match",
            Refresh((string)second["refresh_token"]!, "other"));
        await Fails(client, "test", HttpStatusCode.BadRequest, "invalid_grant", "Invalid refresh token", Refresh((string)second["access_token"]!));
        await Fails(client, "test", HttpStatusCode.BadRequest, "invalid_grant", "Invalid refresh token", Refresh("garbage"));
        await Fails(client, "test", HttpStatusCode.BadRequest, "invalid_request", "No refresh token", [("grant_type", "refresh_token"), ("client_id", "web")]);

        var offline = await Exchange(client, "test", ("grant_type", "password"), ("client_id", "web"), ("username", "alice@example.com"),
            ("scope", "offline_access"));
        Assert.Equal((0, "profile email offline_access"), ((int)offline["refresh_expires_in"]!, (string?)offline["scope"]));
        Assert.Equal("Offline", (string?)Payload((string)offline["refresh_token"]!)["typ"]);
        var again = await Exchange(client, "test", Refresh((string)offline["refresh_token"]!));
        Assert.Equal("Offline", (string?)Payload((string)again["refresh_token"]!)["typ"]);

        var alice = store.GetRealm("test")!.FindUser("alice@example.com")!;
        store.Update(_ => alice.Enabled = false);
        await Fails(client, "test", HttpStatusCode.BadRequest, "invalid_grant", "User disabled", Refresh((string)again["refresh_token"]!));
    }

    [Fact]
    public async Task Client_credentials_uses_a_service_account_user_with_editable_roles_and_claims()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var store = factory.Services.GetRequiredService<Store>();
        var realm = store.GetRealm("shop")!;

        var response = await Send(client, "shop", [("grant_type", "client_credentials")], Basic("store.api", "api-secret"));
        var body = await Body(response);
        Assert.Equal(["access_token", "expires_in", "refresh_expires_in", "token_type", "not-before-policy", "scope"], body.Select(p => p.Key));
        Assert.Equal(0, (int)body["refresh_expires_in"]!);
        var account = realm.FindUser("service-account-store.api")!;
        var access = Payload((string)body["access_token"]!);
        Assert.Equal((account.Id, "service-account-store.api", "store.api", "store.api", "account", false),
            ((string?)access["sub"], (string?)access["preferred_username"], (string?)access["client_id"], (string?)access["azp"],
                (string?)access["aud"], (bool)access["email_verified"]!));
        Assert.Null(access["sid"]);
        Assert.Null(access["allowed-origins"]);

        store.Update(_ =>
        {
            account.RealmRoles = ["admin"];
            account.ClientRoles["store.web"] = ["orders.export"];
            account.Claims = new JsonObject { ["tenant_id"] = "acme", ["limits"] = new JsonObject { ["rpm"] = 100 } };
        });
        var edited = await Exchange(client, "shop", ("grant_type", "client_credentials"), ("client_id", "store.api"), ("client_secret", "api-secret"),
            ("scope", "openid"));
        access = Payload((string)edited["access_token"]!);
        Assert.Contains("admin", Strings(access["realm_access"]!["roles"]));
        Assert.Equal(["orders.export"], Strings(access["resource_access"]!["store.web"]!["roles"]));
        Assert.Equal(["store.web", "account"], Strings(access["aud"]));
        Assert.Equal(("acme", 100), ((string?)access["tenant_id"], (int)access["limits"]!["rpm"]!));
        Assert.Equal("acme", (string?)Payload((string)edited["id_token"]!)["tenant_id"]);
        Assert.Single(realm.Users, u => u.Username == "service-account-store.api");

        await Fails(client, "shop", HttpStatusCode.Unauthorized, "unauthorized_client", "Client not enabled to retrieve service account",
            [("grant_type", "client_credentials"), ("client_id", "store.web"), ("client_secret", "web-secret")]);
        await Fails(client, "shop", HttpStatusCode.Unauthorized, "unauthorized_client", "Public client not allowed to retrieve service account",
            [("grant_type", "client_credentials"), ("client_id", "store.spa")]);
        await Exchange(client, "test", ("grant_type", "client_credentials"), ("client_id", "anything"), ("client_secret", "any"));
    }

    [Fact]
    public async Task Keycloak_jwt_bearer_accepts_access_tokens_and_authorizes_by_realm_role()
    {
        var zf = Start();
        var zfClient = zf.CreateClient();

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthorization();
        // Aspire resolves https+http://keycloak through service discovery; point it at the in-memory 0factor instead.
        // Registered first so it runs before JwtBearer's own post-configure builds the metadata manager.
        builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o => (o.Authority, o.Backchannel) = (Shop, zfClient));
        builder.Services.AddAuthentication()
            .AddKeycloakJwtBearer("keycloak", "shop", o =>
            {
                o.Audience = "store.api"; // added to store.web tokens by the realm's oidc-audience-mapper
                o.RequireHttpsMetadata = false;
                o.MapInboundClaims = false;
                // The usual Keycloak recipe: flatten realm_access.roles into role claims.
                o.Events = new JwtBearerEvents
                {
                    OnTokenValidated = c =>
                    {
                        var identity = (ClaimsIdentity)c.Principal!.Identity!;
                        if (identity.FindFirst("realm_access") is { } realmAccess)
                            foreach (var role in JsonNode.Parse(realmAccess.Value)!["roles"]!.AsArray())
                                identity.AddClaim(new Claim(identity.RoleClaimType, (string)role!));
                        return Task.CompletedTask;
                    },
                };
            });
        await using var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/orders", [Authorize] () => "orders");
        app.MapGet("/admin", [Authorize(Roles = "admin")] () => "admin");
        await app.StartAsync(Ct);
        var api = app.GetTestClient();

        async Task<HttpStatusCode> Call(string path, JsonObject tokens)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Authorization = new("Bearer", (string)tokens["access_token"]!);
            return (await api.SendAsync(request, Ct)).StatusCode;
        }
        Task<JsonObject> Password(string username) => Exchange(zfClient, "shop", ("grant_type", "password"), ("client_id", "store.web"),
            ("client_secret", "web-secret"), ("username", username));

        var alice = await Password("alice@example.com");
        Assert.Equal(HttpStatusCode.OK, await Call("/orders", alice));
        Assert.Equal(HttpStatusCode.OK, await Call("/admin", alice));
        var bob = await Password("bob@example.com");
        Assert.Equal(HttpStatusCode.OK, await Call("/orders", bob));
        Assert.Equal(HttpStatusCode.Forbidden, await Call("/admin", bob));

        // A store.api service-account token's audience is only "account".
        var service = await Exchange(zfClient, "shop", ("grant_type", "client_credentials"), ("client_id", "store.api"), ("client_secret", "api-secret"));
        Assert.Equal(HttpStatusCode.Unauthorized, await Call("/orders", service));
    }

    /// <summary><paramref name="jwt"/> re-signed with the realm key after <paramref name="edit"/>, e.g. to make it expired.</summary>
    static string Resign(WebApplicationFactory<Program> factory, string realm, string jwt, Action<JsonObject> edit)
    {
        var store = factory.Services.GetRequiredService<Store>();
        var payload = Payload(jwt);
        edit(payload);
        return Jwt.Create(RealmKey.For(store, store.GetRealm(realm)!), payload);
    }

    static void Expire(JsonObject payload) => payload["exp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10;

    [Fact]
    public async Task Userinfo_returns_profile_and_custom_claims_and_rejects_bad_tokens()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var store = factory.Services.GetRequiredService<Store>();

        var shop = await Exchange(client, "shop", ("grant_type", "password"), ("client_id", "store.web"), ("client_secret", "web-secret"),
            ("username", "alice@example.com"), ("scope", "openid"));
        async Task<HttpResponseMessage> Get(string token)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/realms/shop/protocol/openid-connect/userinfo");
            request.Headers.Authorization = new("Bearer", token);
            return await client.SendAsync(request, Ct);
        }
        var response = await Get((string)shop["access_token"]!);
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        var alice = store.GetRealm("shop")!.FindUser("alice@example.com")!;
        // Exactly what Keycloak 26 returns for this fixture user.
        Assert.Equal($$"""{"sub":"{{alice.Id}}","email_verified":true,"name":"Alice Admin","preferred_username":"alice@example.com","given_name":"Alice","family_name":"Admin","email":"alice@example.com"}""",
            (await Body(response)).ToJsonString());

        // Custom claims (#6, #7): registration-field claim and extra JSON claims, which override profile claims; reserved names skipped.
        var testAlice = store.GetRealm("test")!.FindUser("alice@example.com")!;
        store.Update(_ => testAlice.Claims!["sub"] = "hijacked");
        var test = await Exchange(client, "test", ("grant_type", "password"), ("client_id", "web"), ("username", "alice@example.com"));
        var form = await client.PostAsync("/realms/test/protocol/openid-connect/userinfo",
            new FormUrlEncodedContent([new("access_token", (string)test["access_token"]!)]), Ct);
        var claims = await Body(form);
        Assert.Equal((testAlice.Id, "override@example.com", "ops", "Alice", "acme"), ((string?)claims["sub"], (string?)claims["email"],
            (string?)claims["department"], (string?)claims["name"], (string?)claims["tenant_id"]));
        Assert.Equal("""["orders:read","orders:write"]""", claims["permissions"]!.ToJsonString());
        Assert.Equal("""{"id":42,"admin":true}""", claims["org"]!.ToJsonString());

        const string invalid = "Bearer realm=\"shop\", error=\"invalid_token\", error_description=\"Token verification failed\"";
        foreach (var bad in new[] { "garbage", (string)shop["id_token"]!, (string)shop["refresh_token"]!,
            Resign(factory, "shop", (string)shop["access_token"]!, Expire) })
        {
            var rejected = await Get(bad);
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
            Assert.Equal(invalid, rejected.Headers.WwwAuthenticate.ToString());
        }
        var missing = await client.GetAsync("/realms/shop/protocol/openid-connect/userinfo", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal("Bearer realm=\"shop\"", missing.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Introspection_requires_a_confidential_client_and_reports_only_valid_tokens_active()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var tokens = await Exchange(client, "shop", ("grant_type", "password"), ("client_id", "store.web"), ("client_secret", "web-secret"),
            ("username", "alice@example.com"), ("scope", "openid"));
        async Task<HttpResponseMessage> Introspect(string token, string? hint = null, AuthenticationHeaderValue? auth = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/realms/shop/protocol/openid-connect/token/introspect")
            {
                Content = new FormUrlEncodedContent(hint is null ? [new("token", token)] : [new("token", token), new("token_type_hint", hint)]),
            };
            request.Headers.Authorization = auth ?? Basic("store.api", "api-secret");
            return await client.SendAsync(request, Ct);
        }

        var access = (string)tokens["access_token"]!;
        var active = await Body(await Introspect(access));
        Assert.Equal([.. Payload(access).Select(p => p.Key), "client_id", "username", "token_type", "active"], active.Select(p => p.Key));
        Assert.Equal(("store.web", "alice@example.com", "Bearer", true, "Alice Admin"), ((string?)active["client_id"], (string?)active["username"],
            (string?)active["token_type"], (bool)active["active"]!, (string?)active["name"]));

        var refresh = await Body(await Introspect((string)tokens["refresh_token"]!, "refresh_token"));
        Assert.Equal(("Refresh", true), ((string?)refresh["token_type"], (bool)refresh["active"]!));

        foreach (var (token, hint) in new[] { ("garbage", null), ((string)tokens["id_token"]!, null), ((string)tokens["refresh_token"]!, null),
            (Resign(factory, "shop", access, Expire), (string?)null) })
            Assert.Equal("""{"active":false}""", (await Body(await Introspect(token, hint))).ToJsonString());

        async Task Fails(HttpResponseMessage response, HttpStatusCode status, string description)
        {
            Assert.Equal(status, response.StatusCode);
            Assert.Equal($$"""{"error":"invalid_request","error_description":"{{description}}"}""", (await Body(response)).ToJsonString());
        }
        await Fails(await Introspect(access, auth: Basic("store.api", "wrong")), HttpStatusCode.Unauthorized, "Authentication failed.");
        await Fails(await Introspect(access, auth: Basic("nope", "x")), HttpStatusCode.Unauthorized, "Authentication failed.");
        await Fails(await client.PostAsync("/realms/shop/protocol/openid-connect/token/introspect",
            new FormUrlEncodedContent([new("client_id", "store.spa"), new("token", access)]), Ct), HttpStatusCode.Forbidden, "Client not allowed.");
        await Fails(await Introspect(""), HttpStatusCode.BadRequest, "Token not provided.");
    }

    [Fact]
    public async Task Revocation_authenticates_the_client_and_is_a_no_op()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var tokens = await Exchange(client, "test", ("grant_type", "password"), ("client_id", "web"), ("username", "alice@example.com"));
        Task<HttpResponseMessage> Revoke(string realm, params (string Name, string Value)[] form) =>
            client.PostAsync($"/realms/{realm}/protocol/openid-connect/revoke",
                new FormUrlEncodedContent(form.Select(f => new KeyValuePair<string, string>(f.Name, f.Value))), Ct);

        var revoked = await Revoke("test", ("client_id", "web"), ("token", (string)tokens["refresh_token"]!));
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Equal("", await revoked.Content.ReadAsStringAsync(Ct));
        // Stateless: the revoked refresh token still works.
        await Exchange(client, "test", ("grant_type", "refresh_token"), ("client_id", "web"), ("refresh_token", (string)tokens["refresh_token"]!));

        var garbage = await Revoke("test", ("client_id", "web"), ("token", "garbage"));
        Assert.Equal(HttpStatusCode.OK, garbage.StatusCode);
        Assert.Equal("""{"error":"invalid_token","error_description":"Invalid token"}""", (await Body(garbage)).ToJsonString());
        Assert.Equal(HttpStatusCode.BadRequest, (await Revoke("test", ("client_id", "web"))).StatusCode);
        var wrong = await Revoke("shop", ("client_id", "store.web"), ("client_secret", "wrong"), ("token", "garbage"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("unauthorized_client", (string?)(await Body(wrong))["error"]);
    }

    [Fact]
    public async Task Logout_clears_the_session_and_checks_post_logout_redirect_uris_in_strict_realms()
    {
        var factory = Start();
        var browser = Browser(factory);
        const string Logout = "/realms/shop/protocol/openid-connect/logout";
        const string Back = "https://localhost:7001/signin-oidc";

        string code = Query(await SignIn(browser, WebSignIn, "alice@example.com", "shop"))["code"]!;
        var tokens = await Exchange(factory.CreateClient(), "shop", ("grant_type", "authorization_code"), ("client_id", "store.web"),
            ("client_secret", "web-secret"), ("code", code), ("redirect_uri", Back), ("code_verifier", Verifier));
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(Auth("shop", WebSignIn), Ct)).StatusCode);

        async Task ErrorPage(string query, string message)
        {
            var response = await browser.GetAsync($"{Logout}?{query}", Ct);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains(message, await Html(response));
        }
        await ErrorPage($"post_logout_redirect_uri={Back}", "Missing parameters: id_token_hint");
        await ErrorPage($"post_logout_redirect_uri=https://evil.test/&client_id=store.web", "Invalid redirect uri");
        await ErrorPage("id_token_hint=garbage", "Invalid parameter: id_token_hint");
        await ErrorPage($"id_token_hint={tokens["access_token"]}", "Invalid parameter: id_token_hint");
        await ErrorPage($"id_token_hint={tokens["id_token"]}&client_id=store.spa", "Invalid parameter: id_token_hint");
        // Errors leave the session alone.
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(Auth("shop", WebSignIn), Ct)).StatusCode);

        // "+" in post.logout.redirect.uris means the client's redirect URIs; an expired id_token_hint is fine, as in Keycloak.
        var hint = Resign(factory, "shop", (string)tokens["id_token"]!, Expire);
        var logout = await browser.GetAsync($"{Logout}?id_token_hint={hint}&post_logout_redirect_uri={Back}&state=s1", Ct);
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.Equal($"{Back}?state=s1", logout.Headers.Location!.ToString());
        var cleared = Assert.Single(logout.Headers.GetValues("Set-Cookie"), c => c.StartsWith("ZF_SESSION="));
        Assert.StartsWith("ZF_SESSION=;", cleared);
        Assert.Contains("path=/realms/shop/", cleared);

        var login = await browser.GetAsync(Auth("shop", WebSignIn), Ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("Sign in to shop", await Html(login));

        // No redirect URI: a plain page, no confirmation step. POST works the same.
        var page = await browser.PostAsync(Logout, new FormUrlEncodedContent([new("client_id", "store.web")]), Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("You are signed out.", await Html(page));

        // Lenient realms accept any post_logout_redirect_uri.
        var lenient = await browser.GetAsync("/realms/test/protocol/openid-connect/logout?client_id=web&post_logout_redirect_uri=http://app.test/bye", Ct);
        Assert.Equal("http://app.test/bye", lenient.Headers.Location!.ToString());
    }
}
