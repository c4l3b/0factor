using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Mvc.Testing.Handlers;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace ZeroFactor.Tests;

public sealed class AuthorizeTests : IDisposable
{
    const string Issuer = "http://localhost/realms/test";
    const string Request = "client_id=web&redirect_uri=http://app.test/cb&response_type=code&state=s1";
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

    WebApplicationFactory<Program> Start(string? registrationFields = null)
    {
        File.WriteAllText(Path.Combine(importDir, "test.json"), """{ "realm": "test", "users": [{ "username": "alice@example.com", "email": "alice@example.com" }] }""");
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", importDir).UseSetting("ZF_REGISTRATION_FIELDS", registrationFields));
        disposables.Add(factory);
        return factory;
    }

    internal static HttpClient Browser(WebApplicationFactory<Program> factory) => factory.CreateClient(new() { AllowAutoRedirect = false });

    internal static string Auth(string realm, string query) => $"/realms/{realm}/protocol/openid-connect/auth?{query}";

    internal static string Field(string html, string name) =>
        WebUtility.HtmlDecode(Regex.Match(html, $"name=\"{name}\" value=\"([^\"]*)\"").Groups[1].Value);

    internal static async Task<string> Html(HttpResponseMessage response)
    {
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        var html = await response.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain("type=\"password\"", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        return html;
    }

    /// <summary>Opens the login page for <paramref name="query"/> and posts only an email.</summary>
    internal static async Task<HttpResponseMessage> SignIn(HttpClient client, string query, string email, string realm = "test")
    {
        var login = await client.GetAsync(Auth(realm, query), Ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return await Post(client, realm, Field(await Html(login), "auth"), email);
    }

    internal static Task<HttpResponseMessage> Post(HttpClient client, string realm, string auth, string email) =>
        client.PostAsync($"/realms/{realm}/login-actions/authenticate",
            new FormUrlEncodedContent([new("auth", auth), new("email", email)]), Ct);

    internal static Dictionary<string, Microsoft.Extensions.Primitives.StringValues> Query(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return QueryHelpers.ParseQuery(response.Headers.Location!.Query);
    }

    [Fact]
    public async Task Oidc_handler_completes_login_by_posting_only_an_email()
    {
        var zf = Start();
        var zfHandler = zf.Server.CreateHandler();
        var store = zf.Services.GetRequiredService<Store>();

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthorization();
        builder.Services.AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(o =>
            {
                o.Authority = Issuer;
                o.ClientId = "web";
                o.ClientSecret = "secret";
                o.ResponseType = "code";
                o.RequireHttpsMetadata = false;
                o.MapInboundClaims = false;
                o.BackchannelHttpHandler = zfHandler;
                o.SaveTokens = true;
            });
        await using var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/me", (HttpContext c) => c.User.FindFirst("sub")!.Value).RequireAuthorization();
        // Explicit return type, or the lambda binds as a RequestDelegate and the token is discarded.
        app.MapGet("/access-token", Task<string?> (HttpContext c) => c.GetTokenAsync("access_token")).RequireAuthorization();
        app.MapGet("/signout", () => Results.SignOut(new() { RedirectUri = "/signed-out" },
            [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));
        await app.StartAsync(Ct);

        var browser = new HttpClient(new CookieContainerHandler { InnerHandler = new Router(zfHandler, app.GetTestServer().CreateHandler()) });

        var challenge = await browser.GetAsync("https://app.test/me", Ct);
        Assert.StartsWith($"{Issuer}/protocol/openid-connect/auth?", challenge.Headers.Location!.ToString());

        var login = await Html(await browser.GetAsync(challenge.Headers.Location, Ct));
        Assert.Contains("Sign in to test", login);
        var formPost = await browser.PostAsync("http://localhost/realms/test/login-actions/authenticate",
            new FormUrlEncodedContent([new("auth", Field(login, "auth")), new("email", "alice@example.com")]), Ct);

        // Default ASP.NET response_mode is form_post: a plain form with a Continue button.
        var html = await Html(formPost);
        var fields = Regex.Matches(html, "name=\"([^\"]+)\" value=\"([^\"]*)\"")
            .ToDictionary(m => m.Groups[1].Value, m => WebUtility.HtmlDecode(m.Groups[2].Value));
        Assert.Equal(Issuer, fields["iss"]);
        Assert.Contains("session_state", fields.Keys);
        Assert.Contains("state", fields.Keys);
        var action = WebUtility.HtmlDecode(Regex.Match(html, "action=\"([^\"]+)\"").Groups[1].Value);
        Assert.Equal("https://app.test/signin-oidc", action);

        var callback = await browser.PostAsync(action, new FormUrlEncodedContent(fields), Ct);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/me", callback.Headers.Location!.ToString());

        var me = await browser.GetStringAsync("https://app.test/me", Ct);
        var alice = store.GetRealm("test")!.FindUser("alice@example.com")!;
        Assert.Equal(alice.Id, me);
        Assert.NotNull(alice.LastLoginAt);

        // Tokens came from the real token endpoint (code + PKCE, client_secret_post).
        var access = TokenTests.Payload(await browser.GetStringAsync("https://app.test/access-token", Ct));
        Assert.Equal(("web", "Bearer", alice.Id, "account"), ((string?)access["azp"], (string?)access["typ"], (string?)access["sub"], (string?)access["aud"]));
        Assert.Equal("openid profile email", (string?)access["scope"]);
        Assert.Equal(fields["session_state"], (string?)access["sid"]);

        // SignOutAsync: RP-initiated logout with id_token_hint, back through signout-callback-oidc with state.
        var signOut = await browser.GetAsync("https://app.test/signout", Ct);
        var endSession = signOut.Headers.Location!;
        Assert.StartsWith($"{Issuer}/protocol/openid-connect/logout?", endSession.ToString());
        Assert.Contains("id_token_hint", QueryHelpers.ParseQuery(endSession.Query).Keys);
        var back = await browser.GetAsync(endSession, Ct);
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        Assert.StartsWith("https://app.test/signout-callback-oidc?state=", back.Headers.Location!.ToString());
        var done = await browser.GetAsync(back.Headers.Location, Ct);
        Assert.Equal("/signed-out", done.Headers.Location!.ToString());

        // The SSO session is gone: the next authorize shows the login page.
        var again = await browser.GetAsync("https://app.test/me", Ct);
        Assert.StartsWith($"{Issuer}/protocol/openid-connect/auth?", again.Headers.Location!.ToString());
        Assert.Contains("Sign in to test", await Html(await browser.GetAsync(again.Headers.Location, Ct)));
    }

    [Fact]
    public async Task Session_cookie_skips_login_and_prompt_login_forces_it()
    {
        var client = Browser(Start());

        var first = await SignIn(client, Request + "&nonce=n1", "alice@example.com");
        var query = Query(first);
        Assert.StartsWith("http://app.test/cb?", first.Headers.Location!.ToString());
        Assert.Equal(["state", "session_state", "iss", "code"], query.Keys);
        Assert.Equal("s1", query["state"]);
        Assert.Equal(Issuer, query["iss"]);
        var cookie = Assert.Single(first.Headers.GetValues("Set-Cookie"));
        Assert.StartsWith("ZF_SESSION=", cookie);
        Assert.Contains("path=/realms/test/", cookie);
        Assert.Contains("httponly", cookie);
        Assert.Contains("samesite=lax", cookie);

        var again = Query(await client.GetAsync(Auth("test", Request.Replace("s1", "s2")), Ct));
        Assert.Equal("s2", again["state"]);
        Assert.Equal(query["session_state"], again["session_state"]);
        Assert.NotEqual(query["code"], again["code"]);

        var forced = await client.GetAsync(Auth("test", Request + "&prompt=login"), Ct);
        Assert.Equal(HttpStatusCode.OK, forced.StatusCode);
        Assert.Contains("Sign in to test", await Html(forced));

        var none = Query(await Browser(Start()).GetAsync(Auth("test", Request + "&prompt=none"), Ct));
        Assert.Equal("login_required", none["error"]);
        Assert.Equal("s1", none["state"]);
    }

    [Fact]
    public async Task Code_is_single_use_and_bound_to_the_request()
    {
        var factory = Start();
        var challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        var query = Query(await SignIn(Browser(factory),
            Request + $"&scope=openid%20email&nonce=n1&code_challenge={challenge}&code_challenge_method=S256", "alice@example.com"));

        var codes = factory.Services.GetRequiredService<AuthCodes>();
        var code = codes.Redeem(query["code"]!)!;
        Assert.Equal(("test", "web", "http://app.test/cb", "openid email", "n1", challenge, "S256"),
            (code.Realm, code.ClientId, code.RedirectUri, code.Scope, code.Nonce, code.CodeChallenge, code.CodeChallengeMethod));
        Assert.Equal(query["session_state"], code.Sid);
        Assert.Equal(factory.Services.GetRequiredService<Store>().GetRealm("test")!.FindUser("alice@example.com")!.Id, code.UserId);
        Assert.InRange(code.Expires - DateTimeOffset.UtcNow, TimeSpan.FromSeconds(50), TimeSpan.FromSeconds(60));
        Assert.Equal(43, query["code"].ToString().Length);
        Assert.Null(codes.Redeem(query["code"]!));
    }

    [Fact]
    public async Task Client_and_redirect_uri_errors_render_a_page_other_errors_redirect()
    {
        File.Copy(Path.Combine(AppContext.BaseDirectory, "fixtures", "shop-realm.json"), Path.Combine(importDir, "shop-realm.json"));
        var client = Browser(Start());

        async Task ErrorPage(string query, string message)
        {
            var response = await client.GetAsync(Auth("shop", query), Ct);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.Contains(message, await Html(response));
        }
        await ErrorPage("client_id=nope&redirect_uri=https://localhost:7001/signin-oidc&response_type=code", "Client not found.");
        await ErrorPage("client_id=store.web&redirect_uri=https://evil.test/signin-oidc&response_type=code", "Invalid parameter: redirect_uri");
        await ErrorPage("client_id=store.web&response_type=code", "Invalid parameter: redirect_uri");
        await ErrorPage("redirect_uri=https://localhost:7001/signin-oidc", "Missing parameter: client_id");

        var pkce = Query(await client.GetAsync(Auth("shop", "client_id=store.web&redirect_uri=https://localhost:7001/signin-oidc&response_type=code&state=x"), Ct));
        Assert.Equal(("invalid_request", "Missing parameter: code_challenge", "x"), (pkce["error"].ToString(), pkce["error_description"].ToString(), pkce["state"].ToString()));

        var spa = "client_id=store.spa&redirect_uri=http://localhost:5173/any/path";
        var token = Query(await client.GetAsync(Auth("shop", spa + "&response_type=token"), Ct));
        Assert.Equal("unsupported_response_type", token["error"]);

        // Trailing-* wildcard redirect URI; fragment response mode.
        var fragment = await SignIn(client, spa + "&response_type=code&response_mode=fragment&state=f", "bob@example.com", "shop");
        var location = fragment.Headers.Location!;
        Assert.StartsWith("http://localhost:5173/any/path#state=f&session_state=", location.ToString());
        Assert.Contains("&code=", location.Fragment);
        Assert.Equal("", location.Query);

        var unknownRealm = await client.GetAsync(Auth("nope", Request), Ct);
        Assert.Equal(HttpStatusCode.OK, unknownRealm.StatusCode); // lenient: auto-created
    }

    [Fact]
    public async Task Login_page_lists_users_and_rejects_unknown_and_disabled_users()
    {
        File.WriteAllText(Path.Combine(importDir, "closed.json"), """
            {
              "realm": "closed",
              "registrationAllowed": false,
              "users": [
                { "username": "off@example.com", "email": "off@example.com", "enabled": false },
                { "username": "carol", "email": "carol@example.com", "firstName": "Carol", "lastName": "Doe",
                  "realmRoles": ["admin"], "clientRoles": { "api": ["orders.read"] }, "agentNotes": "admin in tenant acme, billing tests" },
                { "username": "dave@example.com", "email": "dave@example.com" }
              ]
            }
            """);
        var factory = Start();
        var client = Browser(factory);

        var page = await client.GetAsync(Auth("closed", Request + "&login_hint=hint@example.com"), Ct);
        var html = await Html(page);
        Assert.Contains("<title>Sign in to closed · 0factor</title>", html);
        Assert.Contains("0factor test identity provider. No passwords. Pick a user below or type an email.", html);
        Assert.Contains("<label for=\"email\">Email</label>", html);
        Assert.Contains("<input id=\"email\" name=\"email\" type=\"email\" required autofocus value=\"hint@example.com\"", html);
        Assert.Contains("<button type=\"submit\" id=\"continue\" data-testid=\"continue\">Continue</button>", html);
        Assert.Contains("<button type=\"submit\" name=\"email\" value=\"carol@example.com\"", html);
        Assert.Contains("Carol Doe", html);
        Assert.Contains("Roles: admin, api:orders.read", html);
        Assert.Contains("admin in tenant acme, billing tests", html);
        Assert.Contains("off@example.com (disabled)", html);
        var auth = Field(html, "auth");

        var unknown = await Post(client, "closed", auth, "who@example.com");
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        var unknownHtml = await Html(unknown);
        Assert.Contains("No user with that email.", unknownHtml);
        Assert.Contains("value=\"who@example.com\"", unknownHtml);
        Assert.Null(factory.Services.GetRequiredService<Store>().GetRealm("closed")!.FindUser("who@example.com"));

        var disabled = await Post(client, "closed", auth, "off@example.com");
        Assert.Contains("Account is disabled", await Html(disabled));
        Assert.False(disabled.Headers.Contains("Set-Cookie"));

        var forged = await Post(client, "closed", auth[..^4] + "AAAA", "dave@example.com");
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        Assert.Contains("timed out", await Html(forged));

        // Login by email works for a user whose username differs; most recently used user is listed first.
        Assert.Equal(HttpStatusCode.Redirect, (await Post(client, "closed", auth, "CAROL@example.com")).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await Post(client, "closed", auth, "dave@example.com")).StatusCode);
        var listed = await Html(await client.GetAsync(Auth("closed", Request + "&prompt=login"), Ct));
        Assert.True(listed.IndexOf("value=\"dave@example.com\"") < listed.IndexOf("value=\"carol@example.com\""));
    }

    static Task<HttpResponseMessage> PostRegistration(HttpClient client, string realm, params (string Name, string Value)[] fields) =>
        client.PostAsync($"/realms/{realm}/login-actions/registration",
            new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value))), Ct);

    const string Shop = """
        {
          "realm": "shop",
          "registrationAllowed": true,
          "roles": { "realm": [{ "name": "admin" }] },
          "registrationFields": [
            { "name": "firstName", "label": "First name", "required": true },
            { "name": "lastName", "label": "Last name", "required": true },
            { "name": "phone", "label": "Phone", "type": "tel", "claim": "phone_number" },
            { "name": "tenant", "label": "Tenant", "type": "select", "options": ["acme", "globex"], "claim": "tenant" }
          ]
        }
        """;

    [Fact]
    public async Task Unknown_email_registers_with_configured_fields_roles_and_claims()
    {
        File.WriteAllText(Path.Combine(importDir, "shop.json"), Shop);
        var factory = Start();
        var client = Browser(factory);

        var login = await Html(await client.GetAsync(Auth("shop", Request + "&scope=openid&nonce=n1"), Ct));
        Assert.Contains("No users yet. Type any email to create one.", login);
        var registration = await Post(client, "shop", Field(login, "auth"), "New@Example.com");
        Assert.Equal(HttpStatusCode.OK, registration.StatusCode);
        var html = await Html(registration);
        Assert.Contains("<input id=\"email\" name=\"email\" type=\"email\" readonly value=\"new@example.com\"", html);
        Assert.Contains("href=\"/realms/shop/protocol/openid-connect/auth?client_id=web&amp;redirect_uri=http%3A%2F%2Fapp.test%2Fcb&amp;response_type=code&amp;scope=openid&amp;state=s1&amp;nonce=n1\"", html);
        Assert.Contains("<label for=\"firstName\">First name (required)</label>", html);
        Assert.Contains("<input id=\"phone\" name=\"phone\" type=\"tel\" data-testid=\"phone\">", html);
        Assert.Contains("<option value=\"globex\">globex</option>", html);
        Assert.Contains("<option value=\"admin\"></option>", html);
        Assert.Contains("<input id=\"realmRoles\" name=\"realmRoles\"", html);
        Assert.Contains("<input id=\"clientRoles\" name=\"clientRoles\"", html);
        Assert.Contains("<textarea id=\"claims\" name=\"claims\"", html);
        Assert.Contains("<textarea id=\"agentNotes\" name=\"agentNotes\" required=\"required\"", html);
        Assert.Contains("Shown on the login page so agents can pick the right account later.", html);
        Assert.True(html.IndexOf("id=\"tenant\"") < html.IndexOf("Roles and claims") && html.IndexOf("Roles and claims") < html.IndexOf("id=\"agentNotes\""));
        Assert.Contains(">Create user and sign in</button>", html);
        Assert.Null(factory.Services.GetRequiredService<Store>().GetRealm("shop")!.FindUser("new@example.com"));

        var response = await PostRegistration(client, "shop", ("auth", Field(html, "auth")), ("email", "new@example.com"),
            ("firstName", "Nina"), ("lastName", "New"), ("phone", "+1 555 0100"), ("tenant", "acme"),
            ("realmRoles", "admin, auditor"), ("clientRoles", "store.api:orders.write, store.api:orders:read"),
            ("claims", """{"tenant_id": "acme", "permissions": ["orders:read"], "org": {"id": 42}}"""),
            ("agentNotes", "admin in tenant acme, used for billing tests"));
        var query = Query(response);
        Assert.Equal("s1", query["state"]);
        Assert.StartsWith("ZF_SESSION=", response.Headers.GetValues("Set-Cookie").Single());

        var realm = factory.Services.GetRequiredService<Store>().GetRealm("shop")!;
        var user = realm.FindUser("new@example.com")!;
        Assert.Equal(("new@example.com", "Nina", "New", true), (user.Email, user.FirstName, user.LastName, user.EmailVerified));
        Assert.Equal(["admin", "auditor"], user.RealmRoles);
        Assert.Equal(["orders.write", "orders:read"], user.ClientRoles["store.api"]);
        Assert.Equal("""{"tenant_id":"acme","permissions":["orders:read"],"org":{"id":42}}""", user.Claims!.ToJsonString());
        Assert.Equal("admin in tenant acme, used for billing tests", user.AgentNotes);
        var mapped = realm.AttributeClaims(user);
        Assert.Equal(("+1 555 0100", "acme", 2), ((string?)mapped["phone_number"], (string?)mapped["tenant"], mapped.Count));
        Assert.Contains(realm.Roles.Realm, r => r.Name == "auditor");
        Assert.Contains(realm.Roles.Client["store.api"], r => r.Name == "orders:read");

        // Fields with a claim, roles and extra claims reach the tokens with their JSON types.
        var tokens = await TokenTests.Exchange(client, "shop", ("grant_type", "authorization_code"), ("client_id", "web"),
            ("code", query["code"]!), ("redirect_uri", "http://app.test/cb"));
        foreach (var token in new[] { (string)tokens["access_token"]!, (string)tokens["id_token"]! })
        {
            var payload = TokenTests.Payload(token);
            Assert.Equal(user.Id, (string?)payload["sub"]);
            Assert.Equal(("+1 555 0100", "acme", "Nina New"), ((string?)payload["phone_number"], (string?)payload["tenant"], (string?)payload["name"]));
            Assert.Equal("""{"tenant_id":"acme","permissions":["orders:read"],"org":{"id":42}}""",
                new JsonObject { ["tenant_id"] = payload["tenant_id"]?.DeepClone(), ["permissions"] = payload["permissions"]?.DeepClone(), ["org"] = payload["org"]?.DeepClone() }.ToJsonString());
        }
        var access = TokenTests.Payload((string)tokens["access_token"]!);
        Assert.Equal(["offline_access", "default-roles-shop", "admin", "auditor", "uma_authorization"], access["realm_access"]!["roles"]!.AsArray().Select(r => (string?)r));
        Assert.Equal(["orders.write", "orders:read"], access["resource_access"]!["store.api"]!["roles"]!.AsArray().Select(r => (string?)r));
        Assert.Equal(["store.api", "account"], access["aud"]!.AsArray().Select(a => (string?)a));
        Assert.Equal("n1", (string?)TokenTests.Payload((string)tokens["id_token"]!)["nonce"]);

        var listed = await Html(await client.GetAsync(Auth("shop", Request + "&prompt=login"), Ct));
        Assert.Contains("value=\"new@example.com\"", listed);
        Assert.Contains("admin in tenant acme, used for billing tests", listed);
        Assert.Contains("Roles: admin, auditor, store.api:orders.write, store.api:orders:read", listed);
    }

    [Theory]
    [InlineData("claims", "{\"tenant_id\": ", "Invalid JSON:")]
    [InlineData("claims", "[1, 2]", "Claims must be a JSON object")]
    [InlineData("claims", "{\"sub\": \"x\", \"realm_access\": {}}", "Reserved claim names can&#x27;t be set: sub, realm_access.")]
    [InlineData("clientRoles", "orders.write", "is not a client:role pair")]
    [InlineData("firstName", "", "Please specify this field.")]
    [InlineData("agentNotes", "", "Please specify this field.")]
    [InlineData("tenant", "initech", "Choose one of the options.")]
    public async Task Invalid_registration_rerenders_with_values_and_persists_nothing(string field, string value, string message)
    {
        File.WriteAllText(Path.Combine(importDir, "shop.json"), Shop);
        var factory = Start();
        var client = Browser(factory);
        var login = await Html(await client.GetAsync(Auth("shop", Request), Ct));
        var auth = Field(await Html(await Post(client, "shop", Field(login, "auth"), "new@example.com")), "auth");

        var fields = new Dictionary<string, string>
        {
            ["auth"] = auth, ["email"] = "new@example.com", ["firstName"] = "Nina", ["lastName"] = "New", ["tenant"] = "acme",
            ["realmRoles"] = "brand-new-role", ["agentNotes"] = "notes kept", [field] = value,
        };
        var response = await PostRegistration(client, "shop", fields.Select(f => (f.Key, f.Value)).ToArray());
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var html = await Html(response);
        Assert.Matches($"<p class=\"error\" id=\"{field}-error\" data-testid=\"{field}-error\">[^<]*{Regex.Escape(message)}", html);
        Assert.Contains("value=\"brand-new-role\"", html);
        if (field != "agentNotes") Assert.Contains(">notes kept</textarea>", html);
        Assert.False(response.Headers.Contains("Set-Cookie"));

        var realm = factory.Services.GetRequiredService<Store>().GetRealm("shop")!;
        Assert.Empty(realm.Users);
        Assert.DoesNotContain(realm.Roles.Realm, r => r.Name == "brand-new-role");
        Assert.DoesNotContain("new@example.com", File.ReadAllText(Path.Combine(dataDir, "0factor.json")));
    }

    [Fact]
    public async Task Auto_created_realm_uses_env_registration_fields_and_optional_notes_can_be_skipped()
    {
        var factory = Start("""[{ "name": "dept", "label": "Department", "type": "select", "options": ["sales", "ops"], "required": true, "claim": "dept" }]""");
        var client = Browser(factory);
        var login = await Html(await client.GetAsync(Auth("fresh", Request), Ct));
        var html = await Html(await Post(client, "fresh", Field(login, "auth"), "x@example.com"));
        Assert.Contains("<label for=\"dept\">Department (required)</label>", html);
        Assert.DoesNotContain("firstName", html);

        var store = factory.Services.GetRequiredService<Store>();
        store.Update(_ => store.GetRealm("fresh")!.AgentNotesRequired = false);
        var response = await PostRegistration(client, "fresh", ("auth", Field(html, "auth")), ("email", "x@example.com"), ("dept", "ops"));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var user = store.GetRealm("fresh")!.FindUser("x@example.com")!;
        Assert.Equal(["ops"], user.Attributes["dept"]);
        Assert.Null(user.AgentNotes);

        // Registering an email that now exists is rejected; a forged auth is rejected.
        var again = await PostRegistration(client, "fresh", ("auth", Field(html, "auth")), ("email", "X@example.com"), ("dept", "ops"));
        Assert.Contains("Email already exists.", await Html(again));
        var forged = await PostRegistration(client, "fresh", ("auth", "nope"), ("email", "y@example.com"), ("dept", "ops"));
        Assert.Contains("timed out", await Html(forged));
    }

    /// <summary>Routes the test browser to 0factor (localhost) or the client app (app.test).</summary>
    sealed class Router(HttpMessageHandler zf, HttpMessageHandler app) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            new HttpMessageInvoker(request.RequestUri!.Host == "app.test" ? app : zf, false).SendAsync(request, ct);
    }
}
