using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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

    WebApplicationFactory<Program> Start()
    {
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", importDir));
        disposables.Add(factory);
        return factory;
    }

    static HttpClient Browser(WebApplicationFactory<Program> factory) => factory.CreateClient(new() { AllowAutoRedirect = false });

    static string Auth(string realm, string query) => $"/realms/{realm}/protocol/openid-connect/auth?{query}";

    static string Field(string html, string name) =>
        WebUtility.HtmlDecode(Regex.Match(html, $"name=\"{name}\" value=\"([^\"]*)\"").Groups[1].Value);

    static async Task<string> Html(HttpResponseMessage response)
    {
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        var html = await response.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain("type=\"password\"", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        return html;
    }

    /// <summary>Opens the login page for <paramref name="query"/> and posts only an email.</summary>
    static async Task<HttpResponseMessage> SignIn(HttpClient client, string query, string email, string realm = "test")
    {
        var login = await client.GetAsync(Auth(realm, query), Ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return await Post(client, realm, Field(await Html(login), "auth"), email);
    }

    static Task<HttpResponseMessage> Post(HttpClient client, string realm, string auth, string email) =>
        client.PostAsync($"/realms/{realm}/login-actions/authenticate",
            new FormUrlEncodedContent([new("auth", auth), new("email", email)]), Ct);

    static Dictionary<string, Microsoft.Extensions.Primitives.StringValues> Query(HttpResponseMessage response)
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
                o.BackchannelHttpHandler = new TokenEndpointStub(zfHandler, zf.Services.GetRequiredService<AuthCodes>(),
                    RealmKey.For(store, store.GetRealm("test")!));
            });
        await using var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/me", (HttpContext c) => c.User.FindFirst("sub")!.Value).RequireAuthorization();
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

    [Fact]
    public async Task Empty_realm_shows_empty_state_and_new_email_signs_in()
    {
        var factory = Start();
        var client = Browser(factory);
        var html = await Html(await client.GetAsync(Auth("fresh", Request), Ct));
        Assert.Contains("No users yet. Type any email to create one.", html);

        var response = await Post(client, "fresh", Field(html, "auth"), "New@Example.com");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(factory.Services.GetRequiredService<Store>().GetRealm("fresh")!.FindUser("new@example.com"));
    }

    /// <summary>Routes the test browser to 0factor (localhost) or the client app (app.test).</summary>
    sealed class Router(HttpMessageHandler zf, HttpMessageHandler app) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            new HttpMessageInvoker(request.RequestUri!.Host == "app.test" ? app : zf, false).SendAsync(request, ct);
    }

    /// <summary>
    /// Backchannel for the OIDC handler: discovery and JWKS come from 0factor; the token endpoint (#7) is stubbed by
    /// redeeming the code and signing an ID token with the realm key.
    /// </summary>
    sealed class TokenEndpointStub(HttpMessageHandler zf, AuthCodes codes, RealmKey key) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (!request.RequestUri!.AbsolutePath.EndsWith("/token"))
                return await new HttpMessageInvoker(zf, false).SendAsync(request, ct);

            var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(ct));
            var code = codes.Redeem(form["code"]!)!;
            Assert.Equal(code.RedirectUri, form["redirect_uri"]);
            Assert.Equal(code.CodeChallenge, Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"]!))));
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var idToken = Jwt.Create(key, new JsonObject
            {
                ["iss"] = Issuer, ["sub"] = code.UserId, ["aud"] = code.ClientId, ["exp"] = now + 300, ["iat"] = now,
                ["nonce"] = code.Nonce, ["auth_time"] = code.AuthTime, ["sid"] = code.Sid, ["typ"] = "ID",
            });
            var body = new JsonObject { ["access_token"] = "stub", ["token_type"] = "Bearer", ["expires_in"] = 300, ["id_token"] = idToken };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }
}
