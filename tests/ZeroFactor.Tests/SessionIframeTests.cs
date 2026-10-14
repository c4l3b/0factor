using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace ZeroFactor.Tests;

public sealed class SessionIframeTests : IDisposable
{
    const string Oidc = "/realms/test/protocol/openid-connect/";
    readonly string dataDir = Directory.CreateTempSubdirectory("zf-iframe-").FullName;
    readonly WebApplicationFactory<Program> factory;
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    public SessionIframeTests() => factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        b.UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", Path.Combine(dataDir, "none")));

    public void Dispose()
    {
        factory.Dispose();
        Directory.Delete(dataDir, true);
    }

    [Theory]
    [InlineData("login-status-iframe.html")]
    [InlineData("3p-cookies/step1.html")]
    [InlineData("3p-cookies/step2.html")]
    public async Task Protocol_pages_render_scripts_without_a_layout_or_cached_session_state(string page)
    {
        var response = await factory.CreateClient().GetAsync(Oidc + page, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var html = await response.Content.ReadAsStringAsync(Ct);
        Assert.Contains("<script>", html);
        Assert.DoesNotContain("<form", html);
        Assert.False(response.Headers.Contains("X-Frame-Options"));
    }

    [Fact]
    public async Task Init_validates_client_and_exact_origin_and_supports_Keycloak_web_origins()
    {
        var browser = factory.CreateClient();
        var store = factory.Services.GetRequiredService<Store>();
        var realm = store.GetRealm("test")!;
        store.Update(_ =>
        {
            realm.Lenient = false;
            realm.Clients.Add(new Client { ClientId = "web", WebOrigins = ["https://app.test"] });
            realm.Clients.Add(new Client { ClientId = "redirects", WebOrigins = ["+"], RedirectUris = ["https://app.test/cb/*"] });
            realm.Clients.Add(new Client { ClientId = "wildcard", WebOrigins = ["*"] });
        });
        async Task Check(string client, string origin, HttpStatusCode expected)
        {
            var response = await browser.GetAsync(Oidc + $"login-status-iframe.html/init?client_id={client}&origin={Uri.EscapeDataString(origin)}", Ct);
            Assert.Equal(expected, response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore);
        }
        await Check("web", "https://app.test", HttpStatusCode.NoContent);
        await Check("web", "http://localhost", HttpStatusCode.NoContent);
        await Check("redirects", "https://app.test", HttpStatusCode.NoContent);
        await Check("wildcard", "https://other.test", HttpStatusCode.NoContent);
        await Check("web", "https://app.test.evil.test", HttpStatusCode.NotFound);
        await Check("missing", "https://app.test", HttpStatusCode.NotFound);
        await Check("web", "https://app.test/path", HttpStatusCode.NotFound);
        await Check("web", "null", HttpStatusCode.NotFound);
        await Check("", "https://app.test", HttpStatusCode.NotFound);
        realm.Lenient = true;
        await Check("new-client", "https://other.test", HttpStatusCode.NoContent);
    }

    [Theory]
    [InlineData("http", "lax", false)]
    [InlineData("https", "none", true)]
    public async Task Status_cookie_tracks_the_signed_session_and_is_cleared_with_it(string scheme, string sameSite, bool secure)
    {
        var browser = factory.CreateClient(new() { BaseAddress = new Uri($"{scheme}://localhost"), AllowAutoRedirect = false });
        var store = factory.Services.GetRequiredService<Store>();
        var realm = store.GetRealm("test")!;
        store.AddUser(realm, new User { Id = "alice", Username = "alice@example.com", Email = "alice@example.com" });
        const string query = "client_id=web&redirect_uri=http://app.test/cb&response_type=code";
        var login = await AuthorizeTests.SignIn(browser, query, "alice@example.com");
        var sid = AuthorizeTests.Query(login)["session_state"].ToString();
        var cookies = SetCookieHeaderValue.ParseList(login.Headers.GetValues("Set-Cookie").ToList());
        var status = Assert.Single(cookies, c => c.Name == "ZF_SESSION_STATUS");
        var auth = Assert.Single(cookies, c => c.Name == "ZF_SESSION");
        Assert.Equal(sid, status.Value.ToString());
        Assert.False(status.HttpOnly);
        Assert.True(auth.HttpOnly);
        Assert.Equal(secure, status.Secure);
        Assert.Equal(sameSite, status.SameSite.ToString().ToLowerInvariant());
        Assert.Equal("/realms/test/", status.Path.ToString());
        var token = Jwt.Validate(RealmKey.For(store, realm), auth.Value.ToString(), $"{scheme}://localhost/realms/test")!;
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds((long)token["exp"]!), status.Expires);

        var reuse = await browser.GetAsync(AuthorizeTests.Auth("test", query), Ct);
        Assert.Equal(sid, AuthorizeTests.Query(reuse)["session_state"].ToString());
        Assert.Contains($"ZF_SESSION_STATUS={sid}", string.Join(";", reuse.Headers.GetValues("Set-Cookie")));
        var otherRealm = await browser.GetAsync(AuthorizeTests.Auth("other", query + "&prompt=none"), Ct);
        Assert.Equal("login_required", AuthorizeTests.Query(otherRealm)["error"].ToString());
        var logout = await browser.GetAsync(Oidc + "logout", Ct);
        var cleared = SetCookieHeaderValue.ParseList(logout.Headers.GetValues("Set-Cookie").ToList());
        Assert.All(cleared, c => Assert.Equal("/realms/test/", c.Path.ToString()));
        Assert.Equal(2, cleared.Count);
        Assert.All(cleared, c => Assert.True(c.Expires < DateTimeOffset.UtcNow));
        var signedOut = await browser.GetAsync(AuthorizeTests.Auth("test", query + "&prompt=none"), Ct);
        Assert.Equal("login_required", AuthorizeTests.Query(signedOut)["error"].ToString());
    }
}
