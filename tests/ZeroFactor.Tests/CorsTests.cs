using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace ZeroFactor.Tests;

public sealed class CorsTests : IDisposable
{
    const string Oidc = "/realms/test/protocol/openid-connect/";
    readonly string dataDir = Directory.CreateTempSubdirectory("zf-cors-").FullName;
    readonly WebApplicationFactory<Program> factory;
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    public CorsTests() => factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        b.UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", Path.Combine(dataDir, "none")));

    public void Dispose()
    {
        factory.Dispose();
        Directory.Delete(dataDir, true);
    }

    [Theory]
    [InlineData("token")]
    [InlineData("userinfo")]
    [InlineData("logout")]
    [InlineData("revoke")]
    public async Task Preflight_is_answered_for_any_origin(string endpoint)
    {
        var request = new HttpRequestMessage(HttpMethod.Options, Oidc + endpoint);
        request.Headers.Add("Origin", "http://localhost:5173");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        var response = await factory.CreateClient().SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("http://localhost:5173", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Contains("Authorization", response.Headers.GetValues("Access-Control-Allow-Headers").Single());
    }

    [Fact]
    public async Task Token_response_allows_only_the_clients_web_origins()
    {
        var store = factory.Services.GetRequiredService<Store>();
        var realm = store.GetRealm("test")!;
        store.Update(_ =>
        {
            realm.Lenient = false;
            realm.Clients.Add(new Client { ClientId = "spa", PublicClient = true, WebOrigins = ["http://localhost:5173"] });
            realm.Clients.Add(new Client { ClientId = "redirects", PublicClient = true, WebOrigins = ["+"], RedirectUris = ["https://app.test/cb/*"] });
        });
        async Task<string?> AllowedOrigin(string client, string origin)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, Oidc + "token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code", ["client_id"] = client, ["code"] = "nope",
                }),
            };
            request.Headers.Add("Origin", origin);
            var response = await factory.CreateClient().SendAsync(request, Ct);
            // Errors carry CORS too, so the SPA can read invalid_grant instead of a network failure.
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            return response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values) ? values.Single() : null;
        }
        Assert.Equal("http://localhost:5173", await AllowedOrigin("spa", "http://localhost:5173"));
        Assert.Null(await AllowedOrigin("spa", "https://evil.test"));
        Assert.Equal("https://app.test", await AllowedOrigin("redirects", "https://app.test"));
        Assert.Null(await AllowedOrigin("redirects", "https://other.test"));
    }
}
