using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using static ZeroFactor.Tests.AuthorizeTests;

namespace ZeroFactor.Tests;

/// <summary>The Auth0-shaped endpoints that let @auth0/auth0-spa-js use 0factor: /authorize, /oauth/token (JSON body),
/// /.well-known/jwks.json, /userinfo and /v2/logout, plus the per-request <c>audience</c> on the access token.</summary>
public sealed class Auth0Tests : IDisposable
{
    const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const string Redirect = "http://localhost:9876/callback";
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
        File.WriteAllText(Path.Combine(importDir, "local.json"), """
            { "realm": "local", "lenient": true,
              "users": [{ "id": "auth0|abc", "username": "alice@example.com", "email": "alice@example.com",
                "claims": { "https://app.example.com/user_id": "u-1", "tenant_id": "acme" } }] }
            """);
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", importDir));
        disposables.Add(factory);
        return factory;
    }

    static StringContent Json(params (string Name, string Value)[] fields)
    {
        var json = new JsonObject();
        foreach (var (name, value) in fields) json[name] = value;
        return new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
    }

    static async Task<JsonObject> Body(HttpResponseMessage response)
    {
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!.AsObject();
    }

    static List<string?> Strings(JsonNode? array) => array!.AsArray().Select(n => (string?)n).ToList();

    [Fact]
    public async Task Spa_code_flow_sets_the_requested_audience_and_custom_claims_and_refresh_keeps_the_audience()
    {
        var factory = Start();
        var browser = Browser(factory);
        var client = factory.CreateClient();

        // auth0-spa-js sends the browser to /authorize with an `audience` naming the target API.
        var query = $"client_id=web&redirect_uri={Redirect}&response_type=code&scope=openid%20offline_access&audience=my.api"
            + $"&code_challenge={Challenge}&code_challenge_method=S256";
        var login = await browser.GetAsync($"/realms/local/authorize?{query}", Ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var redirect = await Post(browser, "local", Field(await Html(login), "auth"), "alice@example.com");
        var code = Query(redirect)["code"]!;

        // Then it POSTs the code to /oauth/token as JSON (auth0-spa-js's default body format).
        var tokens = await Body(await client.PostAsync("/realms/local/oauth/token", Json(
            ("grant_type", "authorization_code"), ("client_id", "web"), ("code", code!),
            ("code_verifier", Verifier), ("redirect_uri", Redirect)), Ct));

        var access = TokenTests.Payload((string)tokens["access_token"]!);
        Assert.Contains("my.api", Strings(access["aud"]));
        Assert.Equal("auth0|abc", (string?)access["sub"]);
        Assert.Equal(("u-1", "acme"),
            ((string?)access["https://app.example.com/user_id"], (string?)access["tenant_id"]));
        Assert.Equal("web", (string?)TokenTests.Payload((string)tokens["id_token"]!)["aud"]);

        var refreshed = await Body(await client.PostAsync("/realms/local/oauth/token", Json(
            ("grant_type", "refresh_token"), ("client_id", "web"), ("refresh_token", (string)tokens["refresh_token"]!)), Ct));
        Assert.Contains("my.api", Strings(TokenTests.Payload((string)refreshed["access_token"]!)["aud"]));
    }

    [Fact]
    public async Task Jwks_alias_matches_the_certs_endpoint()
    {
        var client = Start().CreateClient();
        var alias = await (await client.GetAsync("/realms/local/.well-known/jwks.json", Ct)).Content.ReadAsStringAsync(Ct);
        var certs = await (await client.GetAsync("/realms/local/protocol/openid-connect/certs", Ct)).Content.ReadAsStringAsync(Ct);
        Assert.Equal(certs, alias);
        Assert.Contains("\"kid\"", alias);
    }

    [Fact]
    public async Task V2_logout_maps_return_to_and_clears_the_session()
    {
        var factory = Start();
        var browser = Browser(factory);
        var query = $"client_id=web&redirect_uri={Redirect}&response_type=code&scope=openid&code_challenge={Challenge}&code_challenge_method=S256";
        var login = await browser.GetAsync($"/realms/local/authorize?{query}", Ct);
        await Post(browser, "local", Field(await Html(login), "auth"), "alice@example.com");

        var logout = await browser.GetAsync($"/realms/local/v2/logout?client_id=web&returnTo=http://localhost:9876/bye", Ct);
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.Equal("http://localhost:9876/bye", logout.Headers.Location!.ToString());
        Assert.Contains(logout.Headers.GetValues("Set-Cookie"), c => c.StartsWith("ZF_SESSION=;"));
    }
}
